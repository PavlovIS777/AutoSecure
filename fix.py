import os
import sys
import subprocess
import json
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import requests
from rich.console import Console

console = Console()

@dataclass
class Vulnerability:
    tool: str
    file_path: str
    line: int
    message: str
    severity: str
    column: Optional[int] = None

class StaticAnalyzer:
    def __init__(self, source_dir: Path, output_dir: Path):
        self.source_dir = source_dir
        self.reports_dir = output_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def run_all(self) -> List[Vulnerability]:
        vulnerabilities = []
        vulnerabilities.extend(self._run_cppcheck())
        vulnerabilities.extend(self._run_flawfinder())
        return vulnerabilities

    def _run_cppcheck(self) -> List[Vulnerability]:
        xml_path = self.reports_dir / "cppcheck.xml"
        cmd = [
            "cppcheck", "--enable=warning,performance,portability,style", 
            "--inconclusive", "--xml", "--xml-version=2", 
            str(self.source_dir)
        ]
        
        with open(xml_path, "w") as f:
            subprocess.run(cmd, stderr=f, stdout=subprocess.DEVNULL)

        vulns = []
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for error in root.iter("error"):
                location = error.find("location")
                if location is not None:
                    file_path = location.get("file")
                    if file_path:
                        abs_path = str(Path(file_path).resolve())
                        vulns.append(Vulnerability(
                            tool="cppcheck",
                            file_path=abs_path,
                            line=int(location.get("line", 0)),
                            message=error.get("msg", ""),
                            severity=error.get("severity", "info")
                        ))
        except ET.ParseError:
            pass
        
        return vulns

    def _run_flawfinder(self) -> List[Vulnerability]:
        csv_path = self.reports_dir / "flawfinder.csv"
        cmd = f"flawfinder --quiet --csv {self.source_dir} > {csv_path}"
        subprocess.run(cmd, shell=True)

        vulns = []
        if csv_path.exists():
            with open(csv_path, 'r') as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.strip().split(',')
                    if len(parts) >= 7:
                        vulns.append(Vulnerability(
                            tool="flawfinder",
                            file_path=str(Path(parts[0]).resolve()),
                            line=int(parts[1]) if parts[1].isdigit() else 0,
                            message=parts[6],
                            severity=parts[3]
                        ))
        return vulns

class AIHealer:
    def __init__(self, model_name: str, api_url: str = "http://localhost:11434/api/generate"):
        self.model_name = model_name
        self.api_url = api_url

    def fix_file(self, file_path: str, vulnerabilities: List[Vulnerability]):
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            console.print(f"[red]File not found: {file_path}[/red]")
            return

        grouped_vulns = self._group_vulnerabilities(vulnerabilities)
        
        modified_lines = lines[:]
        fixed_count = 0

        for vuln_group in grouped_vulns:
            if not vuln_group:
                continue
                
            primary_vuln = vuln_group[0]
            line_idx = primary_vuln.line - 1
            
            if 0 <= line_idx < len(modified_lines):
                original_line = modified_lines[line_idx]
                indentation = self._get_indentation(original_line)
                
                context_start = max(0, line_idx - 2)
                context_end = min(len(modified_lines), line_idx + 3)
                code_context = "".join(modified_lines[context_start:context_end])
                
                console.print(f"\n[yellow]Fixing {primary_vuln.tool} issue in {Path(file_path).name}:{primary_vuln.line}[/yellow]")
                console.print(f"[dim]Vulnerability: {primary_vuln.message}[/dim]")
                console.print(f"[dim]Original: {original_line.rstrip()}[/dim]")
                
                fix_data = self._query_llm_for_fix(original_line, code_context, primary_vuln)
                
                if fix_data and 'fixed_line' in fix_data:
                    fixed_content = fix_data['fixed_line'].rstrip()
                    fixed_line = indentation + fixed_content + '\n'

                    if fixed_line != original_line and len(fixed_content.strip()) > 0:
                        modified_lines[line_idx] = fixed_line
                        fixed_count += 1
                        console.print(f"[green]✓ Fixed line {primary_vuln.line}:[/green]")
                        console.print(f"  [red]- {original_line.rstrip()}[/red]")
                        console.print(f"  [green]+ {fixed_line.rstrip()}[/green]")
                        console.print(f"  [blue]  Reason: {fix_data.get('reason', 'Security improvement')}[/blue]")
                    else:
                        console.print(f"[blue]~ No significant change needed[/blue]")
                else:
                    console.print(f"[orange3]~ Could not generate fix[/orange3]")

        if fixed_count > 0:
            backup_path = Path(file_path).with_suffix('.bak')
            shutil.copy2(file_path, backup_path)
            console.print(f"\n[yellow]Backup created: {backup_path}[/yellow]")
            
            with open(file_path, 'w') as f:
                f.writelines(modified_lines)
            
            console.print(f"[green]Fixed {fixed_count} issues in {Path(file_path).name}[/green]")
        else:
            console.print(f"[blue]No changes made to {Path(file_path).name}[/blue]")

    def _get_indentation(self, line: str) -> str:
        stripped = line.lstrip()
        if not stripped or stripped == '\n':
            return line
        return line[:len(line) - len(stripped)]

    def _group_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[List[Vulnerability]]:
        if not vulnerabilities:
            return []
        
        sorted_vulns = sorted(vulnerabilities, key=lambda x: x.line)
        groups = []
        current_group = [sorted_vulns[0]]
        
        for vuln in sorted_vulns[1:]:
            if vuln.line - current_group[-1].line <= 3:
                current_group.append(vuln)
            else:
                groups.append(current_group)
                current_group = [vuln]
        
        if current_group:
            groups.append(current_group)
            
        return groups

    def _query_llm_for_fix(self, original_line: str, code_context: str, issue: Vulnerability) -> Optional[Dict]:
        prompt = f"""
        You are a secure C/C++ coding expert. Fix ONLY the specific vulnerability on the target line.

        VULNERABILITY: {issue.message}
        FILE: {issue.file_path}
        TARGET LINE: {original_line}

        SURROUNDING CODE:
        {code_context}

        INSTRUCTIONS:
        - Fix ONLY the vulnerability in the target line
        - Preserve all other functionality and logic
        - Keep the same variable names and structure where possible
        - Maintain the original indentation and formatting
        - Return valid JSON with the corrected single line (without leading/trailing whitespace for indentation)
        - Do NOT change surrounding lines unless absolutely necessary

        JSON FORMAT:
        {{
            "reason": "Brief explanation of the fix",
            "fixed_line": "The corrected content of the line (without indentation prefix)"
        }}
        """
        
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.1, "num_ctx": 4096}
        }
        
        try:
            response = requests.post(self.api_url, json=payload)
            response.raise_for_status()
            response_json = response.json()
            return json.loads(response_json.get("response", "{}"))
        except Exception as e:
            console.print(f"[red]LLM query failed: {e}[/red]")
            return None

def setup_checked_folder(source_path: Path) -> Path:
    checked_path = source_path / "checked"
    if checked_path.exists():
        shutil.rmtree(checked_path)
    checked_path.mkdir()

    for item in source_path.iterdir():
        if item.name == "checked":
            continue
            
        dest = checked_path / item.name
        
        if item.is_dir():
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)
            
    return checked_path

def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage: python script.py <source_folder> [model_name][/red]")
        sys.exit(1)
        
    source_folder = Path(sys.argv[1]).resolve()
    model_name = sys.argv[2] if len(sys.argv) > 2 else "codellama:7b"
    
    if not source_folder.exists():
        console.print(f"[red]Source folder does not exist: {source_folder}[/red]")
        sys.exit(1)

    console.print(f"[bold blue]Preparing checked folder in {source_folder}...[/bold blue]")
    checked_folder = setup_checked_folder(source_folder)

    analyzer = StaticAnalyzer(checked_folder, checked_folder)
    all_issues = analyzer.run_all()

    if not all_issues:
        console.print("[green]No issues found[/green]")
        sys.exit(0)

    files_with_issues = {}
    for issue in all_issues:
        if issue.file_path not in files_with_issues:
            files_with_issues[issue.file_path] = []
        files_with_issues[issue.file_path].append(issue)

    healer = AIHealer(model_name=model_name)

    console.print(f"[bold]Found {len(all_issues)} issues in {len(files_with_issues)} files[/bold]")

    for file_path, issues in files_with_issues.items():
        file_obj = Path(file_path)
        if file_obj.exists():
            console.print(f"\n[bold]Processing {file_obj.name}...[/bold]")
            healer.fix_file(file_path, issues)
        else:
            console.print(f"[red]File not found: {file_path}[/red]")
            
    console.print(f"\n[bold green]Done. Results in {checked_folder}[/bold green]")
    console.print("[yellow]Remember to test the fixed code thoroughly![/yellow]")
    
if __name__ == "__main__":
    main()