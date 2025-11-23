Here is a comprehensive `README.md` file for your project. It covers all the features, prerequisites, installation steps, and usage instructions you specified.

***

# AutoSecure

**AutoSecure** is an automated vulnerability detection and remediation tool designed for C/C++ codebases. It combines traditional static analysis tools with Generative AI to not only find bugs but also propose secure fixes locally.

## 🚀 Features

*   **Dual-Engine Detection**: Utilizes industry-standard static analysis tools **Cppcheck** and **Flawfinder** to identify potential security loopholes, memory leaks, and undefined behaviors.
*   **AI-Powered Remediation**: Integrates with **CodeLlama:7b** (running locally) to analyze detected vulnerabilities and generate secure code patches automatically.
*   **Privacy Focused**: All analysis and AI generation happen locally on your machine. No code leaves your environment.
*   **Automated Workflow**: Scans a directory, parses vulnerability reports, and prompts the LLM for fixes in a single workflow.

## 📋 Prerequisites

Before running AutoSecure, ensure you have the following installed:

1.  **Python 3.8+**
2.  **Cppcheck** (System binary)
3.  **Ollama** (For running the LLM)

### Installing Cppcheck
You need the `cppcheck` binary accessible in your system path.

*   **Ubuntu/Debian**: `sudo apt install cppcheck`
*   **macOS**: `brew install cppcheck`
*   **Windows**: Download from [cppcheck.sourceforge.io](http://cppcheck.sourceforge.io/)

## 🛠️ Installation Guide

Follow these steps to set up the environment.

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/autosecure.git
cd autosecure
```

### 2. Set up Python Dependencies
It is recommended to use a virtual environment.

```bash
# Create virtual environment
python -m venv venv

# Activate environment (Linux/macOS)
source venv/bin/activate

# Activate environment (Windows)
venv\Scripts\activate
```

Install the required Python libraries (including `flawfinder`):

```bash
pip install -r requirements.txt
```

### 3. Install and Setup CodeLlama
AutoSecure relies on [Ollama](https://ollama.com/) to run the `codellama:7b` model.

1.  Download and install **Ollama** from [ollama.com](https://ollama.com/download).
2.  Start the Ollama service (if it's not running automatically in the background).
3.  Pull the specific model required for this tool:

```bash
ollama pull codellama:7b
```

*Note: The download is approximately 3.8 GB. Ensure you have stable internet and sufficient disk space.*

## 🏃 Usage

To scan a directory and generate fixes, simply point the `check.py` script to your source code folder.

```bash
python check.py /path/to/check_dir
```

### Example
If your C++ project is located in `./my_project`, run:

```bash
python check.py ./my_project
```

## ⚙️ How It Works

1.  **Scan**: The script executes `cppcheck` and `flawfinder` against the provided directory.
2.  **Parse**: It aggregates the logs to identify specific lines of code with security severity.
3.  **Contextualize**: It extracts the vulnerable code snippets.
4.  **Fix**: It spins up a connection to the local `codellama:7b` server, sends the code context, and requests a secure rewritten version of the specific function or block.

## 📄 Requirements.txt
Ensure your `requirements.txt` looks something like this (example):

```text
flawfinder
requests
langchain       # If used for LLM chain
langchain-community
```

##  license
[MIT](https://choosealicense.com/licenses/mit/)