# AI LLM Vulnerability Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-1.3-brightgreen)](https://github.com/dipta-roy/AI-Model-Scanner/releases/tag/v1.3)

## Overview

AI LLM Vulnerability Scanner is a graphical user interface (GUI) tool designed to scan Large Language Models (LLMs) for security vulnerabilities using the [Garak](https://github.com/leondz/garak) framework. It allows users to probe AI models (such as those from Ollama, Hugging Face, or OpenAI) for common LLM risks based on the OWASP Top 10 for LLMs and additional custom categories.

The tool provides an intuitive Tkinter-based interface to select probe categories, configure models, run scans, and generate reports in JSON or HTML format. It supports timeout controls, log management, and dependency verification to ensure a smooth user experience.

This project is inspired by OWASP guidelines for LLM security and extends Garak's capabilities with categorized probes for easier vulnerability assessment.

## Features

- **User-Friendly GUI**: Built with Tkinter for easy interaction, including dropdowns for model selection, checkboxes for probe categories, and buttons for scan control.
- **Model Support**: Compatible with multiple LLM providers:
  - Ollama (local models, auto-detects installed models).
  - Hugging Face (e.g., bert-base-uncased, gpt2).
  - OpenAI (e.g., gpt-3.5-turbo, gpt-4; requires API keys configured in Garak).
- **Probe Categories**: Pre-defined categories based on OWASP LLM Top 10 and extras (e.g., Prompt Injection, Data Leakage, Jailbreak Prompts). Supports loading custom probes from JSON files.
- **Scan Management**: Start/stop scans, progress bar, real-time logging, and timeout settings (default: 900 seconds per probe).
- **Report Generation**: Outputs detailed hitlogs (.jsonl) per probe, plus a summary report in JSON or HTML format with totals, failures, passes, and example snippets.
- **Dependency Checker**: Built-in tool to verify and install missing dependencies like Garak and Ollama.
- **Dark Mode**: Toggle for better visibility in low-light environments.
- **Log and Export Tools**: View, reset, and export scan logs; open report folders directly.
- **Security Features**: Input validation to prevent injection attacks, path restrictions to avoid traversal, and timeouts to mitigate DoS risks.
- **Probes Import**: Import all available Garak probes dynamically and save to JSON for customization.

## Installation

### Prerequisites
- Python 3.8 or higher (tested on 3.12.3).
- Git for cloning the repository.

### Steps
1. Clone the repository:
   ```
   git clone https://github.com/dipta-roy/AI-Model-Scanner.git
   cd ai-llm-scanner
   ```

2. Install Python dependencies (if not already present; the tool can help install Garak and Ollama via the GUI):
   ```
   pip install garak ollama
   ```
   - Note: Ollama requires the Ollama server to be running. Download and install from [ollama.com](https://ollama.com/).

3. Run the application:
   ```
   python AI_Model_Scanner_v1.3.py
   ```

### Dependencies
- **Core Python Libraries** (built-in or standard):
  - `tkinter`: For the GUI (included in most Python installations).
  - `subprocess`, `threading`, `os`, `sys`, `pathlib`, `json`, `re`, `datetime`, `collections`: Standard libraries used for process management, file I/O, and data handling.
- **External Tools**:
  - [Garak](https://github.com/leondz/garak): The core LLM probing framework. Installed via `pip install garak`.
  - [Ollama](https://ollama.com/): For local LLM model support. Installed via `pip install ollama` (CLI wrapper), but requires the Ollama binary/server.
- **Optional**:
  - For Hugging Face or OpenAI models: Configure Garak accordingly (e.g., API keys for OpenAI).
- No additional pip-installable libraries are required beyond Garak and Ollama, as the tool uses Python's standard library for most functionality.

If dependencies are missing, use the "Verify Dependencies" button in the GUI to install them (with user confirmation for security).

## Usage

1. **Launch the App**: Run `python AI_LLM_Scanner_v1.2.py`.
2. **Select Model**:
   - Choose Model Type (e.g., Ollama).
   - Select or enter Model Name (auto-populates for Ollama).
3. **Choose Probes**:
   - Select categories from the left panel (use Select All/Deselect All).
   - Optionally, load custom probes via "Probes Setup" > "Import All Probes" or browse a JSON file.
4. **Configure Settings**:
   - Set Report Folder (must be a subdirectory of the current working directory for security).
   - Choose Report Format (JSON or HTML).
   - Adjust Timeout (in seconds).
5. **Run Scan**:
   - Click "Start Scan" to begin probing.
   - Monitor progress and logs in the bottom panel.
   - Stop if needed with "Stop Scan".
6. **View Results**:
   - Reports are saved in the specified folder (e.g., hitlogs per probe and a SummaryReport).
   - Use "Open Report Folder" to browse results.
   - Export logs for archiving.

### Example Workflow
- Select "ollama" as Model Type and "llama2" as Model Name.
- Check categories like "LLM01: Prompt Injection" and "Jailbreak Prompts".
- Set report to HTML and start the scan.
- Review the HTML summary for vulnerabilities detected.

## Probes Information

### What are Probes?
Probes are specialized tests from the Garak framework designed to detect vulnerabilities in LLMs. Each probe simulates attacks or scenarios to check if the model responds insecurely (e.g., leaking data, following malicious instructions).

The tool organizes probes into categories aligned with:
- **OWASP Top 10 for LLMs**: Covers risks like Prompt Injection (LLM01), Data Leakage (LLM02), etc.
- **Additional Categories**: Includes Toxicity & Bias, Jailbreak Prompts, Hallucination Checks, and specialized attacks (e.g., Encoding Attacks, Malware Generation).

### Source of Probes
- **Primary Source**: Probes are sourced from the Garak library (via `garak --list_probes` command).
- **Fallback/Default**: The code includes a hardcoded dictionary of ~200 probes as a fallback, categorized manually based on Garak's modules.
- **Customization**: 
  - Use "Probes Setup" > "Import All Probes" to fetch the latest from Garak and save to `probes_list.json`.
  - Load custom JSON files for tailored probe sets.
- **Cleaning Process**: Probes are cleaned (removing ANSI codes, emojis) for consistency.
- **Examples**:
  - LLM01: Prompt Injection – Includes probes like `promptinject.HijackLongPrompt`.
  - Jailbreak Prompts – Includes DAN variants like `dan.DAN_Jailbreak`.

For the full list of default probes, see the `ALL_PROBES` dictionary in the source code or export via the tool.

Updates to probes depend on Garak's releases; always check [Garak's GitHub](https://github.com/leondz/garak) for new probes.

## Security Considerations
- The tool runs subprocesses for Garak and Ollama – ensure these are trusted.
- Input validation prevents common attacks (e.g., regex checks on model names/probes).
- Reports are restricted to subdirectories to avoid unauthorized file access.
- No internet access is required during scans (except for OpenAI models via Garak).

## Credits
- Designed by Dipta.
- Powered by [Garak](https://github.com/leondz/garak) and [Ollama](https://ollama.com/).
- Inspired by OWASP LLM Top 10.
