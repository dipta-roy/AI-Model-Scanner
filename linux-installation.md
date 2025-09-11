# Installation Instructions for AI_LLM_Scanner_v1.3.py on Kali Linux

This guide provides step-by-step instructions to install and run the `AI_LLM_Scanner_v1.3.py` script on Kali Linux. The script depends on the `garak` library, which we'll install using `pipx` to avoid environment conflicts, as direct `pip install garak` may fail due to system restrictions. These instructions assume you're running as a non-root user (e.g., `kali`) and have Kali Linux updated.

## Prerequisites
- **Kali Linux**: Ensure your system is up-to-date:
  ```bash
  sudo apt update && sudo apt upgrade -y
  ```
- **Python 3.10 or higher**: Check with `python3 --version`. If below 3.10, install a newer version:
  ```bash
  sudo apt install python3.11 -y
  ```
  (Use Python <=3.12, as `garak` supports Python >=3.10, <=3.12.)
- **Internet access**: Required for downloading packages.
- **Required tools**: Install `git`, `curl`, and build essentials:
  ```bash
  sudo apt install git curl build-essential python3-venv python3-pip -y
  ```
- **Script file**: Save `AI_LLM_Scanner_v1.3.py` in your working directory (e.g., `~/Downloads` or a project folder). If you don't have it, copy the script content into a file using:
  ```bash
  nano AI_LLM_Scanner_v1.3.py
  ```
  Paste the script, save (Ctrl+O, Enter), and exit (Ctrl+X).

## Step 1: Install pipx
`pipx` installs Python CLI applications in isolated virtual environments, preventing conflicts with system packages.

1. Open a terminal.
2. Install `pipx` via `apt` (recommended for Kali):
   ```bash
   sudo apt install pipx -y
   ```
   If `apt` fails, install manually:
   ```bash
   python3 -m pip install --user pipx
   python3 -m pipx ensurepath
   ```
3. Verify installation:
   ```bash
   pipx --version
   ```
   You should see a version number (e.g., 1.2.0 or higher).

## Step 2: Install garak Using pipx
The `garak` library is the core dependency for the script.

1. Install `garak` in an isolated environment:
   ```bash
   pipx install garak
   ```
   - This creates a virtual environment at `~/.local/share/pipx/venvs/garak/` and adds the `garak` executable to `~/.local/bin/`.
   - If you encounter errors or have a previous installation, force reinstall:
     ```bash
     pipx install --force garak
     ```
2. Add `~/.local/bin/` to your PATH (if not already added):
   ```bash
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
   source ~/.bashrc
   ```
3. Verify `garak` installation:
   ```bash
   garak --help
   ```
   - This should display the help menu without errors.
   - Check the Python module:
     ```bash
     ~/.local/share/pipx/venvs/garak/bin/python -c "import garak; print(garak.__version__)"
     ```
     - It should print the version (e.g., 0.13.0).

## Step 3: Install Additional Dependencies
The script uses `tkinter` for the GUI and optionally `ollama` for certain models.

1. Install `tkinter`:
   ```bash
   sudo apt install python3-tk -y
   ```
2. If using Ollama models (optional):
   - Install Ollama:
     ```bash
     curl -fsSL https://ollama.com/install.sh | sh
     ```
   - Start the Ollama server:
     ```bash
     ollama serve &
     ```
   - Pull a test model (e.g., `llama3`):
     ```bash
     ollama pull llama3
     ```
3. Other dependencies (e.g., `subprocess`, `threading`, `json`) are part of Python’s standard library, so no additional installation is needed.

## Step 4: Prepare the Script
1. Navigate to the directory containing `AI_LLM_Scanner_v1.3.py`:
   ```bash
   cd /path/to/your/script/directory
   ```
   (Replace with your actual path, e.g., `~/Downloads`.)
2. Make the script executable (optional but recommended):
   ```bash
   chmod +x AI_LLM_Scanner_v1.3.py
   ```

## Step 5: Run the Script
Since `garak` is installed in a `pipx` environment, use the corresponding Python executable to avoid "No module named garak" errors.

1. Run the script with the `pipx` Python:
   ```bash
   ~/.local/share/pipx/venvs/garak/bin/python AI_LLM_Scanner_v1.3.py
   ```
   - Replace `~/.local/share/pipx/venvs/garak/bin/python` with the full path if your username isn’t `kali` (e.g., `/home/yourusername/.local/share/pipx/venvs/garak/bin/python`).
2. Alternatively, update the script’s shebang for convenience:
   - Open the script:
     ```bash
     nano AI_LLM_Scanner_v1.3.py
     ```
   - Modify the first line to:
     ```
     #!/home/kali/.local/share/pipx/venvs/garak/bin/python
     ```
     (Use your username if different, e.g., `/home/yourusername/.local/share/pipx/venvs/garak/bin/python`.)
   - Save (Ctrl+O, Enter) and exit (Ctrl+X).
   - Run directly:
     ```bash
     ./AI_LLM_Scanner_v1.3.py
     ```

## Step 6: Using the Script
- The script launches a GUI.
- Select a model type (e.g., `ollama`), model name (e.g., `llama3`), categories to scan, and click "Start Scan."
- Reports are saved in the specified folder (default: `./reports` in the script’s directory).
- Use the "Probes Setup" button to import probes if `probes_list.json` is missing.

## Step 7: Troubleshooting
- **"No module named garak"**:
  - Ensure you’re using the `pipx` Python (`~/.local/share/pipx/venvs/garak/bin/python`).
  - Verify the module:
    ```bash
    ~/.local/share/pipx/venvs/garak/bin/python -c "import garak; print(garak.__version__)"
    ```
  - If it fails, reinstall `garak` (Step 2).
- **Permission errors**: Run commands without `sudo` unless specified. Check ownership:
  ```bash
  ls -l ~/.local/share/pipx/
  ```
- **GUI not appearing**: Ensure `python3-tk` is installed. Test with:
  ```bash
  python3 -c "import tkinter"
  ```
- **Ollama errors**: Ensure the Ollama server is running (`ollama serve &`).
- **Script hangs/timeouts**: Increase the timeout in the GUI or check system resources (CPU/memory).
- **Probes not loading**: Ensure `probes_list.json` is in the script’s directory or use the "Import All Probes" button in the GUI.
- **Environment conflicts**: Deactivate other virtual environments:
  ```bash
  deactivate  # For virtualenv
  conda deactivate  # For Conda
  ```
- **Reinstall everything**: If issues persist:
  ```bash
  pipx uninstall garak
  ```
  Then repeat Step 2.

## Notes
- Run all commands as the `kali` user (or your username), not root, unless specified.
- If errors occur, note the exact message for debugging.
- The script should now run without issues, leveraging the isolated `pipx` environment for `garak`.