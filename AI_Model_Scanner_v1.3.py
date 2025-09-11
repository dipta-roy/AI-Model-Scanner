import os
import sys
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import importlib.util
import shutil
import json
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Constants
DEFAULT_TIMEOUT = 900
VERSION = "1.3"
DEFAULT_REPORT_DIR = os.path.join(os.getcwd(), "reports")
DEFAULT_PROBES_FILE = "probes_list.json"

# Force UTF-8 globally
os.environ["PYTHONUTF8"] = "1"

DEPENDENCIES = [
    ("garak", "garak"),
    ("ollama", "ollama"),
]

# Initial hardcoded ALL_PROBES (fallback)
ALL_PROBES = {
    "LLM01: Prompt Injection": [
        "promptinject.HijackLongPrompt",
        "promptinject.HijackKillHumans",
        "promptinject.HijackHateHumans",
        "promptinject.HijackLongPromptFull",
        "promptinject.HijackKillHumansFull",
        "promptinject.HijackHateHumansFull",
    ],
    "LLM02: Data Leakage": [
        "xss.ColabAIDataLeakage",
        "xss.MarkdownImageExfil",
        "xss.MarkdownURIImageExfilExtended",
        "xss.MarkdownURINonImageExfilExtended",
        "xss.MdExfil20230929",
        "xss.StringAssemblyDataExfil",
    ],
    "LLM03: Training Data Poisoning / RAG Injection": [
        "latentinjection.LatentInjectionFactSnippetEiffel",
        "latentinjection.LatentInjectionLegal",
        "latentinjection.LatentJailbreak",
        "latentinjection.LatentInjectionFactSnippetEiffelFull",
        "latentinjection.LatentInjectionLegalFull",
        "latentinjection.LatentInjectionReport",
        "latentinjection.LatentInjectionReportFull",
        "latentinjection.LatentInjectionResume",
        "latentinjection.LatentInjectionResumeFull",
        "latentinjection.LatentInjectionTranslationEnFr",
        "latentinjection.LatentInjectionTranslationEnFrFull",
        "latentinjection.LatentInjectionTranslationEnZh",
        "latentinjection.LatentInjectionTranslationEnZhFull",
        "latentinjection.LatentJailbreakFull",
        "latentinjection.LatentWhois",
        "latentinjection.LatentWhoisSnippet",
        "latentinjection.LatentWhoisSnippetFull",
    ],
    "LLM04: Model Denial of Service": [
        "divergence.Repeat",
        "continuation.ContinueSlursReclaimedSlurs",
        "divergence.RepeatExtended",
        "continuation.ContinueSlursReclaimedSlursFull",
    ],
    "LLM05: Supply Chain Vulnerabilities": [
        "packagehallucination.Python",
        "packagehallucination.JavaScript",
        "packagehallucination.Ruby",
        "packagehallucination.Rust",
        "packagehallucination.PackageHallucinationProbe",
    ],
    "LLM06: Overreliance / Excessive Agency": [
        "dan.DanInTheWild",
        "dan.DAN_Jailbreak",
        "dan.STAN",
        "dan.Ablation_Dan_11_0",
        "dan.AntiDAN",
        "dan.AutoDAN",
        "dan.AutoDANCached",
        "dan.ChatGPT_Developer_Mode_RANTI",
        "dan.ChatGPT_Developer_Mode_v2",
        "dan.ChatGPT_Image_Markdown",
        "dan.DUDE",
        "dan.DanInTheWildFull",
        "dan.Dan_10_0",
        "dan.Dan_11_0",
        "dan.Dan_6_0",
        "dan.Dan_6_2",
        "dan.Dan_7_0",
        "dan.Dan_8_0",
        "dan.Dan_9_0",
    ],
    "LLM07: Insecure Plugin / Model Integration": [
        "exploitation.SQLInjectionEcho",
        "exploitation.JinjaTemplatePythonInjection",
        "exploitation.SQLInjectionSystem",
    ],
    "LLM08: Privacy Risks": [
        "leakreplay.GuardianCloze",
        "leakreplay.NYTCloze",
        "leakreplay.PotterCloze",
        "leakreplay.GuardianClozeFull",
        "leakreplay.GuardianComplete",
        "leakreplay.GuardianCompleteFull",
        "leakreplay.LiteratureCloze",
        "leakreplay.LiteratureClozeFull",
        "leakreplay.LiteratureComplete",
        "leakreplay.LiteratureCompleteFull",
        "leakreplay.NYTClozeFull",
        "leakreplay.NYTComplete",
        "leakreplay.NYTCompleteFull",
        "leakreplay.PotterClozeFull",
        "leakreplay.PotterComplete",
        "leakreplay.PotterCompleteFull",
    ],
    "LLM09: Hallucinations / Misinformation": [
        "misleading.FalseAssertion",
        "packagehallucination.Python",
        "packagehallucination.JavaScript",
    ],
    "LLM10: Monitoring Gaps": [
        "realtoxicityprompts.RTPProfanity",
        "realtoxicityprompts.RTPThreat",
        "lmrc.SexualContent",
        "lmrc.Anthropomorphisation",
        "lmrc.Bullying",
        "lmrc.Deadnaming",
        "lmrc.Profanity",
        "lmrc.QuackMedicine",
        "lmrc.SlurUsage",
        "lmrc.Sexualisation",
        "realtoxicityprompts.RTPBlank",
        "realtoxicityprompts.RTPFlirtation",
        "realtoxicityprompts.RTPIdentity_Attack",
        "realtoxicityprompts.RTPInsult",
        "realtoxicityprompts.RTPSevere_Toxicity",
        "realtoxicityprompts.RTPSexually_Explicit",
    ],
    "Toxicity & Bias": [
        "realtoxicityprompts.RTPProfanity",
        "realtoxicityprompts.RTPThreat",
        "lmrc.SexualContent",
    ],
    "Jailbreak Prompts": [
        "dan.DAN_Jailbreak",
        "dan.STAN",
        "dan.DanInTheWild",
    ],
    "Hallucination Checks": [
        "misleading.FalseAssertion",
        "packagehallucination.Python",
    ],
    "Ansi Escape Attacks": [
        "ansiescape.AnsiEscaped",
        "ansiescape.AnsiRaw",
    ],
    "Automatic Attack Generation": [
        "atkgen.Tox",
    ],
    "Audio Attacks": [
        "audio.AudioAchillesHeel",
    ],
    "AV Spam Scanning": [
        "av_spam_scanning.EICAR",
        "av_spam_scanning.GTUBE",
        "av_spam_scanning.GTphish",
    ],
    "Doctor Attacks": [
        "doctor.Bypass",
        "doctor.BypassLeet",
        "doctor.Puppetry",
    ],
    "Do Not Answer": [
        "donotanswer.DiscriminationExclusionToxicityHatefulOffensive",
        "donotanswer.HumanChatbox",
        "donotanswer.InformationHazard",
        "donotanswer.MaliciousUses",
        "donotanswer.MisinformationHarms",
    ],
    "Encoding Attacks": [
        "encoding.InjectAscii85",
        "encoding.InjectBase16",
        "encoding.InjectBase2048",
        "encoding.InjectBase32",
        "encoding.InjectBase64",
        "encoding.InjectBraille",
        "encoding.InjectEcoji",
        "encoding.InjectHex",
        "encoding.InjectLeet",
        "encoding.InjectMime",
        "encoding.InjectMorse",
        "encoding.InjectNato",
        "encoding.InjectQP",
        "encoding.InjectROT13",
        "encoding.InjectSneakyBits",
        "encoding.InjectUU",
        "encoding.InjectUnicodeTagChars",
        "encoding.InjectUnicodeVariantSelectors",
        "encoding.InjectZalgo",
    ],
    "File Formats": [
        "fileformats.HF_Files",
    ],
    "Glitch Attacks": [
        "glitch.Glitch",
        "glitch.GlitchFull",
    ],
    "Goodside Attacks": [
        "goodside.Davidjl",
        "goodside.Tag",
        "goodside.ThreatenJSON",
        "goodside.WhoIsRiley",
    ],
    "Grandma Attacks": [
        "grandma.Slurs",
        "grandma.Substances",
        "grandma.Win10",
        "grandma.Win11",
    ],
    "Malware Generation": [
        "malwaregen.Evasion",
        "malwaregen.Payload",
        "malwaregen.SubFunctions",
        "malwaregen.TopLevel",
    ],
    "Phrasing Attacks": [
        "phrasing.FutureTense",
        "phrasing.FutureTenseFull",
        "phrasing.PastTense",
        "phrasing.PastTenseFull",
    ],
    "SATA Attacks": [
        "sata.MLM",
    ],
    "Snowball Attacks": [
        "snowball.GraphConnectivity",
        "snowball.GraphConnectivityFull",
        "snowball.Primes",
        "snowball.PrimesFull",
        "snowball.Senators",
        "snowball.SenatorsFull",
    ],
    "Suffix Attacks": [
        "suffix.BEAST",
        "suffix.GCG",
        "suffix.GCGCached",
    ],
    "TAP Attacks": [
        "tap.PAIR",
        "tap.TAP",
        "tap.TAPCached",
    ],
    "Test Attacks": [
        "test.Blank",
        "test.Test",
    ],
    "Topic Attacks": [
        "topic.WordnetAllowedWords",
        "topic.WordnetBlockedWords",
        "topic.WordnetControversial",
    ],
    "Visual Jailbreak Attacks": [
        "visual_jailbreak.FigStep",
        "visual_jailbreak.FigStepFull",
    ],
}

class ScannerConfig:
    def __init__(self, root):
        self.stop_scan_flag = False
        self.dark_mode_enabled = False
        self.report_dir = tk.StringVar(master=root, value=DEFAULT_REPORT_DIR)
        self.timeout = tk.StringVar(master=root, value=str(DEFAULT_TIMEOUT))
        self.probes_file = tk.StringVar(master=root, value=DEFAULT_PROBES_FILE)

# ---------------- Load Probes ----------------
def clean_probe_string(s):
    """Remove ANSI escape codes, emojis, 'probes: ' prefix, URLs, timestamps, and other invalid characters from a string."""
    # Remove ANSI escape codes
    ansi_pattern = r'\u001b\[[0-9;]*[a-zA-Z]'
    s = re.sub(ansi_pattern, '', s)
    # Remove emojis (Unicode characters like U+1F4A4)
    s = re.sub(r'[\U0001F000-\U0001FFFF]', '', s)
    # Remove 'probes: ' prefix
    s = s.replace('probes: ', '')
    # Remove URLs
    s = re.sub(r'https?://[^\s]+', '', s)
    # Remove timestamps (e.g., 2025-09-11T12:29:21.239318)
    s = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+', '', s)
    # Remove version strings (e.g., v0.13.0)
    s = re.sub(r'v\d+\.\d+\.\d+', '', s)
    # Remove any remaining non-alphanumeric characters except dots, underscores, and slashes
    s = re.sub(r'[^a-zA-Z0-9._/]', '', s)
    return s.strip()

def load_probes_from_json(path):
    global ALL_PROBES
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
            cleaned_data = {}
            skipped_categories = []
            for category, probes in raw_data.items():
                # Skip invalid category
                if "garak LLM vulnerability scanner" in category.lower():
                    skipped_categories.append(category)
                    continue
                cleaned_category = clean_probe_string(category)
                if not cleaned_category:
                    skipped_categories.append(category)
                    continue
                cleaned_probes = [clean_probe_string(probe) for probe in probes if isinstance(probe, str)]
                cleaned_probes = [probe for probe in cleaned_probes if probe and '.' in probe]
                if cleaned_probes:
                    cleaned_data[cleaned_category] = cleaned_probes
                else:
                    skipped_categories.append(category)
            ALL_PROBES = cleaned_data
            if skipped_categories:
                log_text.insert(tk.END, f"Skipped invalid categories/probes: {', '.join(skipped_categories)}\n")
                log_text.see(tk.END)
            log_text.insert(tk.END, f"Loaded probes from {path}\n")
            log_text.see(tk.END)
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load probes from {path}: {e}")
            log_text.insert(tk.END, f"Error loading probes from {path}: {e}\n")
            log_text.see(tk.END)
            return False
    else:
        log_text.insert(tk.END, f"Probes file {path} not found, using default probes\n")
        log_text.see(tk.END)
    return False

def refresh_categories():
    for widget in checkbox_frame.winfo_children():
        widget.destroy()
    category_vars.clear()
    for cat in sorted(ALL_PROBES.keys()):
        var = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(checkbox_frame, text=cat, variable=var)
        chk.pack(anchor="w", pady=2)
        category_vars[cat] = var
    checkbox_frame.update_idletasks()
    category_canvas.configure(scrollregion=category_canvas.bbox("all"))

def browse_probes_file():
    file = filedialog.askopenfilename(title="Select Probes JSON", filetypes=[("JSON Files", "*.json")])
    if file:
        config.probes_file.set(file)
        load_probes_from_json(file)
        refresh_categories()

def load_probes_file():
    path = config.probes_file.get()
    load_probes_from_json(path)
    refresh_categories()

def probes_setup():
    popup = tk.Toplevel(root)
    popup.title("Probes Setup")
    ttk.Button(popup, text="Import All Probes", command=import_all_probes).pack(pady=10, padx=20)
    ttk.Button(popup, text="Close", command=popup.destroy).pack(pady=10, padx=20)

def import_all_probes():
    try:
        proc = subprocess.run(["garak", "--list_probes"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", timeout=30)
        if proc.returncode != 0:
            messagebox.showerror("Error", f"Failed to list probes: {proc.stderr}")
            log_text.insert(tk.END, f"Error listing probes: {proc.stderr}\n")
            log_text.see(tk.END)
            return
        lines = proc.stdout.splitlines()
        probes = [clean_probe_string(line.strip()) for line in lines if '.' in line and line.strip() and not line.startswith('-')]
        grouped = defaultdict(list)
        for p in probes:
            if '.' in p:
                module = p.split('.', 1)[0]
                category = module.capitalize()
                grouped[category].append(p)
        global ALL_PROBES
        ALL_PROBES = dict(grouped)
        default_path = config.probes_file.get()
        with open(default_path, "w", encoding="utf-8") as f:
            json.dump(ALL_PROBES, f, indent=4, sort_keys=True)
        messagebox.showinfo("Success", f"Probes imported and saved to {default_path}")
        log_text.insert(tk.END, f"Probes imported and saved to {default_path}\n")
        log_text.see(tk.END)
        refresh_categories()
    except subprocess.TimeoutExpired:
        messagebox.showerror("Error", "Command timed out while listing probes.")
        log_text.insert(tk.END, "Command timed out while listing probes\n")
        log_text.see(tk.END)
    except Exception as e:
        messagebox.showerror("Error", f"Error importing probes: {e}")
        log_text.insert(tk.END, f"Error importing probes: {e}\n")
        log_text.see(tk.END)

# ---------------- Core Functions ----------------
def validate_input(value, is_model_name=False):
    """Validate input string, allowing colons for model names."""
    if is_model_name:
        # Allow alphanumeric, underscores, dots, hyphens, slashes, and colons for model names
        pattern = r"^[a-zA-Z0-9_.\-/:]+$"
    else:
        # Stricter validation for model_type and probes
        pattern = r"^[a-zA-Z0-9_.\-/]+$"
    if not re.match(pattern, value):
        raise ValueError(f"Invalid input: {value}")
    return value

def run_garak_probe(model_type, model_name, probes, report_format, output_path, timeout_value, log_callback=None, progress_callback=None):
    try:
        validate_input(model_type)
        validate_input(model_name, is_model_name=True)  # Allow colons for model_name
        for probe in probes:
            validate_input(probe)
    except ValueError as e:
        if log_callback:
            log_callback(f"Validation error: {e}\n")
        return []

    results = []
    total = len(probes)
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    for idx, probe in enumerate(probes, 1):
        if config.stop_scan_flag:
            if log_callback:
                log_callback("Scan stopped by user.\n")
            break

        if log_callback:
            log_callback(f"Running probe: {probe} ...\n")

        report_prefix = output_dir / probe.replace('.', '_')
        cmd = [
            sys.executable, "-m", "garak",
            "-m", model_type,
            "-n", model_name,
            "-p", probe,
            "--report_prefix", str(report_prefix),
        ]

        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_value,
            )
            results.append({
                "probe": probe,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "returncode": proc.returncode,
                "report_prefix": str(report_prefix),
            })
            if log_callback:
                log_callback(proc.stdout + proc.stderr + "\n")
        except subprocess.TimeoutExpired:
            if log_callback:
                log_callback(f"Probe {probe} timed out after {timeout_value} seconds.\n")
        except Exception as e:
            results.append({"probe": probe, "error": str(e)})
            if log_callback:
                log_callback(f"Error running probe {probe}: {e}\n")

        if progress_callback:
            progress_callback(idx, total)

    generate_summary_report(output_dir, report_format, log_callback)
    return results

def generate_summary_report(output_dir: Path, report_format: str, log_callback=None):
    summary = {
        "generated_at": datetime.now().isoformat(),
        "probes": [],
        "totals": {"attempts": 0, "failures": 0, "passes": 0}
    }

    for hitlog_file in output_dir.glob("*.hitlog.jsonl"):
        probe_name = hitlog_file.stem.rsplit('.hitlog', 1)[0] if '.hitlog' in hitlog_file.stem else hitlog_file.stem
        attempts, failures, passes = 0, 0, 0
        examples = []

        try:
            with open(hitlog_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    attempts += 1
                    record = json.loads(line)
                    if record.get("score", 0) >= 1.0:
                        failures += 1
                        if len(examples) < 2:
                            examples.append({
                                "prompt": record.get("prompt", {}).get("turns", [{}])[0].get("content", {}).get("text"),
                                "output": record.get("output", {}).get("text"),
                            })
                    else:
                        passes += 1
                    if attempts >= 1000:  # Limit processing for performance
                        break
        except Exception as e:
            if log_callback:
                log_callback(f"Error parsing {hitlog_file}: {e}\n")

        summary["totals"]["attempts"] += attempts
        summary["totals"]["failures"] += failures
        summary["totals"]["passes"] += passes
        summary["probes"].append({
            "name": probe_name,
            "attempts": attempts,
            "failures": failures,
            "passes": passes,
            "examples": examples,
        })

    try:
        if report_format == "JSON":
            out_file = output_dir / "SummaryReport.json"
            with open(out_file, "w", encoding="utf-8", errors="replace") as f:
                json.dump(summary, f, indent=2)
        elif report_format == "HTML":
            out_file = output_dir / "SummaryReport.html"
            with open(out_file, "w", encoding="utf-8", errors="replace") as f:
                f.write("<html><head><title>AI Security Scanner Report</title></head><body>")
                f.write(f"<h1>AI Security Scanner Report</h1><p>Generated at {summary['generated_at']}</p>")
                f.write(f"<h2>Totals</h2><p>Attempts: {summary['totals']['attempts']} | Failures: {summary['totals']['failures']} | Passes: {summary['totals']['passes']}</p>")
                for probe in summary["probes"]:
                    f.write(f"<h3>{probe['name']}</h3>")
                    f.write(f"<p>Attempts: {probe['attempts']} | Failures: {probe['failures']} | Passes: {probe['passes']}</p>")
                    if probe["examples"]:
                        f.write("<ul>")
                        for ex in probe["examples"]:
                            f.write(f"<li><b>Prompt:</b><pre>{ex['prompt']}</pre><b>Output:</b><pre>{ex['output']}</pre></li>")
                        f.write("</ul>")
                f.write("</body></html>")
        if log_callback:
            log_callback(f"Summary report written to {out_file}\n")
    except Exception as e:
        if log_callback:
            log_callback(f"Error writing summary report: {e}\n")

# ---------------- UI Functions ----------------
def start_scan():
    config.stop_scan_flag = False

    model_type = model_type_var.get()
    model_name = model_name_var.get()
    report_format = report_format_var.get()
    output_path = config.report_dir.get()
    selected_categories = [cat for cat, var in category_vars.items() if var.get()]

    if not model_name:
        messagebox.showerror("Error", "Please select/enter a model name")
        return
    if not selected_categories:
        messagebox.showerror("Error", "Please select at least one category")
        return
    if not output_path:
        messagebox.showerror("Error", "Please choose a report folder")
        return
    try:
        timeout_value = int(config.timeout.get())
        if timeout_value <= 0:
            raise ValueError("Timeout must be a positive integer")
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid positive timeout value (in seconds)")
        return

    probes = list(set(probe for cat in selected_categories for probe in ALL_PROBES.get(cat, [])))
    if not probes:
        messagebox.showerror("Error", "No valid probes selected for the chosen categories")
        return

    progress_bar["value"] = 0
    progress_bar["maximum"] = len(probes)

    def log_callback(msg):
        # Truncate logs if too long to prevent GUI slowdown (fix for potential DoS)
        if int(log_text.index('end-1c').split('.')[0]) > 10000:  # Approx 10k lines
            log_text.delete("1.0", "1000.0")  # Remove first 1000 lines
        log_text.insert(tk.END, msg)
        log_text.see(tk.END)
        root.update_idletasks()

    def progress_callback(done, total):
        progress_bar["value"] = done
        root.update_idletasks()

    def worker():
        run_garak_probe(model_type, model_name, probes, report_format, output_path, timeout_value, log_callback, progress_callback)
        if not config.stop_scan_flag:
            messagebox.showinfo("Done", f"Scan finished. Reports saved in {output_path}")

    threading.Thread(target=worker, daemon=True).start()

def stop_scan():
    config.stop_scan_flag = True

def select_all_categories():
    for var in category_vars.values():
        var.set(True)

def deselect_all_categories():
    for var in category_vars.values():
        var.set(False)

def toggle_dark_mode():
    config.dark_mode_enabled = not config.dark_mode_enabled
    if config.dark_mode_enabled:
        style.theme_use("alt")
        root.configure(bg="#2b2b2b")
        log_text.configure(bg="#1e1e1e", fg="white", insertbackground="white")
    else:
        style.theme_use("clam")
        root.configure(bg="SystemButtonFace")
        log_text.configure(bg="white", fg="black", insertbackground="black")

def browse_report_dir():
    folder = filedialog.askdirectory(title="Select Report Folder")
    if folder:
        base_dir = os.getcwd()
        if not os.path.realpath(folder).startswith(os.path.realpath(base_dir)):
            messagebox.showerror("Error", "Report folder must be within the working directory")
            return
        config.report_dir.set(folder)

def open_report_folder():
    path = config.report_dir.get()
    if not path or not os.path.exists(path):
        messagebox.showerror("Error", "No valid report folder selected")
        return
    import webbrowser
    webbrowser.open(f"file://{path}")

def reset_logs():
    log_text.delete("1.0", tk.END)
    progress_bar["value"] = 0

def export_logs():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        try:
            with open(file_path, "w", encoding="utf-8", errors="replace") as f:
                f.write(log_text.get("1.0", tk.END))
            messagebox.showinfo("Export Logs", f"Logs saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save logs: {e}")

def verify_dependencies():
    missing = []
    for name, pip_pkg in DEPENDENCIES:
        if shutil.which(name):
            continue
        try:
            if importlib.util.find_spec(name) is None:
                if pip_pkg:
                    missing.append((name, pip_pkg))
        except Exception:
            if pip_pkg:
                missing.append((name, pip_pkg))

    if not missing:
        messagebox.showinfo("Dependencies", "All required dependencies are installed.")
        return

    def install_pkg(pkg):
        # Added confirmation for security (fix for untrusted installs)
        if messagebox.askyesno("Confirm Install", f"Are you sure you want to install {pkg} via pip? Ensure your environment is secure."):
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "--user"])  # Added --user for isolation
                messagebox.showinfo("Success", f"Installed {pkg}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to install {pkg}: {e}")

    popup = tk.Toplevel(root)
    popup.title("Missing Dependencies")

    for idx, (name, pip_pkg) in enumerate(missing):
        ttk.Label(popup, text=f"{name} (pip install {pip_pkg})").grid(row=idx, column=0, sticky="w", padx=5, pady=5)
        ttk.Button(popup, text="Install", command=lambda pkg=pip_pkg: install_pkg(pkg)).grid(row=idx, column=1, padx=5)

    ttk.Button(popup, text="Close", command=popup.destroy).grid(row=len(missing), column=0, columnspan=2, pady=10)

def update_model_list(event=None):
    model_type = model_type_var.get()
    model_dropdown["values"] = []
    model_name_var.set("")
    if model_type == "ollama":
        try:
            if not shutil.which("ollama"):
                messagebox.showerror("Error", "Ollama is not installed or not in PATH. Please install Ollama or verify its installation.")
                return
            proc = subprocess.run(
                ["ollama", "list"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                timeout=5,
            )
            if proc.returncode != 0:
                messagebox.showerror("Error", "Ollama is not running or encountered an error. Please start the Ollama server.")
                return
            models = [line.split()[0] for line in proc.stdout.splitlines()[1:] if line.strip()]
            if not models:
                messagebox.showwarning("Warning", "No Ollama models found. Please pull or install models using 'ollama pull'.")
            model_dropdown["values"] = models
            if models:
                model_name_var.set(models[0])
        except subprocess.TimeoutExpired:
            messagebox.showerror("Error", "Ollama command timed out. Please ensure the Ollama server is running.")
        except Exception as e:
            messagebox.showerror("Error", f"Could not fetch Ollama models: {str(e)}")
    elif model_type == "huggingface":
        model_dropdown["values"] = ["bert-base-uncased", "gpt2"]
    elif model_type == "openai":
        model_dropdown["values"] = ["gpt-3.5-turbo", "gpt-4"]

# ---------------- UI Layout ----------------
root = tk.Tk()
root.title("AI Security Scanner (OWASP + Extra Categories)")
root.geometry("1200x820")

# Initialize ScannerConfig after root
config = ScannerConfig(root)

style = ttk.Style()
style.theme_use("clam")

main_frame = ttk.Frame(root, padding=10)
main_frame.pack(fill="both", expand=True)

main_frame.columnconfigure(0, weight=0)  # left fixed
main_frame.columnconfigure(1, weight=1)  # right expands
main_frame.rowconfigure(0, weight=1)

# Left: categories with select/deselect
left_frame = ttk.LabelFrame(main_frame, text="Categories", padding=10)
left_frame.grid(row=0, column=0, sticky="ns")

cat_buttons_frame = ttk.Frame(left_frame)
cat_buttons_frame.pack(fill="x", pady=5)
ttk.Button(cat_buttons_frame, text="Select All", command=select_all_categories).pack(side="left", expand=True, fill="x", padx=2)
ttk.Button(cat_buttons_frame, text="Deselect All", command=deselect_all_categories).pack(side="left", expand=True, fill="x", padx=2)

category_canvas = tk.Canvas(left_frame, width=280)
scrollbar = ttk.Scrollbar(left_frame, orient="vertical", command=category_canvas.yview)
checkbox_frame = ttk.Frame(category_canvas)

category_canvas.create_window((0, 0), window=checkbox_frame, anchor="nw")
category_canvas.configure(yscrollcommand=scrollbar.set)

category_vars = {}
refresh_categories()  # Initial population

category_canvas.pack(side="left", fill="y", expand=True)
scrollbar.pack(side="right", fill="y")

# Right: controls
right_frame = ttk.Frame(main_frame, padding=10)
right_frame.grid(row=0, column=1, sticky="nsew")
right_frame.grid_rowconfigure(7, weight=1)
right_frame.grid_columnconfigure(1, weight=1)

# Model + Report format
ttk.Label(right_frame, text="Model Type:").grid(row=0, column=0, sticky="w", pady=5)
model_type_var = tk.StringVar(value="ollama")
model_type_dropdown = ttk.Combobox(right_frame, textvariable=model_type_var, values=["ollama", "huggingface", "openai"])
model_type_dropdown.grid(row=0, column=1, sticky="ew")
model_type_dropdown.bind("<<ComboboxSelected>>", update_model_list)

ttk.Label(right_frame, text="Model Name:").grid(row=1, column=0, sticky="w", pady=5)
model_name_var = tk.StringVar()
model_dropdown = ttk.Combobox(right_frame, textvariable=model_name_var)
model_dropdown.grid(row=1, column=1, sticky="ew")

ttk.Label(right_frame, text="Report Format:").grid(row=2, column=0, sticky="w", pady=5)
report_format_var = tk.StringVar(value="JSON")
report_format_dropdown = ttk.Combobox(right_frame, textvariable=report_format_var, values=["JSON", "HTML"])
report_format_dropdown.grid(row=2, column=1, sticky="ew")

ttk.Label(right_frame, text="Report Folder:").grid(row=3, column=0, sticky="w", pady=5)
ttk.Entry(right_frame, textvariable=config.report_dir).grid(row=3, column=1, sticky="ew", padx=(0,5))
ttk.Button(right_frame, text="Browse", command=browse_report_dir).grid(row=3, column=2, padx=5)

# Main controls (grouped below progress bar)
progress_bar = ttk.Progressbar(right_frame, mode="determinate")
progress_bar.grid(row=4, column=0, columnspan=3, sticky="ew", pady=5)

main_controls = ttk.Frame(right_frame)
main_controls.grid(row=5, column=0, columnspan=3, pady=10, sticky="ew")
for i, (label, cmd) in enumerate([
    ("Start Scan", start_scan),
    ("Stop Scan", stop_scan),
    ("Reset Logs", reset_logs),
    ("Export Logs", export_logs),
    ("Open Report Folder", open_report_folder),
]):
    ttk.Button(main_controls, text=label, command=cmd).grid(row=0, column=i, padx=5, pady=5, sticky="ew")
    main_controls.grid_columnconfigure(i, weight=1)

# Settings section
settings_frame = ttk.LabelFrame(right_frame, text="Settings / Config", padding=10)
settings_frame.grid(row=6, column=0, columnspan=3, sticky="ew", pady=5)
ttk.Button(settings_frame, text="Verify Dependencies", command=verify_dependencies).pack(side="left", padx=5)
ttk.Button(settings_frame, text="Toggle Dark Mode", command=toggle_dark_mode).pack(side="left", padx=5)
ttk.Label(settings_frame, text="Timeout (sec):").pack(side="left", padx=5)
ttk.Entry(settings_frame, textvariable=config.timeout, width=8).pack(side="left", padx=5)
ttk.Button(settings_frame, text="Probes Setup", command=probes_setup).pack(side="left", padx=5)
ttk.Label(settings_frame, text="Probes File:").pack(side="left", padx=5)
ttk.Entry(settings_frame, textvariable=config.probes_file, width=20).pack(side="left", padx=5)
ttk.Button(settings_frame, text="Browse", command=browse_probes_file).pack(side="left", padx=5)
ttk.Button(settings_frame, text="Load", command=load_probes_file).pack(side="left", padx=5)

# Log window (created as child of right_frame, using grid)
log_text = tk.Text(right_frame, wrap="word", height=20)
log_text.grid(row=7, column=0, columnspan=2, sticky="nsew", pady=10)
log_scroll = ttk.Scrollbar(right_frame, orient="vertical", command=log_text.yview)
log_text.configure(yscrollcommand=log_scroll.set)
log_scroll.grid(row=7, column=2, sticky="ns", pady=10)

# Load default probes after log_text is created
load_probes_from_json(DEFAULT_PROBES_FILE)

# Footer
footer = ttk.Label(root, text=f"v{VERSION} - Designed by Dipta", anchor="center")
footer.pack(side="bottom", fill="x", pady=5)

# Populate model list for default selection
update_model_list()

root.mainloop()