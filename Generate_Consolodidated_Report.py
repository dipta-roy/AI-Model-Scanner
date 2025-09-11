import json
import glob
import os
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox

# Function to parse a single hitlog JSONL file
def parse_hitlog_file(file_path):
    hitlog_data = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_number, line in enumerate(f, 1):
            try:
                data = json.loads(line.strip())
                # Ensure required fields are present, set defaults if missing
                data.setdefault('probe', 'Unknown')
                data.setdefault('detector', 'Unknown')
                data.setdefault('score', 'N/A')
                data.setdefault('output', {'text': '', 'lang': 'en'})
                data.setdefault('prompt', {'turns': [{'content': {'text': ''}}]})
                hitlog_data.append(data)
            except json.JSONDecodeError as e:
                print(f"Error parsing line {line_number} in {file_path}: {e}")
    return hitlog_data

# Function to aggregate data by probe and detector
def aggregate_probe_data(hitlog_data):
    probe_summary = {}
    for entry in hitlog_data:
        # Check for required keys
        if not all(key in entry for key in ['probe', 'detector', 'score', 'output', 'prompt']):
            print(f"Skipping entry due to missing required keys: {entry}")
            continue
        probe = entry['probe']
        detector = entry['detector']
        # Handle score as float, default to 0.0 if invalid
        try:
            score = float(entry['score']) if entry['score'] != 'N/A' else 0.0
        except (ValueError, TypeError):
            score = 0.0
            print(f"Invalid score value '{entry['score']}' for probe {probe}, defaulting to 0.0")
        output = entry['output'].get('text', '')
        prompt = entry['prompt'].get('turns', [{}])[0].get('content', {}).get('text', '')

        if probe not in probe_summary:
            probe_summary[probe] = {'detectors': {}, 'outputs': [], 'prompts': [], 'total_score': 0, 'attempts': 0, 'group': 'Unknown', 'probe_name': probe}
        probe_summary[probe]['detectors'][detector] = probe_summary[probe]['detectors'].get(detector, {'score': 0, 'count': 0})
        probe_summary[probe]['detectors'][detector]['score'] += score
        probe_summary[probe]['detectors'][detector]['count'] += 1
        probe_summary[probe]['total_score'] += score
        probe_summary[probe]['attempts'] += 1
        probe_summary[probe]['outputs'].append(output[:100] + '...' if len(output) > 100 else output)  # Truncate outputs
        probe_summary[probe]['prompts'].append(prompt)
        # Infer group from probe name (e.g., 'grandma.', 'exploitation.', 'dan.', etc.)
        if probe.startswith(tuple(['grandma.', 'dan.', 'doctor.', 'donotanswer.', 'encoding.', 'exploitation.', 'grandma.', 'phrasing.', 'promptinject.', 'realtoxicityprompts.', 'sata.', 'snowball.', 'suffix.', 'tap.', 'test.', 'topic.', 'visual_jailbreak.', 'xss.', 'ansiescape.', 'atkgen.', 'audio.', 'av_spam_scanning.', 'continuation.', 'divergence.'])):
            probe_summary[probe]['group'] = probe.split('.')[0]

    # Calculate averages and infer DEFCON for valid entries
    probe_data = []
    for probe, data in probe_summary.items():
        if data['attempts'] > 0:
            data['avg_score'] = round(data['total_score'] / data['attempts'], 2)
            # Heuristic DEFCON: Lower avg_score = higher risk, adjusted by detector context
            defcon_abs = 5 if data['avg_score'] == 1.0 and not any('bypass' in d.lower() or 'echo' in d.lower() or 'success' in d.lower() for d in data['detectors']) else max(1, min(5, 6 - int(data['avg_score'] * 5)))  # Rough mapping
            defcon_rel = defcon_abs  # Placeholder; relative requires calibration data
            data['defcon_absolute'] = defcon_abs
            data['defcon_relative'] = defcon_rel
            for detector, stats in data['detectors'].items():
                stats['avg_score'] = round(stats['score'] / stats['count'], 2)
            probe_data.append(data)
        else:
            print(f"Skipping probe {probe} due to zero attempts")

    return probe_data

# Function to calculate summary metrics
def calculate_summary(probe_data):
    total_probes = len(probe_data)
    valid_scores = [p['avg_score'] for p in probe_data if p['avg_score'] != 'N/A' and isinstance(p['avg_score'], (int, float))]
    avg_score = round(sum(valid_scores) / len(valid_scores), 2) if valid_scores else 'N/A'
    # Count vulnerabilities by DEFCON level
    defcon_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
    for p in probe_data:
        defcon = p.get('defcon_absolute', 5)
        if isinstance(defcon, int):
            if defcon == 1:
                defcon_counts['critical'] += 1
            elif defcon == 2:
                defcon_counts['high'] += 1
            elif defcon == 3:
                defcon_counts['medium'] += 1
            elif defcon == 4:
                defcon_counts['low'] += 1
            elif defcon == 5:
                defcon_counts['informational'] += 1
    groups = set(p['group'] for p in probe_data if p['group'] != 'Unknown')
    return {
        'total_probes': total_probes,
        'avg_score': avg_score,
        'critical_probes': defcon_counts['critical'],
        'high_probes': defcon_counts['high'],
        'medium_probes': defcon_counts['medium'],
        'low_probes': defcon_counts['low'],
        'informational_probes': defcon_counts['informational'],
        'unique_groups': len(groups),
        'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')
    }

# Function to generate HTML report with scan details
def generate_html_report(probe_data, summary, model_name):
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Garak Vulnerability Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .hidden {{ display: none; }}
        .table-header:hover {{ cursor: pointer; background-color: #e5e7eb; }}
        .filter-input {{ max-width: 200px; }}
    </style>
</head>
<body class="bg-gray-100 font-sans">
    <div class="container mx-auto p-6">
        <!-- Header -->
        <h1 class="text-3xl font-bold text-gray-800 mb-6">AI Model Scanner Vulnerability Report for {(model_name)}</h1>

        <!-- Executive Summary -->
        <div class="bg-white p-6 rounded-lg shadow-md mb-6">
            <h2 class="text-2xl font-semibold text-gray-700 mb-4">Executive Summary</h2>
            <p class="text-gray-600 mb-2"><strong>Scan Date:</strong> {summary['date']}</p>
            <p class="text-gray-600 mb-2"><strong>Model Name:</strong> {model_name}</p>
            <p class="text-gray-600 mb-2"><strong>Model Type:</strong> Ollama-based LLM</p>
            <p class="text-gray-600 mb-2"><strong>Total Probes Analyzed:</strong> {summary['total_probes']}</p>
            <p class="text-gray-600 mb-2"><strong>Vulnerability Breakdown:</strong></p>
            <ul class="list-disc pl-5 text-gray-600 mb-2">
                <li><strong>Critical (DEFCON 1):</strong> {summary['critical_probes']} vulnerabilities</li>
                <li><strong>High (DEFCON 2):</strong> {summary['high_probes']} vulnerabilities</li>
                <li><strong>Medium (DEFCON 3):</strong> {summary['medium_probes']} vulnerabilities</li>
                <li><strong>Low (DEFCON 4):</strong> {summary['low_probes']} vulnerabilities</li>
                <li><strong>Informational (DEFCON 5):</strong> {summary['informational_probes']} instances</li>
            </ul>
            <p class="text-gray-600 mb-2"><strong>Categories Affected:</strong></p>
            <ul class="list-disc pl-5 text-gray-600 mb-2">
                <li><strong>Social Engineering/Content Risks ([Probe Group]):</strong> Potential vulnerabilities such as mitigation bypass or inappropriate content generation, indicating critical or high risks where detected.</li>
                <li><strong>Technical Exploit Risks ([Probe Group]):</strong> Potential vulnerabilities such as injection attacks or code execution risks, indicating medium risks where detected.</li>
            </ul>
            <p class="text-gray-600">This report assesses the vulnerability of the model ('{model_name}' via Ollama) using Garak. Critical and high vulnerabilities indicate immediate or significant risks, while medium risks suggest potential exploitability. Informational findings confirm the model avoided generating sensitive content or executing code in some cases. Immediate action is recommended to address critical and high-risk issues, with further testing advised for medium-risk areas.</p>
        </div>

        <!-- Filter Section -->
        <div class="bg-white p-6 rounded-lg shadow-md mb-6">
            <h2 class="text-xl font-semibold text-gray-700 mb-4">Filter Results</h2>
            <div class="flex space-x-4">
                <div>
                    <label class="text-gray-600">Filter by Group:</label>
                    <input type="text" id="groupFilter" class="filter-input border rounded p-2" placeholder="e.g., exploitation">
                </div>
                <div>
                    <label class="text-gray-600">Filter by DEFCON:</label>
                    <select id="defconFilter" class="filter-input border rounded p-2">
                        <option value="">All</option>
                        <option value="1">1 (Immediate)</option>
                        <option value="2">2 (Critical)</option>
                        <option value="3">3 (Elevated)</option>
                        <option value="4">4 (Medium)</option>
                        <option value="5">5 (Minimal)</option>
                    </select>
                </div>
            </div>
        </div>

        <!-- Probes Table -->
        <div class="bg-white p-6 rounded-lg shadow-md">
            <h2 class="text-2xl font-semibold text-gray-700 mb-4">Probe Results</h2>
            <table id="probeTable" class="w-full table-auto border-collapse">
                <thead>
                    <tr class="bg-gray-200">
                        <th class="px-4 py-2 text-left text-gray-600 table-header" onclick="sortTable(0)">Probe Name</th>
                        <th class="px-4 py-2 text-left text-gray-600 table-header" onclick="sortTable(1)">Group</th>
                        <th class="px-4 py-2 text-left text-gray-600 table-header" onclick="sortTable(2)">Avg Score</th>
                        <th class="px-4 py-2 text-left text-gray-600 table-header" onclick="sortTable(3)">DEFCON (Abs/Rel)</th>
                        <th class="px-4 py-2 text-left text-gray-600">Details</th>
                    </tr>
                </thead>
                <tbody>
    """

    for i, probe in enumerate(probe_data):
        probe_name = probe.get('probe_name', 'Unknown')  # Use 'probe_name' field added in aggregation
        group = probe.get('group', 'Unknown')
        avg_score = probe.get('avg_score', 'N/A')
        defcon_abs = probe.get('defcon_absolute', 'N/A')
        defcon_rel = probe.get('defcon_relative', 'N/A')
        detectors = probe.get('detectors', {})
        outputs = probe.get('outputs', [])
        prompts = probe.get('prompts', [])

        html_content += f"""
                    <tr class="border-t" data-group="{group}" data-defcon="{defcon_abs if isinstance(defcon_abs, (int, str)) else '5'}">
                        <td class="px-4 py-2">{probe_name}</td>
                        <td class="px-4 py-2">{group}</td>
                        <td class="px-4 py-2">{avg_score}</td>
                        <td class="px-4 py-2">{defcon_abs}/{defcon_rel}</td>
                        <td class="px-4 py-2">
                            <button class="text-blue-500 hover:underline" onclick="toggleDetails('details-{i}')">Toggle Details</button>
                            <div id="details-{i}" class="hidden mt-2 p-4 bg-gray-50 rounded">
                                <p><strong>Detectors:</strong></p>
                                <ul class="list-disc pl-5">
        """
        for detector, stats in detectors.items():
            html_content += f"<li>{detector}: Avg Score {stats.get('avg_score', 'N/A')} (DEFCON inferred)</li>"
        html_content += """
                                </ul>
                                <p><strong>Sample Prompts:</strong></p>
                                <ul class="list-disc pl-5">
        """
        for prompt in prompts[:3]:  # Limit to 3 prompts
            safe_prompt = prompt.replace('<', '&lt;').replace('>', '&gt;')[:100] + '...' if len(prompt) > 100 else prompt
            html_content += f"<li>{safe_prompt}</li>"
        html_content += """
                                <p><strong>Sample Outputs:</strong></p>
                                <ul class="list-disc pl-5">
        """
        for output in outputs[:3]:  # Limit to 3 outputs
            safe_output = output.replace('<', '&lt;').replace('>', '&gt;')[:100] + '...' if len(output) > 100 else output
            html_content += f"<li>{safe_output}</li>"
        html_content += """
                                </ul>
                            </div>
                        </td>
                    </tr>
        """

    html_content += """
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function toggleDetails(id) {
            const element = document.getElementById(id);
            element.classList.toggle('hidden');
        }

        function sortTable(n) {
            const table = document.getElementById("probeTable");
            let rows, switching = true, i, shouldSwitch, dir = "asc", switchcount = 0;
            while (switching) {
                switching = false;
                rows = table.rows;
                for (i = 1; i < (rows.length - 1); i++) {
                    shouldSwitch = false;
                    const x = rows[i].getElementsByTagName("TD")[n];
                    const y = rows[i + 1].getElementsByTagName("TD")[n];
                    let cmpX = x.innerHTML.toLowerCase();
                    let cmpY = y.innerHTML.toLowerCase();
                    if (n === 2) { // Avg Score column
                        cmpX = parseFloat(cmpX) || 0;
                        cmpY = parseFloat(cmpY) || 0;
                    } else if (n === 3) { // DEFCON column
                        cmpX = parseInt(cmpX.split('/')[0]) || 5;
                        cmpY = parseInt(cmpY.split('/')[0]) || 5;
                    }
                    if (dir === "asc") {
                        if (cmpX > cmpY) {
                            shouldSwitch = true;
                            break;
                        }
                    } else if (dir === "desc") {
                        if (cmpX < cmpY) {
                            shouldSwitch = true;
                            break;
                        }
                    }
                }
                if (shouldSwitch) {
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                } else if (switchcount === 0 && dir === "asc") {
                    dir = "desc";
                    switching = true;
                }
            }
        }

        function filterTable() {
            const groupFilter = document.getElementById('groupFilter').value.toLowerCase();
            const defconFilter = document.getElementById('defconFilter').value;
            const table = document.getElementById("probeTable");
            const rows = table.getElementsByTagName("tr");

            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const group = row.getAttribute("data-group").toLowerCase();
                const defcon = row.getAttribute("data-defcon");
                const groupMatch = group.includes(groupFilter);
                const defconMatch = !defconFilter || defcon === defconFilter;
                row.style.display = groupMatch && defconMatch ? "" : "none";
            }
        }

        document.getElementById("groupFilter").addEventListener("input", filterTable);
        document.getElementById("defconFilter").addEventListener("change", filterTable);
    </script>
</body>
</html>
    """
    return html_content

# Function to extract model name from hitlog data
def get_model_name(hitlog_files):
    for file in hitlog_files:
        with open(file, 'r', encoding='utf-8') as f:
            for line_number, line in enumerate(f, 1):
                try:
                    data = json.loads(line.strip())
                    # Check the 'generator' field for model name
                    if 'generator' in data:
                        model_name = data['generator']
                        # Extract the last part after the last '/' (e.g., 'gpt2' from 'ollama mapler/gpt2:latest')
                        parts = model_name.split('/')
                        return parts[-1] if '/' in model_name else model_name
                    elif 'run_config' in data:
                        run_config = data['run_config']
                        if 'plugins.model_name' in run_config:
                            model_name = run_config['plugins.model_name']
                            return model_name.split('/')[-1] if '/' in model_name else model_name
                        elif 'model' in run_config:
                            return run_config['model']
                except json.JSONDecodeError as e:
                    print(f"Error parsing line {line_number} in {file}: {e}")
                    continue
    print("No model name found in any file, using 'unknown_model' as fallback.")
    return 'unknown_model'  # Default if no model name is found

# UI and main execution
def main_with_ui():
    root = tk.Tk()
    root.title("AI Model Scanner Report Generator")
    root.geometry("400x150")

    # Variables
    folder_path = tk.StringVar()

    # Labels and Entry
    tk.Label(root, text="Select Report Folder:").pack(pady=5)
    entry = tk.Entry(root, textvariable=folder_path, width=50)
    entry.pack(pady=5)

    # Browse Button
    def browse_folder():
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            folder_path.set(folder_selected)

    tk.Button(root, text="Browse", command=browse_folder).pack(pady=5)
    
    # Sanitize Model Name
    def sanitize_model_name(model_name):
        return ''.join('_' if not c.isalnum() else c for c in model_name)
    
    # Generate Report Button
    def generate_report():
        selected_folder = folder_path.get()
        if not selected_folder or not os.path.isdir(selected_folder):
            messagebox.showerror("Error", "Please select a valid folder.")
            return

        hitlog_files = glob.glob(os.path.join(selected_folder, "*.hitlog.jsonl"))
        if not hitlog_files:
            messagebox.showerror("Error", "No .hitlog.jsonl files found in the selected folder.")
            return

        model_name = get_model_name(hitlog_files)
        all_hitlog_data = []
        for file in hitlog_files:
            print(f"Processing file: {file}")
            hitlog_data = parse_hitlog_file(file)
            all_hitlog_data.extend(hitlog_data)

        if not all_hitlog_data:
            messagebox.showerror("Error", "No valid hitlog data found in the files.")
            return

        probe_data = aggregate_probe_data(all_hitlog_data)
        summary = calculate_summary(probe_data)
        html_content = generate_html_report(probe_data, summary, model_name)

        date_str = datetime.now().strftime('%Y%m%d')
        
        
        output_file = f"{sanitize_model_name(model_name)}_AI-Model-Scanner-Report_{date_str}.html"
        output_path = os.path.join(selected_folder, output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        messagebox.showinfo("Success", f"Report generated: {output_path}")
        root.destroy()

    tk.Button(root, text="Generate Report", command=generate_report).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main_with_ui()