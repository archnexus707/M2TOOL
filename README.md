# M2TOOL — Endpoint File Monitor + VirusTotal Reporting

M2TOOL is a Python-based endpoint monitoring and reporting toolkit that watches a directory in real time, submits newly created or modified files to **VirusTotal** for analysis, and produces structured reports for local archiving and centralized SOC visibility.

The project includes:
- an **Agent** (endpoint client) that monitors a directory, uploads files to VirusTotal, waits for analysis completion, and forwards the analysis report to a server
- a **Server** (SOC receiver + web dashboard) that receives reports, stores them in SQLite, and exposes a lightweight HTTP dashboard

---

## Components

### Agent (Endpoint)
Primary scripts:
- `client6.py` (general)
- `client6-windows.py` (Windows-focused)

Behavior:
- Watches a directory using `watchdog`
- Moves detected files into a temporary processing folder
- Uploads the file to VirusTotal
- Polls VirusTotal until analysis is completed
- If analysis indicates malicious detections, the file is removed and an alert workflow is triggered
- Saves the VirusTotal JSON report locally under `backup_reports/`
- Sends the VirusTotal JSON report to the SOC server over TCP

### Server (SOC Receiver + Dashboard)
Primary script:
- `server8.py`

Behavior:
- Listens for incoming JSON reports over TCP
- Persists reports to:
  - disk under `received_reports/<host>/...`
  - SQLite database `reports.db`
- Serves an HTTP dashboard (aiohttp) to view stored reports and basic statistics

### Utility
- `scanner.py` — simple GUI utility for observing system/network activity (Tkinter + psutil)

---

## How it Works (Flow)

1. Agent monitors a directory for new/changed files  
2. Agent submits the file to VirusTotal  
3. Agent polls for completion and receives a JSON analysis report  
4. Agent writes the report locally to `backup_reports/`  
5. Agent sends the report JSON to the SOC server over TCP  
6. Server stores the JSON report on disk and in SQLite  
7. Dashboard provides a view into ingested reports

---

## Tech Stack

- Python 3.x
- VirusTotal API via `virustotal-python`
- File monitoring: `watchdog`
- Server dashboard: `aiohttp`
- Data storage: `sqlite3`
- Logging/UI: `rich`, `colorama`
- Crypto utility: `cryptography`
- Optional email alerts: `resend` (if used by your workflow)

---

## Installation

```bash
python -m venv .venv

Windows (PowerShell):
.venv\Scripts\Activate.ps1

macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt



Start the SOC Server (Receiver + Dashboard)
python server8.py


Start the Agent (Endpoint)

Windows:
python client6-windows.py

macOS/Linux:
python client6.py

