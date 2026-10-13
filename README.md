<div align="center">

# 🛡️ SentinelSOC

### Enterprise Security Operations Center — Detection Engine & Analyst Dashboard

_A local, defensive-security platform that ingests authentication logs, detects
suspicious login activity with tunable rules, and presents the results in a
corporate dark-theme Streamlit dashboard._

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-FF4B4B?logo=streamlit&logoColor=white)
![pandas](https://img.shields.io/badge/pandas-2.1%2B-150458?logo=pandas&logoColor=white)
![Plotly](https://img.shields.io/badge/Plotly-5.18%2B-3F4F75?logo=plotly&logoColor=white)
![pytest](https://img.shields.io/badge/pytest-8.0%2B-0A9EDC?logo=pytest&logoColor=white)
![License](https://img.shields.io/badge/license-TBD-inactive)

</div>

---

## 📖 System Overview

**SentinelSOC** is a self-contained Security Operations Center (SOC) lab. It
reads synthetic authentication logs (CSV / JSON / JSONL), validates and cleans
them, runs configurable detection rules, and surfaces the findings through two
front-ends:

- a **command-line interface** (`python -m sentinelsoc`) for headless analysis
  and export; and
- an **interactive Streamlit dashboard** (`sentinelsoc/app.py`) with executive
  KPIs, incident-distribution and time-series analytics, and an interactive
  triage table over a synthetic telemetry feed.

The project is intentionally **defensive and offline**: it contains no offensive
functionality, makes no network calls, and needs no credentials. All sample data
is synthetic.

> ⚠️ **Data disclaimer.** Every log is synthetic. Usernames are invented,
> internal addresses use the private `10.x` range, and "external" addresses use
> the documentation-reserved ranges (RFC 5737). No real credentials, hosts or
> personal data are present.

---

## ✨ Key Features

- **Multi-format ingestion** — CSV, JSON and JSON Lines, with common column-name
  aliases accepted automatically.
- **Hardened loader** — malformed rows, invalid timestamps/IPs, blanks and
  duplicates are dropped and itemised in a data-quality report instead of
  crashing the pipeline.
- **Tunable detection rules**
  - `SOC-001` — repeated failed logins within a sliding time window.
  - `SOC-002` — a successful login preceded by repeated failures.
- **Actionable alerts** — severity ranking, precise timestamps, human-readable
  evidence, event IDs behind each alert, defensive recommendations, and MITRE
  ATT&CK references (only where justified).
- **Executive dashboard** — top KPIs, incident distribution by severity and
  event type, log frequency over time, and an interactive triage table.
- **Clean exports** — CSV and JSON export hardened against spreadsheet formula
  (CSV) injection.
- **Typed, testable core** — detection logic lives in pure, framework-agnostic
  modules covered by an automated test suite.

---

## 🏗️ Architecture

SentinelSOC is a linear, offline pipeline: **load → clean → detect →
present/export**. The detection core is deliberately UI-agnostic so it can be
driven by either the dashboard or the CLI.

```
   CSV / JSON / JSONL
          │
          ▼
 ┌─────────────────────┐
 │  loader.load_logs() │  validate · normalise · deduplicate
 └─────────────────────┘  └─► LoadReport (what was dropped, and why)
          │  events
          ▼
 ┌──────────────────────────┐
 │ detectors.run_detections │  SOC-001 · SOC-002  (driven by DetectionConfig)
 └──────────────────────────┘
          │  alerts
          ▼
      alerts table ─────────► export.alerts_to_csv() / alerts_to_json()
          │
          ▼
 ┌─────────────────────┐        ┌───────────────────────────┐
 │  metrics.py (pure)  │ ─────► │  sentinelsoc/app.py (UI)  │
 │ filters/timelines   │        │  python -m sentinelsoc    │
 └─────────────────────┘        └───────────────────────────┘
```

### Module responsibilities

| Module | Responsibility |
|--------|----------------|
| `sentinelsoc/loader.py` | Read CSV/JSON/JSONL, validate, normalise, deduplicate, report data-quality issues. |
| `sentinelsoc/data/config.py` | `DetectionConfig`: validated detection thresholds. |
| `sentinelsoc/detectors.py` | Detection rules plus their severity, evidence, recommendation and MITRE text. |
| `sentinelsoc/alerts.py` | `Alert` model, severity ordering, stable alert IDs. |
| `sentinelsoc/metrics.py` | Pure functions for filters, timelines and summary numbers (kept out of the UI so they can be tested). |
| `sentinelsoc/export.py` | CSV and JSON export with formula-injection protection. |
| `sentinelsoc/data/sample_data.py` | Typed enums + cached synthetic telemetry feed + pure analytics helpers for the dashboard. |
| `sentinelsoc/__main__.py` | Command-line interface. |
| `sentinelsoc/app.py` | Streamlit dashboard (dark corporate theme). |

### Dashboard components

The dashboard (`sentinelsoc/app.py`) is composed of focused render functions:

| Component | Purpose |
|-----------|---------|
| `render_sidebar` | Severity / status / event-type filters. |
| `render_kpis` | Totals, critical & high counts, open incidents, global risk posture. |
| `render_charts` | Distribution by severity, event mix by type, log frequency over time. |
| `render_triage_table` | Sortable incident table with one-click CSV export. |


---

## 🚀 Quick Start

### 1. Prerequisites

- **Python 3.10 or newer** — <https://www.python.org/downloads/>
  (on Windows, tick **"Add python.exe to PATH"** during install).

### 2. Create a virtual environment

```powershell
# Windows (PowerShell)
py -m venv venv
.\venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

> If PowerShell blocks activation, run once:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Launch the dashboard

```powershell
streamlit run sentinelsoc/app.py
```

Your browser opens at <http://localhost:8501>. Use the sidebar to filter by
severity, incident status and event type; KPIs, charts and the triage table
update instantly. Press `Ctrl+C` to stop.

### 5. Run headless (CLI) analysis

```powershell
python -m sentinelsoc data\sample_auth_logs.csv --csv alerts.csv --json alerts.json
python -m sentinelsoc --help
```

### 6. Run the test suite

```powershell
python -m pytest
```

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.10+ |
| Data handling | pandas |
| Dashboard | Streamlit |
| Charts | Plotly Express / Graph Objects |
| Dataframe rendering | pyarrow |
| Testing | pytest |

---

## 📥 Log Format

Required columns: `timestamp`, `username`, `source_ip`, `event_type`, `status`.
Optional: `hostname`, `service`. Common alternative column names (e.g. `time`,
`user`, `src_ip`, `action`, `result`) are accepted automatically.

```csv
timestamp,username,source_ip,event_type,status,hostname,service
2026-03-09T13:40:00Z,carla,198.51.100.77,login,failure,vpn-gw-01,vpn
```

---

## 📚 Documentation

- [Detection rules & MITRE ATT&CK mapping](docs/detection_rules.md)
- [Architecture, data handling & security notes](docs/architecture.md)

## ⚠️ Limitations

- Only two authentication rules; no detection for other attack types.
- The dashboard has no authentication and is intended for local use only.
- Sample data is synthetic, so results demonstrate rule behaviour, not
  real-world performance.

