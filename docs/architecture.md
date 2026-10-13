# Architecture

SentinelSOC is a small, local pipeline: **load -> clean -> detect -> present/export**.
Everything runs on your own computer; nothing is sent over the network.

```
 CSV / JSON / JSONL file
          |
          v
   loader.load_logs()      validates, cleans, normalises, removes duplicates
          |                returns events + a LoadReport (what was dropped and why)
          v
 detectors.run_detections()   SOC-001 and SOC-002, driven by DetectionConfig
          |
          v
     alerts table  ------>  export.alerts_to_csv() / alerts_to_json()
          |
          v
 metrics.py (filters, timelines, summary numbers)
          |
          v
 app/dashboard.py (Streamlit)        python -m sentinelsoc (command line)
```

## Modules

| File | Responsibility |
|------|----------------|
| `sentinelsoc/loader.py` | Read CSV/JSON/JSONL, validate, normalise, deduplicate, report problems. |
| `sentinelsoc/config.py` | `DetectionConfig`: validated detection thresholds. |
| `sentinelsoc/detectors.py` | The detection rules and their severity, evidence, recommendation and MITRE text. |
| `sentinelsoc/alerts.py` | `Alert` model, severity order, alerts table with stable IDs. |
| `sentinelsoc/metrics.py` | Pure functions for filters, timelines and summary numbers (kept out of the UI so they can be tested). |
| `sentinelsoc/export.py` | CSV and JSON export. |
| `sentinelsoc/sample_data.py` | Deterministic generator for the synthetic logs in `data/`. |
| `sentinelsoc/__main__.py` | Command-line interface. |
| `app/dashboard.py` | Streamlit user interface. Contains no detection logic. |

## Input format

Required columns (names are matched case-insensitively; common aliases such as
`time`, `user`, `src_ip`, `action`, `result` are accepted):

| Column | Meaning | Example |
|--------|---------|---------|
| `timestamp` | When the event happened. ISO 8601 recommended. Values without a time zone are treated as UTC; other offsets are converted to UTC. | `2026-03-09T10:00:00Z` |
| `username` | Account name (lower-cased on load). | `alice` |
| `source_ip` | IPv4 or IPv6 address of the client. | `203.0.113.45` |
| `event_type` | What happened. `login` (also `logon`, `signin`, `authentication`, ...) is analysed; other types are kept for context. | `login` |
| `status` | `success` or `failure` (also `ok`, `accepted`, `failed`, `denied`, ...). Anything else becomes `unknown` and is ignored by the rules. | `failure` |

Optional columns: `hostname`, `service`.

Accepted files: `.csv`; `.json` (a list of objects, or an object with an `events` list);
`.jsonl`/`.ndjson` (one object per line). Maximum size: 50 MB.

## How bad data is handled

| Problem | Behaviour |
|---------|-----------|
| Empty file, or header only | Returns zero events and a warning. The dashboard shows a message instead of failing. |
| Missing required column | `LogLoadError` listing the missing and the found columns. |
| Unsupported extension, unreadable or invalid JSON/CSV, file over 50 MB | `LogLoadError` with a plain message. |
| Row with too many fields, JSON line that is not an object | Skipped and counted. |
| Missing or invalid timestamp | Row dropped and counted. |
| Blank username, source IP, event type or status | Row dropped and counted. |
| Invalid IP address (for example `999.1.1.1`) | Row dropped and counted. |
| Unknown status value | Row kept, status set to `unknown`, ignored by the rules, counted. |
| Exact duplicate events | First one kept, others removed and counted. |

Every count is shown in the dashboard's *Data quality* panel and returned in `LoadReport`.
Try it with `data/sample_malformed_demo.csv`.

## Normalised events table

`event_id` (`EVT-000001`, assigned after sorting), `timestamp` (UTC), `username`,
`source_ip`, `event_type`, `status`, `hostname`, `service`.

## Alerts table

| Column | Meaning |
|--------|---------|
| `alert_id` | `ALT-0001`, ... ordered by severity (highest first), then time. |
| `severity` | Low, Medium, High or Critical. |
| `rule_id`, `rule_name` | Which rule fired. |
| `first_seen`, `last_seen` | Time span of the evidence (UTC). |
| `username` | Account(s) involved; several accounts are joined with `; `. |
| `source_ip` | Source of the activity. |
| `event_count` | Number of evidence events. |
| `evidence` | Human-readable explanation. |
| `recommendation` | Suggested defensive response. |
| `mitre_attack` | Related ATT&CK technique(s). |
| `evidence_event_ids` | IDs of the events behind the alert (`;`-separated in CSV, a list in JSON). |

## Security notes

* Log content is treated as untrusted. It is never executed. The dashboard does not enable
  raw HTML, and log values shown as Markdown (usernames, evidence text) are escaped first.
* CSV export prefixes cells that start with `=`, `+`, `-` or `@` with an apostrophe so a
  hostile username cannot become a spreadsheet formula.
* No credentials, API keys or network access are used or needed.
* The app is meant for local use. It has no login and should not be exposed to the internet.

## Testing

`tests/` uses pytest and covers the loader, both detection rules (including boundary
and false-negative cases), exports, metrics/filters, and the shipped sample files
(including a check that the committed samples match the generator output).
`app/dashboard.py` is intentionally thin; its logic lives in `metrics.py`.
