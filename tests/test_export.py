import io
import json
from datetime import datetime, timezone

import pandas as pd
from helpers import build_events, failures, success

from sentinelsoc.alerts import ALERT_COLUMNS
from sentinelsoc.config import DetectionConfig
from sentinelsoc.detectors import run_detections
from sentinelsoc.export import alerts_to_csv, alerts_to_json


def sample_alerts():
    rows = failures("2026-03-09 10:00:00", 6, 10) + [success("2026-03-09 10:02:00")]
    return run_detections(build_events(rows), DetectionConfig())


def test_csv_has_all_columns_and_iso_timestamps():
    alerts = sample_alerts()
    parsed = pd.read_csv(io.StringIO(alerts_to_csv(alerts)), dtype=str)
    assert list(parsed.columns) == ALERT_COLUMNS
    assert len(parsed) == len(alerts)
    assert parsed.loc[0, "first_seen"] == "2026-03-09T10:00:00Z"
    assert parsed.loc[0, "evidence_event_ids"].startswith("EVT-000001;EVT-000002")


def test_json_has_metadata_and_one_object_per_alert():
    alerts = sample_alerts()
    stamp = datetime(2026, 3, 10, 12, 0, tzinfo=timezone.utc)
    payload = json.loads(alerts_to_json(alerts, generated_at=stamp))
    assert payload["generated_at"] == "2026-03-10T12:00:00Z"
    assert payload["alert_count"] == len(alerts) == len(payload["alerts"])
    first = payload["alerts"][0]
    assert set(first) == set(ALERT_COLUMNS)
    assert isinstance(first["event_count"], int)
    assert isinstance(first["evidence_event_ids"], list)
    assert first["first_seen"].endswith("Z")


def test_exporting_no_alerts_still_works():
    empty = run_detections(build_events([]), DetectionConfig())
    csv_text = alerts_to_csv(empty)
    assert csv_text.strip().split(",") == ALERT_COLUMNS
    payload = json.loads(alerts_to_json(empty))
    assert payload["alert_count"] == 0
    assert payload["alerts"] == []


def test_csv_neutralises_spreadsheet_formulas_from_log_data():
    rows = failures("2026-03-09 10:00:00", 6, 10, user="=cmd|' /C calc'!A0")
    alerts = run_detections(build_events(rows), DetectionConfig())
    parsed = pd.read_csv(io.StringIO(alerts_to_csv(alerts)), dtype=str)
    assert parsed.loc[0, "username"].startswith("'=")
