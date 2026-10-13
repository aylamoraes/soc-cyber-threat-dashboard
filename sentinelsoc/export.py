"""Export alerts to CSV and JSON.

Log fields such as usernames come from untrusted data. CSV cells that start with
``=``, ``+``, ``-`` or ``@`` could be run as formulas when the file is opened in
a spreadsheet ("CSV injection"), so they are prefixed with an apostrophe.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pandas as pd

_ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
_TIME_COLUMNS = ("first_seen", "last_seen")


def alerts_to_csv(alerts: pd.DataFrame) -> str:
    """Return the alerts as CSV text. Evidence event IDs are joined with ';'."""
    frame = alerts.copy()
    for column in _TIME_COLUMNS:
        frame[column] = pd.to_datetime(frame[column], utc=True).dt.strftime(_ISO_FORMAT)
    frame["evidence_event_ids"] = frame["evidence_event_ids"].map(
        lambda ids: ";".join(ids) if isinstance(ids, (list, tuple)) else str(ids)
    )
    for column in frame.columns:
        if pd.api.types.is_string_dtype(frame[column]) or frame[column].dtype == object:
            frame[column] = frame[column].map(_neutralise_formula)
    return frame.to_csv(index=False, lineterminator="\n")


def alerts_to_json(alerts: pd.DataFrame, generated_at: datetime | None = None) -> str:
    """Return the alerts as a JSON document with a small metadata header."""
    stamp = (generated_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    payload = {
        "generated_at": stamp.strftime(_ISO_FORMAT),
        "alert_count": int(len(alerts)),
        "alerts": [
            {key: _json_value(value) for key, value in record.items()}
            for record in alerts.to_dict(orient="records")
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def _neutralise_formula(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _json_value(value: Any) -> Any:
    if isinstance(value, pd.Timestamp):
        return value.tz_convert("UTC").strftime(_ISO_FORMAT)
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    if hasattr(value, "item"):  # numpy scalar
        return value.item()
    return value
