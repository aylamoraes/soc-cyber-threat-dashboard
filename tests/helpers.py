"""Small builders shared by the tests."""

from __future__ import annotations

import pandas as pd

COLUMNS = ["event_id", "timestamp", "username", "source_ip", "event_type", "status", "hostname", "service"]


def build_events(rows) -> pd.DataFrame:
    """Build a normalised events table.

    Each row is ``(timestamp, username, source_ip, status[, event_type[, service]])``.
    """
    records = []
    for number, row in enumerate(rows, start=1):
        when, user, ip, status, *rest = row
        event_type = rest[0] if rest else "login"
        service = rest[1] if len(rest) > 1 else "ssh"
        records.append(
            {
                "event_id": f"EVT-{number:06d}",
                "timestamp": when,
                "username": user,
                "source_ip": ip,
                "event_type": event_type,
                "status": status,
                "hostname": "host-01",
                "service": service,
            }
        )
    frame = pd.DataFrame.from_records(records, columns=COLUMNS)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, format="mixed")
    return frame


def failures(start: str, count: int, step_seconds: int, user: str = "admin", ip: str = "203.0.113.10"):
    """Return ``count`` failed-login rows spaced ``step_seconds`` apart."""
    first = pd.Timestamp(start, tz="UTC")
    return [
        ((first + pd.Timedelta(seconds=step_seconds * i)).isoformat(), user, ip, "failure")
        for i in range(count)
    ]


def success(when: str, user: str = "admin", ip: str = "203.0.113.10"):
    return (pd.Timestamp(when, tz="UTC").isoformat(), user, ip, "success")
