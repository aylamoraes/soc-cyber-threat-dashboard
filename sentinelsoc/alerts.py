"""Alert data model and conversion to a DataFrame."""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_LEVELS)}

ALERT_COLUMNS = [
    "alert_id",
    "severity",
    "rule_id",
    "rule_name",
    "first_seen",
    "last_seen",
    "username",
    "source_ip",
    "event_count",
    "evidence",
    "recommendation",
    "mitre_attack",
    "evidence_event_ids",
]


@dataclass(frozen=True)
class Alert:
    """One detection result, before an alert ID is assigned."""

    rule_id: str
    rule_name: str
    severity: str
    first_seen: pd.Timestamp
    last_seen: pd.Timestamp
    username: str
    source_ip: str
    event_count: int
    evidence: str
    recommendation: str
    mitre_attack: str
    evidence_event_ids: tuple[str, ...]


def empty_alerts_frame() -> pd.DataFrame:
    """Return an empty alerts table that still has the correct columns and types."""
    frame = pd.DataFrame(columns=ALERT_COLUMNS)
    for column in ("first_seen", "last_seen"):
        frame[column] = pd.to_datetime(frame[column], utc=True)
    frame["event_count"] = frame["event_count"].astype("int64")
    return frame


def alerts_to_frame(alerts: list[Alert]) -> pd.DataFrame:
    """Sort alerts (most severe first, then oldest first) and assign stable IDs."""
    if not alerts:
        return empty_alerts_frame()

    ordered = sorted(
        alerts,
        key=lambda a: (
            -SEVERITY_RANK.get(a.severity, -1),
            a.first_seen,
            a.rule_id,
            a.source_ip,
            a.username,
        ),
    )
    records = []
    for number, alert in enumerate(ordered, start=1):
        records.append(
            {
                "alert_id": f"ALT-{number:04d}",
                "severity": alert.severity,
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "first_seen": alert.first_seen,
                "last_seen": alert.last_seen,
                "username": alert.username,
                "source_ip": alert.source_ip,
                "event_count": int(alert.event_count),
                "evidence": alert.evidence,
                "recommendation": alert.recommendation,
                "mitre_attack": alert.mitre_attack,
                "evidence_event_ids": list(alert.evidence_event_ids),
            }
        )
    return pd.DataFrame.from_records(records, columns=ALERT_COLUMNS)
