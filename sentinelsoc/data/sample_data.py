"""Synthetic SOC telemetry: typed vocabulary, a cached loader and pure analytics.

The dashboard needs a small, self-contained incident feed so it can run with no
external data source. This module keeps three concerns apart so each stays easy
to reason about and test:

* an ``enum``-based vocabulary (severity, event type, incident status) that is
  the single source of truth for labels, ordering and colour;
* a ``@st.cache_data`` loader that parses the synthetic events once per session;
* side-effect-free helpers that filter and aggregate a loaded frame.

All data is synthetic. Addresses come from the RFC 5737 documentation ranges or
the private ``10.x`` space; no real hosts, accounts or credentials are present.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta, timezone
from typing import Final

import pandas as pd
import streamlit as st

# Canonical column names. Centralising them avoids magic strings scattered
# across the loader, the helpers and the dashboard.
COL_TIMESTAMP: Final = "timestamp"
COL_SOURCE_IP: Final = "source_ip"
COL_EVENT_TYPE: Final = "event_type"
COL_SEVERITY: Final = "severity"
COL_STATUS: Final = "status"

EVENT_COLUMNS: Final = (
    COL_TIMESTAMP,
    COL_SOURCE_IP,
    COL_EVENT_TYPE,
    COL_SEVERITY,
    COL_STATUS,
)


class Severity(enum.Enum):
    """Incident severity, ordered from least to most urgent."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class EventType(enum.Enum):
    """Security event categories shown in the dashboard."""

    ACCEPTED_PASSWORD = "Accepted Password"
    SSH_FAILED_PASSWORD = "SSH Failed Password"
    BRUTE_FORCE = "Brute Force Attempt"
    PORT_SCAN = "Port Scan Detected"
    MALWARE_C2 = "Malware C2 Traffic"
    DDOS_SPIKE = "DDoS Spike Detected"
    SUDO_ESCALATION = "Sudo Privilege Escalation"
    UNAUTHORIZED_FILE_ACCESS = "Unauthorized File Access"


class IncidentStatus(enum.Enum):
    """Triage workflow state of an incident."""

    OPEN = "Open"
    INVESTIGATING = "Investigating"
    CLOSED = "Closed"


# Ordering and colour live next to the enums so charts, filters and KPI cards
# cannot drift apart. Colours follow a green -> amber -> orange -> red ramp.
SEVERITY_ORDER: Final[tuple[Severity, ...]] = (
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)
SEVERITY_LABELS: Final[tuple[str, ...]] = tuple(s.value for s in SEVERITY_ORDER)
SEVERITY_COLORS: Final[dict[Severity, str]] = {
    Severity.LOW: "#10B981",  # Emerald
    Severity.MEDIUM: "#F59E0B",  # Amber
    Severity.HIGH: "#F97316",  # Orange
    Severity.CRITICAL: "#DC2626",  # Crimson
}
STATUS_ORDER: Final[tuple[IncidentStatus, ...]] = (
    IncidentStatus.OPEN,
    IncidentStatus.INVESTIGATING,
    IncidentStatus.CLOSED,
)
STATUS_LABELS: Final[tuple[str, ...]] = tuple(s.value for s in STATUS_ORDER)


# Synthetic feed: (minutes_ago, source_ip, event_type, severity, status).
# Each row's first field is how many minutes before "now" the event occurred, so
# the feed is anchored to the moment the app runs and always looks live today.
# ``_build_frame`` turns these offsets into real UTC timestamps. Timestamps stay
# naive because tz-aware datetimes introduce artefacts in the Plotly charts.
# The mix is hand-tuned to exercise every severity and status so the dashboard
# charts have something meaningful to show out of the box.
_RAW_EVENTS: Final[tuple[tuple[int, str, EventType, Severity, IncidentStatus], ...]] = (
    (175, "10.20.1.11", EventType.ACCEPTED_PASSWORD, Severity.LOW, IncidentStatus.CLOSED),
    (171, "10.20.2.22", EventType.ACCEPTED_PASSWORD, Severity.LOW, IncidentStatus.CLOSED),
    (168, "10.20.3.32", EventType.ACCEPTED_PASSWORD, Severity.LOW, IncidentStatus.INVESTIGATING),
    (165, "203.0.113.45", EventType.SSH_FAILED_PASSWORD, Severity.MEDIUM, IncidentStatus.OPEN),
    (165, "203.0.113.45", EventType.SSH_FAILED_PASSWORD, Severity.MEDIUM, IncidentStatus.OPEN),
    (164, "203.0.113.45", EventType.SSH_FAILED_PASSWORD, Severity.HIGH, IncidentStatus.OPEN),
    (164, "203.0.113.45", EventType.SSH_FAILED_PASSWORD, Severity.HIGH, IncidentStatus.OPEN),
    (164, "203.0.113.45", EventType.SSH_FAILED_PASSWORD, Severity.HIGH, IncidentStatus.OPEN),
    (163, "203.0.113.45", EventType.BRUTE_FORCE, Severity.HIGH, IncidentStatus.INVESTIGATING),
    (163, "10.20.1.13", EventType.ACCEPTED_PASSWORD, Severity.LOW, IncidentStatus.CLOSED),
    (160, "198.51.100.77", EventType.PORT_SCAN, Severity.MEDIUM, IncidentStatus.CLOSED),
    (159, "198.51.100.77", EventType.PORT_SCAN, Severity.MEDIUM, IncidentStatus.CLOSED),
    (155, "185.220.101.5", EventType.MALWARE_C2, Severity.CRITICAL, IncidentStatus.OPEN),
    (152, "185.220.101.5", EventType.MALWARE_C2, Severity.CRITICAL, IncidentStatus.INVESTIGATING),
    (150, "10.20.4.43", EventType.SUDO_ESCALATION, Severity.HIGH, IncidentStatus.INVESTIGATING),
    (144, "10.20.4.43", EventType.UNAUTHORIZED_FILE_ACCESS, Severity.MEDIUM, IncidentStatus.CLOSED),
    (142, "45.33.32.156", EventType.UNAUTHORIZED_FILE_ACCESS, Severity.HIGH, IncidentStatus.OPEN),
    (140, "10.20.1.12", EventType.ACCEPTED_PASSWORD, Severity.LOW, IncidentStatus.CLOSED),
    (134, "10.20.5.8", EventType.ACCEPTED_PASSWORD, Severity.LOW, IncidentStatus.CLOSED),
    (130, "45.33.32.156", EventType.DDOS_SPIKE, Severity.CRITICAL, IncidentStatus.OPEN),
    (127, "45.33.32.156", EventType.DDOS_SPIKE, Severity.CRITICAL, IncidentStatus.OPEN),
    (115, "192.0.2.99", EventType.SSH_FAILED_PASSWORD, Severity.LOW, IncidentStatus.CLOSED),
    (95, "192.0.2.99", EventType.SSH_FAILED_PASSWORD, Severity.LOW, IncidentStatus.CLOSED),
    (75, "192.0.2.99", EventType.SSH_FAILED_PASSWORD, Severity.LOW, IncidentStatus.INVESTIGATING),
    (65, "203.0.113.45", EventType.BRUTE_FORCE, Severity.HIGH, IncidentStatus.OPEN),
    (62, "203.0.113.45", EventType.BRUTE_FORCE, Severity.HIGH, IncidentStatus.INVESTIGATING),
    (50, "185.220.101.5", EventType.MALWARE_C2, Severity.CRITICAL, IncidentStatus.OPEN),
    (44, "10.20.9.20", EventType.ACCEPTED_PASSWORD, Severity.LOW, IncidentStatus.CLOSED),
    (40, "10.20.9.20", EventType.UNAUTHORIZED_FILE_ACCESS, Severity.MEDIUM, IncidentStatus.CLOSED),
    (34, "10.20.2.21", EventType.ACCEPTED_PASSWORD, Severity.LOW, IncidentStatus.CLOSED),
    (19, "10.20.3.32", EventType.ACCEPTED_PASSWORD, Severity.LOW, IncidentStatus.INVESTIGATING),
    (10, "198.51.100.77", EventType.PORT_SCAN, Severity.MEDIUM, IncidentStatus.OPEN),
    (0, "10.20.1.11", EventType.ACCEPTED_PASSWORD, Severity.LOW, IncidentStatus.CLOSED),
)


def _build_frame() -> pd.DataFrame:
    """Materialise the synthetic events into a typed, chronologically sorted frame.

    Each row's ``minutes_ago`` offset is resolved against a single UTC "now" so
    the feed always looks live: the newest event lands at the current minute and
    older events fall back in time by their offset. Timestamps are kept naive
    (tz-aware values add artefacts to the Plotly charts) and are understood as
    UTC. Severity and status are stored as ordered categoricals so group-by and
    chart code sort by urgency (Low -> Critical) and workflow order.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    records = [
        {
            COL_TIMESTAMP: now - timedelta(minutes=minutes_ago),
            COL_SOURCE_IP: source_ip,
            COL_EVENT_TYPE: event.value,
            COL_SEVERITY: severity.value,
            COL_STATUS: status.value,
        }
        for minutes_ago, source_ip, event, severity, status in _RAW_EVENTS
    ]
    frame = pd.DataFrame.from_records(records, columns=list(EVENT_COLUMNS))
    frame[COL_TIMESTAMP] = pd.to_datetime(frame[COL_TIMESTAMP])
    frame[COL_SEVERITY] = pd.Categorical(
        frame[COL_SEVERITY], categories=SEVERITY_LABELS, ordered=True
    )
    frame[COL_STATUS] = pd.Categorical(
        frame[COL_STATUS], categories=STATUS_LABELS, ordered=True
    )
    return frame.sort_values(COL_TIMESTAMP, kind="stable").reset_index(drop=True)


@st.cache_data(show_spinner=False)
def load_incidents() -> pd.DataFrame:
    """Return the cached incident feed.

    Caching is scoped to the session: the synthetic set never changes, so there
    is no reason to rebuild the frame on every Streamlit rerun. Treat the result
    as read-only; the helpers below always return new frames rather than mutating
    the cached one.
    """
    return _build_frame()


def filter_events(
    frame: pd.DataFrame,
    severities: Iterable[Severity] | None = None,
    statuses: Iterable[IncidentStatus] | None = None,
    event_types: Iterable[EventType] | None = None,
) -> pd.DataFrame:
    """Return rows matching every supplied filter; an empty/omitted filter is ignored.

    Args:
        frame: Incident frame produced by :func:`load_incidents`.
        severities: Severities to keep. ``None`` or empty keeps all.
        statuses: Incident statuses to keep. ``None`` or empty keeps all.
        event_types: Event types to keep. ``None`` or empty keeps all.

    Returns:
        A new frame; the input is never modified.
    """
    mask = pd.Series(True, index=frame.index)
    for column, members in (
        (COL_SEVERITY, severities),
        (COL_STATUS, statuses),
        (COL_EVENT_TYPE, event_types),
    ):
        selected = [member.value for member in members or []]
        if selected:
            mask &= frame[column].isin(selected)
    return frame[mask]


def severity_counts(frame: pd.DataFrame) -> pd.Series:
    """Count events per severity, ordered Low -> Critical (zero-filled)."""
    counts = frame[COL_SEVERITY].value_counts()
    return counts.reindex(SEVERITY_LABELS, fill_value=0).astype(int)


def status_counts(frame: pd.DataFrame) -> pd.Series:
    """Count events per triage status, ordered Open -> Investigating -> Closed."""
    counts = frame[COL_STATUS].value_counts()
    return counts.reindex(STATUS_LABELS, fill_value=0).astype(int)


def event_type_counts(frame: pd.DataFrame) -> pd.Series:
    """Count events per event type, most frequent first."""
    return frame[COL_EVENT_TYPE].value_counts().astype(int)


def event_frequency(frame: pd.DataFrame, freq: str = "5min") -> pd.DataFrame:
    """Aggregate events into fixed time buckets for the frequency chart.

    Args:
        frame: Incident frame (any row order; it is sorted internally).
        freq: Pandas offset alias, e.g. ``"5min"`` or ``"15min"``.

    Returns:
        Frame with ``timestamp`` (bucket start) and ``count`` columns. Empty
        input yields an empty frame with the same columns.
    """
    columns = {
        COL_TIMESTAMP: pd.Series(dtype="datetime64[ns]"),
        "count": pd.Series(dtype=int),
    }
    if frame.empty:
        return pd.DataFrame(columns)
    ordered = frame.sort_values(COL_TIMESTAMP, kind="stable")
    buckets = ordered.set_index(COL_TIMESTAMP)[COL_EVENT_TYPE].resample(freq).size()
    return buckets.rename("count").reset_index()


def risk_level(critical: int, high: int) -> str:
    """Map severity counts to a headline risk posture for the KPI card.

    The thresholds are deliberately simple: a cluster of critical findings is an
    emergency, a single one is serious, and sustained high-severity noise without
    anything critical is only elevated.
    """
    if critical >= 4:
        return "Critical"
    if critical >= 1:
        return "High"
    if high >= 4:
        return "Elevated"
    if high >= 1:
        return "Moderate"
    return "Low"


def summary_metrics(frame: pd.DataFrame) -> dict[str, int | str]:
    """Compute the dashboard KPIs from an already-filtered frame."""
    total = int(len(frame))
    severity = severity_counts(frame)
    status = status_counts(frame)
    critical = int(severity.get(Severity.CRITICAL.value, 0))
    high = int(severity.get(Severity.HIGH.value, 0))
    return {
        "total_events": total,
        "critical_threats": critical,
        "high_threats": high,
        "unique_sources": int(frame[COL_SOURCE_IP].nunique()) if total else 0,
        "open_incidents": int(status.get(IncidentStatus.OPEN.value, 0)),
        "risk_level": risk_level(critical, high),
    }


def severity_options() -> Sequence[Severity]:
    """Severities in display order, for building sidebar filters."""
    return SEVERITY_ORDER


def status_options() -> Sequence[IncidentStatus]:
    """Incident statuses in display order, for building sidebar filters."""
    return STATUS_ORDER


def event_type_options() -> Sequence[EventType]:
    """All known event types, for building sidebar filters."""
    return tuple(EventType)

