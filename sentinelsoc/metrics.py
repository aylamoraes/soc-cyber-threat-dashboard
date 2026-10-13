"""Summary numbers, timelines, filters and display helpers used by the dashboard.

Keeping this logic out of the Streamlit script makes it easy to test.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

import pandas as pd

from .alerts import SEVERITY_LEVELS

BUCKET_CHOICES = ("1min", "5min", "15min", "30min", "1h", "3h", "6h", "12h", "1D")
ALERT_TABLE_COLUMNS = [
    "alert_id",
    "severity",
    "rule_id",
    "rule_name",
    "first_seen",
    "last_seen",
    "username",
    "source_ip",
    "event_count",
]


def summary_metrics(events: pd.DataFrame, alerts: pd.DataFrame) -> dict[str, int]:
    """Headline numbers for the dashboard."""
    if len(events):
        is_login = events["event_type"] == "login"
        failures = int((is_login & (events["status"] == "failure")).sum())
        successes = int((is_login & (events["status"] == "success")).sum())
        sources = int(events["source_ip"].nunique())
        users = int(events["username"].nunique())
    else:
        failures = successes = sources = users = 0
    serious = int(alerts["severity"].isin(["High", "Critical"]).sum()) if len(alerts) else 0
    return {
        "total_events": int(len(events)),
        "login_failures": failures,
        "login_successes": successes,
        "unique_sources": sources,
        "unique_users": users,
        "total_alerts": int(len(alerts)),
        "high_or_critical_alerts": serious,
    }


def top_failed_logins(events: pd.DataFrame, column: str, limit: int = 10) -> pd.DataFrame:
    """Rank values of ``column`` (e.g. source_ip, username) by failed login count."""
    result_columns = [column, "failed_logins"]
    if len(events) == 0:
        return pd.DataFrame(columns=result_columns)
    failed = events[(events["event_type"] == "login") & (events["status"] == "failure")]
    if failed.empty:
        return pd.DataFrame(columns=result_columns)
    counts = failed.groupby(column).size().sort_values(ascending=False, kind="stable")
    return counts.head(limit).rename("failed_logins").reset_index()[result_columns]


def bucket_frequency(events: pd.DataFrame, max_buckets: int = 120) -> str:
    """Pick the smallest time bucket that keeps the timeline under ``max_buckets``."""
    if len(events) == 0:
        return BUCKET_CHOICES[0]
    span = events["timestamp"].max() - events["timestamp"].min()
    for choice in BUCKET_CHOICES:
        if span / pd.Timedelta(choice) <= max_buckets:
            return choice
    return BUCKET_CHOICES[-1]


def event_timeline(events: pd.DataFrame, freq: str | None = None) -> pd.DataFrame:
    """Count events per time bucket and status. Index is a naive UTC datetime."""
    if len(events) == 0:
        return pd.DataFrame()
    freq = freq or bucket_frequency(events)
    return _bucketed_counts(events, "timestamp", "status", freq)


def alert_timeline(alerts: pd.DataFrame, freq: str) -> pd.DataFrame:
    """Count alerts per time bucket and severity. Index is a naive UTC datetime."""
    if len(alerts) == 0:
        return pd.DataFrame()
    table = _bucketed_counts(alerts, "first_seen", "severity", freq)
    ordered = [level for level in SEVERITY_LEVELS if level in table.columns]
    return table[ordered]


def _bucketed_counts(frame: pd.DataFrame, time_column: str, category: str, freq: str) -> pd.DataFrame:
    bucket = frame[time_column].dt.floor(freq)
    table = frame.assign(_bucket=bucket).groupby(["_bucket", category]).size().unstack(fill_value=0)
    full_range = pd.date_range(table.index.min(), table.index.max(), freq=freq)
    table = table.reindex(full_range, fill_value=0)
    table.index = table.index.tz_convert("UTC").tz_localize(None)
    table.index.name = "time (UTC)"
    table.columns.name = None
    return table


def filter_events(
    events: pd.DataFrame,
    start: pd.Timestamp | None = None,
    end: pd.Timestamp | None = None,
    source_ips: Iterable[str] | None = None,
    username_contains: str = "",
) -> pd.DataFrame:
    """Filter events. ``end`` is exclusive; empty ``source_ips`` means no IP filter."""
    mask = pd.Series(True, index=events.index)
    if start is not None:
        mask &= events["timestamp"] >= start
    if end is not None:
        mask &= events["timestamp"] < end
    selected = list(source_ips or [])
    if selected:
        mask &= events["source_ip"].isin(selected)
    text = username_contains.strip()
    if text:
        mask &= events["username"].str.contains(text, case=False, regex=False, na=False)
    return events[mask]


def filter_alerts(
    alerts: pd.DataFrame,
    severities: Iterable[str] | None = None,
    rule_ids: Iterable[str] | None = None,
    source_ips: Iterable[str] | None = None,
    username_contains: str = "",
    start: pd.Timestamp | None = None,
    end: pd.Timestamp | None = None,
) -> pd.DataFrame:
    """Filter alerts. An alert is kept if its time span overlaps ``[start, end)``."""
    mask = pd.Series(True, index=alerts.index)
    chosen = list(severities or [])
    if chosen:
        mask &= alerts["severity"].isin(chosen)
    rules = list(rule_ids or [])
    if rules:
        mask &= alerts["rule_id"].isin(rules)
    sources = list(source_ips or [])
    if sources:
        mask &= alerts["source_ip"].isin(sources)
    text = username_contains.strip()
    if text:
        mask &= alerts["username"].str.contains(text, case=False, regex=False, na=False)
    if start is not None:
        mask &= alerts["last_seen"] >= start
    if end is not None:
        mask &= alerts["first_seen"] < end
    return alerts[mask]


def alerts_table(alerts: pd.DataFrame) -> pd.DataFrame:
    """Compact view of alerts for display (no long text or list columns)."""
    return alerts[ALERT_TABLE_COLUMNS].reset_index(drop=True)


_MARKDOWN_SPECIAL = re.compile(r"([\\`*_\[\]()<>#|~$&:!])")


def escape_markdown(text: object) -> str:
    """Backslash-escape characters that Markdown would interpret.

    Usernames and other log values are untrusted; this stops them from creating
    links, emphasis or other formatting when shown with ``st.markdown``.
    """
    return _MARKDOWN_SPECIAL.sub(r"\\\1", str(text))
