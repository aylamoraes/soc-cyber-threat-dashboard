"""Detection rules for suspicious authentication activity.

Rules (documented in docs/detection_rules.md):

* SOC-001  Repeated failed logins within a time window.
* SOC-002  Successful login after repeated failed logins.

Both rules only look at events with ``event_type == "login"`` and a known status.
"""

from __future__ import annotations

import pandas as pd

from .alerts import Alert, alerts_to_frame, empty_alerts_frame
from .config import GROUP_BY_SOURCE, DetectionConfig
from .loader import REQUIRED_COLUMNS

RULE_FAILED_BURST = "SOC-001"
RULE_SUCCESS_AFTER_FAILURES = "SOC-002"
RULE_NAMES = {
    RULE_FAILED_BURST: "Repeated failed logins",
    RULE_SUCCESS_AFTER_FAILURES: "Successful login after repeated failures",
}

MITRE_BRUTE_FORCE = "T1110 - Brute Force (Credential Access)"
MITRE_PASSWORD_GUESSING = "T1110.001 - Brute Force: Password Guessing (Credential Access)"
MITRE_SUCCESS_AFTER_FAILURES = (
    "T1110 - Brute Force (Credential Access); "
    "T1078 - Valid Accounts, if the login is confirmed as unauthorised"
)

RECOMMENDATION_BURST = (
    "Check whether the activity is expected (for example a user who forgot a password). "
    "If not, block or rate-limit the source IP, review other logs from the same source, "
    "consider a temporary account lockout, and require multi-factor authentication."
)
RECOMMENDATION_SUCCESS = (
    "Treat the account as potentially compromised until verified: contact the account owner, "
    "reset the password, revoke active sessions and tokens, review what the account did after "
    "the login, and require multi-factor authentication."
)

_TIME_FORMAT = "%Y-%m-%d %H:%M:%S UTC"


def run_detections(events: pd.DataFrame, config: DetectionConfig | None = None) -> pd.DataFrame:
    """Run every rule and return one alerts table (empty if nothing was found)."""
    config = config or DetectionConfig()
    if events is None or len(events) == 0:
        return empty_alerts_frame()
    alerts = detect_failed_login_bursts(events, config) + detect_success_after_failures(
        events, config
    )
    return alerts_to_frame(alerts)


# ------------------------------------------------------------------------- SOC-001


def detect_failed_login_bursts(events: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """SOC-001: at least ``failure_threshold`` failures within ``failure_window_minutes``.

    Overlapping qualifying windows are merged, so one continuous attack raises
    one alert instead of many.
    """
    failures = _login_events(events)
    failures = failures[failures["status"] == "failure"]
    if failures.empty:
        return []

    window = pd.Timedelta(minutes=config.failure_window_minutes)
    by_source = config.group_by == GROUP_BY_SOURCE
    keys = ["source_ip"] if by_source else ["source_ip", "username"]

    alerts: list[Alert] = []
    for _, group in failures.groupby(keys, sort=True):
        times = list(group["timestamp"])
        for first, last in _burst_ranges(times, config.failure_threshold, window):
            alerts.append(_burst_alert(group.iloc[first : last + 1], config))
    return alerts


def _burst_ranges(
    times: list[pd.Timestamp], threshold: int, window: pd.Timedelta
) -> list[tuple[int, int]]:
    """Return merged (first, last) index ranges covered by any qualifying window.

    A window starts at an event and spans ``window`` (inclusive). It qualifies when
    it holds at least ``threshold`` events. ``times`` must be sorted.
    """
    ranges: list[tuple[int, int]] = []
    end = 0
    for start in range(len(times)):
        end = max(end, start)
        while end < len(times) and times[end] - times[start] <= window:
            end += 1
        if end - start >= threshold:
            if ranges and start <= ranges[-1][1]:
                ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end - 1))
            else:
                ranges.append((start, end - 1))
    return ranges


def _burst_alert(burst: pd.DataFrame, config: DetectionConfig) -> Alert:
    count = len(burst)
    users = sorted(burst["username"].unique())
    source_ip = burst["source_ip"].iloc[0]
    first_seen = burst["timestamp"].iloc[0]
    last_seen = burst["timestamp"].iloc[-1]

    severity = "High" if count >= 2 * config.failure_threshold else "Medium"
    if len(users) == 1:
        target = f"account '{users[0]}'"
    else:
        target = f"{len(users)} accounts ({_preview(users)})"
    mitre = MITRE_BRUTE_FORCE if config.group_by == GROUP_BY_SOURCE else MITRE_PASSWORD_GUESSING

    evidence = (
        f"{count} failed logins against {target} from {source_ip} between "
        f"{first_seen.strftime(_TIME_FORMAT)} and {last_seen.strftime(_TIME_FORMAT)} "
        f"(rule: at least {config.failure_threshold} failures within "
        f"{config.failure_window_minutes} min).{_context(burst['service'], burst['hostname'])}"
    )
    return Alert(
        rule_id=RULE_FAILED_BURST,
        rule_name=RULE_NAMES[RULE_FAILED_BURST],
        severity=severity,
        first_seen=first_seen,
        last_seen=last_seen,
        username="; ".join(users),
        source_ip=source_ip,
        event_count=count,
        evidence=evidence,
        recommendation=RECOMMENDATION_BURST,
        mitre_attack=mitre,
        evidence_event_ids=tuple(burst["event_id"]),
    )


# ------------------------------------------------------------------------- SOC-002


def detect_success_after_failures(events: pd.DataFrame, config: DetectionConfig) -> list[Alert]:
    """SOC-002: a success preceded by at least ``success_min_failures`` failures.

    Failures must come from the same account and source IP and fall within
    ``success_lookback_minutes`` before the success. A success resets the failure
    counter, so repeated successes do not raise repeated alerts.
    """
    logins = _login_events(events)
    if logins.empty:
        return []

    lookback = pd.Timedelta(minutes=config.success_lookback_minutes)
    alerts: list[Alert] = []
    for _, group in logins.groupby(["source_ip", "username"], sort=True):
        pending: list = []
        for row in group.itertuples(index=False):
            if row.status == "failure":
                pending.append(row)
            elif row.status == "success":
                recent = [r for r in pending if row.timestamp - r.timestamp <= lookback]
                if len(recent) >= config.success_min_failures:
                    alerts.append(_success_alert(recent, row, config))
                pending = []
    return alerts


def _success_alert(failures: list, success, config: DetectionConfig) -> Alert:
    count = len(failures)
    if count >= 2 * config.failure_threshold:
        severity = "Critical"
    elif count >= config.failure_threshold:
        severity = "High"
    else:
        severity = "Medium"

    first_failure = failures[0].timestamp
    minutes = (success.timestamp - first_failure).total_seconds() / 60
    related = failures + [success]
    context = _context(
        pd.Series([row.service for row in related]), pd.Series([row.hostname for row in related])
    )
    evidence = (
        f"Successful login for '{success.username}' from {success.source_ip} at "
        f"{success.timestamp.strftime(_TIME_FORMAT)}, preceded by {count} failed attempts "
        f"from the same IP starting at {first_failure.strftime(_TIME_FORMAT)} "
        f"({minutes:.1f} min earlier; look-back: {config.success_lookback_minutes} min)."
        f"{context}"
    )
    return Alert(
        rule_id=RULE_SUCCESS_AFTER_FAILURES,
        rule_name=RULE_NAMES[RULE_SUCCESS_AFTER_FAILURES],
        severity=severity,
        first_seen=first_failure,
        last_seen=success.timestamp,
        username=success.username,
        source_ip=success.source_ip,
        event_count=count + 1,
        evidence=evidence,
        recommendation=RECOMMENDATION_SUCCESS,
        mitre_attack=MITRE_SUCCESS_AFTER_FAILURES,
        evidence_event_ids=tuple(r.event_id for r in failures) + (success.event_id,),
    )


# ------------------------------------------------------------------------- helpers


def _login_events(events: pd.DataFrame) -> pd.DataFrame:
    """Return login events with a known status, oldest first."""
    missing = [column for column in REQUIRED_COLUMNS if column not in events.columns]
    if missing:
        raise ValueError(f"Events table is missing column(s): {', '.join(missing)}")
    for column in ("event_id", "service", "hostname"):
        if column not in events.columns:
            raise ValueError(f"Events table is missing column: {column}")
    mask = (events["event_type"] == "login") & events["status"].isin(["success", "failure"])
    return events[mask].sort_values("timestamp", kind="stable")


def _preview(values: list[str], limit: int = 5) -> str:
    shown = ", ".join(values[:limit])
    extra = len(values) - limit
    return f"{shown}, +{extra} more" if extra > 0 else shown


def _context(services: pd.Series, hostnames: pd.Series) -> str:
    parts = []
    service_values = sorted({value for value in services if value})
    host_values = sorted({value for value in hostnames if value})
    if service_values:
        parts.append(f"Services: {', '.join(service_values)}.")
    if host_values:
        parts.append(f"Hosts: {', '.join(host_values)}.")
    return " " + " ".join(parts) if parts else ""
