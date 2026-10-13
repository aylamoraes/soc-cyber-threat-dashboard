import pandas as pd
from helpers import build_events, failures, success

from sentinelsoc.config import DetectionConfig
from sentinelsoc.detectors import run_detections
from sentinelsoc.metrics import (
    alert_timeline,
    alerts_table,
    bucket_frequency,
    escape_markdown,
    event_timeline,
    filter_alerts,
    filter_events,
    summary_metrics,
    top_failed_logins,
)


def scenario():
    rows = (
        failures("2026-03-09 10:00:00", 6, 10, user="carla", ip="198.51.100.7")
        + [success("2026-03-09 10:02:00", user="carla", ip="198.51.100.7")]
        + [("2026-03-09 11:00:00", "alice", "10.0.0.1", "success")]
        + [("2026-03-09 11:05:00", "alice", "10.0.0.1", "failure", "file_access")]
    )
    events = build_events(rows)
    return events, run_detections(events, DetectionConfig())


def test_summary_metrics_count_logins_only():
    events, alerts = scenario()
    metrics = summary_metrics(events, alerts)
    assert metrics["total_events"] == 9
    assert metrics["login_failures"] == 6  # the failed file_access is not a login failure
    assert metrics["login_successes"] == 2
    assert metrics["unique_sources"] == 2
    assert metrics["unique_users"] == 2
    assert metrics["total_alerts"] == 2
    assert metrics["high_or_critical_alerts"] == 1  # SOC-002 with 6 failures is High


def test_summary_metrics_handle_empty_tables():
    empty_events = build_events([])
    empty_alerts = run_detections(empty_events, DetectionConfig())
    assert set(summary_metrics(empty_events, empty_alerts).values()) == {0}


def test_top_failed_logins_ranks_by_count():
    events, _ = scenario()
    top = top_failed_logins(events, "source_ip")
    assert list(top.columns) == ["source_ip", "failed_logins"]
    assert top.loc[0, "source_ip"] == "198.51.100.7"
    assert top.loc[0, "failed_logins"] == 6


def test_top_failed_logins_with_no_failures_is_empty():
    events = build_events([("2026-03-09 10:00:00", "alice", "10.0.0.1", "success")])
    assert top_failed_logins(events, "username").empty


def test_bucket_frequency_scales_with_the_time_span():
    short = build_events(failures("2026-03-09 10:00:00", 5, 60))
    long = build_events(failures("2026-03-01 00:00:00", 5, 86400 * 2))
    assert bucket_frequency(short) == "1min"
    assert bucket_frequency(long) in {"1h", "3h", "6h"}
    assert bucket_frequency(build_events([])) == "1min"


def test_event_timeline_counts_by_status_with_a_naive_utc_index():
    events, _ = scenario()
    timeline = event_timeline(events, "1h")
    assert timeline.index.tz is None
    assert int(timeline["failure"].sum()) == 7
    assert int(timeline["success"].sum()) == 2
    assert timeline.loc[pd.Timestamp("2026-03-09 10:00"), "failure"] == 6


def test_event_timeline_fills_gaps_with_zero():
    events = build_events(
        [("2026-03-09 10:00:00", "a", "10.0.0.1", "failure"), ("2026-03-09 13:00:00", "a", "10.0.0.1", "failure")]
    )
    timeline = event_timeline(events, "1h")
    assert len(timeline) == 4
    assert int(timeline.loc[pd.Timestamp("2026-03-09 11:00"), "failure"]) == 0


def test_alert_timeline_orders_columns_by_severity():
    _, alerts = scenario()
    timeline = alert_timeline(alerts, "1h")
    assert list(timeline.columns) == ["Medium", "High"]
    assert event_timeline(build_events([])).empty and alert_timeline(alerts.iloc[0:0], "1h").empty


def test_filter_events_by_time_source_and_username():
    events, _ = scenario()
    start = pd.Timestamp("2026-03-09 10:30", tz="UTC")
    assert set(filter_events(events, start=start)["username"]) == {"alice"}
    assert len(filter_events(events, end=start)) == 7
    assert len(filter_events(events, source_ips=["198.51.100.7"])) == 7
    assert len(filter_events(events, username_contains="ALI")) == 2
    assert len(filter_events(events)) == len(events)


def test_filter_alerts_by_severity_rule_source_and_time():
    _, alerts = scenario()
    assert len(filter_alerts(alerts, severities=["Medium"])) == 1
    assert len(filter_alerts(alerts, rule_ids=["SOC-002"])) == 1
    assert len(filter_alerts(alerts, source_ips=["10.0.0.1"])) == 0
    assert len(filter_alerts(alerts, username_contains="carl")) == 2
    late = pd.Timestamp("2026-03-09 12:00", tz="UTC")
    assert filter_alerts(alerts, start=late).empty
    assert len(filter_alerts(alerts)) == 2


def test_escape_markdown_neutralises_links_and_emphasis():
    escaped = escape_markdown("[click](http://example.test) **bold** `code` <b>x</b>")
    assert "\\[click\\]\\(http\\://example.test\\)" in escaped
    assert "\\*\\*bold\\*\\*" in escaped
    assert "\\<b\\>" in escaped
    assert escape_markdown("alice") == "alice"
    assert escape_markdown(None) == "None"


def test_alerts_table_hides_long_columns():
    _, alerts = scenario()
    table = alerts_table(alerts)
    assert "evidence" not in table.columns
    assert "evidence_event_ids" not in table.columns
    assert len(table) == len(alerts)
