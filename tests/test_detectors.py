import pandas as pd
import pytest
from helpers import build_events, failures, success

from sentinelsoc.alerts import ALERT_COLUMNS
from sentinelsoc.config import GROUP_BY_SOURCE, DetectionConfig
from sentinelsoc.detectors import (
    RULE_FAILED_BURST,
    RULE_SUCCESS_AFTER_FAILURES,
    detect_failed_login_bursts,
    detect_success_after_failures,
    run_detections,
)

DEFAULT = DetectionConfig()


# ---------------------------------------------------------------- SOC-001 bursts


def test_burst_at_threshold_raises_one_medium_alert():
    events = build_events(failures("2026-03-09 10:00:00", 5, 30))
    alerts = detect_failed_login_bursts(events, DEFAULT)
    assert len(alerts) == 1
    assert alerts[0].rule_id == RULE_FAILED_BURST
    assert alerts[0].severity == "Medium"
    assert alerts[0].event_count == 5


def test_below_threshold_raises_nothing():
    events = build_events(failures("2026-03-09 10:00:00", 4, 30))
    assert detect_failed_login_bursts(events, DEFAULT) == []


def test_failures_spread_beyond_window_raise_nothing():
    events = build_events(failures("2026-03-09 10:00:00", 5, 300))  # 20 minutes in total
    assert detect_failed_login_bursts(events, DEFAULT) == []


def test_window_boundary_is_inclusive():
    events = build_events(failures("2026-03-09 10:00:00", 5, 150))  # exactly 10 minutes
    assert len(detect_failed_login_bursts(events, DEFAULT)) == 1


def test_window_is_configurable():
    events = build_events(failures("2026-03-09 10:00:00", 5, 300))
    config = DetectionConfig(failure_window_minutes=30)
    assert len(detect_failed_login_bursts(events, config)) == 1


def test_threshold_is_configurable():
    events = build_events(failures("2026-03-09 10:00:00", 3, 30))
    config = DetectionConfig(failure_threshold=3)
    assert len(detect_failed_login_bursts(events, config)) == 1


def test_large_burst_is_high_severity():
    events = build_events(failures("2026-03-09 10:00:00", 10, 20))
    assert detect_failed_login_bursts(events, DEFAULT)[0].severity == "High"


def test_two_separate_bursts_raise_two_alerts():
    rows = failures("2026-03-09 10:00:00", 5, 30) + failures("2026-03-09 14:00:00", 5, 30)
    assert len(detect_failed_login_bursts(build_events(rows), DEFAULT)) == 2


def test_long_continuous_attack_is_one_alert_with_all_events():
    events = build_events(failures("2026-03-09 10:00:00", 40, 30))  # about 20 minutes
    alerts = detect_failed_login_bursts(events, DEFAULT)
    assert len(alerts) == 1
    assert alerts[0].event_count == 40
    assert len(alerts[0].evidence_event_ids) == 40


def test_same_account_from_different_sources_is_not_combined():
    rows = failures("2026-03-09 10:00:00", 3, 30, ip="203.0.113.1") + failures(
        "2026-03-09 10:00:10", 3, 30, ip="203.0.113.2"
    )
    assert detect_failed_login_bursts(build_events(rows), DEFAULT) == []


def spray_rows():
    """One source tries 10 different accounts, one failure each, 10 seconds apart."""
    first = pd.Timestamp("2026-03-09 10:00:00", tz="UTC")
    return [
        ((first + pd.Timedelta(seconds=10 * n)).isoformat(), f"user{n}", "192.0.2.9", "failure")
        for n in range(10)
    ]


def test_password_spraying_is_missed_per_account_but_found_per_source():
    events = build_events(spray_rows())
    assert detect_failed_login_bursts(events, DEFAULT) == []

    alerts = detect_failed_login_bursts(events, DetectionConfig(group_by=GROUP_BY_SOURCE))
    assert len(alerts) == 1
    assert alerts[0].event_count == 10
    assert alerts[0].severity == "High"
    assert "10 accounts" in alerts[0].evidence


def test_failures_of_other_event_types_are_ignored():
    rows = [(w, u, i, s, "file_access") for (w, u, i, s) in failures("2026-03-09 10:00:00", 10, 10)]
    assert detect_failed_login_bursts(build_events(rows), DEFAULT) == []


def test_unknown_status_events_are_ignored():
    rows = [(w, u, i, "unknown") for (w, u, i, _) in failures("2026-03-09 10:00:00", 10, 10)]
    assert run_detections(build_events(rows), DEFAULT).empty


# --------------------------------------------------- SOC-002 success after failures


def test_success_after_three_failures_is_medium():
    rows = failures("2026-03-09 10:00:00", 3, 10) + [success("2026-03-09 10:01:00")]
    alerts = detect_success_after_failures(build_events(rows), DEFAULT)
    assert len(alerts) == 1
    assert alerts[0].rule_id == RULE_SUCCESS_AFTER_FAILURES
    assert alerts[0].severity == "Medium"
    assert alerts[0].event_count == 4
    assert alerts[0].last_seen > alerts[0].first_seen


@pytest.mark.parametrize(
    "failure_count, expected",
    [(3, "Medium"), (4, "Medium"), (5, "High"), (9, "High"), (10, "Critical"), (15, "Critical")],
)
def test_success_severity_grows_with_failures(failure_count, expected):
    rows = failures("2026-03-09 10:00:00", failure_count, 5) + [success("2026-03-09 10:05:00")]
    alerts = detect_success_after_failures(build_events(rows), DEFAULT)
    assert alerts[0].severity == expected


def test_too_few_failures_before_success_raise_nothing():
    rows = failures("2026-03-09 10:00:00", 2, 10) + [success("2026-03-09 10:01:00")]
    assert detect_success_after_failures(build_events(rows), DEFAULT) == []


def test_failures_older_than_lookback_are_ignored():
    rows = failures("2026-03-09 09:00:00", 3, 10) + [success("2026-03-09 10:00:00")]
    assert detect_success_after_failures(build_events(rows), DEFAULT) == []


def test_success_from_another_source_does_not_match():
    rows = failures("2026-03-09 10:00:00", 4, 10) + [success("2026-03-09 10:02:00", ip="198.51.100.5")]
    assert detect_success_after_failures(build_events(rows), DEFAULT) == []


def test_success_for_another_account_does_not_match():
    rows = failures("2026-03-09 10:00:00", 4, 10) + [success("2026-03-09 10:02:00", user="alice")]
    assert detect_success_after_failures(build_events(rows), DEFAULT) == []


def test_repeated_successes_raise_only_one_alert():
    rows = failures("2026-03-09 10:00:00", 4, 10) + [
        success("2026-03-09 10:02:00"),
        success("2026-03-09 10:03:00"),
    ]
    assert len(detect_success_after_failures(build_events(rows), DEFAULT)) == 1


def test_failures_are_not_reused_after_a_success():
    rows = (
        failures("2026-03-09 10:00:00", 3, 10)
        + [success("2026-03-09 10:02:00")]
        + failures("2026-03-09 10:05:00", 2, 10)
        + [success("2026-03-09 10:07:00")]
    )
    assert len(detect_success_after_failures(build_events(rows), DEFAULT)) == 1


def test_min_failures_is_configurable():
    rows = failures("2026-03-09 10:00:00", 2, 10) + [success("2026-03-09 10:01:00")]
    config = DetectionConfig(success_min_failures=2)
    assert len(detect_success_after_failures(build_events(rows), config)) == 1


def test_success_alert_cites_failures_and_the_success():
    events = build_events(failures("2026-03-09 10:00:00", 3, 10) + [success("2026-03-09 10:01:00")])
    alert = detect_success_after_failures(events, DEFAULT)[0]
    assert alert.evidence_event_ids == ("EVT-000001", "EVT-000002", "EVT-000003", "EVT-000004")


# ----------------------------------------------------------------- run_detections


def test_run_detections_combines_rules_and_sorts_by_severity():
    rows = failures("2026-03-09 10:00:00", 12, 10) + [success("2026-03-09 10:03:00")]
    alerts = run_detections(build_events(rows), DEFAULT)
    assert list(alerts["rule_id"]) == [RULE_SUCCESS_AFTER_FAILURES, RULE_FAILED_BURST]
    assert list(alerts["severity"]) == ["Critical", "High"]
    assert list(alerts["alert_id"]) == ["ALT-0001", "ALT-0002"]


def test_alert_fields_are_complete_and_evidence_exists_in_events():
    rows = failures("2026-03-09 10:00:00", 6, 10) + [success("2026-03-09 10:02:00")]
    events = build_events(rows)
    alerts = run_detections(events, DEFAULT)
    assert list(alerts.columns) == ALERT_COLUMNS
    for _, alert in alerts.iterrows():
        assert alert["evidence"] and alert["recommendation"] and alert["mitre_attack"].startswith("T1")
        assert pd.notna(alert["first_seen"]) and pd.notna(alert["last_seen"])
        assert set(alert["evidence_event_ids"]) <= set(events["event_id"])


def test_run_detections_on_empty_events_returns_empty_alerts_with_columns():
    empty = build_events([])
    alerts = run_detections(empty, DEFAULT)
    assert alerts.empty
    assert list(alerts.columns) == ALERT_COLUMNS


def test_run_detections_rejects_a_table_without_required_columns():
    with pytest.raises(ValueError):
        run_detections(pd.DataFrame({"timestamp": [pd.Timestamp("2026-03-09", tz="UTC")]}), DEFAULT)


def test_unsorted_input_gives_the_same_alerts():
    rows = failures("2026-03-09 10:00:00", 6, 10)
    forward = run_detections(build_events(rows), DEFAULT)
    backward = run_detections(build_events(list(reversed(rows))), DEFAULT)
    assert len(forward) == len(backward) == 1
    assert forward.loc[0, "first_seen"] == backward.loc[0, "first_seen"]


# ------------------------------------------------------------------ configuration


@pytest.mark.parametrize("field", ["failure_threshold", "failure_window_minutes", "success_min_failures"])
def test_config_rejects_non_positive_numbers(field):
    with pytest.raises(ValueError):
        DetectionConfig(**{field: 0})


def test_config_rejects_unknown_grouping():
    with pytest.raises(ValueError):
        DetectionConfig(group_by="everything")
