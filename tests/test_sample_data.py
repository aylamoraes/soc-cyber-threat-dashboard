"""Integration tests: the shipped sample files must load and produce the documented alerts."""

from pathlib import Path

from sentinelsoc.config import GROUP_BY_SOURCE, DetectionConfig
from sentinelsoc.detectors import run_detections
from sentinelsoc.loader import load_logs
from sentinelsoc.sample_data import write_samples

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def analyse(name, config=None):
    result = load_logs(DATA_DIR / name)
    return result, run_detections(result.events, config or DetectionConfig())


def test_committed_samples_match_the_generator(tmp_path):
    for path in write_samples(tmp_path):
        assert path.read_bytes() == (DATA_DIR / path.name).read_bytes(), path.name


def test_csv_and_json_samples_give_identical_alerts():
    csv_result, csv_alerts = analyse("sample_auth_logs.csv")
    json_result, json_alerts = analyse("sample_auth_logs.json")
    assert len(csv_result.events) == len(json_result.events) > 300
    assert list(csv_alerts["evidence"]) == list(json_alerts["evidence"])


def test_samples_include_duplicates_that_are_removed():
    result, _ = analyse("sample_auth_logs.csv")
    assert result.report.duplicates_removed >= 6
    assert result.report.rows_read == result.report.rows_loaded + result.report.duplicates_removed


def test_default_settings_find_the_planned_scenarios():
    _, alerts = analyse("sample_auth_logs.csv")
    found = set(zip(alerts["rule_id"], alerts["severity"], alerts["username"], alerts["source_ip"]))
    assert found == {
        ("SOC-002", "Critical", "carla", "198.51.100.77"),
        ("SOC-001", "High", "admin", "203.0.113.45"),
        ("SOC-001", "High", "carla", "198.51.100.77"),
        ("SOC-002", "Medium", "elena", "10.20.2.22"),
    }


def test_low_and_slow_guessing_is_not_detected_by_default():
    _, alerts = analyse("sample_auth_logs.csv")
    assert "203.0.113.120" not in set(alerts["source_ip"])


def test_password_spraying_appears_only_when_grouping_by_source():
    _, alerts = analyse("sample_auth_logs.csv", DetectionConfig(group_by=GROUP_BY_SOURCE))
    spray = alerts[alerts["source_ip"] == "192.0.2.99"]
    assert len(spray) == 1
    assert spray.iloc[0]["event_count"] == 16
    assert spray.iloc[0]["severity"] == "High"


def test_malformed_demo_is_cleaned_and_still_analysed():
    result, alerts = analyse("sample_malformed_demo.csv")
    report = result.report
    assert report.malformed_rows_skipped == 1
    assert report.invalid_timestamps_dropped == 1
    assert report.missing_values_dropped == 1
    assert report.invalid_ips_dropped == 1
    assert report.duplicates_removed == 1
    assert report.unknown_status_rows == 1
    assert report.rows_loaded == 9
    assert sorted(alerts["rule_id"]) == ["SOC-001", "SOC-002"]
