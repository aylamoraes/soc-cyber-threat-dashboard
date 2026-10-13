import io
import json

import pandas as pd
import pytest

from sentinelsoc import loader
from sentinelsoc.loader import EVENT_COLUMNS, LogLoadError, load_logs

HEADER = "timestamp,username,source_ip,event_type,status,hostname,service\n"
GOOD_ROW = "2026-03-09T10:00:00Z,alice,10.0.0.1,login,success,host-01,vpn\n"


def load_csv(text, name="logs.csv"):
    return load_logs(io.StringIO(text), filename=name)


def test_loads_a_valid_csv():
    result = load_csv(HEADER + GOOD_ROW + "2026-03-09T09:00:00Z,bob,10.0.0.2,login,failure,host-01,vpn\n")
    events = result.events
    assert list(events.columns) == list(EVENT_COLUMNS)
    assert list(events["username"]) == ["bob", "alice"]  # sorted by time
    assert list(events["event_id"]) == ["EVT-000001", "EVT-000002"]
    assert str(events["timestamp"].dt.tz) == "UTC"
    assert result.report.rows_read == 2
    assert result.report.rows_loaded == 2
    assert result.report.warnings == []


def test_loads_a_json_array():
    records = [
        {"timestamp": "2026-03-09T10:00:00Z", "username": "alice", "source_ip": "10.0.0.1",
         "event_type": "login", "status": "success"}
    ]
    result = load_logs(io.BytesIO(json.dumps(records).encode()), filename="logs.json")
    assert len(result.events) == 1
    assert result.events.loc[0, "hostname"] == ""  # optional columns default to empty


def test_loads_a_json_object_with_an_events_list():
    payload = {"events": [{"timestamp": "2026-03-09T10:00:00Z", "username": "alice",
                           "source_ip": "10.0.0.1", "event_type": "login", "status": "success"}]}
    result = load_logs(io.StringIO(json.dumps(payload)), filename="logs.json")
    assert len(result.events) == 1


def test_loads_json_lines_and_skips_bad_lines():
    good = json.dumps({"timestamp": "2026-03-09T10:00:00Z", "username": "alice",
                       "source_ip": "10.0.0.1", "event_type": "login", "status": "success"})
    text = good + "\nthis is not json\n[1, 2]\n\n"
    result = load_logs(io.StringIO(text), filename="logs.jsonl")
    assert len(result.events) == 1
    assert result.report.malformed_rows_skipped == 2


def test_loads_from_a_path(tmp_path):
    path = tmp_path / "logs.csv"
    path.write_text(HEADER + GOOD_ROW, encoding="utf-8")
    assert len(load_logs(path).events) == 1
    assert len(load_logs(str(path)).events) == 1


def test_column_names_are_matched_case_insensitively_with_aliases():
    text = "Time,User,Src_IP,Action,Outcome\n2026-03-09T10:00:00Z,Alice,10.0.0.1,Logon,FAILED\n"
    events = load_csv(text).events
    assert events.loc[0, "username"] == "alice"
    assert events.loc[0, "event_type"] == "login"
    assert events.loc[0, "status"] == "failure"


def test_status_synonyms_are_normalised():
    rows = "".join(
        f"2026-03-09T10:00:0{n}Z,u{n},10.0.0.1,login,{status}\n"
        for n, status in enumerate(["Accepted", "Denied", "OK", "failed"])
    )
    events = load_csv("timestamp,username,source_ip,event_type,status\n" + rows).events
    assert list(events["status"]) == ["success", "failure", "success", "failure"]


def test_unknown_status_is_kept_and_counted():
    text = HEADER + "2026-03-09T10:00:00Z,alice,10.0.0.1,login,maybe,h,s\n"
    result = load_csv(text)
    assert result.events.loc[0, "status"] == "unknown"
    assert result.report.unknown_status_rows == 1
    assert any("unrecognised status" in warning for warning in result.report.warnings)


def test_missing_required_column_raises_a_clear_error():
    with pytest.raises(LogLoadError) as error:
        load_csv("timestamp,source_ip,event_type,status\n2026-03-09T10:00:00Z,10.0.0.1,login,success\n")
    assert "username" in str(error.value)


def test_invalid_timestamps_are_dropped_and_counted():
    text = HEADER + GOOD_ROW + "not-a-date,bob,10.0.0.2,login,success,h,s\n,carol,10.0.0.3,login,success,h,s\n"
    result = load_csv(text)
    assert len(result.events) == 1
    assert result.report.invalid_timestamps_dropped == 2


def test_rows_with_blank_required_values_are_dropped():
    text = HEADER + GOOD_ROW + "2026-03-09T11:00:00Z,,10.0.0.2,login,success,h,s\n"
    result = load_csv(text)
    assert len(result.events) == 1
    assert result.report.missing_values_dropped == 1


def test_invalid_ip_addresses_are_dropped():
    text = HEADER + GOOD_ROW + "2026-03-09T11:00:00Z,bob,999.1.1.1,login,success,h,s\n"
    result = load_csv(text)
    assert len(result.events) == 1
    assert result.report.invalid_ips_dropped == 1


def test_duplicate_events_are_removed_ignoring_username_case():
    text = HEADER + GOOD_ROW + GOOD_ROW + GOOD_ROW.replace("alice", "ALICE")
    result = load_csv(text)
    assert len(result.events) == 1
    assert result.report.duplicates_removed == 2


def test_same_second_events_with_different_details_are_not_duplicates():
    text = HEADER + GOOD_ROW + GOOD_ROW.replace("success", "failure")
    assert len(load_csv(text).events) == 2


def test_empty_file_returns_an_empty_result_with_a_warning():
    result = load_logs(io.BytesIO(b""), filename="logs.csv")
    assert result.events.empty
    assert list(result.events.columns) == list(EVENT_COLUMNS)
    assert result.report.warnings


def test_header_only_csv_returns_an_empty_result():
    result = load_csv(HEADER)
    assert result.events.empty
    assert result.report.warnings


def test_file_where_every_row_is_invalid_returns_an_empty_result():
    result = load_csv(HEADER + "bad,,,,,,\n")
    assert result.events.empty
    assert any("No valid events" in warning for warning in result.report.warnings)


def test_rows_with_too_many_fields_are_skipped_not_fatal():
    text = HEADER + GOOD_ROW + "2026-03-09T11:00:00Z,bob,10.0.0.2,login,success,h,s,extra,fields\n"
    result = load_csv(text)
    assert len(result.events) == 1
    assert result.report.malformed_rows_skipped == 1


def test_unsupported_extension_raises():
    with pytest.raises(LogLoadError):
        load_logs(io.StringIO("hello"), filename="logs.txt")


def test_invalid_json_raises():
    with pytest.raises(LogLoadError):
        load_logs(io.StringIO("{not json"), filename="logs.json")


def test_json_object_without_events_raises():
    with pytest.raises(LogLoadError):
        load_logs(io.StringIO('{"hello": "world"}'), filename="logs.json")


def test_missing_file_raises(tmp_path):
    with pytest.raises(LogLoadError):
        load_logs(tmp_path / "does-not-exist.csv")


def test_oversized_input_is_rejected():
    original = loader.MAX_FILE_BYTES
    loader.MAX_FILE_BYTES = 10
    try:
        with pytest.raises(LogLoadError):
            load_csv(HEADER + GOOD_ROW)
    finally:
        loader.MAX_FILE_BYTES = original


def test_naive_timestamps_are_treated_as_utc_and_offsets_are_converted():
    text = (
        "timestamp,username,source_ip,event_type,status\n"
        "2026-03-09 10:00:00,alice,10.0.0.1,login,success\n"
        "2026-03-09T10:00:00+02:00,bob,10.0.0.2,login,success\n"
    )
    events = load_csv(text).events
    assert events.loc[events["username"] == "alice", "timestamp"].iloc[0] == pd.Timestamp("2026-03-09 10:00", tz="UTC")
    assert events.loc[events["username"] == "bob", "timestamp"].iloc[0] == pd.Timestamp("2026-03-09 08:00", tz="UTC")


def test_byte_order_mark_is_ignored():
    result = load_logs(io.BytesIO(("﻿" + HEADER + GOOD_ROW).encode("utf-8")), filename="logs.csv")
    assert len(result.events) == 1
