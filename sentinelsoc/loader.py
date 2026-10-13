"""Load, validate and normalise authentication logs from CSV or JSON files.

The loader never trusts its input. Bad rows are dropped and counted in a
``LoadReport`` instead of crashing the application. Only problems that make the
whole file unusable (unreadable file, wrong format, missing required columns)
raise ``LogLoadError``.
"""

from __future__ import annotations

import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pandas as pd

REQUIRED_COLUMNS = ("timestamp", "username", "source_ip", "event_type", "status")
OPTIONAL_COLUMNS = ("hostname", "service")
EVENT_COLUMNS = ("event_id",) + REQUIRED_COLUMNS + OPTIONAL_COLUMNS

MAX_FILE_BYTES = 50 * 1024 * 1024
SUPPORTED_FORMATS = {".csv": "csv", ".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl"}

COLUMN_ALIASES = {
    "time": "timestamp",
    "datetime": "timestamp",
    "date_time": "timestamp",
    "event_time": "timestamp",
    "ts": "timestamp",
    "user": "username",
    "user_name": "username",
    "account": "username",
    "account_name": "username",
    "src_ip": "source_ip",
    "src": "source_ip",
    "ip": "source_ip",
    "ip_address": "source_ip",
    "client_ip": "source_ip",
    "remote_ip": "source_ip",
    "source_address": "source_ip",
    "source_ip_address": "source_ip",
    "event": "event_type",
    "action": "event_type",
    "type": "event_type",
    "event_name": "event_type",
    "result": "status",
    "outcome": "status",
    "event_status": "status",
    "host": "hostname",
    "host_name": "hostname",
    "computer": "hostname",
    "device": "hostname",
    "app": "service",
    "application": "service",
    "protocol": "service",
}

STATUS_ALIASES = {
    "success": "success",
    "succeeded": "success",
    "successful": "success",
    "ok": "success",
    "accepted": "success",
    "allowed": "success",
    "pass": "success",
    "passed": "success",
    "failure": "failure",
    "failed": "failure",
    "fail": "failure",
    "unsuccessful": "failure",
    "denied": "failure",
    "rejected": "failure",
    "invalid": "failure",
}

LOGIN_ALIASES = {
    "login",
    "logon",
    "signin",
    "sign_in",
    "auth",
    "authentication",
    "user_login",
    "user_logon",
    "logged_in",
}


class LogLoadError(ValueError):
    """Raised when a log file cannot be used at all."""


@dataclass
class LoadReport:
    """What happened while loading a file (shown in the dashboard's data-quality panel)."""

    source_name: str = ""
    file_format: str = ""
    rows_read: int = 0
    rows_loaded: int = 0
    malformed_rows_skipped: int = 0
    missing_values_dropped: int = 0
    invalid_timestamps_dropped: int = 0
    invalid_ips_dropped: int = 0
    duplicates_removed: int = 0
    unknown_status_rows: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def rows_discarded(self) -> int:
        return (
            self.missing_values_dropped
            + self.invalid_timestamps_dropped
            + self.invalid_ips_dropped
            + self.duplicates_removed
        )


@dataclass
class LoadResult:
    events: pd.DataFrame
    report: LoadReport


def load_logs(source: Any, filename: str | None = None) -> LoadResult:
    """Load a CSV, JSON or JSON Lines log from a path, bytes or file-like object.

    ``filename`` is used to detect the format when ``source`` has no usable name
    (for example an uploaded file wrapped in ``io.BytesIO``).
    """
    data, name = _read_bytes(source, filename)
    suffix = Path(name).suffix.lower()
    if suffix not in SUPPORTED_FORMATS:
        raise LogLoadError(
            f"Unsupported file type '{suffix or name}'. Use .csv, .json or .jsonl files."
        )
    report = LoadReport(source_name=Path(name).name, file_format=SUPPORTED_FORMATS[suffix])

    text = data.decode("utf-8-sig", errors="replace")
    if not text.strip():
        return _empty_result(report, "The file is empty.")

    if report.file_format == "csv":
        raw = _parse_csv(text, report)
    elif report.file_format == "json":
        raw = _parse_json(text, report)
    else:
        raw = _parse_jsonl(text, report)

    if raw.shape[1] == 0:
        return _empty_result(report, "The file contains no event records.")

    raw = _normalise_columns(raw, report)
    missing = [column for column in REQUIRED_COLUMNS if column not in raw.columns]
    if missing:
        raise LogLoadError(
            f"Missing required column(s): {', '.join(missing)}. "
            f"Columns found: {', '.join(map(str, raw.columns)) or 'none'}. "
            f"Required columns: {', '.join(REQUIRED_COLUMNS)}."
        )
    if len(raw) == 0:
        return _empty_result(report, "The file contains a header but no event records.")

    events = _clean(raw, report)
    report.rows_loaded = len(events)
    _add_warnings(report)
    return LoadResult(events=events, report=report)


# --------------------------------------------------------------------------- reading


def _read_bytes(source: Any, filename: str | None) -> tuple[bytes, str]:
    if isinstance(source, (str, Path)):
        path = Path(source)
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise LogLoadError(_too_large_message())
            return path.read_bytes(), filename or path.name
        except FileNotFoundError as exc:
            raise LogLoadError(f"File not found: {path}") from exc
        except OSError as exc:
            raise LogLoadError(f"Could not read '{path}': {exc.strerror or exc}") from exc

    if isinstance(source, (bytes, bytearray)):
        data, name = bytes(source), filename or ""
    elif hasattr(source, "read"):
        data = source.read()
        if isinstance(data, str):
            data = data.encode("utf-8")
        name = filename or str(getattr(source, "name", "") or "")
    else:
        raise LogLoadError(f"Unsupported input of type {type(source).__name__}.")

    if len(data) > MAX_FILE_BYTES:
        raise LogLoadError(_too_large_message())
    return data, name


def _too_large_message() -> str:
    return f"The file is larger than the {MAX_FILE_BYTES // (1024 * 1024)} MB limit."


def _parse_csv(text: str, report: LoadReport) -> pd.DataFrame:
    skipped: list[Any] = []
    try:
        raw = pd.read_csv(
            io.StringIO(text),
            dtype=str,
            keep_default_na=False,
            engine="python",
            on_bad_lines=skipped.append,  # returns None, so the bad row is skipped
        )
    except pd.errors.EmptyDataError:
        return pd.DataFrame()
    except (pd.errors.ParserError, ValueError) as exc:
        raise LogLoadError(f"Could not parse the CSV file: {exc}") from exc
    report.malformed_rows_skipped += len(skipped)
    return raw


def _parse_json(text: str, report: LoadReport) -> pd.DataFrame:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise LogLoadError(f"Could not parse the JSON file: {exc}") from exc

    if isinstance(data, dict):
        if not isinstance(data.get("events"), list):
            raise LogLoadError("A JSON object must contain an 'events' list of event records.")
        data = data["events"]
    if not isinstance(data, list):
        raise LogLoadError("JSON logs must be a list of event objects.")

    records = [item for item in data if isinstance(item, dict)]
    report.malformed_rows_skipped += len(data) - len(records)
    return pd.DataFrame.from_records(records) if records else pd.DataFrame()


def _parse_jsonl(text: str, report: LoadReport) -> pd.DataFrame:
    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            report.malformed_rows_skipped += 1
            continue
        if isinstance(item, dict):
            records.append(item)
        else:
            report.malformed_rows_skipped += 1
    return pd.DataFrame.from_records(records) if records else pd.DataFrame()


# ------------------------------------------------------------------------ cleaning


def _normalise_columns(raw: pd.DataFrame, report: LoadReport) -> pd.DataFrame:
    columns: dict[str, pd.Series] = {}
    for original in raw.columns:
        key = re.sub(r"[^0-9a-z]+", "_", str(original).strip().lower()).strip("_")
        key = COLUMN_ALIASES.get(key, key)
        if key in columns:
            report.warnings.append(f"Column '{original}' duplicates '{key}' and was ignored.")
            continue
        columns[key] = raw[original].map(_cell_to_str)
    return pd.DataFrame(columns, index=raw.index)


def _cell_to_str(value: Any) -> str:
    if value is None or value is pd.NA:
        return ""
    if isinstance(value, float) and value != value:  # NaN
        return ""
    return str(value).strip()


def _clean(raw: pd.DataFrame, report: LoadReport) -> pd.DataFrame:
    frame = raw.copy()
    for column in OPTIONAL_COLUMNS:
        if column not in frame.columns:
            frame[column] = ""
    report.rows_read = len(frame)

    timestamps = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True, format="mixed")
    bad_timestamp = timestamps.isna()

    text_columns = ["username", "source_ip", "event_type", "status"]
    blank = (frame[text_columns] == "").any(axis=1) & ~bad_timestamp

    addresses = frame["source_ip"].map(_normalise_ip)
    bad_ip = addresses.isna() & ~bad_timestamp & ~blank

    report.invalid_timestamps_dropped = int(bad_timestamp.sum())
    report.missing_values_dropped = int(blank.sum())
    report.invalid_ips_dropped = int(bad_ip.sum())

    keep = ~(bad_timestamp | blank | bad_ip)
    cleaned = pd.DataFrame(
        {
            "timestamp": timestamps[keep],
            "username": frame.loc[keep, "username"].str.lower(),
            "source_ip": addresses[keep],
            "event_type": frame.loc[keep, "event_type"].map(_normalise_event_type),
            "status": frame.loc[keep, "status"].map(_normalise_status),
            "hostname": frame.loc[keep, "hostname"],
            "service": frame.loc[keep, "service"].str.lower(),
        }
    )

    before = len(cleaned)
    cleaned = cleaned.drop_duplicates(keep="first")
    report.duplicates_removed = before - len(cleaned)
    report.unknown_status_rows = int((cleaned["status"] == "unknown").sum())

    cleaned = cleaned.sort_values("timestamp", kind="stable").reset_index(drop=True)
    cleaned.insert(0, "event_id", [f"EVT-{n:06d}" for n in range(1, len(cleaned) + 1)])
    return cleaned[list(EVENT_COLUMNS)]


def _normalise_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _normalise_status(value: str) -> str:
    return STATUS_ALIASES.get(value.strip().lower(), "unknown")


def _normalise_event_type(value: str) -> str:
    cleaned = re.sub(r"[\s\-]+", "_", value.strip().lower())
    return "login" if cleaned in LOGIN_ALIASES else cleaned


def _add_warnings(report: LoadReport) -> None:
    if report.malformed_rows_skipped:
        report.warnings.append(
            f"{report.malformed_rows_skipped} malformed row(s) could not be parsed and were skipped."
        )
    if report.invalid_timestamps_dropped:
        report.warnings.append(
            f"{report.invalid_timestamps_dropped} row(s) had a missing or invalid timestamp "
            "and were dropped."
        )
    if report.missing_values_dropped:
        report.warnings.append(
            f"{report.missing_values_dropped} row(s) had an empty username, source_ip, "
            "event_type or status and were dropped."
        )
    if report.invalid_ips_dropped:
        report.warnings.append(
            f"{report.invalid_ips_dropped} row(s) had an invalid IP address and were dropped."
        )
    if report.duplicates_removed:
        report.warnings.append(f"{report.duplicates_removed} duplicate event(s) were removed.")
    if report.unknown_status_rows:
        report.warnings.append(
            f"{report.unknown_status_rows} event(s) have an unrecognised status "
            "and are ignored by the detection rules."
        )
    if report.rows_loaded == 0:
        report.warnings.append("No valid events remained after cleaning.")


# --------------------------------------------------------------------------- empties


def _empty_events() -> pd.DataFrame:
    frame = pd.DataFrame({column: pd.Series(dtype="object") for column in EVENT_COLUMNS})
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    return frame


def _empty_result(report: LoadReport, message: str) -> LoadResult:
    report.warnings.append(message)
    return LoadResult(events=_empty_events(), report=report)
