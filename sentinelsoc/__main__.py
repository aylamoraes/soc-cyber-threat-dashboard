"""Command-line entry point: analyse a log file without opening the dashboard.

Examples::

    python -m sentinelsoc data/sample_auth_logs.csv --json alerts.json
    python -m sentinelsoc            # no file -> analyse the built-in synthetic feed
"""

from __future__ import annotations

import argparse
import io
import sys

from .alerts import SEVERITY_LEVELS
from .config import GROUP_BY_ACCOUNT_AND_SOURCE, VALID_GROUP_BY, DetectionConfig
from .detectors import run_detections
from .export import alerts_to_csv, alerts_to_json
from .loader import LogLoadError, LoadResult, load_logs
from .sample_data import synthetic_csv_text

SYNTHETIC_SOURCE_NAME = "synthetic_auth_logs.csv"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m sentinelsoc",
        description=(
            "Detect suspicious authentication activity in a CSV, JSON or JSONL log. "
            "If no log file is given, the built-in synthetic dataset is analysed."
        ),
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        default=None,
        help="path to the log file (optional; defaults to the built-in synthetic feed)",
    )
    parser.add_argument("--threshold", type=int, default=5, help="failures needed for SOC-001")
    parser.add_argument("--window", type=int, default=10, help="SOC-001 window in minutes")
    parser.add_argument(
        "--group-by",
        choices=VALID_GROUP_BY,
        default=GROUP_BY_ACCOUNT_AND_SOURCE,
        help="count failures per account+source or per source only",
    )
    parser.add_argument("--min-failures", type=int, default=3, help="failures needed for SOC-002")
    parser.add_argument("--lookback", type=int, default=30, help="SOC-002 look-back in minutes")
    parser.add_argument("--csv", metavar="PATH", help="write alerts to a CSV file")
    parser.add_argument("--json", metavar="PATH", help="write alerts to a JSON file")
    return parser


def _load_source(logfile: str | None) -> LoadResult:
    """Load the given file, or the built-in synthetic feed when none is provided.

    Keeping this separate lets the CLI run with no arguments (e.g. from
    ``streamlit run``) while still reporting where the data came from.
    """
    if logfile:
        return load_logs(logfile)
    return load_logs(io.StringIO(synthetic_csv_text()), filename=SYNTHETIC_SOURCE_NAME)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        config = DetectionConfig(
            failure_threshold=args.threshold,
            failure_window_minutes=args.window,
            group_by=args.group_by,
            success_min_failures=args.min_failures,
            success_lookback_minutes=args.lookback,
        )
        result = _load_source(args.logfile)
    except (ValueError, LogLoadError) as exc:  # LogLoadError is a ValueError
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    report = result.report
    print(f"Loaded {report.rows_loaded} events from {report.source_name} ({report.rows_read} rows read).")
    for warning in report.warnings:
        print(f"  warning: {warning}")

    alerts = run_detections(result.events, config)
    print(f"\n{len(alerts)} alert(s)")
    for level in reversed(SEVERITY_LEVELS):
        count = int((alerts["severity"] == level).sum())
        if count:
            print(f"  {level}: {count}")
    for row in alerts.itertuples(index=False):
        print(f"\n[{row.alert_id}] {row.severity} - {row.rule_id} {row.rule_name}")
        print(f"  {row.evidence}")

    if args.csv:
        with open(args.csv, "w", encoding="utf-8", newline="") as handle:
            handle.write(alerts_to_csv(alerts))
        print(f"\nWrote {args.csv}")
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="") as handle:
            handle.write(alerts_to_json(alerts))
        print(f"Wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
