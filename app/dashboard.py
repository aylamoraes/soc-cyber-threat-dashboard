"""SentinelSOC dashboard.

Run from the project folder with:

    streamlit run app/dashboard.py
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from sentinelsoc.alerts import SEVERITY_LEVELS  # noqa: E402
from sentinelsoc.config import (  # noqa: E402
    GROUP_BY_ACCOUNT_AND_SOURCE,
    GROUP_BY_SOURCE,
    DetectionConfig,
)
from sentinelsoc.detectors import RULE_NAMES, run_detections  # noqa: E402
from sentinelsoc.export import alerts_to_csv, alerts_to_json  # noqa: E402
from sentinelsoc.loader import LoadResult, LogLoadError, load_logs  # noqa: E402
from sentinelsoc.metrics import (  # noqa: E402
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

DATA_DIR = ROOT / "data"
SAMPLES = {
    "Sample logs (CSV)": DATA_DIR / "sample_auth_logs.csv",
    "Sample logs (JSON)": DATA_DIR / "sample_auth_logs.json",
    "Malformed-data demo (CSV)": DATA_DIR / "sample_malformed_demo.csv",
}
UPLOAD_OPTION = "Upload a file"
GROUP_LABELS = {
    GROUP_BY_ACCOUNT_AND_SOURCE: "Account + source IP (targeted guessing)",
    GROUP_BY_SOURCE: "Source IP only (also catches one source / many accounts)",
}
MAX_TABLE_ROWS = 2000


def choose_source() -> LoadResult | None:
    """Sidebar step 1: pick a sample or upload a file, then load it safely."""
    st.sidebar.header("1. Data source")
    choice = st.sidebar.radio("Logs to analyse", list(SAMPLES) + [UPLOAD_OPTION])
    try:
        if choice == UPLOAD_OPTION:
            uploaded = st.sidebar.file_uploader("CSV, JSON or JSONL", type=["csv", "json", "jsonl"])
            if uploaded is None:
                st.info("Upload a log file, or choose one of the sample logs in the sidebar.")
                return None
            return load_logs(io.BytesIO(uploaded.getvalue()), filename=uploaded.name)
        return load_logs(SAMPLES[choice])
    except LogLoadError as exc:
        st.error(f"Could not load the logs: {exc}")
        if choice != UPLOAD_OPTION:
            st.caption("Sample files are created with: python -m sentinelsoc.sample_data")
        return None


def choose_detection_settings() -> DetectionConfig:
    """Sidebar step 2: detection thresholds."""
    st.sidebar.header("2. Detection settings")
    threshold = st.sidebar.number_input(
        "Failed logins to alert (SOC-001)", min_value=2, max_value=100, value=5, step=1
    )
    window = st.sidebar.number_input(
        "Failure window, minutes (SOC-001)", min_value=1, max_value=1440, value=10, step=1
    )
    group_by = st.sidebar.selectbox(
        "Count failures per", options=list(GROUP_LABELS), format_func=GROUP_LABELS.get
    )
    min_failures = st.sidebar.number_input(
        "Failures before a success is suspicious (SOC-002)",
        min_value=1,
        max_value=50,
        value=3,
        step=1,
    )
    lookback = st.sidebar.number_input(
        "Look-back before the success, minutes (SOC-002)",
        min_value=1,
        max_value=1440,
        value=30,
        step=1,
    )
    return DetectionConfig(
        failure_threshold=int(threshold),
        failure_window_minutes=int(window),
        group_by=group_by,
        success_min_failures=int(min_failures),
        success_lookback_minutes=int(lookback),
    )


def choose_filters(events: pd.DataFrame) -> dict:
    """Sidebar step 3: filters applied to events and alerts."""
    st.sidebar.header("3. Filters")
    first_day = events["timestamp"].min().date()
    last_day = events["timestamp"].max().date()
    picked = st.sidebar.date_input(
        "Date range (UTC)", value=(first_day, last_day), min_value=first_day, max_value=last_day
    )
    if isinstance(picked, (tuple, list)):
        start_day = picked[0]
        end_day = picked[-1]
    else:
        start_day = end_day = picked

    severities = st.sidebar.multiselect(
        "Severity (empty = all)", list(SEVERITY_LEVELS), default=list(SEVERITY_LEVELS)
    )
    rules = st.sidebar.multiselect(
        "Rule (empty = all)",
        list(RULE_NAMES),
        default=list(RULE_NAMES),
        format_func=lambda r: f"{r} - {RULE_NAMES[r]}",
    )
    sources = st.sidebar.multiselect("Source IP (empty = all)", sorted(events["source_ip"].unique()))
    username = st.sidebar.text_input("Username contains")
    return {
        "start": pd.Timestamp(start_day, tz="UTC"),
        "end": pd.Timestamp(end_day, tz="UTC") + pd.Timedelta(days=1),
        "severities": severities,
        "rules": rules,
        "sources": sources,
        "username": username,
    }


def show_data_quality(result: LoadResult) -> None:
    report = result.report
    with st.expander(f"Data quality: {report.rows_loaded} events loaded from {report.source_name}"):
        left, middle, right = st.columns(3)
        left.metric("Rows read", report.rows_read)
        middle.metric("Events loaded", report.rows_loaded)
        right.metric("Rows discarded", report.rows_discarded + report.malformed_rows_skipped)
        if report.warnings:
            for message in report.warnings:
                st.warning(message)
        else:
            st.success("No data-quality problems found.")


def show_metrics(metrics: dict) -> None:
    columns = st.columns(6)
    columns[0].metric("Events", metrics["total_events"])
    columns[1].metric("Failed logins", metrics["login_failures"])
    columns[2].metric("Successful logins", metrics["login_successes"])
    columns[3].metric("Source IPs", metrics["unique_sources"])
    columns[4].metric("Alerts", metrics["total_alerts"])
    columns[5].metric("High / Critical", metrics["high_or_critical_alerts"])


def show_overview(events: pd.DataFrame, alerts: pd.DataFrame) -> None:
    if events.empty:
        st.info("No events match the current filters.")
        return
    freq = bucket_frequency(events)
    st.subheader("Events over time")
    st.caption(f"Bucket size: {freq}. Times are UTC.")
    st.bar_chart(event_timeline(events, freq))

    st.subheader("Alerts over time")
    if alerts.empty:
        st.caption("No alerts match the current filters.")
    else:
        st.bar_chart(alert_timeline(alerts, freq))

    left, right = st.columns(2)
    with left:
        st.subheader("Top sources by failed logins")
        st.dataframe(top_failed_logins(events, "source_ip"), hide_index=True)
    with right:
        st.subheader("Top accounts by failed logins")
        st.dataframe(top_failed_logins(events, "username"), hide_index=True)


def show_alerts(alerts: pd.DataFrame, events: pd.DataFrame) -> None:
    if alerts.empty:
        st.success("No alerts match the current settings and filters.")
        return

    st.dataframe(alerts_table(alerts), hide_index=True)
    st.caption("Exports contain the alerts currently shown (after filters).")
    left, right, _ = st.columns([1, 1, 3])
    left.download_button(
        "Download CSV",
        data=alerts_to_csv(alerts),
        file_name="sentinelsoc_alerts.csv",
        mime="text/csv",
    )
    right.download_button(
        "Download JSON",
        data=alerts_to_json(alerts),
        file_name="sentinelsoc_alerts.json",
        mime="application/json",
    )

    st.subheader("Alert details")
    rows = alerts.set_index("alert_id")
    selected = st.selectbox(
        "Select an alert",
        options=list(rows.index),
        format_func=lambda a: f"{a} | {rows.loc[a, 'severity']} | {rows.loc[a, 'rule_name']}",
    )
    alert = rows.loc[selected]
    # Values that come from the logs are escaped so they cannot inject Markdown.
    st.markdown(f"**Severity:** {alert['severity']}  \n**Rule:** {alert['rule_id']} - {alert['rule_name']}")
    st.markdown(
        f"**Account(s):** {escape_markdown(alert['username'])}  \n"
        f"**Source IP:** {escape_markdown(alert['source_ip'])}  \n"
        f"**First seen:** {alert['first_seen']:%Y-%m-%d %H:%M:%S} UTC  \n"
        f"**Last seen:** {alert['last_seen']:%Y-%m-%d %H:%M:%S} UTC"
    )
    st.markdown(f"**Evidence:** {escape_markdown(alert['evidence'])}")
    st.markdown(f"**Recommended response:** {alert['recommendation']}")
    st.markdown(f"**MITRE ATT&CK:** {escape_markdown(alert['mitre_attack'])}")
    evidence = events[events["event_id"].isin(alert["evidence_event_ids"])]
    st.markdown(f"**Evidence events ({len(evidence)}):**")
    st.dataframe(evidence, hide_index=True)


def show_events(events: pd.DataFrame) -> None:
    if events.empty:
        st.info("No events match the current filters.")
        return
    st.dataframe(events.head(MAX_TABLE_ROWS), hide_index=True)
    if len(events) > MAX_TABLE_ROWS:
        st.caption(f"Showing the first {MAX_TABLE_ROWS} of {len(events)} events.")


def main() -> None:
    st.set_page_config(page_title="SentinelSOC", page_icon=":shield:", layout="wide")
    st.title("SentinelSOC - Security Monitoring Lab")
    st.caption("Defensive analysis of synthetic authentication logs. No data leaves this computer.")

    result = choose_source()
    config = choose_detection_settings()
    if result is None:
        st.stop()

    show_data_quality(result)
    if result.events.empty:
        st.warning("There are no valid events to analyse.")
        st.stop()

    all_alerts = run_detections(result.events, config)
    filters = choose_filters(result.events)
    events = filter_events(
        result.events, filters["start"], filters["end"], filters["sources"], filters["username"]
    )
    alerts = filter_alerts(
        all_alerts,
        filters["severities"],
        filters["rules"],
        filters["sources"],
        filters["username"],
        filters["start"],
        filters["end"],
    )

    show_metrics(summary_metrics(events, alerts))
    overview_tab, alerts_tab, events_tab = st.tabs(["Overview", "Alerts", "Events"])
    with overview_tab:
        show_overview(events, alerts)
    with alerts_tab:
        show_alerts(alerts, events)
    with events_tab:
        show_events(events)


main()
