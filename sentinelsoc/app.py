"""SentinelSOC - Enterprise Security Operations Center dashboard.

A Streamlit front-end over the synthetic incident feed in
``sentinelsoc.data.sample_data``. The UI is split into small render functions so
the layout reads like a set of components (KPIs, distribution, time series,
triage table) and each can change independently of the others.

Run from the project root::

    streamlit run sentinelsoc/app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow ``streamlit run sentinelsoc/app.py`` from any working directory: make the
# project root importable so ``sentinelsoc.*`` resolves.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import plotly.express as px  # noqa: E402
import plotly.graph_objects as go  # noqa: E402
import streamlit as st  # noqa: E402

from sentinelsoc.data.sample_data import (  # noqa: E402
    COL_SEVERITY,
    COL_SOURCE_IP,
    COL_STATUS,
    COL_TIMESTAMP,
    SEVERITY_COLORS,
    SEVERITY_LABELS,
    EventType,
    IncidentStatus,
    Severity,
    event_frequency,
    event_type_counts,
    event_type_options,
    filter_events,
    load_incidents,
    severity_counts,
    severity_options,
    status_options,
    summary_metrics,
)

# Corporate SOC palette: deep slate/navy surfaces with emerald and crimson
# accents. Kept here (not only in CSS) because the charts need the same values.
COLOR_BACKGROUND = "#0B1220"
COLOR_SURFACE = "#111A2B"
COLOR_BORDER = "#23304A"
COLOR_TEXT = "#E6EDF7"
COLOR_MUTED = "#8A9AB8"
COLOR_EMERALD = "#10B981"
COLOR_CRIMSON = "#DC2626"
COLOR_AMBER = "#F59E0B"

RISK_COLORS = {
    "Critical": COLOR_CRIMSON,
    "High": "#F97316",
    "Elevated": COLOR_AMBER,
    "Moderate": COLOR_AMBER,
    "Low": COLOR_EMERALD,
}

# Column headers shown in the triage table (human-readable, English).
TABLE_LABELS = {
    COL_TIMESTAMP: "Timestamp (UTC)",
    COL_SOURCE_IP: "Source IP",
    "event_type": "Event",
    COL_SEVERITY: "Severity",
    COL_STATUS: "Status",
}

# Hide only Streamlit's own chrome. These selectors are scoped to specific
# data-testid targets (never the root .stApp or the main content container), so
# the dashboard itself can never be hidden. ``visibility`` preserves layout.
HIDE_ST_STYLE = """
<style>
[data-testid="stHeader"] {visibility: hidden;}
[data-testid="stSidebarNav"] {margin-top: -2rem;}
footer {visibility: hidden;}
</style>
"""


def _inject_theme() -> None:
    """Inject the corporate dark theme via a single CSS block.

    Streamlit exposes styling hooks through element attributes; overriding them
    here keeps the whole app coherent without a separate stylesheet asset.
    """
    st.markdown(
        f"""
        <style>
        :root {{
            --soc-bg: {COLOR_BACKGROUND};
            --soc-surface: {COLOR_SURFACE};
            --soc-border: {COLOR_BORDER};
            --soc-text: {COLOR_TEXT};
            --soc-muted: {COLOR_MUTED};
        }}
        .stApp {{ background-color: var(--soc-bg); color: var(--soc-text); }}
        h1, h2, h3 {{ color: var(--soc-text); }}
        [data-testid="stSidebar"] {{
            background-color: var(--soc-surface);
            border-right: 1px solid var(--soc-border);
        }}
        [data-testid="stMetric"] {{
            background-color: var(--soc-surface);
            border: 1px solid var(--soc-border);
            border-radius: 10px;
            padding: 16px 18px;
        }}
        [data-testid="stMetricLabel"] {{ color: var(--soc-muted); }}
        [data-testid="stMetricValue"] {{ color: var(--soc-text); }}
        .stDataFrame {{ border: 1px solid var(--soc-border); border-radius: 10px; }}
        hr {{ border-color: var(--soc-border); }}
        </style>
        """,
        unsafe_allow_html=True,
    )
    # Hide Streamlit's own chrome without touching the main content containers.
    st.markdown(HIDE_ST_STYLE, unsafe_allow_html=True)


def _apply_plotly_theme(fig: go.Figure) -> go.Figure:
    """Apply the shared dark surface and typography to a Plotly figure."""
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color=COLOR_TEXT,
        margin=dict(l=24, r=24, t=48, b=24),
        legend_title_text="",
    )
    fig.update_xaxes(gridcolor=COLOR_BORDER, zerolinecolor=COLOR_BORDER)
    fig.update_yaxes(gridcolor=COLOR_BORDER, zerolinecolor=COLOR_BORDER)
    return fig


def render_sidebar() -> tuple[list[Severity], list[IncidentStatus], list[EventType]]:
    """Render the SOC filter panel and return the active selections.

    Returns:
        The selected severities, statuses and event types. Empty selections are
        treated downstream as "no filter".
    """
    with st.sidebar:
        st.markdown("# 🛡️")
        st.title("SOC Filters")
        st.caption("Narrow the telemetry shown across the dashboard.")

        severities = st.multiselect(
            "Severity",
            options=list(severity_options()),
            format_func=lambda s: s.value,
            default=[],
        )
        statuses = st.multiselect(
            "Incident status",
            options=list(status_options()),
            format_func=lambda s: s.value,
            default=[],
        )
        event_types = st.multiselect(
            "Event type",
            options=list(event_type_options()),
            format_func=lambda s: s.value,
            default=[],
        )

        st.markdown("---")
        st.caption("Data source: synthetic SOC telemetry feed.")
    return severities, statuses, event_types


def render_header() -> None:
    """Render the main page title and subtitle."""
    st.title("🛡️ SentinelSOC — Enterprise Operations Center")
    st.markdown(
        "Advanced monitoring, incident triage and threat intelligence over a "
        "synthetic security telemetry feed."
    )
    st.markdown("---")


def render_kpis(metrics: dict[str, int | str]) -> None:
    """Render the top-row executive KPI cards."""
    risk = str(metrics["risk_level"])
    risk_color = RISK_COLORS.get(risk, COLOR_TEXT)
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Events", metrics["total_events"])
    col2.metric("Critical Threats", metrics["critical_threats"])
    col3.metric("High Severity", metrics["high_threats"])
    col4.metric("Open Incidents", metrics["open_incidents"])
    col5.metric("Global Risk Level", risk)
    st.markdown(
        f"<span style='color:{risk_color};font-weight:600'>Posture: {risk}</span>",
        unsafe_allow_html=True,
    )
    st.markdown("---")


def _severity_bar(frame: pd.DataFrame) -> go.Figure:
    """Build the severity distribution bar chart."""
    counts = severity_counts(frame)
    fig = px.bar(
        x=list(counts.index),
        y=counts.values,
        color=list(counts.index),
        color_discrete_map={
            label: SEVERITY_COLORS[sev] for sev, label in zip(Severity, SEVERITY_LABELS)
        },
        category_orders={"x": list(SEVERITY_LABELS)},
        labels={"x": "Severity", "y": "Events"},
        title="Incident Distribution by Severity",
    )
    fig.update_traces(marker_line_width=0)
    return _apply_plotly_theme(fig)


def _event_type_bar(frame: pd.DataFrame) -> go.Figure:
    """Build the event-type distribution bar chart (horizontal, ranked)."""
    counts = event_type_counts(frame).sort_values()
    fig = px.bar(
        x=counts.values,
        y=list(counts.index),
        orientation="h",
        color=counts.values,
        color_continuous_scale=[COLOR_EMERALD, COLOR_AMBER, COLOR_CRIMSON],
        labels={"x": "Events", "y": "Event type"},
        title="Event Mix by Type",
    )
    fig.update(layout_coloraxis_showscale=False)
    return _apply_plotly_theme(fig)


def _frequency_area(frame: pd.DataFrame) -> go.Figure:
    """Build the time-series log frequency chart."""
    freq = event_frequency(frame, freq="15min")
    fig = go.Figure()
    if not freq.empty:
        fig.add_trace(
            go.Scatter(
                x=freq[COL_TIMESTAMP],
                y=freq["count"],
                mode="lines+markers",
                line=dict(color=COLOR_EMERALD, width=2),
                fill="tozeroy",
                fillcolor="rgba(16,185,129,0.15)",
                name="Events",
            )
        )
    fig.update_layout(
        title="Log Frequency Over Time",
        xaxis_title="Time (UTC)",
        yaxis_title="Events per 15 min",
    )
    return _apply_plotly_theme(fig)


def render_charts(frame: pd.DataFrame) -> None:
    """Render the incident distribution and time-series charts."""
    st.subheader("📊 Threat Analysis")
    left, right = st.columns(2)
    with left:
        st.plotly_chart(_severity_bar(frame), width="stretch")
    with right:
        st.plotly_chart(_event_type_bar(frame), width="stretch")
    st.plotly_chart(_frequency_area(frame), width="stretch")
    st.markdown("---")


def render_triage_table(frame: pd.DataFrame) -> None:
    """Render the interactive incident triage table with a CSV export."""
    st.subheader("📋 Incident Triage")
    if frame.empty:
        st.info("No incidents match the current filters.")
        return

    display = frame.sort_values(COL_TIMESTAMP, ascending=False).rename(columns=TABLE_LABELS)
    st.dataframe(display, width="stretch", hide_index=True)

    # The empty case returned above, so there is always data to export here.
    csv_data = frame.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📁 Export Incident Report (csv)",
        data=csv_data,
        file_name="sentinel_soc_incidents.csv",
        mime="text/csv",
    )


def main() -> None:
    """Compose the dashboard: theme, filters, KPIs, charts, and table."""
    st.set_page_config(
        page_title="SentinelSOC - Enterprise SOC Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _inject_theme()

    severities, statuses, event_types = render_sidebar()
    render_header()

    incidents = load_incidents()
    filtered = filter_events(incidents, severities, statuses, event_types)

    render_kpis(summary_metrics(filtered))
    render_charts(filtered)
    render_triage_table(filtered)


if __name__ == "__main__":
    main()