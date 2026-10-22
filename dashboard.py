#!/usr/bin/env python3
"""KernelSense local host-security dashboard."""
from __future__ import annotations

import io
import json
import platform
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import psutil
import streamlit as st
try:
    from streamlit_autorefresh import st_autorefresh
except ImportError:  # dashboard remains usable without optional auto-refresh package
    st_autorefresh = None

from dashboard_core import (
    BASE_DIR,
    event_timestamp_age_seconds,
    load_acknowledged,
    load_events,
    load_process_snapshots,
    parse_timestamp,
    read_text_tail,
    save_acknowledged,
)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪", "warning": "🟡", "error": "🔴"}
MONITOR_FRESHNESS_SECONDS = {
    "all-processes-monitoring": 100,
    "directory-monitoring": 200,
    "kernel-monitoring": 750,
    "privilege-escalation-detector": 200,
}

st.set_page_config(page_title="KernelSense | Host Security", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
  .block-container { padding-top: 1.4rem; padding-bottom: 2rem; max-width: 1600px; }
  [data-testid="stMetric"] { background: var(--secondary-background-color); border: 1px solid rgba(128,128,128,.22); padding: 14px 16px; border-radius: 12px; }
  .ks-eyebrow { color: #7F8EA3; font-size: .78rem; letter-spacing: .14em; font-weight: 700; text-transform: uppercase; }
  .ks-subtitle { color: #7F8EA3; margin-top: -.3rem; }
  .ks-event { border: 1px solid rgba(128,128,128,.25); border-left-width: 4px; border-radius: 10px; padding: 12px 14px; margin: 8px 0; }
  .ks-muted { color: #7F8EA3; font-size: .86rem; }
  div[data-testid="stTabs"] button { font-weight: 600; }
</style>
""", unsafe_allow_html=True)


def safe_readable_path(value: str, fallback: Path) -> Path:
    value = (value or "").strip()
    return Path(value).expanduser() if value else fallback


def get_host_metrics() -> dict[str, Any]:
    try:
        cpu = float(psutil.cpu_percent(interval=0.1))
        memory = psutil.virtual_memory()
        disk_path = str(Path.home().anchor or "/")
        disk = psutil.disk_usage(disk_path)
        boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
        return {
            "cpu": cpu,
            "memory": float(memory.percent),
            "memory_used_gb": memory.used / (1024 ** 3),
            "memory_total_gb": memory.total / (1024 ** 3),
            "disk": float(disk.percent),
            "disk_used_gb": disk.used / (1024 ** 3),
            "disk_total_gb": disk.total / (1024 ** 3),
            "uptime": datetime.now(timezone.utc) - boot_time,
        }
    except Exception as exc:
        return {"error": str(exc)}


def friendly_age(seconds: float | None) -> str:
    if seconds is None:
        return "Unknown time"
    if seconds < 60:
        return f"{int(seconds)} sec ago"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)} hr ago"
    return f"{int(seconds // 86400)} days ago"


def event_age(event: dict[str, Any]) -> str:
    return friendly_age(event_timestamp_age_seconds(event))


def norm_severity(value: Any) -> str:
    s = str(value or "info").lower()
    if s == "error":
        return "critical"
    if s == "warning":
        return "medium"
    return s if s in SEVERITY_ORDER else "info"


def format_details(details: Any) -> str:
    if details is None:
        return "No additional details recorded."
    if isinstance(details, str):
        return details
    return json.dumps(details, indent=2, ensure_ascii=False, default=str)


def event_frame(events: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for event in events:
        rows.append({
            "timestamp": event.get("timestamp", ""),
            "severity": norm_severity(event.get("severity")),
            "source": event.get("source", "unknown"),
            "category": event.get("category", "general"),
            "message": event.get("message", ""),
            "event_id": event.get("event_id", ""),
            "details": format_details(event.get("details")),
        })
    return pd.DataFrame(rows, columns=["timestamp", "severity", "source", "category", "message", "event_id", "details"])


def parse_legacy_kernel_lines(path: Path) -> list[dict[str, Any]]:
    lines = read_text_tail(path, max_lines=400)
    rows = []
    for index, line in enumerate(lines):
        text = line.strip()
        if not text or text == "---":
            continue
        severity = "medium" if "error" in text.lower() or "failed" in text.lower() else "info"
        rows.append({
            "timestamp": "",
            "severity": severity,
            "source": "kernel-monitor.log",
            "category": "legacy.kernel_log",
            "message": text[:400],
            "event_id": f"legacy-kernel-{index}",
            "details": text,
        })
    return rows


def summarize_monitors(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    latest: dict[str, dict[str, Any]] = {}
    now = datetime.now(timezone.utc)
    for event in events:
        source = str(event.get("source", ""))
        if event.get("category") in {"monitor.heartbeat", "monitor.started", "monitor.worker_started"} and source not in latest:
            latest[source] = event
    expected = [
        ("all-processes-monitoring", "Process monitor"),
        ("directory-monitoring", "Directory monitor"),
        ("kernel-monitoring", "Kernel log monitor"),
        ("privilege-escalation-detector", "Privilege/config monitor"),
    ]
    rows = []
    for source, label in expected:
        event = latest.get(source)
        if not event:
            status = "Not reporting"
            age_text = "No heartbeat recorded"
        else:
            age = event_timestamp_age_seconds(event, now)
            threshold = MONITOR_FRESHNESS_SECONDS.get(source, 200)
            if age is not None and age <= threshold:
                status = "Active"
            elif age is not None and age <= threshold * 2:
                status = "Possibly stale"
            else:
                status = "Stale"
            age_text = friendly_age(age)
        rows.append({"Monitor": label, "Status": status, "Last signal": age_text})
    return rows


def create_csv_download(frame: pd.DataFrame) -> bytes:
    return frame.to_csv(index=False).encode("utf-8-sig")


# Sidebar / data source settings
with st.sidebar:
    st.markdown("<div class='ks-eyebrow'>KernelSense</div>", unsafe_allow_html=True)
    st.title("Host Security")
    st.caption("Local monitoring console")
    auto_refresh = st.toggle("Auto-refresh", value=True)
    refresh_seconds = st.select_slider("Refresh interval", options=[5, 10, 15, 30, 60], value=10, format_func=lambda x: f"{x} seconds")
    if auto_refresh and st_autorefresh is not None:
        st_autorefresh(interval=refresh_seconds * 1000, key="kernelsense_auto_refresh")
    elif auto_refresh and st_autorefresh is None:
        st.caption("Install streamlit-autorefresh to enable automatic refresh.")
    st.divider()
    with st.expander("Data sources", expanded=False):
        process_path_text = st.text_input("Process snapshots", value=str(BASE_DIR / "process_log.jsonl"))
        event_path_text = st.text_input("Structured events", value=str(BASE_DIR / "security_events.jsonl"))
        kernel_default = BASE_DIR / "kernel-monitor.log"
        kernel_path_text = st.text_input("Legacy kernel log (optional)", value=str(kernel_default))
        st.caption("Paths are read locally. This dashboard does not upload logs.")
    st.divider()
    st.markdown("**Host**")
    st.write(f"`{socket.gethostname()}`")
    st.caption(f"{platform.system()} {platform.release()}")
    st.caption(f"Updated at {datetime.now().astimezone().strftime('%H:%M:%S %Z')}")

process_path = safe_readable_path(process_path_text if 'process_path_text' in locals() else "", BASE_DIR / "process_log.jsonl")
event_path = safe_readable_path(event_path_text if 'event_path_text' in locals() else "", BASE_DIR / "security_events.jsonl")
kernel_path = safe_readable_path(kernel_path_text if 'kernel_path_text' in locals() else "", BASE_DIR / "kernel-monitor.log")

# Secondary fallback paths support earlier builds which wrote kernel-monitor.log to the invoking home folder.
if not kernel_path.exists():
    candidates = [Path.home() / "kernel-monitor.log", Path("/root/kernel-monitor.log")]
    kernel_path = next((candidate for candidate in candidates if candidate.is_file()), kernel_path)

events = load_events(event_path)
snapshots = load_process_snapshots(process_path)
latest_snapshot = snapshots[-1] if snapshots else None
processes = latest_snapshot.get("processes", []) if latest_snapshot else []
legacy_rows = parse_legacy_kernel_lines(kernel_path) if kernel_path.is_file() else []
all_log_rows = event_frame(events).to_dict("records") + legacy_rows
all_log_rows.sort(key=lambda row: str(row.get("timestamp", "")), reverse=True)

# Header
st.markdown("<div class='ks-eyebrow'>Linux host intrusion detection</div>", unsafe_allow_html=True)
st.title("KernelSense Security Dashboard")
st.markdown("<div class='ks-subtitle'>Continuous visibility into processes, system configuration, kernel messages, and monitor health.</div>", unsafe_allow_html=True)
st.write("")

metrics = get_host_metrics()
high_count = sum(1 for e in events if norm_severity(e.get("severity")) in {"critical", "high"} and e.get("category") not in {"monitor.started", "monitor.heartbeat"})
medium_count = sum(1 for e in events if norm_severity(e.get("severity")) == "medium")
monitor_rows = summarize_monitors(events)
active_monitors = sum(1 for item in monitor_rows if item["Status"] == "Active")

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.metric("High-priority alerts", high_count, help="Count of recorded critical/high severity events; not a verdict that an intrusion occurred.")
with c2:
    st.metric("Medium-priority findings", medium_count)
with c3:
    st.metric("Processes in latest snapshot", len(processes))
with c4:
    st.metric("Monitors reporting", f"{active_monitors}/4")

if not events:
    st.info("No structured security events are recorded yet. Start the monitoring workers with `python3 main.py` (or your configured launch method); monitor findings will appear here as JSONL events.")
if not snapshots:
    st.warning(f"No process snapshots found at `{process_path}`. Check the data-source path or start the process monitor.")
elif latest_snapshot:
    snapshot_time = parse_timestamp(latest_snapshot.get("timestamp"))
    snapshot_age = (datetime.now(timezone.utc) - snapshot_time).total_seconds() if snapshot_time else None
    if snapshot_age is not None and snapshot_age > 20:
        st.warning(f"The latest process snapshot is stale ({friendly_age(snapshot_age)}). The process monitor may be stopped or writing to a different path.")

# Main sections
tab_overview, tab_alerts, tab_processes, tab_logs, tab_monitors, tab_about = st.tabs(
    ["Overview", "Alerts", "Processes", "Logs & exports", "Monitor health", "About & safety"]
)

with tab_overview:
    left, right = st.columns([1.35, 1])
    with left:
        st.subheader("Host resource usage")
        if "error" in metrics:
            st.warning(f"Could not collect host resource metrics: {metrics['error']}")
        else:
            mm1, mm2, mm3 = st.columns(3)
            mm1.metric("CPU", f"{metrics['cpu']:.1f}%")
            mm2.metric("Memory", f"{metrics['memory']:.1f}%", f"{metrics['memory_used_gb']:.1f} / {metrics['memory_total_gb']:.1f} GB")
            mm3.metric("Disk", f"{metrics['disk']:.1f}%", f"{metrics['disk_used_gb']:.1f} / {metrics['disk_total_gb']:.1f} GB")
            st.progress(min(100, int(metrics["cpu"])), text="Current CPU utilization")
            st.progress(min(100, int(metrics["memory"])), text="Current memory utilization")
            st.progress(min(100, int(metrics["disk"])), text="Disk utilization for the dashboard host's root filesystem")
            uptime = metrics["uptime"]
            st.caption(f"System uptime: {uptime.days} days, {uptime.seconds // 3600} hours")
    with right:
        st.subheader("Monitor status")
        for item in monitor_rows:
            if item["Status"] == "Active":
                st.success(f"**{item['Monitor']}** · {item['Last signal']}")
            elif item["Status"] == "Possibly stale":
                st.warning(f"**{item['Monitor']}** · {item['Last signal']}")
            else:
                st.error(f"**{item['Monitor']}** · {item['Last signal']}")
        st.caption("Status is inferred from the latest heartbeat, not from systemd service state.")

    st.subheader("Recent alerts and findings")
    non_heartbeat = [e for e in events if e.get("category") not in {"monitor.heartbeat", "monitor.started", "monitor.worker_started", "monitor.launching"}]
    if non_heartbeat:
        for event in non_heartbeat[:6]:
            sev = norm_severity(event.get("severity"))
            icon = SEVERITY_EMOJI.get(sev, "⚪")
            st.markdown(f"{icon} **{str(event.get('message', 'Finding'))}**  \n`{event.get('timestamp', 'time unavailable')}` · `{event.get('source', 'unknown')}` · **{sev.upper()}**")
            if event.get("recommendation"):
                st.caption(str(event["recommendation"]))
            st.divider()
    else:
        st.caption("No finding events have been recorded in the structured event log.")

with tab_alerts:
    st.subheader("Alert center")
    st.caption("Findings are indicators to investigate—not automatic proof of compromise. Acknowledging an alert only changes its dashboard state.")
    filter_col1, filter_col2, filter_col3 = st.columns([1, 1, 1.4])
    with filter_col1:
        severity_options = st.multiselect("Severity", SEVERITY_ORDER, default=["critical", "high", "medium", "low", "info"])
    with filter_col2:
        source_options = sorted({str(e.get("source", "unknown")) for e in events})
        selected_sources = st.multiselect("Monitor source", source_options, default=source_options)
    with filter_col3:
        search_alert = st.text_input("Search alerts", placeholder="Message, path, PID, audit text…")
    show_ack = st.toggle("Show acknowledged", value=True)
    acked = load_acknowledged()
    filtered = []
    for event in events:
        if norm_severity(event.get("severity")) not in severity_options:
            continue
        if str(event.get("source", "unknown")) not in selected_sources:
            continue
        if not show_ack and event.get("event_id") in acked:
            continue
        haystack = " ".join([str(event.get("message", "")), str(event.get("source", "")), str(event.get("category", "")), format_details(event.get("details"))]).lower()
        if search_alert and search_alert.lower() not in haystack:
            continue
        filtered.append(event)
    st.caption(f"Showing {len(filtered)} of {len(events)} structured events.")
    if filtered:
        csv_frame = event_frame(filtered)
        st.download_button("Export filtered alerts as CSV", create_csv_download(csv_frame), file_name="kernelsense-alerts.csv", mime="text/csv")
        for event in filtered:
            event_id = str(event.get("event_id", ""))
            sev = norm_severity(event.get("severity"))
            is_acked = event_id in acked
            title = f"{SEVERITY_EMOJI.get(sev, '⚪')} {sev.upper()} · {event.get('message', 'Finding')}"
            with st.expander(f"{title} — {event_age(event)}" + (" · ACKNOWLEDGED" if is_acked else ""), expanded=(sev in {"critical", "high"} and not is_acked)):
                st.write(f"**Source:** `{event.get('source', 'unknown')}`  |  **Category:** `{event.get('category', 'general')}`")
                st.write(f"**Timestamp:** {event.get('timestamp', 'Unavailable')}")
                st.markdown("**Details**")
                st.code(format_details(event.get("details")), language="json" if isinstance(event.get("details"), (dict, list)) else None)
                if event.get("recommendation"):
                    st.markdown("**Suggested next step**")
                    st.write(event["recommendation"])
                if is_acked:
                    if st.button("Unacknowledge", key=f"unack-{event_id}"):
                        acked.discard(event_id)
                        save_acknowledged(acked)
                        st.rerun()
                else:
                    if st.button("Acknowledge", key=f"ack-{event_id}"):
                        acked.add(event_id)
                        save_acknowledged(acked)
                        st.rerun()
    else:
        st.info("No alerts match the selected filters.")

with tab_processes:
    st.subheader("Latest process snapshot")
    if latest_snapshot:
        parsed = parse_timestamp(latest_snapshot.get("timestamp"))
        age = (datetime.now(timezone.utc) - parsed).total_seconds() if parsed else None
        st.caption(f"Snapshot time: {latest_snapshot.get('timestamp', 'unknown')} · {friendly_age(age)} · {len(processes)} process records")
        process_search = st.text_input("Search processes", placeholder="Process name, PID, executable path…")
        show_cmdline = st.checkbox("Reveal full command-line arguments", value=False, help="Command lines can contain paths, tokens, or other sensitive values. Keep hidden unless needed for investigation.")
        rows = []
        for proc in processes:
            cmdline = proc.get("cmdline") or []
            exe = proc.get("exe") or ""
            name = proc.get("name") or "unknown"
            row = {
                "PID": proc.get("pid"),
                "Process": name,
                "CPU %": round(float(proc.get("cpu_percent") or 0), 2),
                "Memory %": round(float(proc.get("memory_percent") or 0), 3),
                "Executable": exe,
            }
            if show_cmdline:
                row["Command line"] = " ".join(map(str, cmdline))
            rows.append(row)
        process_frame = pd.DataFrame(rows)
        if not process_frame.empty:
            if process_search:
                searchable = process_frame.astype(str).apply(lambda col: col.str.contains(process_search, case=False, na=False)).any(axis=1)
                process_frame = process_frame[searchable]
            sort_col = st.selectbox("Sort processes by", ["CPU %", "Memory %", "Process", "PID"], index=0)
            if sort_col in process_frame.columns:
                process_frame = process_frame.sort_values(sort_col, ascending=(sort_col in {"Process", "PID"}), kind="stable")
            st.dataframe(process_frame, use_container_width=True, hide_index=True, height=520)
            st.download_button("Export visible process table as CSV", create_csv_download(process_frame), file_name="kernelsense-processes.csv", mime="text/csv")
        else:
            st.info("No process records match this search.")
    else:
        st.info("No process snapshot is available. Start the process monitor and check the configured snapshot path.")

with tab_logs:
    st.subheader("Local logs and exports")
    lcol1, lcol2 = st.columns([1, 1])
    with lcol1:
        st.metric("Structured events loaded", len(events))
        st.metric("Legacy kernel log lines loaded", len(legacy_rows))
    with lcol2:
        st.caption(f"Event log: `{event_path}`")
        st.caption(f"Process log: `{process_path}`")
        st.caption(f"Kernel log: `{kernel_path}`" if kernel_path.exists() else "Legacy kernel log not found; structured kernel events may still be available.")
    log_search = st.text_input("Search logs", placeholder="Search event messages, sources, details…", key="log_search")
    log_source_options = sorted({str(row.get("source", "unknown")) for row in all_log_rows})
    chosen_log_sources = st.multiselect("Log sources", log_source_options, default=log_source_options, key="log_sources")
    filtered_logs = []
    for row in all_log_rows:
        if str(row.get("source", "unknown")) not in chosen_log_sources:
            continue
        searchable = " ".join([str(row.get("message", "")), str(row.get("source", "")), str(row.get("category", "")), str(row.get("details", ""))]).lower()
        if log_search and log_search.lower() not in searchable:
            continue
        filtered_logs.append(row)
    st.caption(f"Showing {min(500, len(filtered_logs))} of {len(filtered_logs)} matching log records.")
    log_frame = pd.DataFrame(filtered_logs)
    if not log_frame.empty:
        display_columns = [c for c in ["timestamp", "severity", "source", "category", "message"] if c in log_frame.columns]
        st.dataframe(log_frame[display_columns].head(500), use_container_width=True, hide_index=True, height=500)
        st.download_button("Export filtered logs as CSV", create_csv_download(log_frame), file_name="kernelsense-logs.csv", mime="text/csv")
        jsonl_bytes = ("\n".join(json.dumps(row, ensure_ascii=False, default=str) for row in filtered_logs) + "\n").encode("utf-8")
        st.download_button("Export filtered logs as JSONL", jsonl_bytes, file_name="kernelsense-logs.jsonl", mime="application/x-ndjson")
    else:
        st.info("No logs match the selected filters.")

with tab_monitors:
    st.subheader("Monitor health and data sources")
    status_frame = pd.DataFrame(monitor_rows)
    st.dataframe(status_frame, use_container_width=True, hide_index=True)
    st.markdown("**Configured log sources**")
    source_rows = [
        {"Type": "Process snapshots", "Path": str(process_path), "Exists": process_path.is_file(), "Records loaded": len(snapshots)},
        {"Type": "Structured events", "Path": str(event_path), "Exists": event_path.is_file(), "Records loaded": len(events)},
        {"Type": "Legacy kernel log", "Path": str(kernel_path), "Exists": kernel_path.is_file(), "Records loaded": len(legacy_rows)},
    ]
    st.dataframe(pd.DataFrame(source_rows), use_container_width=True, hide_index=True)
    st.markdown("**Troubleshooting**")
    st.markdown("- A monitor that has no heartbeat may not have been started, may lack permission, or may have failed before writing its first event.\n- `journalctl` visibility depends on local system permissions and configuration.\n- Filesystem monitoring is limited to the configured directories; it is not a complete view of every filesystem change.\n- Use the exact path shown above if the monitor logs were created in another directory.")

with tab_about:
    st.subheader("What KernelSense currently shows")
    st.markdown("""
    - **Process inventory:** the latest captured process snapshot, with optional command-line visibility.
    - **Structured findings:** file changes under the watched system directories, relevant privilege/configuration changes, and high-priority kernel journal entries.
    - **Monitor health:** last-seen monitor heartbeat timestamps.
    - **Investigation tools:** severity/source/search filters, acknowledgement, and CSV/JSONL export.

    **Safety and limitations**

    This dashboard is a local investigation interface, not a guarantee that the host is clean. Events can be false positives; a missing event does not mean an activity did not happen. KernelSense does not run remediation commands from the dashboard and does not automatically revert system changes. Review suggested actions before running commands in a terminal. Log files may contain usernames, paths, process arguments, and other sensitive local metadata, so keep them private.
    """)
    st.caption("KernelSense · continuous host monitoring prototype")
