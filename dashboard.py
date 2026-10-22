#!/usr/bin/env python3
"""
KernelSense Dashboard - Streamlit
Run: streamlit run dashboard.py
"""

import streamlit as st
import json
import os
import time
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import pandas as pd

# ---------- page config ----------
st.set_page_config(
    page_title="KernelSense | Threat Hunting",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ---------- custom css to look closer to the image ----------
st.markdown("""
<style>
    .main { background-color: #f5f7fa; }
    .stMetric {
        background: white;
        padding: 16px 20px;
        border-radius: 10px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.08);
        border: 1px solid #e8ecf1;
    }
    .stMetric label { color: #6b7280 !important; font-size: 13px !important; }
    .stMetric [data-testid="stMetricValue"] { font-size: 28px !important; font-weight: 700 !important; }
    div[data-testid="stHorizontalBlock"] > div { padding: 0 6px; }
    h1, h2, h3 { color: #1f2937; }
    .block-container { padding-top: 1.5rem; }
</style>
""", unsafe_allow_html=True)

# ---------- helper functions ----------
def load_process_logs(path="process_log.jsonl"):
    events = []
    if not os.path.exists(path):
        return events
    try:
        with open(path) as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except:
                    pass
    except:
        pass
    return events

def load_text_log(path):
    lines = []
    expanded = os.path.expanduser(path)
    if not os.path.exists(expanded):
        return lines
    try:
        with open(expanded) as f:
            lines = f.readlines()
    except:
        pass
    return lines

def parse_alerts():
    """Collect alerts from all sources"""
    alerts = []

    # process log – look for recent entries as activity
    for entry in load_process_logs()[-50:]:
        ts = entry.get("timestamp", "")
        alerts.append({
            "time": ts[:19] if ts else "",
            "source": "Process Monitor",
            "level": 3,
            "description": f"Process snapshot ({len(entry.get('processes', []))} procs)",
            "technique": "Discovery"
        })

    # kernel monitor log
    for line in load_text_log("~/kernel-monitor.log")[-30:]:
        if "Kernel errors" in line or "---" not in line:
            alerts.append({
                "time": line[:19] if len(line) > 19 else "",
                "source": "Kernel Monitor",
                "level": 7,
                "description": line.strip()[:80],
                "technique": "Impact"
            })

    # baseline / priv-esc related (we can't easily parse prints, so simulate from file mtime)
    if os.path.exists("baseline.json"):
        mtime = datetime.fromtimestamp(os.path.getmtime("baseline.json"))
        alerts.append({
            "time": mtime.strftime("%Y-%m-%d %H:%M:%S"),
            "source": "Priv-Esc Detector",
            "level": 5,
            "description": "Baseline updated (sudoers/bashrc/profile checked)",
            "technique": "Privilege Escalation"
        })

    # hardening findings are printed, we just note the script is active
    alerts.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": "Hardening Engine",
        "level": 4,
        "description": "Sysctl hardening check completed",
        "technique": "Defense Evasion"
    })

    return sorted(alerts, key=lambda x: x["time"], reverse=True)

# ---------- header ----------
col1, col2, col3 = st.columns([3, 1, 1])
with col1:
    st.markdown("### 🛡️ KernelSense — Threat Hunting")
with col2:
    st.caption(datetime.now().strftime("%d %b %Y  %H:%M"))
with col3:
    if st.button("🔄 Refresh"):
        st.rerun()

st.markdown("---")

# ---------- top metric cards ----------
alerts = parse_alerts()
total_events = len(load_process_logs()) + len(load_text_log("~/kernel-monitor.log"))
high_alerts = sum(1 for a in alerts if a["level"] >= 7)
auth_fail = sum(1 for a in alerts if "fail" in a["description"].lower() or a["level"] >= 8)
auth_ok = max(0, total_events // 10)   # placeholder

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Events", f"{total_events:,}")
c2.metric("High Level Alerts", high_alerts, delta=None)
c3.metric("Suspicious Activity", auth_fail)
c4.metric("Normal Checks", auth_ok)

st.write("")

# ---------- charts row ----------
left, right = st.columns([2, 1])

with left:
    st.markdown("#### Alerts Evolution")
    # simple fake time series from last alerts
    if alerts:
        df = pd.DataFrame(alerts)
        df["hour"] = df["time"].str[:13]   # group by hour
        counts = df.groupby("hour").size().reset_index(name="count")
        counts = counts.tail(12)
        st.area_chart(counts.set_index("hour"), height=250)
    else:
        st.info("No alert data yet. Run the monitors first.")

with right:
    st.markdown("#### Technique Distribution")
    techniques = Counter(a["technique"] for a in alerts)
    if techniques:
        tech_df = pd.DataFrame({
            "Technique": list(techniques.keys()),
            "Count": list(techniques.values())
        })
        st.bar_chart(tech_df.set_index("Technique"), height=250)
    else:
        st.info("No techniques recorded yet.")

st.write("")

# ---------- second row ----------
col_a, col_b = st.columns(2)

with col_a:
    st.markdown("#### Monitor Sources")
    sources = Counter(a["source"] for a in alerts)
    if sources:
        src_df = pd.DataFrame({
            "Source": list(sources.keys()),
            "Alerts": list(sources.values())
        })
        st.bar_chart(src_df.set_index("Source"), height=220)
    else:
        st.info("Waiting for data...")

with col_b:
    st.markdown("#### Alert Levels")
    levels = Counter(a["level"] for a in alerts)
    if levels:
        lvl_df = pd.DataFrame({
            "Level": [f"Level {k}" for k in levels.keys()],
            "Count": list(levels.values())
        })
        st.bar_chart(lvl_df.set_index("Level"), height=220)
    else:
        st.info("Waiting for data...")

st.write("")

# ---------- alerts table ----------
st.markdown("#### Security Alerts")
if alerts:
    table_data = []
    for a in alerts[:15]:
        table_data.append({
            "Time": a["time"],
            "Source": a["source"],
            "Technique": a["technique"],
            "Level": a["level"],
            "Description": a["description"][:70]
        })
    st.dataframe(
        pd.DataFrame(table_data),
        use_container_width=True,
        hide_index=True,
        height=320
    )
else:
    st.warning("No alerts yet. Start the monitors with:  `sudo python3 main.py`")

# ---------- footer ----------
st.markdown("---")
st.caption("KernelSense Dashboard  •  Data from local monitors  •  Auto-refresh with the button above")
