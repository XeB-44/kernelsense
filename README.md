# KernelSense — Professional Local Security Dashboard

A beginner-friendly, dark multicolor Linux host-monitoring dashboard. It uses Python's built-in HTTP server and a custom HTML/CSS/JavaScript interface—**no Streamlit, no React build step, and no frontend package installation**.

## What's included

- The structured local event logger and monitors for process snapshots, selected system-directory changes, kernel journal messages, and privilege/configuration activity.
- Kernel module load/unload monitoring and a hardening-check recommender.
- Live browser updates using Server-Sent Events; responsive dark UI, colourful severity badges, resource rings, recent-alert timeline, monitor status, and hardening recommendations.
- Plain-language deterministic explanations for known event patterns.
- Optional on-demand OpenRouter analysis: enter your key in the page, then click **Explain with AI** on a specific alert. The key is not saved to disk by KernelSense. Only the selected alert is sent when requested; the app does not send all logs automatically.
- AI output is advice only. KernelSense does not execute commands or apply changes.

## Install on Linux Mint / Ubuntu

From the extracted project directory:

```bash
python3 -m venv myenv
source myenv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If you already have a virtual environment named `myenv`, use it rather than creating another one.

## Run

```bash
source myenv/bin/activate
python3 dashboard.py
```

Open **http://127.0.0.1:8501**. The dashboard starts the included monitor scripts and serves the interface locally. Stop everything with `Ctrl+C`.

Preview the UI with clearly labelled synthetic data (does not represent actual host events):

```bash
python3 dashboard.py --demo
```

Show the dashboard without launching monitor scripts:

```bash
python3 dashboard.py --no-monitors
```

For headless monitoring without the browser dashboard, run `python3 main.py`. Do not run `main.py` alongside `dashboard.py`, because both launch monitor workers.

If port 8501 is already in use, choose another port:

```bash
python3 dashboard.py --port 8510
```

## Optional OpenRouter analysis

1. Create an API key through your OpenRouter account.
2. In the dashboard's **AI explanation** panel, enter the key and a model ID available to your account.
3. Expand an alert and click **Explain with AI**.
4. Review the plain-language summary and verify any suggested commands before running them.

The dashboard forwards only the selected alert's title, severity, source, existing explanation, recommendation, and technical evidence to OpenRouter after you click. Avoid sending secrets, private user data, or unredacted logs. The AI API key is held in the page and request memory only; do not expose this dashboard to a shared network. OpenRouter model IDs and pricing/availability can change; choose a model available to your account.

## Privacy and safety

- Dashboard binds to `127.0.0.1` by default. Do not use `--host 0.0.0.0` unless you add appropriate authentication and network controls; this prototype has no login system.
- Do not run the dashboard itself as root. Some monitor inputs may require permissions; unavailable sources should be treated as reduced coverage, not proof of safety.
- Local files such as `security_events.jsonl`, `process_log.jsonl`, and baseline snapshots can contain sensitive paths and process metadata. Keep them out of public repositories.
- AI output can be incorrect or unsafe. It is never executed by KernelSense. Treat recommendations as investigation guidance and verify them independently.
- No ML anomaly detector is included in this build; ML remains future scope as requested.

## Project files

- `dashboard.py` — local HTTP dashboard, UI, monitor supervision, and optional on-demand OpenRouter analysis.
- `event_logger.py` — structured JSONL event writer shared by monitors.
- `all-processes_monitoring.py` — process snapshots with basic command-line secret redaction.
- `directory-monitoring.py` — watches selected system directories.
- `kernel-monitoring.py` — polls high-priority kernel journal messages.
- `privilege_escalation-detector.py` — watches selected configuration changes and readable audit records.
- `kernel_modules_monitor.py` — module load/unload events.
- `hardening_recommender.py` — checks selected sysctl settings and prints recommendations.

This is a prototype, not a certified intrusion-detection product. Absence of alerts does not guarantee that a host is clean.
