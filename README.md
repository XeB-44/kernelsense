# KernelSense — Local Linux Host Security Dashboard

KernelSense is a local host-monitoring prototype. This bundle adds a Streamlit dashboard and a structured JSON Lines (`security_events.jsonl`) event stream to the existing process, directory, kernel-journal, and privilege/configuration monitors.

## Dashboard features

- Host CPU, memory, and disk overview.
- Monitor heartbeat status and source-path diagnostics.
- Searchable alerts with severity/source filters, local acknowledgement, and recommendations.
- Latest process snapshot with search/sorting. Command-line arguments are hidden by default because they may contain sensitive values.
- Searchable log view and CSV/JSONL exports.
- Local-only UI; no cloud service or external telemetry is configured.
- Suggested remediation is guidance only. The dashboard does not execute commands or automatically alter system settings.

## Install

Use a virtual environment from the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run monitors and dashboard

Start monitors in one terminal:

```bash
source .venv/bin/activate
python3 main.py
```

The directory and audit monitors may need access to protected system paths. Start without elevated privileges first and inspect `security_events.jsonl`. Only use `sudo` if required for the particular monitor and you understand the implications; the monitoring scripts do not need the dashboard to run as root.

Start the dashboard in another terminal, as your normal user:

```bash
source .venv/bin/activate
streamlit run dashboard.py
```

Open the local URL printed by Streamlit (normally `http://localhost:8501`). Keep the dashboard bound to localhost unless you intentionally configure and secure remote access.

## Data files

By default, log files are stored alongside the scripts:

- `process_log.jsonl` — append-only process snapshots.
- `security_events.jsonl` — structured monitor events and heartbeats.
- `kernel-monitor.log` — optional legacy text log from an earlier build.
- `~/.local/share/kernelsense/dashboard_state.json` — locally acknowledged alert IDs.

Paths can be overridden with environment variables:

- `KERNELSENSE_DATA_DIR`
- `KERNELSENSE_EVENT_LOG`
- `KERNELSENSE_PROCESS_LOG`
- `KERNELSENSE_AUDIT_LOG`
- `KERNELSENSE_PROCESS_POLL_SECONDS`
- `KERNELSENSE_KERNEL_POLL_SECONDS`
- `KERNELSENSE_PRIVILEGE_POLL_SECONDS`

The dashboard sidebar also allows the log-file paths to be changed at runtime.

## Important limitations

- This is a prototype, not a certified intrusion-detection product. Lack of alerts does not mean the host is clean.
- Filesystem monitoring covers the configured locations only. Kernel log access depends on local journal permissions.
- Events can be benign or false positives; verify the full context before responding.
- Logs can contain usernames, file paths, process metadata, and audit text. Keep them private and do not upload them publicly.
- Do not expose the Streamlit server to the network without authentication and suitable access controls.

## Troubleshooting

- If process data is missing, check the process-log path shown in **Monitor health**.
- If kernel events are missing, check `journalctl -k --no-pager -n 20` manually and review the dashboard's **Monitor health** tab.
- If auto-refresh is unavailable, install all packages in `requirements.txt`; the dashboard still works with manual reruns.
- Each monitor reports its own status to `security_events.jsonl`; check that file's latest lines when diagnosing a worker.
