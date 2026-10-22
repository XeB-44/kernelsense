# Professional implementation prompt — KernelSense Streamlit dashboard

You are acting as a senior Python engineer, Linux host-security engineer, UX designer, and careful code reviewer. Work directly on the supplied KernelSense repository; do not merely describe what should be done.

## Project context

KernelSense is a continuous host-based intrusion-detection prototype for Linux. The existing code includes process monitoring, filesystem monitoring, kernel-journal checks, and privilege/configuration checks. The project intent is to make host security visible and actionable for everyday Linux users through clear alerts, contextual logs, monitor health, and carefully explained next steps.

## Mission

Inspect the actual repository, identify its real log formats and execution model, then implement a polished, usable Streamlit dashboard integrated with the existing monitoring engine. Prioritize the following outcomes:

1. **Overview:** host CPU, memory, disk and process snapshot metrics; last update time; clear monitor heartbeat/status indicators; recent findings.
2. **Alert center:** structured severity, category, timestamp, source, explanation, evidence/details, suggested next step, search and filters, local acknowledge/unacknowledge, and CSV export. Use severity labels consistently and make clear that an alert is an indicator to investigate, not proof of compromise.
3. **Process explorer:** latest available process snapshot, PID/name/CPU/memory/executable, text search and sorting. Hide full command-line arguments by default because they may include credentials or sensitive paths.
4. **Logs and investigation:** readable unified event log; legacy log compatibility where practical; filters by time/source/severity; searchable raw details; CSV and JSONL export; useful empty/error states that explain what data is missing and how to fix the path or start the monitor.
5. **Monitor health:** heartbeat-based freshness for each worker, data-source existence/readability, permission/command failures and actionable diagnostic hints.
6. **Professional UX:** clean hierarchy, responsive layout, restrained colors, readable tables, no misleading green “secure” badge when data is missing, and straightforward navigation suitable for a university project demo.

## Engineering requirements

- Read all relevant source files before editing. Preserve compatible existing behavior unless there is a clear reason to improve it, and document material changes.
- Use a lightweight, explicit data pipeline. Structured JSONL or SQLite is acceptable, but choose one that fits the current project and migrate/read existing logs gracefully.
- The dashboard must display actual monitor output. Never fabricate live incidents or show demo data as if it came from the host.
- Make log reads bounded and efficient; process snapshots can be very large. Handle missing files, malformed JSONL lines, permissions, empty logs, and stale data without crashing.
- Avoid repeated alert spam where practical by de-duplicating recurring source records or applying reasonable debounce windows.
- Provide safe, distro-aware explanations and suggested commands only when supported by evidence. Do not execute remediation, shell commands, privilege changes, service restarts, or destructive actions from the dashboard.
- Keep monitoring local by default. Do not add telemetry, remote uploads, or network exposure. Do not require running the Streamlit dashboard as root.
- Protect sensitive process command-line arguments and logs. Provide an explicit warning when showing raw arguments or audit details.
- Keep components modular, use pathlib and type hints where helpful, handle exceptions narrowly, and avoid unnecessary dependencies.
- Include a `requirements.txt`, clear setup/run instructions, and tests for core log parsing, malformed/missing files, severity normalization, timestamp handling, and alert filtering.
- Do not assert that the system is secure because no alerts were found. Surface coverage gaps and monitor errors clearly.

## Acceptance criteria

- A fresh checkout can install dependencies and launch the Streamlit app using documented commands.
- A user can see which data sources exist and which monitors are fresh or stale.
- Real monitor findings appear as structured alerts with details and recommendations.
- Search, filtering, acknowledgement, sorting and CSV/JSONL exports work without modifying the monitored system.
- Missing/corrupt/unreadable log files produce helpful empty/error states instead of tracebacks.
- Tests and Python syntax checks pass; report anything that could not be verified.
- At the end, summarize changed files, key behavior, exact run commands, test results, limitations, and any remaining manual setup.

## Work method

Start with a brief repository map and implementation plan. Then make the changes directly, test them, inspect the final diff for unsafe side effects and obvious regressions, and deliver the runnable project. Prefer a complete, modestly scoped, working implementation over ambitious placeholder features. Do not stop after writing a plan or giving code snippets: edit the project and verify the result.
