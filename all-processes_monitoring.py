#!/usr/bin/env python3
"""
Simple process monitor (beginner-friendly version).

What it does, every few seconds:
  1. Looks at all running processes and logs which ones started or exited.
  2. Warns if a process is running from a suspicious place (like /tmp).
  3. Reads NEW lines of the Linux audit log and warns if someone ran top/htop/etc.

Run it with:  sudo python3 All-proccessmonitoring-simple.py
(root is needed to read /var/log/audit/audit.log)

For step 3 to work, auditd needs a rule that records program launches:
  sudo auditctl -a always,exit -F arch=b64 -S execve -k proc_watch
"""

import json
import os
import time
from datetime import datetime, timezone

import psutil

# ---------- Settings (change these if you like) ----------
CHECK_EVERY = 3                         # seconds between checks
PROCESS_LOG = "process_log.jsonl"       # started/exited processes go here
ALERT_LOG = "alerts.jsonl"              # warnings go here
AUDIT_LOG = "/var/log/audit/audit.log"
MAX_LOG_SIZE = 50 * 1024 * 1024         # 50 MB, then the log file is renamed
WATCHED_TOOLS = ["ps", "top", "htop", "btop"]
SUSPICIOUS_FOLDERS = ["/tmp/", "/var/tmp/", "/dev/shm/"]
# ---------------------------------------------------------


def now():
    """Current time in UTC as text."""
    return datetime.now(timezone.utc).isoformat()


def write_log(filename, data):
    """Add one line of JSON to a log file."""
    # If the file is too big, rename it so we start a fresh one.
    if os.path.exists(filename) and os.path.getsize(filename) > MAX_LOG_SIZE:
        os.replace(filename, filename + ".old")

    data["timestamp"] = now()
    with open(filename, "a") as f:
        f.write(json.dumps(data) + "\n")


def alert(kind, details):
    """Save a warning to the alert log and show it on screen."""
    write_log(ALERT_LOG, {"alert": kind, "details": details})
    print("[ALERT]", kind, details)


def get_processes():
    """Return all running processes as a dictionary: {pid: info}."""
    processes = {}
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "exe", "cmdline"]):
        processes[proc.info["pid"]] = proc.info
    return processes


def is_suspicious(info):
    """True if the program runs from /tmp etc., or its file was deleted."""
    exe = info["exe"] or ""          # exe can be None if we can't read it
    if "(deleted)" in exe:
        return True
    for folder in SUSPICIOUS_FOLDERS:
        if exe.startswith(folder):
            return True
    return False


def read_new_audit_lines(position):
    """
    Read only the lines added to the audit log since last time.
    'position' is how far into the file we already read.
    Returns (new_lines, new_position).
    """
    try:
        size = os.path.getsize(AUDIT_LOG)

        if position is None:         # first run: skip old history
            return [], size
        if size < position:          # file got smaller = it was rotated, start over
            position = 0

        with open(AUDIT_LOG, "r", errors="replace") as f:
            f.seek(position)
            lines = f.readlines()
            new_position = f.tell()
        return lines, new_position

    except (PermissionError, FileNotFoundError):
        return [], position          # can't read it right now, try again later


def find_watched_tool(line):
    """If this audit line shows top/htop/etc. being launched, return its name."""
    # EXECVE lines look like:  type=EXECVE msg=audit(...): argc=1 a0="top"
    if "type=EXECVE" not in line or 'a0="' not in line:
        return None

    program = line.split('a0="')[1].split('"')[0]   # text between the quotes
    name = os.path.basename(program)                # "/usr/bin/top" -> "top"

    if name in WATCHED_TOOLS:
        return name
    return None


def main():
    # Warn once at the start if we can't read the audit log.
    try:
        open(AUDIT_LOG).close()
    except (PermissionError, FileNotFoundError) as error:
        print("Warning: can't read", AUDIT_LOG, "-", error)
        print("The top/htop check won't work. Try running with sudo.")

    print("Monitoring started. Press Ctrl+C to stop.")

    # First look at the system. This also "warms up" the CPU numbers,
    # because psutil needs two readings to calculate CPU usage.
    old_processes = get_processes()
    write_log(PROCESS_LOG, {"event": "snapshot", "processes": list(old_processes.values())})
    for info in old_processes.values():
        if is_suspicious(info):
            alert("suspicious_process_path", info)

    # Start reading the audit log from its current end.
    _, audit_position = read_new_audit_lines(None)

    try:
        while True:
            time.sleep(CHECK_EVERY)

            # --- Part 1: compare processes now vs. last time ---
            current_processes = get_processes()

            for pid, info in current_processes.items():
                if pid not in old_processes:            # new process
                    write_log(PROCESS_LOG, {"event": "started", "process": info})
                    if is_suspicious(info):
                        alert("suspicious_process_path", info)

            for pid, info in old_processes.items():
                if pid not in current_processes:        # process is gone
                    write_log(PROCESS_LOG, {"event": "exited", "pid": pid, "name": info["name"]})

            old_processes = current_processes

            # --- Part 2: look at new audit log lines ---
            lines, audit_position = read_new_audit_lines(audit_position)
            for line in lines:
                tool = find_watched_tool(line)
                if tool:
                    alert("process_utility_executed", {"tool": tool, "audit_line": line.strip()})

    except KeyboardInterrupt:
        print("Stopped successfully!")


main()