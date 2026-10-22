#!/usr/bin/env python3
"""Start and supervise the KernelSense monitoring workers."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from event_logger import log_event

BASE_DIR = Path(__file__).resolve().parent
SCRIPTS = (
    "all-processes_monitoring.py",
    "directory-monitoring.py",
    "kernel-monitoring.py",
    "privilege_escalation-detector.py",
)
_processes: list[subprocess.Popen] = []
_stopping = False


def stop_all(signum=None, frame=None) -> None:
    global _stopping
    _stopping = True
    log_event("info", "monitor.stopping", "KernelSense shutdown requested", source="main")
    for proc in _processes:
        if proc.poll() is None:
            proc.terminate()
    deadline = time.monotonic() + 5
    for proc in _processes:
        try:
            proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            proc.kill()
    log_event("info", "monitor.stopped", "KernelSense monitoring workers stopped", source="main")


def main() -> int:
    signal.signal(signal.SIGINT, stop_all)
    signal.signal(signal.SIGTERM, stop_all)
    log_event("info", "monitor.launching", "KernelSense is starting monitoring workers", source="main",
              details={"project_dir": str(BASE_DIR)})
    for name in SCRIPTS:
        script_path = BASE_DIR / name
        if not script_path.is_file():
            log_event("high", "monitor.missing_script", "A configured monitor script is missing", source="main",
                      details={"script": str(script_path)})
            continue
        try:
            proc = subprocess.Popen([sys.executable, str(script_path)], cwd=str(BASE_DIR))
            _processes.append(proc)
            log_event("info", "monitor.worker_started", f"Started {name}", source="main",
                      details={"script": name, "pid": proc.pid})
        except OSError as exc:
            log_event("high", "monitor.worker_start_failed", f"Could not start {name}", source="main",
                      details={"script": name, "error": str(exc)[:300]})
    if not _processes:
        return 1
    print("KernelSense monitors started. Press Ctrl+C to stop.", flush=True)
    try:
        while not _stopping:
            for index, proc in enumerate(list(_processes)):
                if proc.poll() is not None and not _stopping:
                    log_event("high", "monitor.worker_exited", "A monitoring worker exited unexpectedly", source="main",
                              details={"pid": proc.pid, "return_code": proc.returncode})
                    _processes.remove(proc)
            if not _processes:
                log_event("high", "monitor.all_workers_stopped", "All monitoring workers have stopped", source="main")
                return 1
            time.sleep(1)
    finally:
        if not _stopping:
            stop_all()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
