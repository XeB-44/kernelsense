#!/usr/bin/env python3
"""Run KernelSense monitors without the browser dashboard.

Use this for headless monitoring only. Do not run this at the same time as
`python3 dashboard.py`, because the dashboard starts its own monitor workers.
"""
from __future__ import annotations
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SCRIPTS = (
    "all-processes_monitoring.py",
    "directory-monitoring.py",
    "kernel-monitoring.py",
    "privilege_escalation-detector.py",
    "kernel_modules_monitor.py",
    "hardening_recommender.py",
)
children: list[subprocess.Popen] = []
stopping = False

def stop_all(*_args):
    global stopping
    stopping = True
    for child in children:
        if child.poll() is None:
            child.terminate()
    for child in children:
        try:
            child.wait(timeout=4)
        except subprocess.TimeoutExpired:
            child.kill()

def main() -> int:
    signal.signal(signal.SIGINT, stop_all)
    signal.signal(signal.SIGTERM, stop_all)
    print("Starting KernelSense monitoring workers (no dashboard). Ctrl+C to stop.", flush=True)
    for script in SCRIPTS:
        path = BASE_DIR / script
        if not path.is_file():
            print(f"Skipping missing monitor: {script}", flush=True)
            continue
        try:
            child = subprocess.Popen([sys.executable, "-u", str(path)], cwd=str(BASE_DIR))
            children.append(child)
            print(f"Started {script} (PID {child.pid})", flush=True)
        except OSError as exc:
            print(f"Could not start {script}: {exc}", flush=True)
    if not children:
        return 1
    try:
        while not stopping and any(p.poll() is None for p in children):
            time.sleep(1)
    finally:
        stop_all()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
