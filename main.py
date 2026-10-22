#!/usr/bin/env python3
"""
main.py - runs all KernelSense monitors in background
Usage:  sudo python3 main.py
Stop with Ctrl+C
"""

import subprocess
import sys
import time
import signal
import os

SCRIPTS = [
    "all-processes_monitoring.py",
    "directory-monitoring.py",
    "kernel-monitoring.py",
    "privilege_escalation-detector.py",
]

procs = []

def stop_all(sig=None, frame=None):
    print("\nStopping all monitors...")
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    sys.exit(0)

signal.signal(signal.SIGINT, stop_all)
signal.signal(signal.SIGTERM, stop_all)

print("Starting KernelSense (all monitors)...")

for script in SCRIPTS:
    if not os.path.exists(script):
        print(f"Missing: {script}")
        continue
    p = subprocess.Popen([sys.executable, script])
    procs.append(p)
    print(f"  started {script} (pid {p.pid})")

print("All running. Press Ctrl+C to stop.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    stop_all()
