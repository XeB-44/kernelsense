#!/usr/bin/env python3
"""Continuous kernel modules monitor"""
import time

known = set()

# first load
with open("/proc/modules") as f:
    for line in f:
        known.add(line.split()[0])
print("Kernel modules baseline ready")

while True:
    current = set()
    with open("/proc/modules") as f:
        for line in f:
            name = line.split()[0]
            current.add(name)
            if name not in known:
                print(f"[ALERT] NEW MODULE LOADED: {name}")
                known.add(name)

    for m in known - current:
        print(f"[ALERT] MODULE REMOVED: {m}")
    known = current
    time.sleep(10)
