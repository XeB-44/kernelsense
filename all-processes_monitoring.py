#!/usr/bin/env python3
"""Capture local process snapshots for KernelSense."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import time
from pathlib import Path

import psutil
from event_logger import log_event

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("KERNELSENSE_DATA_DIR", str(BASE_DIR))).expanduser()
PROCESS_LOG = Path(os.environ.get("KERNELSENSE_PROCESS_LOG", str(DATA_DIR / "process_log.jsonl"))).expanduser()
POLL_SECONDS = max(1, int(os.environ.get("KERNELSENSE_PROCESS_POLL_SECONDS", "3")))


def redact_command_line(args: list[str] | None) -> list[str]:
    """Reduce accidental exposure of credentials passed in command-line flags."""
    if not args:
        return []
    redacted = []
    redact_next = False
    sensitive_flag = re.compile(r"(?i)(token|password|passwd|secret|api[-_]?key|access[-_]?key|credential|authorization)")
    for arg in args:
        value = str(arg)
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        if value.startswith("-") and sensitive_flag.search(value):
            if "=" in value:
                redacted.append(value.split("=", 1)[0] + "=<redacted>")
            else:
                redacted.append(value)
                redact_next = True
            continue
        if re.search(r"(?i)^(sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|Bearer\s+\S+)$", value):
            redacted.append("<redacted>")
        else:
            redacted.append(value)
    return redacted


def main() -> None:
    PROCESS_LOG.parent.mkdir(parents=True, exist_ok=True)
    log_event("info", "monitor.started", "Process monitoring started", source="all-processes-monitoring",
              details={"poll_seconds": POLL_SECONDS, "log_path": str(PROCESS_LOG)})
    snapshot_count = 0
    last_heartbeat = 0.0
    while True:
        data = []
        for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_percent", "exe", "cmdline"]):
            try:
                info = proc.info
                # Keep a consistent, JSON-safe record when process metadata is unavailable.
                info["cmdline"] = redact_command_line(info.get("cmdline"))
                data.append(info)
            except (psutil.ZombieProcess, psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        record = {"timestamp": dt.datetime.now(dt.timezone.utc).isoformat(), "processes": data}
        with PROCESS_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, separators=(",", ":"), default=str) + "\n")
        snapshot_count += 1
        now = time.monotonic()
        if now - last_heartbeat >= 30:
            log_event("info", "monitor.heartbeat", "Process monitor is running", source="all-processes-monitoring",
                      details={"process_count": len(data), "snapshot_count": snapshot_count})
            last_heartbeat = now
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_event("info", "monitor.stopped", "Process monitoring stopped", source="all-processes-monitoring")
        print("Process monitoring stopped.", flush=True)
    except Exception as exc:
        log_event("high", "monitor.error", "Process monitor crashed", source="all-processes-monitoring", details=str(exc))
        raise
