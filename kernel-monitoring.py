#!/usr/bin/env python3
"""Collect recent high-priority kernel journal entries."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

from event_logger import log_event

SOURCE = "kernel-monitoring"
POLL_SECONDS = max(30, int(os.environ.get("KERNELSENSE_KERNEL_POLL_SECONDS", "300")))
_seen: set[str] = set()


def main() -> None:
    log_event("info", "monitor.started", "Kernel journal monitoring started", source=SOURCE,
              details={"poll_seconds": POLL_SECONDS})
    while True:
        try:
            result = subprocess.run(
                ["journalctl", "-k", "--since", f"{POLL_SECONDS + 60} seconds ago", "--priority=0..3",
                 "--no-pager", "--output=json"],
                capture_output=True, text=True, check=False, timeout=25,
            )
            if result.returncode != 0:
                log_event("low", "monitor.permission_or_command_error", "Could not read the kernel journal",
                          source=SOURCE, details={"return_code": result.returncode,
                          "stderr": result.stderr.strip()[:400]},
                          recommendation="Check journalctl availability and whether this user can read kernel journal entries.")
            else:
                for raw in result.stdout.splitlines():
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    message = str(entry.get("MESSAGE", "")).strip()
                    if not message:
                        continue
                    # journalctl priority 0-3 = emergency, alert, critical, error.
                    priority = str(entry.get("PRIORITY", "3"))
                    signature = hashlib.sha256((priority + "\0" + message).encode("utf-8", "replace")).hexdigest()
                    if signature in _seen:
                        continue
                    _seen.add(signature)
                    if len(_seen) > 3000:
                        _seen.clear()
                        _seen.add(signature)
                    severity = "high" if priority in {"0", "1", "2"} else "medium"
                    log_event(severity, "kernel.message", "High-priority kernel journal entry", source=SOURCE,
                              details={"priority": priority, "message": message[:1500],
                                       "unit": entry.get("_SYSTEMD_UNIT"), "comm": entry.get("_COMM")},
                              recommendation="Review the surrounding kernel journal entries. A kernel error is not, by itself, evidence of an intrusion.",
                              dedupe_key=f"kernel:{signature}")
            log_event("info", "monitor.heartbeat", "Kernel monitor completed a journal check", source=SOURCE,
                      details={"poll_seconds": POLL_SECONDS})
        except subprocess.TimeoutExpired:
            log_event("low", "monitor.timeout", "Kernel journal check timed out", source=SOURCE)
        except Exception as exc:
            log_event("low", "monitor.error", "Kernel journal check failed", source=SOURCE, details=str(exc)[:500])
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_event("info", "monitor.stopped", "Kernel journal monitoring stopped", source=SOURCE)
