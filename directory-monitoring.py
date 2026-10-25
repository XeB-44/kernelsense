#!/usr/bin/env python3
"""Watch selected Linux system directories and publish structured events."""
from __future__ import annotations

import os
import time
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from event_logger import log_event

WATCH_PATHS = ("/etc/init.d", "/etc/systemd", "/var/log/journal")
SOURCE = "directory-monitoring"
_recent_events: dict[str, float] = {}


class SecurityFileEventHandler(FileSystemEventHandler):
    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory or event.event_type not in {"created", "deleted", "modified", "moved"}:
            return
        path = getattr(event, "dest_path", None) if event.event_type == "moved" else event.src_path
        path = str(path or event.src_path)
        # Routine journal writes are extremely frequent and are not useful individually.
        if path.startswith("/var/log/journal/") and event.event_type == "modified":
            return
        dedupe_key = f"{event.event_type}:{path}"
        now = time.monotonic()
        if now - _recent_events.get(dedupe_key, 0.0) < 10:
            return
        _recent_events[dedupe_key] = now
        if len(_recent_events) > 5000:
            _recent_events.clear()
            _recent_events[dedupe_key] = now
        protected_config = path.startswith(("/etc/systemd/", "/etc/init.d/"))
        severity = "medium" if protected_config else "info"
        message = f"{event.event_type.title()} filesystem activity detected"
        recommendation = (
            "Review the file and change time. Confirm that the change was expected before taking action."
            if protected_config else
            "This is a journal-directory event, not proof of an intrusion. Investigate only if it coincides with other evidence."
        )
        log_event(
            severity,
            "filesystem.change",
            message,
            source=SOURCE,
            details={"event_type": event.event_type, "path": path, "is_system_configuration": protected_config},
            recommendation=recommendation,
        )


def main() -> None:
    observer = Observer()
    handler = SecurityFileEventHandler()
    active_paths = []
    for path in WATCH_PATHS:
        if not os.path.isdir(path):
            log_event("low", "monitor.path_unavailable", "A configured directory cannot be watched",
                      source=SOURCE, details={"path": path, "reason": "Directory is missing or inaccessible"})
            continue
        try:
            observer.schedule(handler, path, recursive=True)
            active_paths.append(path)
        except Exception as exc:
            log_event("low", "monitor.path_unavailable", "Failed to watch a configured directory",
                      source=SOURCE, details={"path": path, "error": str(exc)[:300]})
    if not active_paths:
        log_event("high", "monitor.error", "No configured directories could be watched", source=SOURCE,
                  recommendation="Check directory permissions and watchdog installation. Run with only the privileges required for monitoring.")
        return
    started = False
    try:
        observer.start()
        started = True
        log_event("info", "monitor.started", "Directory monitoring started", source=SOURCE,
                  details={"watched_paths": active_paths})
        last_heartbeat = 0.0
        while True:
            now = time.monotonic()
            if now - last_heartbeat >= 60:
                log_event("info", "monitor.heartbeat", "Directory monitor is running", source=SOURCE,
                          details={"watched_path_count": len(active_paths)})
                last_heartbeat = now
            time.sleep(1)
    except KeyboardInterrupt:
        log_event("info", "monitor.stopped", "Directory monitoring stopped", source=SOURCE)
    except Exception as exc:
        log_event("high", "monitor.error", "Directory monitor crashed", source=SOURCE, details=str(exc))
        raise
    finally:
        if started:
            observer.stop()
            observer.join(timeout=5)


if __name__ == "__main__":
    main()
