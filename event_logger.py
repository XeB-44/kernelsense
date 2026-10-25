#!/usr/bin/env python3
"""Small, dependency-free JSONL event sink shared by KernelSense monitors."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("KERNELSENSE_DATA_DIR", str(BASE_DIR))).expanduser()
EVENT_LOG = Path(os.environ.get("KERNELSENSE_EVENT_LOG", str(DATA_DIR / "security_events.jsonl"))).expanduser()
_LOCK = threading.Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log_event(
    severity: str,
    category: str,
    message: str,
    *,
    source: str,
    details: Any = None,
    recommendation: str | None = None,
    dedupe_key: str | None = None,
) -> dict[str, Any] | None:
    """Append one bounded, structured event. Never raises into a monitor loop."""
    try:
        payload: dict[str, Any] = {
            "timestamp": utc_now(),
            "severity": severity.lower().strip(),
            "category": category.strip(),
            "source": source.strip(),
            "message": message.strip()[:500],
        }
        if details is not None:
            payload["details"] = details
        if recommendation:
            payload["recommendation"] = recommendation.strip()[:1000]
        seed = dedupe_key or json.dumps(payload, sort_keys=True, default=str)
        payload["event_id"] = hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:20]
        EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
        encoded = (json.dumps(payload, ensure_ascii=False, default=str) + "\n").encode("utf-8")
        # A single O_APPEND write minimizes the chance of interleaved JSONL lines
        # when multiple monitor subprocesses share the same file.
        fd = os.open(str(EVENT_LOG), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            with _LOCK:
                os.write(fd, encoded)
        finally:
            os.close(fd)
        return payload
    except Exception as exc:  # monitoring should continue if event logging fails
        try:
            print(f"KernelSense event logger error: {exc}", flush=True)
        except Exception:
            pass
        return None
