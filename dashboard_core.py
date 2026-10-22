"""Data-access helpers for the local KernelSense Streamlit dashboard."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent


def tail_lines(path: str | Path, max_lines: int = 500, max_bytes: int = 25_000_000) -> list[str]:
    """Read only the tail of a potentially large append-only log file."""
    target = Path(path).expanduser()
    try:
        with target.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = max(0, size - max_bytes)
            handle.seek(start)
            content = handle.read().decode("utf-8", errors="replace")
        lines = content.splitlines()
        if start > 0 and lines:
            lines = lines[1:]  # first line may have been cut by the byte window
        return lines[-max(1, max_lines):]
    except (OSError, PermissionError, ValueError):
        return []


def load_jsonl(path: str | Path, max_lines: int = 500, max_bytes: int = 25_000_000) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in tail_lines(path, max_lines=max_lines, max_bytes=max_bytes):
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                records.append(item)
        except (json.JSONDecodeError, TypeError):
            continue
    return records


def load_events(path: str | Path, max_events: int = 2000) -> list[dict[str, Any]]:
    events = load_jsonl(path, max_lines=max_events, max_bytes=12_000_000)
    allowed = {"critical", "high", "medium", "low", "info", "warning", "error"}
    for event in events:
        severity = str(event.get("severity", "info")).lower()
        event["severity"] = severity if severity in allowed else "info"
        event.setdefault("category", "general")
        event.setdefault("source", "unknown")
        event.setdefault("message", "Event message unavailable")
        if not event.get("event_id"):
            seed = json.dumps(event, sort_keys=True, default=str)
            import hashlib
            event["event_id"] = hashlib.sha256(seed.encode()).hexdigest()[:20]
    events.sort(key=lambda row: str(row.get("timestamp", "")), reverse=True)
    return events


def load_process_snapshots(path: str | Path, max_snapshots: int = 48) -> list[dict[str, Any]]:
    snapshots = load_jsonl(path, max_lines=max_snapshots, max_bytes=30_000_000)
    valid = []
    for snapshot in snapshots:
        processes = snapshot.get("processes")
        if isinstance(processes, list):
            snapshot["processes"] = [p for p in processes if isinstance(p, dict)]
            valid.append(snapshot)
    valid.sort(key=lambda row: str(row.get("timestamp", "")))
    return valid


def parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        return stamp
    except (ValueError, TypeError, OverflowError):
        return None


def read_text_tail(path: str | Path, max_lines: int = 400, max_bytes: int = 2_000_000) -> list[str]:
    return tail_lines(path, max_lines=max_lines, max_bytes=max_bytes)


def load_acknowledged() -> set[str]:
    state_path = Path(os.environ.get("KERNELSENSE_DASHBOARD_STATE", "~/.local/share/kernelsense/dashboard_state.json")).expanduser()
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        values = data.get("acknowledged", []) if isinstance(data, dict) else []
        return {str(value) for value in values}
    except (OSError, json.JSONDecodeError, AttributeError):
        return set()


def save_acknowledged(values: set[str]) -> bool:
    state_path = Path(os.environ.get("KERNELSENSE_DASHBOARD_STATE", "~/.local/share/kernelsense/dashboard_state.json")).expanduser()
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"acknowledged": sorted(values)}, indent=2), encoding="utf-8")
        temporary.replace(state_path)
        return True
    except OSError:
        return False


def event_timestamp_age_seconds(event: dict[str, Any], now: datetime | None = None) -> float | None:
    stamp = parse_timestamp(event.get("timestamp"))
    if stamp is None:
        return None
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return max(0.0, (current - stamp).total_seconds())
