#!/usr/bin/env python3
"""KernelSense HIDS dashboard.

One console for everything the KernelSense project observes:

  all-processes_monitoring.py       -> process_log.jsonl snapshots (+ auditd process-utility use)
  directory-monitoring.py           -> /etc/init.d, /etc/systemd, /var/log/journal changes
  kernel-monitoring.py              -> ~/kernel-monitor.log (journalctl -k errors)
  privilege_escalation-detector.py  -> sudoers/.bashrc/.profile diffs + auditd privilege records
  kernel_modules_monitor.py         -> /proc/modules load/unload
  hardening_recommender.py          -> sysctl hardening checks

The monitor scripts mostly print to their terminal, so the dashboard runs the same
checks itself in one background collector thread (same sources, same rules) and
also reads the files the monitors write. Findings are stored in security_events.jsonl.
The dashboard never runs remediation commands.

Run (root is needed for audit.log, /etc/sudoers and the journal directory):
    sudo streamlit run dashboard.py
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import psutil
import streamlit as st

try:
    from streamlit_autorefresh import st_autorefresh
except ImportError:  # optional
    st_autorefresh = None

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # directory watching degrades gracefully
    Observer = None
    FileSystemEventHandler = object

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
BASE_DIR = Path(os.environ.get("KERNELSENSE_DIR", Path(__file__).resolve().parent)).expanduser()
PROCESS_LOG = BASE_DIR / "process_log.jsonl"          # all-processes_monitoring.py
MONITOR_BASELINE = BASE_DIR / "baseline.json"         # privilege_escalation-detector.py
EVENT_STORE = BASE_DIR / "security_events.jsonl"      # dashboard findings (persisted)
DASH_BASELINE = BASE_DIR / "dashboard_baseline.json"  # dashboard's own config-file baseline
ACK_FILE = BASE_DIR / "acknowledged_alerts.json"
AUDIT_LOG = Path("/var/log/audit/audit.log")
KERNEL_LOG_CANDIDATES = [Path("~/kernel-monitor.log").expanduser(), Path("/root/kernel-monitor.log"), BASE_DIR / "kernel-monitor.log"]

WATCHED_DIRS = {"/etc/init.d/": "init.d", "/etc/systemd/": "systemd", "/var/log/journal/": "journal"}
WATCHED_FILES = ["/etc/sudoers", "~/.bashrc", "~/.profile", "/etc/passwd", "/etc/ssh/sshd_config", "~/.ssh/authorized_keys"]

# (script, label, event source, dashboard collector key, what it covers)
MONITORS = [
    ("all-processes_monitoring.py", "Process monitor", "all-processes-monitoring", "process", "Process snapshots + auditd process-utility use"),
    ("directory-monitoring.py", "Directory monitor", "directory-monitoring", "directory", "/etc/init.d, /etc/systemd, /var/log/journal"),
    ("kernel-monitoring.py", "Kernel log monitor", "kernel-monitoring", "kernel", "journalctl -k errors (priority 0-3)"),
    ("privilege_escalation-detector.py", "Privilege / config monitor", "privilege-escalation-detector", "privilege", "sudoers/.bashrc/.profile diffs + auditd"),
    ("kernel_modules_monitor.py", "Kernel modules monitor", "kernel-modules-monitor", "modules", "/proc/modules load/unload"),
    ("hardening_recommender.py", "Hardening recommender", "hardening-recommender", "hardening", "sysctl hardening checks"),
]

HARDENING_CHECKS = [  # (sysctl key, good value, name, benefit, trade-off) - same list as hardening_recommender.py
    ("net.ipv4.tcp_syncookies", "1", "TCP SYN Cookies", "Protects against SYN flood attacks", "Almost no downside"),
    ("net.ipv4.conf.all.rp_filter", "1", "Reverse Path Filtering", "Blocks spoofed packets", "Can break asymmetric routing"),
    ("net.ipv4.conf.all.accept_redirects", "0", "Ignore ICMP Redirects", "Stops attackers redirecting traffic", "Rarely needed on servers"),
    ("net.ipv4.conf.all.send_redirects", "0", "Do not send redirects", "Prevents your host helping attackers", "None for normal hosts"),
    ("net.ipv4.ip_forward", "0", "IP Forwarding off", "Stops your machine acting as a router", "Disable only if you do not need routing/VPN/containers"),
    ("kernel.randomize_va_space", "2", "ASLR full", "Makes memory exploits harder", "None"),
    ("kernel.kptr_restrict", "1", "Hide kernel pointers", "Harder for attackers to find kernel addresses", "Some debugging tools need 0"),
    ("fs.protected_symlinks", "1", "Protected symlinks", "Stops symlink race attacks in /tmp", "None"),
]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
SEV_COLOR = {"critical": "#d62728", "high": "#ff7f0e", "medium": "#e6b800", "low": "#1f77b4", "info": "#8c8c8c"}
HIDDEN_CATEGORIES = {"monitor.heartbeat", "monitor.started", "monitor.worker_started", "monitor.launching"}
MAX_EVENTS = 5000
SUSPICIOUS_EXE_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")
RISKY_TOOLS = {"nc", "ncat", "netcat", "socat", "nmap", "tcpdump", "hping3"}
KERNEL_HIGH_TERMS = ("kernel panic", "oops", "bug:", "general protection", "call trace", "machine check", "hardware error")


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def epoch_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def parse_ts(value: Any) -> datetime | None:
    """Parse an ISO timestamp to aware UTC. Naive values are treated as local time
    (all-processes_monitoring.py writes naive local timestamps)."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.astimezone(timezone.utc)


def age_seconds(value: Any) -> float | None:
    dt = parse_ts(value)
    return (datetime.now(timezone.utc) - dt).total_seconds() if dt else None


def friendly_age(seconds: float | None) -> str:
    if seconds is None:
        return "unknown time"
    seconds = max(0, seconds)
    if seconds < 60:
        return f"{int(seconds)} sec ago"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)} hr ago"
    return f"{int(seconds // 86400)} days ago"


def make_id(*parts: Any) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode("utf-8", "replace")).hexdigest()[:16]


def as_text(value: Any) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value or "")


def tail_lines(path: Path, n: int, max_bytes: int = 4_000_000) -> list[str]:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read()
    except OSError:
        return []
    return data.decode("utf-8", "replace").splitlines()[-n:]


def read_increment(path: Path, pos: int | None, initial_tail: int = 200) -> tuple[list[str], int]:
    """Return (new complete lines, new offset). First call returns the last lines of the file."""
    size = path.stat().st_size
    if pos is None or size < pos:  # first read, or the file was rotated/truncated
        return tail_lines(path, initial_tail), size
    if size == pos:
        return [], pos
    with open(path, "rb") as f:
        f.seek(pos)
        data = f.read(4_000_000)
    cut = data.rfind(b"\n")
    if cut < 0:
        return [], pos
    data = data[: cut + 1]
    return data.decode("utf-8", "replace").splitlines(), pos + len(data)


def read_text_lines(path: str) -> tuple[list[str] | None, str]:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").splitlines(), "ok"
    except FileNotFoundError:
        return None, "missing"
    except PermissionError:
        return None, "denied"
    except OSError as exc:
        return None, f"error: {exc}"


def path_status(path: Path) -> str:
    if not path.exists():
        return "missing"
    return "ok" if os.access(path, os.R_OK) else "denied"


def last_snapshot(path: Path) -> dict[str, Any] | None:
    """Last complete JSON line of process_log.jsonl, without reading the whole (huge) file."""
    for line in reversed(tail_lines(path, 5, max_bytes=8_000_000)):
        try:
            obj = json.loads(line)
        except ValueError:
            continue  # partial line still being written
        if isinstance(obj, dict) and "processes" in obj:
            return obj
    return None


def live_snapshot() -> dict[str, Any]:
    data = [p.info for p in psutil.process_iter(attrs=["pid", "name", "cpu_percent", "memory_percent", "exe", "cmdline"])]
    return {"timestamp": datetime.now().isoformat(), "processes": data}


def proc_flags(proc: dict[str, Any]) -> list[str]:
    flags = []
    exe = str(proc.get("exe") or "")
    name = str(proc.get("name") or "")
    if exe.endswith("(deleted)"):
        flags.append("executable deleted from disk")
    if exe.startswith(SUSPICIOUS_EXE_DIRS):
        flags.append("runs from a temp directory")
    if name.lower() in RISKY_TOOLS:
        flags.append("network/recon tool")
    return flags


# --------------------------------------------------------------------------- #
# auditd parsing
# --------------------------------------------------------------------------- #
AUDIT_MSG = re.compile(r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)")
AUDIT_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')
ACCOUNT_TYPES = {"ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP", "USER_MGMT"}


def parse_audit(line: str) -> dict[str, str] | None:
    if not line.startswith("type="):
        return None
    rec = {k: v.strip("\"'") for k, v in AUDIT_KV.findall(line)}
    m = AUDIT_MSG.search(line)
    if m:
        rec["_ts"], rec["_serial"] = m.group(1), m.group(2)
    return rec


def classify_audit(rec: dict[str, str], line: str) -> dict[str, Any] | None:
    typ = rec.get("type", "")
    exe, comm = rec.get("exe", ""), rec.get("comm", "")
    names = {os.path.basename(rec.get("a0", ""))} if typ == "EXECVE" else {os.path.basename(exe), comm}
    names.discard("")
    src_priv, src_proc = "privilege-escalation-detector", "all-processes-monitoring"

    if typ in ACCOUNT_TYPES:
        return dict(source=src_priv, category="audit.account", severity="high",
                    message=f"Account or group change recorded by auditd ({typ})",
                    recommendation="Confirm the account/group change was intentional (who ran it: check auid/acct in the record).")
    if typ in {"USER_AUTH", "USER_LOGIN"} and rec.get("res") == "failed":
        who = rec.get("acct") or rec.get("id") or "unknown"
        return dict(source=src_priv, category="audit.auth", severity="medium",
                    message=f"Failed authentication ({typ}) for account {who}",
                    recommendation="Repeated failures from one source can indicate password guessing; check the source address in the record.")
    if typ not in {"SYSCALL", "EXECVE", "USER_CMD"}:
        return None
    if names & {"insmod", "rmmod", "modprobe"}:
        return dict(source=src_priv, category="audit.module_tool", severity="medium",
                    message=f"Kernel module tool executed ({', '.join(sorted(names & {'insmod', 'rmmod', 'modprobe'}))})",
                    recommendation="Check the Kernel tab for the module that changed and confirm it is expected.")
    if "/proc/kallsyms" in line or "/dev/kmem" in line:
        return dict(source=src_priv, category="audit.kernel_access", severity="medium",
                    message="Access to kernel memory/symbol interface (/proc/kallsyms or /dev/kmem)",
                    recommendation="Reading kernel symbols is a common step before kernel exploitation; confirm which process did it.")
    if names & {"sudo", "su"}:
        return dict(source=src_priv, category="audit.privilege", severity="medium",
                    message=f"Privilege elevation command executed ({'/'.join(sorted(names & {'sudo', 'su'}))})",
                    recommendation="Verify the user and command were expected; routine admin work also produces these records.")
    if names & {"chmod", "chown"}:
        args = " ".join(rec.get(f"a{i}", "") for i in range(1, 6))
        setuid = bool(re.search(r"(^|\s)(u\+s|g\+s|[2-7][0-7]{3})(\s|$)", args))
        return dict(source=src_priv, category="audit.chmod", severity="high" if setuid else "low",
                    message="chmod/chown with setuid/setgid bits" if setuid else "chmod/chown executed",
                    recommendation="A setuid/setgid change on an unexpected file is a classic privilege-escalation backdoor." if setuid else None)
    if names & {"ps", "top", "htop", "btop"}:
        return dict(source=src_proc, category="audit.process_utility", severity="low",
                    message=f"Process listing utility executed ({'/'.join(sorted(names & {'ps', 'top', 'htop', 'btop'}))})",
                    recommendation="Normal for admins; unexpected use by another account may indicate reconnaissance.")
    if typ == "SYSCALL" and "execve" in line and rec.get("euid") == "0" and rec.get("auid") not in {None, "0", "4294967295"}:
        return dict(source=src_priv, category="audit.privilege", severity="low",
                    message=f"Root-privileged execution by login user auid={rec.get('auid')} ({exe or comm or 'unknown'})",
                    recommendation="Expected after sudo; investigate if the user does not normally have root access.")
    return None


# --------------------------------------------------------------------------- #
# Collector: one background thread that gathers findings from every source
# --------------------------------------------------------------------------- #
class DirHandler(FileSystemEventHandler):
    def __init__(self, collector: "Collector", label: str):
        super().__init__()
        self.collector, self.label = collector, label

    def on_any_event(self, event):
        if event.event_type in {"opened", "closed", "closed_no_write"}:
            return
        if event.is_directory and event.event_type == "modified":
            return
        self.collector.on_fs_event(self.label, event)


class Collector:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.events: list[dict[str, Any]] = []
        self.seen: set[str] = set()
        self.errors: dict[str, str] = {}
        self.sources: dict[str, str] = {}
        self.health: dict[str, Any] = {"running": {}, "freshness": {}}
        self.latest_snapshot: dict[str, Any] | None = None
        self.snapshot_live = False
        self.last_snapshot_ts: str | None = None
        self.proc_history: deque = deque(maxlen=300)
        self.hot_cpu: dict[int, int] = {}
        self.modules: dict[str, dict[str, Any]] = {}
        self.known_modules: set[str] | None = None
        self.hardening: list[dict[str, Any]] = []
        self.file_state: dict[str, dict[str, Any]] = {}
        self.dir_state: dict[str, str] = {}
        self.audit_pos: int | None = None
        self.kernel_pos: int | None = None
        self.kernel_path: Path | None = None
        self.kernel_ts: str | None = None
        self.fs_window, self.fs_count, self.fs_dropped = 0.0, 0, 0
        self.config_baseline = self._load_config_baseline()
        self._load_history()
        self.observer = None
        self._start_watchers()
        self.jobs = [  # (name, interval seconds, function)
            ("health", 5, self.job_health),
            ("audit", 3, self.job_audit),
            ("processes", 5, self.job_processes),
            ("modules", 10, self.job_modules),
            ("config", 30, self.job_config),
            ("kernel", 30, self.job_kernel),
            ("hardening", 300, self.job_hardening),
        ]
        self.last_run: dict[str, float] = {}
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, name="kernelsense-collector", daemon=True)
        self.thread.start()

    # -- plumbing ----------------------------------------------------------
    def _loop(self) -> None:
        while not self.stop.is_set():
            now = time.time()
            for name, interval, fn in self.jobs:
                if now - self.last_run.get(name, 0) >= interval:
                    self.last_run[name] = now
                    try:
                        fn()
                        self.errors.pop(name, None)
                    except Exception as exc:  # keep the thread alive whatever happens
                        self.errors[name] = f"{type(exc).__name__}: {exc}"
            self.stop.wait(1)

    def _load_history(self) -> None:
        for line in tail_lines(EVENT_STORE, MAX_EVENTS, max_bytes=16_000_000):
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, dict) and ev.get("event_id"):
                self.events.append(ev)
                self.seen.add(str(ev["event_id"]))

    def emit(self, source: str, category: str, severity: str, message: str, key: Any,
             details: Any = None, recommendation: str | None = None, timestamp: str | None = None) -> bool:
        event_id = make_id(source, category, key)
        with self.lock:
            if event_id in self.seen:
                return False
            self.seen.add(event_id)
            event = {"event_id": event_id, "timestamp": timestamp or now_iso(), "severity": severity,
                     "source": source, "category": category, "message": message[:400],
                     "details": details, "recommendation": recommendation}
            self.events.append(event)
            if len(self.events) > MAX_EVENTS:
                del self.events[: len(self.events) - MAX_EVENTS]
            try:
                with open(EVENT_STORE, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
            except OSError as exc:
                self.errors["event-store"] = f"cannot write {EVENT_STORE}: {exc}"
        return True

    def view(self) -> dict[str, Any]:
        with self.lock:
            return {
                "events": list(self.events), "latest_snapshot": self.latest_snapshot, "snapshot_live": self.snapshot_live,
                "proc_history": list(self.proc_history), "modules": dict(self.modules), "hardening": list(self.hardening),
                "health": dict(self.health), "sources": dict(self.sources), "file_state": dict(self.file_state),
                "dir_state": dict(self.dir_state), "errors": dict(self.errors), "fs_dropped": self.fs_dropped,
                "kernel_path": str(self.kernel_path) if self.kernel_path else None, "alive": self.thread.is_alive(),
            }

    # -- directory monitor (directory-monitoring.py) -----------------------
    def _start_watchers(self) -> None:
        if Observer is None:
            for p in WATCHED_DIRS:
                self.dir_state[p] = "watchdog not installed (pip install watchdog)"
            return
        self.observer = Observer()
        for path, label in WATCHED_DIRS.items():
            if not os.path.isdir(path):
                self.dir_state[path] = "directory missing"
                continue
            try:
                self.observer.schedule(DirHandler(self, label), path, recursive=True)
                self.dir_state[path] = "watching"
            except Exception as exc:
                self.dir_state[path] = f"cannot watch: {exc}"
        try:
            self.observer.daemon = True
            self.observer.start()
        except Exception as exc:
            self.errors["directory"] = f"observer failed: {exc}"

    def on_fs_event(self, label: str, event: Any) -> None:
        now = time.time()
        with self.lock:
            if now - self.fs_window > 60:
                self.fs_window, self.fs_count = now, 0
            self.fs_count += 1
            if self.fs_count > 200:  # flood protection (e.g. mass package upgrade)
                self.fs_dropped += 1
                return
        et, path = event.event_type, as_text(event.src_path)
        dest = as_text(getattr(event, "dest_path", ""))
        if label == "journal":
            if et == "modified":
                return  # journal files change constantly
            sev = "medium" if et == "deleted" else "info"
            rec = "Journal files are also rotated and vacuumed normally; if this was unexpected, run `journalctl --verify` and check who had root." if et == "deleted" else None
        else:
            persistence = label == "init.d" or path.endswith((".service", ".timer", ".socket", ".path", ".sh"))
            sev = "high" if persistence and et in {"created", "modified", "moved"} else "medium"
            rec = "Check the change matches a package update or admin action (`dpkg -S <path>` / `rpm -qf <path>`, `systemctl cat <unit>`). Startup scripts and units are a common persistence location."
        msg = f"{label}: {et} {path}" + (f" -> {dest}" if dest else "")
        self.emit("directory-monitoring", "fim.directory", sev, msg, f"{et}|{path}|{dest}|{int(time.time() // 5)}",
                  details={"directory": label, "event": et, "path": path, "destination": dest or None, "is_directory": event.is_directory},
                  recommendation=rec)

    # -- process monitor (all-processes_monitoring.py) ---------------------
    def job_processes(self) -> None:
        snap = last_snapshot(PROCESS_LOG) if PROCESS_LOG.is_file() else None
        age = age_seconds(snap.get("timestamp")) if snap else None
        live = False
        if snap is None or age is None or age > 30:
            snap, live = live_snapshot(), True
        self.sources["process"] = "live psutil fallback (process_log.jsonl missing or stale)" if live else f"process_log.jsonl ({friendly_age(age)})"
        ts = str(snap.get("timestamp"))
        if ts == self.last_snapshot_ts:
            return
        self.last_snapshot_ts = ts
        procs = snap.get("processes") or []
        with self.lock:
            self.latest_snapshot, self.snapshot_live = snap, live
            self.proc_history.append({"time": datetime.now(timezone.utc), "processes": len(procs),
                                      "cpu_total": round(sum(float(p.get("cpu_percent") or 0) for p in procs), 1)})
        hot_now = set()
        for p in procs:
            pid, name, exe = p.get("pid"), str(p.get("name") or "unknown"), str(p.get("exe") or "")
            cmd = " ".join(map(str, p.get("cmdline") or []))[:300]
            flags = proc_flags(p)
            if flags:
                sev = "high" if any(f.startswith(("runs", "executable")) for f in flags) else "medium"
                self.emit("all-processes-monitoring", "process.suspicious", sev,
                          f"Process {name} (pid {pid}): {', '.join(flags)}", f"{pid}|{name}|{exe}",
                          details={"pid": pid, "name": name, "exe": exe, "cmdline": cmd, "flags": flags},
                          recommendation="Inspect the binary (`ls -l /proc/<pid>/exe`, `sha256sum`), its parent and network connections before deciding whether to stop it.")
            if float(p.get("cpu_percent") or 0) >= 85 and isinstance(pid, int):
                hot_now.add(pid)
                self.hot_cpu[pid] = self.hot_cpu.get(pid, 0) + 1
                if self.hot_cpu[pid] == 3:
                    self.emit("all-processes-monitoring", "process.high_cpu", "medium",
                              f"Sustained high CPU: {name} (pid {pid}) above 85% for 3 snapshots", f"{pid}|{name}|{exe}",
                              details={"pid": pid, "name": name, "exe": exe, "cpu_percent": p.get("cpu_percent"), "cmdline": cmd},
                              recommendation="Could be a legitimate workload; unexpected sustained CPU use is also typical of cryptominers and runaway processes.")
        for pid in list(self.hot_cpu):
            if pid not in hot_now:
                del self.hot_cpu[pid]
        self.sources["process"] += f"; {len(procs)} processes"

    # -- audit.log (privilege_escalation-detector.py, all-processes_monitoring.py)
    def job_audit(self) -> None:
        status = path_status(AUDIT_LOG)
        self.sources["audit"] = {"ok": "audit.log readable", "missing": "audit.log not found (is auditd installed/running?)",
                                 "denied": "audit.log not readable (run the dashboard with sudo)"}.get(status, status)
        if status != "ok":
            return
        lines, self.audit_pos = read_increment(AUDIT_LOG, self.audit_pos, initial_tail=200)
        for line in lines:
            rec = parse_audit(line)
            verdict = classify_audit(rec, line) if rec else None
            if not verdict:
                continue
            serial = rec.get("_serial")
            key = f"{serial}|{rec.get('_ts', '')}" if serial else line
            ts = epoch_iso(float(rec["_ts"])) if rec.get("_ts") else None
            details = {k: rec[k] for k in ("type", "auid", "uid", "euid", "exe", "comm", "cmd", "a0", "a1", "a2", "tty", "res", "acct", "addr", "hostname") if k in rec}
            details["raw"] = line[:300]
            self.emit(verdict["source"], verdict["category"], verdict["severity"], verdict["message"], key,
                      details=details, recommendation=verdict.get("recommendation"), timestamp=ts)

    # -- config files (privilege_escalation-detector.py) -------------------
    def _load_config_baseline(self) -> dict[str, Any]:
        try:
            data = json.loads(DASH_BASELINE.read_text())
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
        seeded: dict[str, Any] = {}  # start from the monitor's own baseline when it exists
        try:
            mon = json.loads(MONITOR_BASELINE.read_text())
            for key, path in (("sudoers", "/etc/sudoers"), ("bashrc", "~/.bashrc"), ("profile", "~/.profile")):
                if isinstance(mon.get(key), list):
                    seeded[os.path.expanduser(path)] = {"lines": [str(x).rstrip("\n") for x in mon[key]]}
        except (OSError, ValueError, AttributeError):
            pass
        return seeded

    def _save_config_baseline(self) -> None:
        try:
            DASH_BASELINE.write_text(json.dumps(self.config_baseline, indent=2))
        except OSError as exc:
            self.errors["config-baseline"] = f"cannot write {DASH_BASELINE}: {exc}"

    def job_config(self) -> None:
        src, dirty, readable = "privilege-escalation-detector", False, 0
        for raw in WATCHED_FILES:
            path = os.path.expanduser(raw)
            lines, status = read_text_lines(path)
            old = self.config_baseline.get(path)
            self.file_state[path] = {"status": status, "checked": now_iso(), "baseline_lines": len(old["lines"]) if old and old.get("lines") is not None else None}
            if lines is None:
                if status == "missing" and old and old.get("lines") is not None:
                    self.emit(src, "fim.config", "high", f"Watched file removed: {path}", f"removed|{path}|{make_id(*old['lines'])}",
                              details={"file": path}, recommendation="Confirm the file was removed intentionally.")
                    self.config_baseline[path] = {"lines": None}
                    dirty = True
                continue
            readable += 1
            if old is None or old.get("lines") is None:
                self.config_baseline[path] = {"lines": lines}
                dirty = True
                if old is not None:  # reappeared after removal
                    self.emit(src, "fim.config", "medium", f"Watched file re-created: {path}", f"created|{path}|{make_id(*lines)}", details={"file": path})
                continue
            if old["lines"] == lines:
                continue
            diff = list(difflib.unified_diff(old["lines"], lines, "baseline", "current", lineterm="", n=0))
            added = [l[1:] for l in diff if l.startswith("+") and not l.startswith("+++")]
            removed = [l[1:] for l in diff if l.startswith("-") and not l.startswith("---")]
            bad = [l for l in added if not l.lstrip().startswith("#") and any(t in l for t in ("NOPASSWD", "!authenticate", "PATH="))]
            if any(("NOPASSWD" in l or "!authenticate" in l) for l in bad):
                sev, why = "critical", "adds passwordless sudo (NOPASSWD / !authenticate)"
            elif bad:
                sev, why = "high", "adds a PATH= assignment (command hijack risk)"
            elif path.endswith(("sudoers", "passwd", "sshd_config", "authorized_keys")):
                sev, why = "high", "security-critical file changed"
            else:
                sev, why = "medium", "shell startup file changed"
            self.emit(src, "fim.config", sev, f"{path} modified (+{len(added)} / -{len(removed)} lines): {why}", f"{path}|{make_id(*lines)}",
                      details={"file": path, "added": added[:30], "removed": removed[:30], "suspicious_lines": bad[:10], "diff": "\n".join(diff)[:4000]},
                      recommendation="Compare against the previous content and confirm who made the change (check `last`, auditd records and the file's mtime).")
            self.config_baseline[path] = {"lines": lines}
            dirty = True
        if dirty:
            self._save_config_baseline()
        self.sources["privilege"] = f"{readable}/{len(WATCHED_FILES)} watched files readable; {self.sources.get('audit', 'audit.log unknown')}"

    # -- kernel log (kernel-monitoring.py) ---------------------------------
    def _ingest_kernel_line(self, line: str, header_ts: str | None) -> None:
        text = line.strip()
        if not text or text.startswith("-- ") or text == "---":
            return
        low = text.lower()
        sev = "high" if any(t in low for t in KERNEL_HIGH_TERMS) else "medium"
        ts = None
        if header_ts:
            try:
                ts = datetime.strptime(header_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat(timespec="seconds")
            except ValueError:
                pass
        self.emit("kernel-monitoring", "kernel.log", sev, text, text, details=text,
                  recommendation="Kernel errors can be hardware faults, driver bugs or exploitation side effects; check surrounding journal entries (`journalctl -k -b`).",
                  timestamp=ts)

    def job_kernel(self) -> None:
        path = next((p for p in KERNEL_LOG_CANDIDATES if p.is_file()), KERNEL_LOG_CANDIDATES[0])
        self.kernel_path = path
        header = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - Kernel errors detected on .+:$")
        status = path_status(path)
        if status == "ok":
            lines, self.kernel_pos = read_increment(path, self.kernel_pos, initial_tail=400)
            for line in lines:
                m = header.match(line.strip())
                if m:
                    self.kernel_ts = m.group(1)
                else:
                    self._ingest_kernel_line(line, self.kernel_ts)
            self.sources["kernel"] = f"{path.name} (written by kernel-monitoring.py)"
        monitor_running = bool(self.health.get("running", {}).get("kernel-monitoring.py"))
        if not monitor_running:  # script not running: read the journal directly, same query as the script
            try:
                out = subprocess.run(["journalctl", "-k", "--since", "3 minutes ago", "--priority=0..3", "--no-pager"],
                                     capture_output=True, text=True, timeout=20, check=False).stdout
                for line in out.splitlines():
                    self._ingest_kernel_line(line, None)
                self.sources["kernel"] = "journalctl -k (kernel-monitoring.py not running)"
            except (OSError, subprocess.SubprocessError) as exc:
                self.sources["kernel"] = f"journalctl unavailable: {exc}"
        elif status != "ok":
            self.sources["kernel"] = f"kernel-monitor.log {status}"

    # -- kernel modules (kernel_modules_monitor.py) ------------------------
    def job_modules(self) -> None:
        mods: dict[str, dict[str, Any]] = {}
        try:
            with open("/proc/modules") as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 4:
                        mods[p[0]] = {"size_bytes": int(p[1]), "refcount": p[2], "used_by": p[3].strip(","), "state": p[4] if len(p) > 4 else ""}
        except OSError as exc:
            self.sources["modules"] = f"/proc/modules unreadable: {exc}"
            return
        self.sources["modules"] = f"/proc/modules ({len(mods)} loaded)"
        with self.lock:
            self.modules = mods
        if self.known_modules is None:
            self.known_modules = set(mods)  # baseline, like the original monitor
            return
        for name in sorted(set(mods) - self.known_modules):
            self.emit("kernel-modules-monitor", "kernel.module", "high", f"New kernel module loaded: {name}", f"load|{name}|{time.time()}",
                      details={"module": name, **mods[name]},
                      recommendation="Verify with `modinfo " + name + "`; rootkits are commonly delivered as kernel modules. Expected after hardware or VPN/container changes.")
        for name in sorted(self.known_modules - set(mods)):
            self.emit("kernel-modules-monitor", "kernel.module", "medium", f"Kernel module removed: {name}", f"unload|{name}|{time.time()}",
                      details={"module": name}, recommendation="Unloading is normal for unused drivers; unexpected removal of security modules is not.")
        self.known_modules = set(mods)

    # -- hardening (hardening_recommender.py) ------------------------------
    def job_hardening(self) -> None:
        results = []
        for key, good, name, benefit, tradeoff in HARDENING_CHECKS:
            try:
                current = subprocess.check_output(["sysctl", "-n", key], text=True, stderr=subprocess.DEVNULL, timeout=5).strip()
            except (OSError, subprocess.SubprocessError):
                current = None
            status = "unavailable" if current is None else ("ok" if current == good else "finding")
            results.append({"name": name, "key": key, "current": current, "recommended": good, "status": status, "benefit": benefit,
                            "tradeoff": tradeoff, "fix": [f"sudo sysctl -w {key}={good}", f"echo '{key} = {good}' | sudo tee -a /etc/sysctl.d/99-hardening.conf", "sudo sysctl --system"]})
        with self.lock:
            self.hardening = results
        self.sources["hardening"] = f"{sum(r['status'] != 'unavailable' for r in results)}/{len(results)} sysctl keys readable"

    # -- monitor health ----------------------------------------------------
    def job_health(self) -> None:
        scripts = {m[0] for m in MONITORS} | {"main.py"}
        running: dict[str, int | None] = {s: None for s in scripts}
        for p in psutil.process_iter(attrs=["pid", "cmdline"]):
            for arg in p.info.get("cmdline") or []:
                base = os.path.basename(arg)
                if base in running and running[base] is None and p.info["pid"] != os.getpid():
                    running[base] = p.info["pid"]
        fresh = {}
        for label, path in (("process_log.jsonl", PROCESS_LOG), ("kernel-monitor.log", self.kernel_path or KERNEL_LOG_CANDIDATES[0]),
                            ("baseline.json", MONITOR_BASELINE), ("audit.log", AUDIT_LOG)):
            try:
                fresh[label] = time.time() - path.stat().st_mtime
            except OSError:
                fresh[label] = None
        directory_ok = sum(1 for v in self.dir_state.values() if v == "watching")
        self.sources["directory"] = f"watchdog: {directory_ok}/{len(WATCHED_DIRS)} directories watched" + (f"; {self.fs_dropped} events dropped (flood limit)" if self.fs_dropped else "")
        with self.lock:
            self.health = {"running": running, "freshness": fresh}


@st.cache_resource(show_spinner="Starting KernelSense collectors…")
def get_collector() -> Collector:
    return Collector()


# --------------------------------------------------------------------------- #
# UI helpers
# --------------------------------------------------------------------------- #
def norm_severity(value: Any) -> str:
    s = str(value or "info").lower()
    return {"error": "critical", "warning": "medium"}.get(s, s if s in SEVERITY_ORDER else "info")


def format_details(details: Any) -> str:
    if details is None:
        return "No additional details recorded."
    return details if isinstance(details, str) else json.dumps(details, indent=2, ensure_ascii=False, default=str)


def event_frame(events: list[dict[str, Any]]) -> pd.DataFrame:
    rows = [{"timestamp": e.get("timestamp", ""), "severity": norm_severity(e.get("severity")), "source": e.get("source", "unknown"),
             "category": e.get("category", "general"), "message": e.get("message", ""), "event_id": e.get("event_id", ""),
             "details": format_details(e.get("details"))} for e in events]
    return pd.DataFrame(rows, columns=["timestamp", "severity", "source", "category", "message", "event_id", "details"])


def csv_bytes(frame: pd.DataFrame) -> bytes:
    return frame.to_csv(index=False).encode("utf-8-sig")


def load_ack() -> set[str]:
    try:
        return set(json.loads(ACK_FILE.read_text()))
    except (OSError, ValueError, TypeError):
        return set()


def save_ack(ids: set[str]) -> None:
    try:
        ACK_FILE.write_text(json.dumps(sorted(ids)))
    except OSError as exc:
        st.warning(f"Could not save acknowledgements to {ACK_FILE}: {exc}")


def within(events: list[dict[str, Any]], hours: int | None) -> list[dict[str, Any]]:
    if hours is None:
        return events
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    return [e for e in events if (parse_ts(e.get("timestamp")) or cutoff) >= cutoff]


def host_metrics() -> dict[str, Any]:
    try:
        mem, disk = psutil.virtual_memory(), psutil.disk_usage(str(Path.home().anchor or "/"))
        return {"cpu": float(psutil.cpu_percent(interval=0.1)), "memory": float(mem.percent), "mem_used": mem.used / 1024 ** 3,
                "mem_total": mem.total / 1024 ** 3, "disk": float(disk.percent), "disk_used": disk.used / 1024 ** 3,
                "disk_total": disk.total / 1024 ** 3, "uptime": datetime.now(timezone.utc) - datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)}
    except Exception as exc:
        return {"error": str(exc)}


def render_events(events: list[dict[str, Any]], prefix: str, acked: set[str], max_cards: int = 40) -> None:
    if not events:
        st.info("No matching events yet.")
        return
    for i, ev in enumerate(events[:max_cards]):
        eid, sev = str(ev.get("event_id", i)), norm_severity(ev.get("severity"))
        is_acked = eid in acked
        age = friendly_age(age_seconds(ev.get("timestamp")))
        title = f"{SEV_EMOJI[sev]} {sev.upper()} · {str(ev.get('message', 'Finding'))[:140]} — {age}" + (" · ACKNOWLEDGED" if is_acked else "")
        with st.expander(title, expanded=(sev in {"critical", "high"} and not is_acked and i < 3)):
            st.write(f"**Source:** `{ev.get('source', 'unknown')}`  |  **Category:** `{ev.get('category', 'general')}`  |  **Time:** {ev.get('timestamp', 'unavailable')}")
            details = ev.get("details")
            st.code(format_details(details), language="json" if isinstance(details, (dict, list)) else None)
            if ev.get("recommendation"):
                st.markdown("**Suggested next step**")
                st.write(ev["recommendation"])
            if st.button("Unacknowledge" if is_acked else "Acknowledge", key=f"{prefix}-ack-{eid}-{i}"):
                (acked.discard if is_acked else acked.add)(eid)
                save_ack(acked)
                st.rerun()
    if len(events) > max_cards:
        st.caption(f"Showing the newest {max_cards} of {len(events)} events. Use the Logs tab for the full table and exports.")


def severity_timeline(events: list[dict[str, Any]], hours: int) -> pd.DataFrame | None:
    rows = []
    for e in within(events, hours):
        dt = parse_ts(e.get("timestamp"))
        if dt:
            rows.append({"time": dt, "severity": norm_severity(e.get("severity"))})
    if not rows:
        return None
    df = pd.DataFrame(rows)
    df["time"] = df["time"].dt.tz_convert(datetime.now().astimezone().tzinfo).dt.tz_localize(None)
    freq = {1: "1min", 6: "5min", 24: "30min", 168: "3h"}[hours]
    grouped = df.groupby([pd.Grouper(key="time", freq=freq), "severity"]).size().unstack(fill_value=0)
    return grouped[[s for s in SEVERITY_ORDER if s in grouped.columns]]


# --------------------------------------------------------------------------- #
# Page
# --------------------------------------------------------------------------- #
st.set_page_config(page_title="KernelSense | HIDS", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
  .block-container { padding-top: 1.4rem; padding-bottom: 2rem; max-width: 1600px; }
  [data-testid="stMetric"] { background: var(--secondary-background-color); border: 1px solid rgba(128,128,128,.22); padding: 14px 16px; border-radius: 12px; }
  .ks-eyebrow { color: #7F8EA3; font-size: .78rem; letter-spacing: .14em; font-weight: 700; text-transform: uppercase; }
  .ks-subtitle { color: #7F8EA3; margin-top: -.3rem; }
  div[data-testid="stTabs"] button { font-weight: 600; }
</style>
""", unsafe_allow_html=True)

collector = get_collector()
view = collector.view()
acked = load_ack()
all_events = sorted((e for e in view["events"] if e.get("category") not in HIDDEN_CATEGORIES),
                    key=lambda e: str(e.get("timestamp", "")), reverse=True)

with st.sidebar:
    st.markdown("<div class='ks-eyebrow'>KernelSense</div>", unsafe_allow_html=True)
    st.title("Host IDS")
    auto_refresh = st.toggle("Auto-refresh", value=True)
    refresh_seconds = st.select_slider("Refresh interval", options=[5, 10, 15, 30, 60], value=10, format_func=lambda x: f"{x} seconds")
    if auto_refresh and st_autorefresh is not None:
        st_autorefresh(interval=refresh_seconds * 1000, key="kernelsense_auto_refresh")
    elif auto_refresh:
        st.caption("Install streamlit-autorefresh to enable automatic refresh.")
    st.divider()
    st.markdown("**Host**")
    st.write(f"`{socket.gethostname()}`")
    st.caption(f"{platform.system()} {platform.release()}")
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    st.caption("Running as root" if is_root else "Not running as root")
    st.caption(f"Collector thread: {'running' if view['alive'] else 'stopped'}")
    st.caption(f"Updated at {datetime.now().astimezone().strftime('%H:%M:%S %Z')}")
    with st.expander("Files read and written"):
        for label, p in [("Process snapshots", PROCESS_LOG), ("Kernel log", Path(view["kernel_path"] or KERNEL_LOG_CANDIDATES[0])),
                         ("Monitor baseline", MONITOR_BASELINE), ("Audit log", AUDIT_LOG), ("Event store (written)", EVENT_STORE)]:
            st.caption(f"{label}: `{p}` {'✓' if p.exists() else '✗'}")

st.markdown("<div class='ks-eyebrow'>Linux host intrusion detection</div>", unsafe_allow_html=True)
st.title("KernelSense Security Dashboard")
st.markdown("<div class='ks-subtitle'>Processes, file integrity, privilege activity, kernel messages and hardening in one place.</div>", unsafe_allow_html=True)

last24 = within(all_events, 24)
open_crit = [e for e in last24 if norm_severity(e.get("severity")) == "critical" and e.get("event_id") not in acked]
open_high = [e for e in last24 if norm_severity(e.get("severity")) == "high" and e.get("event_id") not in acked]
if open_crit:
    st.error(f"{len(open_crit)} unacknowledged critical alert(s) in the last 24 hours. Review the Alerts tab.")
elif open_high:
    st.warning(f"{len(open_high)} unacknowledged high-severity alert(s) in the last 24 hours.")
else:
    st.success("No unacknowledged critical or high alerts in the last 24 hours. This reflects what the collectors saw, not proof the host is clean.")
if not is_root:
    st.warning("The dashboard is not running as root, so audit.log, /etc/sudoers and parts of the journal directory may be unreadable. Start it with `sudo streamlit run dashboard.py`.")
for name, err in view["errors"].items():
    st.warning(f"Collector `{name}` reported: {err}")

running = view["health"].get("running", {})
monitors_running = sum(1 for m in MONITORS if running.get(m[0]))
gaps = sum(1 for r in view["hardening"] if r["status"] == "finding")
c = st.columns(6)
c[0].metric("Critical (24h)", sum(1 for e in last24 if norm_severity(e.get("severity")) == "critical"))
c[1].metric("High (24h)", sum(1 for e in last24 if norm_severity(e.get("severity")) == "high"))
c[2].metric("Medium (24h)", sum(1 for e in last24 if norm_severity(e.get("severity")) == "medium"))
c[3].metric("Events stored", len(all_events))
c[4].metric("Monitor scripts running", f"{monitors_running}/{len(MONITORS)}", help="Detected from the process list. The dashboard collects the same data itself, so findings still appear if a script is stopped.")
c[5].metric("Hardening gaps", gaps)

(tab_overview, tab_alerts, tab_processes, tab_files, tab_priv, tab_kernel, tab_hard, tab_logs, tab_health, tab_about) = st.tabs(
    ["Overview", "Alerts", "Processes", "Files & directories", "Privilege & audit", "Kernel", "Hardening", "Logs & exports", "Monitor health", "About & safety"])

# ---- Overview ------------------------------------------------------------
with tab_overview:
    left, right = st.columns([1.4, 1])
    with left:
        st.subheader("Alert activity")
        window = st.radio("Range", [1, 6, 24, 168], index=2, horizontal=True, format_func=lambda h: {1: "1 hour", 6: "6 hours", 24: "24 hours", 168: "7 days"}[h])
        timeline = severity_timeline(all_events, window)
        if timeline is None:
            st.info("No events in this range.")
        else:
            st.bar_chart(timeline, color=[SEV_COLOR[s] for s in timeline.columns])
        st.subheader("Recent alerts")
        recent = [e for e in all_events if norm_severity(e.get("severity")) != "info"][:6] or all_events[:6]
        render_events(recent, "ov", acked, max_cards=6)
    with right:
        st.subheader("Events by source (24h)")
        by_source = pd.Series([str(e.get("source", "unknown")) for e in last24]).value_counts() if last24 else None
        if by_source is None:
            st.caption("Nothing recorded in the last 24 hours.")
        else:
            st.bar_chart(by_source)
        st.subheader("Host resources")
        m = host_metrics()
        if "error" in m:
            st.warning(f"Could not collect host metrics: {m['error']}")
        else:
            a, b, d = st.columns(3)
            a.metric("CPU", f"{m['cpu']:.0f}%")
            b.metric("Memory", f"{m['memory']:.0f}%", f"{m['mem_used']:.1f}/{m['mem_total']:.1f} GB", delta_color="off")
            d.metric("Disk", f"{m['disk']:.0f}%", f"{m['disk_used']:.0f}/{m['disk_total']:.0f} GB", delta_color="off")
            st.caption(f"Uptime: {m['uptime'].days} days, {m['uptime'].seconds // 3600} hours")
        st.subheader("Coverage")
        for script, label, source, key, _ in MONITORS:
            pid = running.get(script)
            st.caption(f"**{label}** · script {'running (pid ' + str(pid) + ')' if pid else 'not running'} · dashboard: {view['sources'].get(key, 'starting…')}")

# ---- Alerts --------------------------------------------------------------
with tab_alerts:
    st.subheader("Alert center")
    st.caption("Findings are indicators to investigate, not proof of compromise. Acknowledging an alert only changes its state in this dashboard.")
    f1, f2, f3, f4 = st.columns([1.2, 1.2, 1, 1.4])
    sev_sel = f1.multiselect("Severity", SEVERITY_ORDER, default=["critical", "high", "medium", "low"])
    src_opts = sorted({str(e.get("source", "unknown")) for e in all_events})
    src_sel = f2.multiselect("Monitor source", src_opts, default=src_opts)
    win_label = f3.selectbox("Time range", ["Last hour", "Last 6 hours", "Last 24 hours", "Last 7 days", "All time"], index=2)
    query = f4.text_input("Search", placeholder="Message, path, PID, audit text…")
    show_acked = st.toggle("Show acknowledged", value=True)
    hours = {"Last hour": 1, "Last 6 hours": 6, "Last 24 hours": 24, "Last 7 days": 168, "All time": None}[win_label]
    shown = []
    for e in within(all_events, hours):
        if norm_severity(e.get("severity")) not in sev_sel or str(e.get("source", "unknown")) not in src_sel:
            continue
        if not show_acked and e.get("event_id") in acked:
            continue
        hay = " ".join([str(e.get("message", "")), str(e.get("source", "")), str(e.get("category", "")), format_details(e.get("details"))]).lower()
        if query and query.lower() not in hay:
            continue
        shown.append(e)
    st.caption(f"Showing {len(shown)} of {len(all_events)} stored events.")
    if shown:
        st.download_button("Export filtered alerts as CSV", csv_bytes(event_frame(shown)), file_name="kernelsense-alerts.csv", mime="text/csv")
    render_events(shown, "al", acked, max_cards=int(st.number_input("Alert cards to show", 10, 500, 50, step=10)))

# ---- Processes -----------------------------------------------------------
with tab_processes:
    st.subheader("Process snapshot")
    snap, procs = view["latest_snapshot"], (view["latest_snapshot"] or {}).get("processes") or []
    if not snap:
        st.info("No process snapshot yet; the collector is still starting.")
    else:
        if view["snapshot_live"]:
            st.warning("process_log.jsonl is missing or older than 30 seconds, so this is a live psutil snapshot. Start all-processes_monitoring.py (or `sudo python3 main.py`) to keep logging.")
        flagged = [p for p in procs if proc_flags(p)]
        p1, p2, p3 = st.columns(3)
        p1.metric("Processes", len(procs))
        p2.metric("Flagged processes", len(flagged), help="Deleted executable, running from /tmp, /dev/shm or /var/tmp, or a network/recon tool.")
        p3.metric("Snapshot", friendly_age(age_seconds(snap.get("timestamp"))))
        hist = view["proc_history"]
        if len(hist) > 2:
            hf = pd.DataFrame(hist).set_index("time")
            hf.index = hf.index.tz_convert(datetime.now().astimezone().tzinfo).tz_localize(None)
            h1, h2 = st.columns(2)
            h1.caption("Process count")
            h1.line_chart(hf["processes"])
            h2.caption("Total CPU % across processes")
            h2.line_chart(hf["cpu_total"])
        search = st.text_input("Search processes", placeholder="Name, PID, executable path…")
        show_cmd = st.checkbox("Reveal command-line arguments", value=False, help="Command lines can contain tokens or other sensitive values.")
        only_flagged = st.checkbox("Only flagged processes", value=False)
        rows = []
        for p in procs:
            flags = proc_flags(p)
            if only_flagged and not flags:
                continue
            row = {"PID": p.get("pid"), "Process": p.get("name") or "unknown", "CPU %": round(float(p.get("cpu_percent") or 0), 2),
                   "Memory %": round(float(p.get("memory_percent") or 0), 3), "Executable": p.get("exe") or "", "Flags": ", ".join(flags)}
            if show_cmd:
                row["Command line"] = " ".join(map(str, p.get("cmdline") or []))
            rows.append(row)
        pf = pd.DataFrame(rows)
        if pf.empty:
            st.info("No process records match.")
        else:
            if search:
                pf = pf[pf.astype(str).apply(lambda col: col.str.contains(search, case=False, na=False, regex=False)).any(axis=1)]
            sort_col = st.selectbox("Sort by", ["CPU %", "Memory %", "Process", "PID"], index=0)
            pf = pf.sort_values(sort_col, ascending=sort_col in {"Process", "PID"}, kind="stable")
            st.dataframe(pf, hide_index=True, height=480)
            st.download_button("Export visible process table as CSV", csv_bytes(pf), file_name="kernelsense-processes.csv", mime="text/csv")
    st.subheader("Process findings")
    render_events([e for e in all_events if str(e.get("category", "")).startswith(("process.", "audit.process_utility"))], "pr", acked, 15)

# ---- Files & directories -------------------------------------------------
with tab_files:
    st.subheader("File and directory integrity")
    d1, d2 = st.columns(2)
    with d1:
        st.markdown("**Watched directories** (inotify via watchdog)")
        st.dataframe(pd.DataFrame([{"Directory": p, "State": s} for p, s in view["dir_state"].items()]), hide_index=True)
    with d2:
        st.markdown("**Watched files** (diffed against a stored baseline)")
        st.dataframe(pd.DataFrame([{"File": p, "Status": s["status"], "Baseline lines": s["baseline_lines"], "Last checked": s["checked"]} for p, s in view["file_state"].items()]), hide_index=True)
    st.caption(f"Add or remove watched files in `WATCHED_FILES` at the top of dashboard.py. The baseline lives in `{DASH_BASELINE.name}`; delete it to re-baseline.")
    render_events([e for e in all_events if str(e.get("category", "")).startswith("fim.")], "fim", acked, 40)

# ---- Privilege & audit ---------------------------------------------------
with tab_priv:
    st.subheader("Privilege escalation and audit activity")
    st.caption(f"auditd: {view['sources'].get('audit', 'checking…')}")
    audit_events = [e for e in all_events if str(e.get("category", "")).startswith("audit.")]
    if audit_events:
        counts = pd.Series([e["category"] for e in audit_events]).value_counts()
        st.bar_chart(counts)
    with st.expander("Which auditd records appear here?"):
        st.markdown("auditd writes failed logins and account changes by default. `execve`, `chmod`, module and kernel-memory records appear only if you add audit rules, for example:")
        st.code("sudo auditctl -a always,exit -F arch=b64 -S execve -k kernelsense_exec\n"
                "sudo auditctl -a always,exit -F arch=b64 -S chmod,fchmodat -k kernelsense_chmod\n"
                "sudo auditctl -w /sbin/insmod -p x -k kernelsense_modules", language="bash")
    render_events(audit_events, "au", acked, 40)

# ---- Kernel --------------------------------------------------------------
with tab_kernel:
    st.subheader("Kernel activity")
    try:
        tainted = int(Path("/proc/sys/kernel/tainted").read_text().strip())
    except (OSError, ValueError):
        tainted = None
    k1, k2, k3 = st.columns(3)
    k1.metric("Loaded modules", len(view["modules"]))
    k2.metric("Kernel taint flags", "unknown" if tainted is None else tainted, help="0 means untainted. A non-zero value can come from proprietary, out-of-tree or force-loaded modules; see Documentation/admin-guide/tainted-kernels.")
    k3.metric("Kernel source", "journal/log" if view["sources"].get("kernel") else "pending")
    st.caption(f"Kernel log: {view['sources'].get('kernel', 'checking…')}")
    mod_search = st.text_input("Search loaded modules", key="modsearch")
    mf = pd.DataFrame([{"Module": n, **v} for n, v in view["modules"].items()])
    if not mf.empty:
        if mod_search:
            mf = mf[mf["Module"].str.contains(mod_search, case=False, regex=False)]
        st.dataframe(mf.sort_values("Module"), hide_index=True, height=300)
    render_events([e for e in all_events if str(e.get("category", "")).startswith("kernel.") or e.get("category") in {"audit.module_tool", "audit.kernel_access"}], "kn", acked, 40)

# ---- Hardening -----------------------------------------------------------
with tab_hard:
    st.subheader("Hardening recommendations")
    results = view["hardening"]
    if not results:
        st.info("Checks have not run yet.")
    else:
        checked = [r for r in results if r["status"] != "unavailable"]
        st.progress(int(100 * sum(r["status"] == "ok" for r in checked) / max(1, len(checked))), text=f"{sum(r['status'] == 'ok' for r in checked)} of {len(checked)} checks pass")
        st.dataframe(pd.DataFrame([{"Check": r["name"], "Key": r["key"], "Current": r["current"], "Recommended": r["recommended"], "Status": r["status"]} for r in results]), hide_index=True)
        findings = [r for r in results if r["status"] == "finding"]
        for r in findings:
            with st.expander(f"🟡 {r['name']}: currently {r['current']}, recommended {r['recommended']}"):
                st.write(f"**Benefit:** {r['benefit']}  \n**Trade-off:** {r['tradeoff']}")
                st.code("\n".join(r["fix"]), language="bash")
        if findings:
            script = "#!/bin/sh\n# Generated by KernelSense. Review every line before running as root.\n" + "".join(
                f"# {r['name']}: {r['benefit']}. Trade-off: {r['tradeoff']}\nsysctl -w {r['key']}={r['recommended']}\n"
                f"echo '{r['key']} = {r['recommended']}' >> /etc/sysctl.d/99-hardening.conf\n" for r in findings) + "sysctl --system\n"
            st.download_button("Download fix script (not executed by the dashboard)", script.encode(), file_name="kernelsense-hardening.sh", mime="text/x-shellscript")
        st.caption("Checks re-run every 5 minutes. Nothing here is applied automatically.")

# ---- Logs ----------------------------------------------------------------
with tab_logs:
    st.subheader("Event log and raw files")
    l1, l2 = st.columns([1, 1])
    log_query = l1.text_input("Search events", key="logq", placeholder="Message, source, details…")
    log_sources = l2.multiselect("Sources", src_opts, default=src_opts, key="logsrc")
    log_rows = [e for e in all_events if str(e.get("source", "unknown")) in log_sources and
                (not log_query or log_query.lower() in " ".join([str(e.get("message", "")), str(e.get("category", "")), format_details(e.get("details"))]).lower())]
    lf = event_frame(log_rows)
    st.caption(f"{len(lf)} matching events (table shows the newest 500).")
    if not lf.empty:
        st.dataframe(lf[["timestamp", "severity", "source", "category", "message"]].head(500), hide_index=True, height=420)
        st.download_button("Export as CSV", csv_bytes(lf), file_name="kernelsense-logs.csv", mime="text/csv")
        st.download_button("Export as JSONL", ("\n".join(json.dumps(r, ensure_ascii=False, default=str) for r in log_rows) + "\n").encode(), file_name="kernelsense-logs.jsonl", mime="application/x-ndjson")
    st.markdown("**Raw file viewer**")
    raw_files = {"kernel-monitor.log": Path(view["kernel_path"] or KERNEL_LOG_CANDIDATES[0]), "audit.log": AUDIT_LOG,
                 "security_events.jsonl": EVENT_STORE, "baseline.json": MONITOR_BASELINE}
    choice = st.selectbox("File", list(raw_files))
    n_lines = st.slider("Last N lines", 20, 500, 100, step=20)
    chosen = raw_files[choice]
    if path_status(chosen) == "ok":
        st.code("\n".join(tail_lines(chosen, n_lines, max_bytes=1_000_000)) or "(empty)", language=None)
    else:
        st.info(f"`{chosen}` is {path_status(chosen)}.")
    st.caption("Raw logs can contain usernames, paths and command arguments. Keep them private.")

# ---- Monitor health ------------------------------------------------------
with tab_health:
    st.subheader("Monitor health")
    last_by_source: dict[str, str] = {}
    for e in all_events:
        last_by_source.setdefault(str(e.get("source")), friendly_age(age_seconds(e.get("timestamp"))))
    rows = []
    for script, label, source, key, covers in MONITORS:
        pid = running.get(script)
        rows.append({"Monitor": label, "Script": script, "Script status": f"running (pid {pid})" if pid else "not running",
                     "Dashboard collector": view["sources"].get(key, "starting…"), "Last finding": last_by_source.get(source, "none yet"), "Covers": covers})
    st.dataframe(pd.DataFrame(rows), hide_index=True)
    st.caption(f"main.py: {'running' if running.get('main.py') else 'not running'}. It launches 4 of the 6 scripts; kernel_modules_monitor.py and hardening_recommender.py must be started separately (the dashboard covers both itself).")
    st.markdown("**Data sources**")
    fresh = view["health"].get("freshness", {})
    st.dataframe(pd.DataFrame([{"File": k, "Last modified": "not found" if v is None else friendly_age(v)} for k, v in fresh.items()]), hide_index=True)
    st.markdown("**Troubleshooting**")
    st.markdown("- *audit.log not readable*: run the dashboard with `sudo`, and make sure `auditd` is installed and running.\n"
                "- *Stale process_log.jsonl*: start `all-processes_monitoring.py` from the project directory. It appends every 3 seconds and never rotates, so rotate or truncate it periodically.\n"
                "- *Directories not watched*: install `watchdog`, run as root for /var/log/journal, and check `fs.inotify.max_user_watches`.\n"
                "- *kernel-monitor.log empty*: no kernel messages at priority 0-3 in the last 5 minutes is normal.")

# ---- About ---------------------------------------------------------------
with tab_about:
    st.subheader("What this dashboard covers")
    st.markdown("""
- **Processes:** latest snapshot from `process_log.jsonl` (live fallback), flags for deleted or temp-directory executables, recon tools and sustained high CPU.
- **File integrity:** changes under `/etc/init.d`, `/etc/systemd`, `/var/log/journal`, and diffs of sudoers, shell startup files, passwd, sshd_config and authorized_keys.
- **Privilege activity:** auditd records for sudo/su, setuid chmod, account changes, failed logins, module tools and kernel-memory access.
- **Kernel:** error-level kernel journal entries, module load/unload, taint flags.
- **Hardening:** sysctl checks with fix commands you run yourself.
- **Investigation:** severity, source, time and text filters, acknowledgement, CSV/JSONL export.

**Limits.** Alerts are leads, not verdicts: false positives happen, and missing events do not prove nothing happened. A host intruder with root can tamper with the logs and files this dashboard reads, so forward logs to a separate machine for anything important. The dashboard never changes system state.
""")
    st.caption("KernelSense · host monitoring prototype")
