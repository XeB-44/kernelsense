#!/usr/bin/env python3
"""Track selected privilege-related configuration changes and audit events."""
from __future__ import annotations

import difflib
import hashlib
import os
import pwd
import shutil
import time
from pathlib import Path

from event_logger import log_event

BASE_DIR = Path(__file__).resolve().parent

def get_invoking_home() -> Path:
    """When launched through sudo, inspect the invoking user's shell files."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


USER_HOME = get_invoking_home()
AUDIT_LOG = Path(os.environ.get("KERNELSENSE_AUDIT_LOG", "/var/log/audit/audit.log"))
CHECK_SECONDS = max(15, int(os.environ.get("KERNELSENSE_PRIVILEGE_POLL_SECONDS", "60")))
SHELL_FILES = ((USER_HOME / ".bashrc", "bashrc_old.txt"), (USER_HOME / ".profile", "profile_old.txt"))
AUDIT_PATTERNS = ("chmod", "execve", "sudo", "insmod", "rmmod", "modprobe", "/proc/kallsyms", "/dev/kmem")
_seen_audit: set[str] = set()
_logged_permission_errors: set[str] = set()


def baseline(path: Path, baseline_name: str) -> Path:
    target = BASE_DIR / baseline_name
    if path.exists() and not target.exists():
        try:
            shutil.copy2(path, target)
            log_event("info", "monitor.baseline_created", "Created initial configuration baseline",
                      source="privilege-escalation-detector", details={"path": str(path)})
        except Exception as exc:
            error_key = f"baseline:{path}"
            if error_key not in _logged_permission_errors:
                log_event("low", "monitor.baseline_error", "Could not create a configuration baseline",
                          source="privilege-escalation-detector", details={"path": str(path), "error": str(exc)[:300]})
                _logged_permission_errors.add(error_key)
    return target


def compare_file(path: Path, baseline_name: str, kind: str) -> None:
    old_path = baseline(path, baseline_name)
    if not path.exists() or not old_path.exists():
        return
    try:
        old_lines = old_path.read_text(encoding="utf-8", errors="replace").splitlines()
        new_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (PermissionError, OSError) as exc:
        error_key = f"read:{path}"
        if error_key not in _logged_permission_errors:
            log_event("low", "monitor.read_error", "Could not inspect a protected configuration file",
                      source="privilege-escalation-detector", details={"path": str(path), "error": str(exc)[:300]})
            _logged_permission_errors.add(error_key)
        return
    if old_lines == new_lines:
        return
    diff = list(difflib.unified_diff(old_lines, new_lines, fromfile=f"baseline:{path.name}", tofile=str(path), lineterm=""))
    added = [line[1:] for line in diff if line.startswith("+") and not line.startswith("+++")]
    removed = [line[1:] for line in diff if line.startswith("-") and not line.startswith("---")]
    joined = "\n".join(added + removed)
    sensitive = kind == "sudoers" and any(token in joined for token in ("NOPASSWD", "!authenticate", "PATH="))
    path_change = "PATH=" in joined
    severity = "high" if sensitive else ("medium" if path_change or kind == "sudoers" else "low")
    log_event(
        severity,
        "privilege.configuration_change",
        f"{kind.capitalize()} configuration changed",
        source="privilege-escalation-detector",
        details={"path": str(path), "added_lines": added[:20], "removed_lines": removed[:20]},
        recommendation="Verify the change against your own recent administrative actions. KernelSense reports the change but does not revert files.",
    )
    try:
        shutil.copy2(path, old_path)
    except OSError as exc:
        log_event("low", "monitor.baseline_error", "Could not update configuration baseline",
                  source="privilege-escalation-detector", details={"path": str(path), "error": str(exc)[:300]})


def read_tail(path: Path, max_bytes: int = 2_000_000) -> list[str]:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            raw = handle.read().decode("utf-8", "replace")
        lines = raw.splitlines()
        return lines[-500:]
    except (OSError, PermissionError):
        return []


def check_audit() -> None:
    if not AUDIT_LOG.exists() or not os.access(AUDIT_LOG, os.R_OK):
        return
    for line in read_tail(AUDIT_LOG):
        lower = line.lower()
        if not any(token in lower for token in AUDIT_PATTERNS):
            continue
        # Avoid treating every audit record that mentions a common command as malicious.
        is_kernel_access = "/proc/kallsyms" in lower or "/dev/kmem" in lower
        is_module_event = any(token in lower for token in ("insmod", "rmmod", "modprobe"))
        is_privileged_exec = "euid=0" in lower and ("execve" in lower or "sudo" in lower)
        is_suspicious_suid = "chmod" in lower and any(token in lower for token in ("4755", "4777", "u+s", "2xxx"))
        if not (is_kernel_access or is_module_event or is_privileged_exec or is_suspicious_suid):
            continue
        signature = hashlib.sha256(line.encode("utf-8", "replace")).hexdigest()
        if signature in _seen_audit:
            continue
        _seen_audit.add(signature)
        if len(_seen_audit) > 5000:
            _seen_audit.clear()
            _seen_audit.add(signature)
        severity = "high" if is_kernel_access or is_suspicious_suid else "medium"
        log_event(severity, "privilege.audit_activity", "Potentially relevant privileged audit activity detected",
                  source="privilege-escalation-detector", details={"audit_record": line[:800]},
                  recommendation="Inspect the full audit record and confirm the process, user, and action are expected. The indicator alone does not confirm exploitation.",
                  dedupe_key=f"audit:{signature}")


def main() -> None:
    sudoers = Path("/etc/sudoers")
    audit_exists = AUDIT_LOG.exists()
    audit_readable = audit_exists and os.access(AUDIT_LOG, os.R_OK)
    log_event("info", "monitor.started", "Privilege and configuration monitoring started",
              source="privilege-escalation-detector", details={"audit_log_exists": audit_exists, "audit_log_readable": audit_readable})
    if not audit_exists or not audit_readable:
        reason = "not found" if not audit_exists else "not readable by this process"
        log_event("low", "monitor.audit_unavailable", "Linux audit log is unavailable to this monitor; audit-based checks are disabled",
                  source="privilege-escalation-detector", details={"path": str(AUDIT_LOG), "reason": reason},
                  recommendation="Check auditd configuration and local permissions. Configuration-file checks may still work when permissions allow.")
    last_heartbeat = 0.0
    while True:
        compare_file(sudoers, "sudoers_old.txt", "sudoers")
        for path, name in SHELL_FILES:
            compare_file(path, name, "shell startup")
        check_audit()
        now = time.monotonic()
        if now - last_heartbeat >= 60:
            log_event("info", "monitor.heartbeat", "Privilege/configuration monitor is running",
                      source="privilege-escalation-detector", details={"audit_log_exists": AUDIT_LOG.exists(), "audit_log_readable": os.access(AUDIT_LOG, os.R_OK)})
            last_heartbeat = now
        time.sleep(CHECK_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_event("info", "monitor.stopped", "Privilege/configuration monitoring stopped",
                  source="privilege-escalation-detector")
