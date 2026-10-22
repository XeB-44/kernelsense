#!/usr/bin/env python3
import time
import difflib
import json
import os

BASELINE_FILE = "baseline.json"

if not os.path.exists("/var/log/audit/audit.log"):
    print("Error: auditd is not install or not running")
    exit(1)

def load_baseline():
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE) as f:
            return json.load(f)
    return {}

def save_baseline(data):
    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f, indent=2)

def get_content(path):
    path = os.path.expanduser(path)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return f.readlines()

baseline = load_baseline()

# first time – create baseline
if "sudoers" not in baseline:
    content = get_content("/etc/sudoers")
    if content:
        baseline["sudoers"] = content
if "bashrc" not in baseline:
    content = get_content("~/.bashrc")
    if content:
        baseline["bashrc"] = content
if "profile" not in baseline:
    content = get_content("~/.profile")
    if content:
        baseline["profile"] = content
save_baseline(baseline)

def check_file(key, real_path):
    old = baseline.get(key, [])
    new = get_content(real_path)
    if not new:
        return
    for line in difflib.unified_diff(old, new):
        if line.startswith("+") and not line.startswith("+++"):
            print(f"Line added in {real_path}:", line.strip())
            if "PATH=" in line or "NOPASSWD" in line or "!authenticate" in line:
                print("Suspicious change:", line.strip())
        elif line.startswith("-") and not line.startswith("---"):
            print(f"Line removed from {real_path}:", line.strip())
    baseline[key] = new
    save_baseline(baseline)

def check_audit():
    try:
        with open("/var/log/audit/audit.log") as f:
            lines = f.readlines()[-100:]
        for line in lines:
            if "chmod" in line or ("execve" in line and "euid=0" in line):
                print("Possible priv-esc related:", line.strip()[:120])
            elif "sudo" in line and "euid=0" in line:
                print("Possible privilege escalation:", line.strip()[:120])
            elif "ACCESS" in line and ("/proc/kallsyms" in line or "/dev/kmem" in line):
                print("Suspicious kernel access:", line.strip()[:120])
            elif "insmod" in line or "rmmod" in line or "modprobe" in line:
                print("Module load/unload:", line.strip()[:120])
    except Exception:
        pass

print("Privilege escalation detector started (continuous)")
while True:
    check_file("sudoers", "/etc/sudoers")
    check_file("bashrc", "~/.bashrc")
    check_file("profile", "~/.profile")
    check_audit()
    time.sleep(60)


