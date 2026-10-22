#!/usr/bin/env python3
import time
import difflib
import shutil
import os

if not os.path.exists("/var/log/audit/audit.log"):
    print("Error: auditd is not install or not running")
    exit(1)

# initial copies
if not os.path.exists("sudoers_old.txt"):
    shutil.copy("/etc/sudoers", "sudoers_old.txt")

for path, oldname in [("~/.bashrc", "bashrc_old.txt"), ("~/.profile", "profile_old.txt")]:
    path = os.path.expanduser(path)
    if os.path.exists(path) and not os.path.exists(oldname):
        shutil.copy(path, oldname)

def check_sudoers():
    with open("sudoers_old.txt") as f:
        old = f.readlines()
    with open("/etc/sudoers") as f:
        new = f.readlines()
    for line in difflib.unified_diff(old, new):
        if line.startswith("+") and not line.startswith("+++"):
            print("Line added in sudoers:", line.strip())
            if "PATH=" in line or "NOPASSWD" in line or "!authenticate" in line:
                print("Suspicious sudoers change:", line.strip())
        elif line.startswith("-") and not line.startswith("---"):
            print("Line removed from sudoers:", line.strip())
    shutil.copy("/etc/sudoers", "sudoers_old.txt")

def check_shell_files():
    for path, oldname in [("~/.bashrc", "bashrc_old.txt"), ("~/.profile", "profile_old.txt")]:
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            continue
        with open(oldname) as f:
            old = f.readlines()
        with open(path) as f:
            new = f.readlines()
        for line in difflib.unified_diff(old, new):
            if line.startswith("+") and not line.startswith("+++"):
                print(f"Line added in {path}:", line.strip())
                if "PATH=" in line:
                    print("Possible PATH modification:", line.strip())
            elif line.startswith("-") and not line.startswith("---"):
                print(f"Line removed from {path}:", line.strip())
        shutil.copy(path, oldname)

def check_audit():
    try:
        with open("/var/log/audit/audit.log") as f:
            lines = f.readlines()[-100:]   # only last 100 lines
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
    check_sudoers()
    check_shell_files()
    check_audit()
    time.sleep(60)



