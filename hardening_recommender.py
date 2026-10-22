#!/usr/bin/env python3
"""Hardening recommender - checks sysctl and gives Ubuntu/Fedora fix commands"""
import os
import subprocess
import time

def get_distro():
    try:
        with open("/etc/os-release") as f:
            data = f.read().lower()
        if "ubuntu" in data or "debian" in data:
            return "ubuntu"
        if "fedora" in data or "rhel" in data or "centos" in data:
            return "fedora"
    except:
        pass
    return "linux"

def get_sysctl(key):
    try:
        out = subprocess.check_output(["sysctl", "-n", key], text=True).strip()
        return out
    except:
        return None

# checks: (sysctl_key, good_value, name, benefit, tradeoff)
CHECKS = [
    ("net.ipv4.tcp_syncookies", "1", "TCP SYN Cookies",
     "Protects against SYN flood attacks", "Almost no downside"),
    ("net.ipv4.conf.all.rp_filter", "1", "Reverse Path Filtering",
     "Blocks spoofed packets", "Can break asymmetric routing"),
    ("net.ipv4.conf.all.accept_redirects", "0", "Ignore ICMP Redirects",
     "Stops attackers redirecting traffic", "Rarely needed on servers"),
    ("net.ipv4.conf.all.send_redirects", "0", "Do not send redirects",
     "Prevents your host helping attackers", "None for normal hosts"),
    ("net.ipv4.ip_forward", "0", "IP Forwarding off",
     "Stops your machine acting as a router", "Disable if you need routing/VPN"),
    ("kernel.randomize_va_space", "2", "ASLR full",
     "Makes memory exploits harder", "None"),
    ("kernel.kptr_restrict", "1", "Hide kernel pointers",
     "Harder for attackers to find kernel addresses", "Some debugging tools need 0"),
    ("fs.protected_symlinks", "1", "Protected symlinks",
     "Stops symlink race attacks in /tmp", "None"),
]

def check_and_recommend():
    distro = get_distro()
    print(f"\n=== Hardening check ({distro}) ===")

    for key, good, name, benefit, tradeoff in CHECKS:
        current = get_sysctl(key)
        if current is None:
            continue
        if current != good:
            print(f"\n[FINDING] {name}")
            print(f"  Current : {current}  (recommended: {good})")
            print(f"  Benefit : {benefit}")
            print(f"  Trade-off: {tradeoff}")
            print(f"  Fix command:")
            print(f"    sudo sysctl -w {key}={good}")
            if distro == "ubuntu":
                print(f"    echo '{key} = {good}' | sudo tee -a /etc/sysctl.d/99-hardening.conf")
                print(f"    sudo sysctl --system")
            else:  # fedora / others
                print(f"    echo '{key} = {good}' | sudo tee -a /etc/sysctl.d/99-hardening.conf")
                print(f"    sudo sysctl --system")
        else:
            print(f"[OK] {name} is already good ({current})")

print("Hardening recommender started (runs every 5 min)")
while True:
    check_and_recommend()
    time.sleep(300)
