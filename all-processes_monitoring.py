#!/usr/bin/env python3
import psutil
import time
import json
import datetime

try:
    while True:
        data = []
        for proc in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'memory_percent', 'exe', 'cmdline']):
            try:
                data.append(proc.info)
            except (psutil.ZombieProcess, psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        with open("process_log.jsonl", "a") as f:
            f.write(json.dumps({
                "timestamp": datetime.datetime.now().isoformat(),
                "processes": data
            }) + "\n")

        # only check last few lines of audit log (not whole file every time)
        try:
            with open("/var/log/audit/audit.log", "r") as log:
                lines = log.readlines()[-50:]
            for line in lines:
                if "execve" in line and any(x in line for x in ("ps", "top", "htop", "btop")):
                    print("Someone's running process utilities like top,htop...", line.strip())
        except Exception:
            pass

        time.sleep(3)

except KeyboardInterrupt:
    print("Stopped Successfully!!")
