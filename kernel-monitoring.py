import os
import time
import sys
import readline
import subprocess
from datetime import datetime, timezone
import socket



while True:
    try:
        result = subprocess.run(
            [
                "journalctl", "-k",
                "--since", f"5 minutes ago",
                "--priority=0..3",
                "--no-pager",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        recent_errors = result.stdout.strip()

        if recent_errors:
            hostname = socket.gethostname()
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

            with open("/var/log/kernel-monitor.log", "a") as f:
                f.write(f"{timestamp} - Kernel errors detected on {hostname}:\n")
                f.write(recent_errors + "\n")
                f.write("---\n")
 
    except Exception as exc:
        print(f"check failed: {exc}", file=sys.stderr, flush=True)
 
    time.sleep(300)
 

