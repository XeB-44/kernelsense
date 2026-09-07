import psutil
import subprocess
import sys
import readline
import time
import json
import datetime


try:

    while True:
        data = []
        for proc in psutil.process_iter(attrs=['pid','name','cpu_percent','memory_percent','exe','cmdline']):
            try:
                data.append(proc.info)
            except psutil.ZombieProcess:
                print(f"The process of pid {proc.pid} is zombie !!")
            except psutil.NoSuchProcess:
                print(f"Error: Process with PID {proc.pid} no longer exist")
            except psutil.AccessDenied:
                print(f"Error: Permission denied accessing PID {proc.pid}")
            finally:
                print("\n")
        time.sleep(3)
        
        with open("process_log.jsonl","a") as f:
            f.write(json.dumps({"timestamp": datetime.datetime.now().isoformat(), "processes": data}) + "\n")

            with open("/var/log/audit/audit.log","r") as log:
                file  = log.readlines()

            for line in file:
                if "execve" in line:
                    if "ps" in line or "top" in line or "htop" in line or "btop" in line:
                        print("Someone's running process utilities like top,htop...",line)


except KeyboardInterrupt:
    print("Stopped Successfully!!")

