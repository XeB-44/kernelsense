import psutil
import time
import json
import datetime


try:

    while True:
        data = []
        for proc in psutil.process_iter(attrs=['pid','ppid','name','cpu_percent','memory_percent','exe','cmdline']):
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


except KeyboardInterrupt:
    print("Stopped Successfully!!")
