import time
import difflib
import shutil
import subprocess
import os


if not os.path.exists("/var/log/audit/audit.log"):
    print("Error: auditd is not install or not running")
    exit(1)




if not os.path.exists("sudoers_old.txt"):
    shutil.copy("/etc/sudoers","sudoers_old.txt")

    with open("sudoers_old.txt","r") as file:
            old = file.readlines()

    with open("/etc/sudoers","r") as file:
            new = file.readlines()

    changes = difflib.unified_diff(old,new)

    for line in changes:
        if line.startswith("+") and not line.startswith("+++"):
                print(f"This Line are added in sudoers file: ",line)

        if "PATH=" in line or "PATH =" in line:
                    print("Possible PATH modification:",line)

        elif line.startswith("-") and not line.startswith("---"):
                print(f"This Line are removed from sudoers file: ",line)

        if "NOPASSWD" in line or "!authenticate" in line:
            print("Suspicious modification in sudoers file:", line)

shutil.copy("/etc/sudoers", "sudoers_old.txt")





with open("/var/log/audit/audit.log","r") as file:
    for line in file:
        if "chmod" in line or "execve" in line:
            print("SUID/SGID change:" ,line)

        elif "sudo" in line and "euid" in line:
            parts = line.split()

            for part in parts:
                if part.startswith("euid="):
                    euid = part.split("=")[1]

                    if euid == "0":
                        print("Possible privilege escalation:", line)



        elif "ACCESS" in line:
            if "/proc/kallsyms" in line or "/dev/kmem" in line:
                print("Suspicious kernel access:",line)



        elif "execve" in line:
            if "euid=0" in line:
                print("Possible root execve:",line)
            parts = line.split()
            for part in parts:
                if part.startswith("a0="):
                    print(part.split("=", 1)[1])
                elif part.startswith("a1="):
                    print(part.split("=", 1)[1])

        elif "dmesg" in line:
            if "module" in line.lower():
                print("Suspicious kernel activity:",line)



files = ["~/.bashrc","~/.profile"]

for path in files:

    path = os.path.expanduser(path)

    if not os.path.exists(path):
        print("does not exist",path)
        continue

    if ".bashrc" in path:
        if not os.path.exists("bashrc_old.txt"):
            shutil.copy(path, "bashrc_old.txt")
            continue

        with open("bashrc_old.txt","r") as file:
            old = file.readlines()

        with open(path,"r") as file:
            new = file.readlines()

        changes = difflib.unified_diff(old,new)

        for line in changes:
            if line.startswith("+") and not line.startswith("+++"):
                print(f"This Line are added in {path} file: ",line)

                if "PATH=" in line or "PATH =" in line:
                    print("Possible PATH modification:",line)

            elif line.startswith("-") and not line.startswith("---"):
                print(f"This Line are removed from {path} file: ",line)

        shutil.copy(path,"bashrc_old.txt")


    elif ".profile" in path:

        if not os.path.exists("profile_old.txt"):
            shutil.copy(path,"profile_old.txt")
            continue

        with open("profile_old.txt","r") as file:
            old = file.readlines()

        with open(path,"r") as file:
            new = file.readlines()

        changes = difflib.unified_diff(old,new)

        for line in changes:
            if line.startswith("+") and not line.startswith("+++"):
                print(f"This Line are added in {path} file: ",line)

                if "PATH=" in line or "PATH =" in line:
                    print("Possible PATH modification:",line)

            elif line.startswith("-") and not line.startswith("---"):
                print(f"This Line are removed from {path} file: ",line)

        shutil.copy(path, "profile_old.txt")



with open("/var/log/audit/audit.log","r") as log:
    file = log.readlines()

    for line in file:
        if "type=SYSCALL" in line:
            if "insmod" in line or "rmmod" in line or "modprobe" in line:
                print("A module get loaded/unloaded right now:",line)




