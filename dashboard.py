#!/usr/bin/env python3
"""
KernelSense dashboard - ONE file. Starts your 6 monitors, turns their output into
plain-English alerts, and shows them live in the browser (no refresh needed).

  python3 dashboard.py                 start monitors + dashboard  -> http://127.0.0.1:8501
  sudo python3 dashboard.py            full coverage (auditd + system folders need root)
  python3 dashboard.py --demo          fake data, to preview the look
  python3 dashboard.py --no-monitors   only show what is already on disk

Run this INSTEAD of main.py (it starts the same monitors itself).
Needs: Python 3.8+, psutil, watchdog (see requirements.txt). Everything stays on localhost.
"""
import argparse, atexit, collections, datetime as dt, json, os, random, re, signal, socket
import subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import psutil
except ImportError:
    psutil = None

APPDIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("KERNELSENSE_DATA_DIR") or APPDIR
PROC_LOG = os.environ.get("KERNELSENSE_PROCESS_LOG", os.path.join(BASE, "process_log.jsonl"))
KLOG = os.path.expanduser("~/kernel-monitor.log")   # written by kernel-monitoring.py

# key, script, friendly name, what it does
MONITORS = [
    ("proc", "all-processes_monitoring.py", "Running programs", "Watches which programs are running on your computer"),
    ("dir", "directory-monitoring.py", "Startup & system folders", "Watches the folders that control what starts at boot, and system logs"),
    ("mod", "kernel_modules_monitor.py", "Kernel add-ons", "Notices when add-ons (modules) are plugged into the Linux core"),
    ("klog", "kernel-monitoring.py", "Kernel errors", "Collects serious error messages from the Linux core"),
    ("priv", "privilege_escalation-detector.py", "Admin access", "Watches sudo settings, shell startup files and admin-rights activity"),
    ("hard", "hardening_recommender.py", "Security settings", "Checks system settings and suggests safer ones"),
]
NAMES = {k: n for k, _, n, _ in MONITORS}

LOCK = threading.Lock()
EVENTS = collections.deque(maxlen=3000)
CH = {}                                  # per-monitor process info
HARD = {"items": {}, "cur": None, "mode": None}
PROCS = {"ts": None, "list": [], "live": False}
LASTRAW, LASTADD = {}, {"line": None, "ev": None, "t": 0}
SEQ = 0
COND = threading.Condition()
SNAP, SNAP_SEQ = "{}", 0
DEMO = False
NOMON = False
ALLOW_ANY_HOST = False
DAY = 86400


# ------------------------------------------------------------ events
def add(src, sev, title, why, todo, raw, ts=None):
    """Store one friendly alert. Identical raw text within an hour is ignored (monitors repeat themselves)."""
    global SEQ
    ts = ts or time.time()
    raw = raw.strip()[:600]
    with LOCK:
        k = (src, raw)
        if ts - LASTRAW.get(k, 0) < 3600 and ts >= LASTRAW.get(k, 0):
            return None
        LASTRAW[k] = ts
        if len(LASTRAW) > 5000:
            for kk in sorted(LASTRAW, key=LASTRAW.get)[:2500]:
                del LASTRAW[kk]
        SEQ += 1
        ev = {"id": SEQ, "ts": ts, "src": src, "srcname": NAMES.get(src, src), "sev": sev,
              "title": title, "why": why, "todo": todo, "raw": raw, "seen": False}
        EVENTS.append(ev)
        return ev


def safe_name(s):
    return s if re.fullmatch(r"[\w.\-]+", s) else None


def friendly_file(p):
    if "sudoers" in p:
        return "the sudo permissions file"
    if "bashrc" in p:
        return "your shell startup file (.bashrc)"
    if "profile" in p:
        return "your login profile (.profile)"
    return p


WHY_FILE = {
    "sudoers": "This file decides who may run commands as administrator. Attackers edit it to give themselves power without a password.",
    "shell": "This file runs every time you open a terminal or log in. Attackers add lines here so their code runs automatically.",
}


def handle_line(key, line, ts=None):
    """Turn one line of monitor output into a friendly alert (or update a status)."""
    ts = ts or time.time()
    line = line.rstrip()
    if key == "mod":
        m = re.match(r"\[ALERT\] NEW MODULE LOADED: (\S+)", line)
        if m:
            n = m.group(1)
            cmd = "Run:  modinfo %s  and search the name online." % n if safe_name(n) else "Search the name online."
            add("mod", 2, "New kernel add-on loaded: " + n,
                "The kernel is the core of Linux and modules are add-ons for it. New ones usually appear when you plug in "
                "hardware or start a VPN or virtual machine. Hidden malware (rootkits) can also pose as a module.",
                "If you just did something like that, it is probably fine. Otherwise: " + cmd, line, ts)
            return
        m = re.match(r"\[ALERT\] MODULE REMOVED: (\S+)", line)
        if m:
            add("mod", 1, "Kernel add-on removed: " + m.group(1),
                "A module was unloaded from the Linux core. This is normal when hardware is unplugged or a service stops.",
                "Nothing, unless you did not expect it.", line, ts)
    elif key == "dir":
        m = re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d - \w+ - (.*)$", line)
        msg = m.group(1) if m else line
        m = re.match(r"(Moved|Created|Deleted|Modified) (file|directory): (?:from )?(\S.*?)(?: to .*)?$", msg)
        if not m or m.group(2) == "directory":
            return
        verb, _, path = m.groups()
        base = os.path.basename(path.rstrip("/")) or path
        if path.startswith("/var/log/journal"):
            if verb == "Modified":
                return                      # journal files change constantly - pure noise
            area, sev = "system log folder", 1
            why = ("System logs record what happened on your computer. Log rotation is normal, but deleting logs is also "
                   "how intruders hide their tracks.")
        else:
            area = "system services folder" if "/etc/systemd" in path else "startup scripts folder"
            sev = 1 if verb == "Modified" else 2
            why = ("Files here run automatically with full rights when your computer starts. Attackers add files here to "
                   "survive reboots. Software updates also change them normally.")
        word = {"Created": "New file added", "Deleted": "File deleted", "Moved": "File moved", "Modified": "File changed"}[verb]
        add("dir", sev, "%s in the %s: %s" % (word, area, base), why,
            "If you did not install or update software just now, look at it:  ls -l " + (path if safe_name(path.replace("/", "")) else os.path.dirname(path)),
            msg, ts)
    elif key == "priv":
        m = re.match(r"Line added in (\S+): (.*)$", line)
        if m:
            p, txt = m.groups()
            kind = "sudoers" if "sudoers" in p else "shell"
            ev = add("priv", 3 if kind == "sudoers" else 2, "A line was added to " + friendly_file(p), WHY_FILE[kind],
                     "If you did not edit this file yourself, open it and remove the unknown line.", line, ts)
            LASTADD.update(line=txt.strip(), ev=ev, t=ts)
            return
        m = re.match(r"Line removed from (\S+): (.*)$", line)
        if m:
            p = m.group(1)
            add("priv", 2 if "sudoers" in p else 1, "A line was removed from " + friendly_file(p),
                "Someone (probably you) edited this file.", "Nothing, unless you did not make the change.", line, ts)
            return
        m = re.match(r"Suspicious change: (.*)$", line)
        if m:
            ev = LASTADD["ev"]
            if ev and LASTADD["line"] == m.group(1).strip() and abs(ts - LASTADD["t"]) < 10:
                with LOCK:
                    ev["sev"] = 3
                    ev["title"] = "Risky line added to " + friendly_file(ev["raw"].split(":")[0].replace("Line added in ", ""))
                    ev["why"] = ("The new line contains PATH=, NOPASSWD or !authenticate. These can run an attacker's program "
                                 "first, or let programs get admin rights without a password.")
                    ev["todo"] = "Check the file now. If you did not add this line, remove it."
            else:
                add("priv", 3, "A risky setting was added", "The line contains PATH=, NOPASSWD or !authenticate, which can give "
                    "programs admin rights without a password.", "Check your sudo and shell files.", line, ts)
            return
        if line.startswith("Possible priv-esc related:"):
            add("priv", 2, "A program changed file permissions or ran with admin rights",
                "chmod changes who can use a file, and programs running as root can do anything. Both are normal during "
                "installs and updates, and both are steps attackers use too.",
                "Usually harmless if you were installing or updating software.", line, ts)
        elif line.startswith("Possible privilege escalation:"):
            add("priv", 2, "A command ran with sudo (admin rights)",
                "This happens every time someone uses sudo, so it is normal if it was you.",
                "If you did not run sudo recently, investigate who did.", line, ts)
        elif line.startswith("Suspicious kernel access:"):
            add("priv", 3, "Something looked at protected kernel information",
                "Programs that read /proc/kallsyms or /dev/kmem can learn secrets of the kernel. Exploits do this to prepare an attack.",
                "If you were not debugging the kernel, treat this seriously and check what ran.", line, ts)
        elif line.startswith("Module load/unload:"):
            add("priv", 2, "A kernel add-on command was used (insmod/rmmod/modprobe)",
                "These commands load or remove modules in the Linux core. Normal for drivers, also used by rootkits.",
                "Fine if you were installing a driver. Otherwise check what ran.", line, ts)
    elif key == "proc":
        if line.startswith("Someone's running process utilities"):
            add("proc", 1, "A process viewer (like top or htop) was started",
                "Tools like top and htop list every running program. You use them to check your PC; attackers use "
                "them to find security tools.", "Normal if it was you.", line, ts)
    elif key == "hard":
        hard_line(line)


def hard_line(line):
    s = line.strip()
    it = HARD["items"]
    if s.startswith("=== Hardening check"):
        HARD["cur"] = HARD["mode"] = None
        return
    m = re.match(r"\[OK\] (.*) is already good \((.*)\)$", s)
    if m:
        it[m.group(1)] = {"ok": True, "name": m.group(1), "current": m.group(2)}
        HARD["cur"] = None
        return
    m = re.match(r"\[FINDING\] (.*)$", s)
    if m:
        HARD["cur"] = it[m.group(1)] = {"ok": False, "name": m.group(1), "current": "", "good": "",
                                         "benefit": "", "tradeoff": "", "cmds": []}
        HARD["mode"] = None
        return
    c = HARD["cur"]
    if not c:
        return
    if s.startswith("Current"):
        m = re.match(r"Current\s*:\s*(.*?)\s+\(recommended:\s*(.*)\)", s)
        if m:
            c["current"], c["good"] = m.groups()
    elif s.startswith("Benefit"):
        c["benefit"] = s.split(":", 1)[1].strip()
    elif s.startswith("Trade-off"):
        c["tradeoff"] = s.split(":", 1)[1].strip()
    elif s.startswith("Fix command"):
        HARD["mode"] = "fix"
    elif HARD["mode"] == "fix" and s:
        c["cmds"].append(s)


# ------------------------------------------------------------ monitors
def stop_reason(c):
    t = "\n".join(c["tail"])
    if "auditd" in t or "audit" in t.lower() and "Error" in t:
        return "Needs auditd installed (Ubuntu: sudo apt install auditd, Fedora: sudo dnf install audit) and administrator rights (start the dashboard with sudo)."
    if "No module named" in t:
        return "A Python package is missing. Run: pip install -r requirements.txt"
    if "Permission" in t or "denied" in t:
        return "Needs administrator permission. Start the dashboard with sudo."
    last = c["tail"][-1] if c["tail"] else "no message"
    return "Stopped (code %s). Last message: %s" % (c.get("code"), last[:140])


def reader(key, p):
    for line in p.stdout:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        with LOCK:
            CH[key]["tail"].append(line)
        try:
            handle_line(key, line)
        except Exception:
            pass
    p.wait()
    with LOCK:
        CH[key]["code"] = p.returncode


def start_monitors():
    for key, fn, _, _ in MONITORS:
        path = os.path.join(APPDIR, fn)
        CH[key] = {"p": None, "tail": collections.deque(maxlen=8), "code": None, "missing": not os.path.exists(path)}
        if CH[key]["missing"]:
            continue
        p = subprocess.Popen([sys.executable, "-u", path], cwd=BASE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, errors="replace", bufsize=1)
        CH[key]["p"] = p
        threading.Thread(target=reader, args=(key, p), daemon=True).start()


def stop_monitors():
    for c in CH.values():
        p = c.get("p")
        if p and p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass


def prot_state(key):
    if DEMO:
        return "running", ""
    c = CH.get(key)
    if NOMON or not c:
        return "off", "Not started by the dashboard"
    if c["missing"]:
        return "stopped", "File not found next to dashboard.py"
    if c["p"].poll() is None:
        return "running", ""
    return "stopped", stop_reason(c)


def tail_klog():
    """kernel-monitoring.py writes blocks to ~/kernel-monitor.log - turn each block into one alert."""
    pos, first, blk = 0, True, None
    while True:
        try:
            st = os.stat(KLOG)
            if st.st_size < pos:
                pos, blk = 0, None
            if first:
                pos = max(0, st.st_size - 1_000_000)
            with open(KLOG, "rb") as f:
                f.seek(pos)
                if first and pos > 0:
                    f.readline()
                    pos = f.tell()
                while True:
                    raw = f.readline()
                    if not raw or not raw.endswith(b"\n"):
                        break
                    pos = f.tell()
                    s = raw.decode("utf-8", "replace").rstrip("\n")
                    m = re.match(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) - Kernel errors detected on", s)
                    if m:
                        t = dt.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp()
                        blk = {"ts": t, "lines": []}
                    elif s.strip() == "---":
                        if blk and time.time() - blk["ts"] < DAY:
                            klog_event(blk["lines"], blk["ts"])
                        blk = None
                    elif blk is not None:
                        blk["lines"].append(s)
            first = False
        except OSError:
            pass
        time.sleep(2)


def klog_event(lines, ts):
    lines = [l for l in lines if l.strip() and not l.startswith("-- ")]   # journalctl prints "-- No entries --" when empty
    if not lines:
        return
    n = len(lines)
    add("klog", 3, "Linux reported %d serious kernel error message%s" % (n, "" if n == 1 else "s"),
        "The kernel writes serious problems here: failing hardware, driver crashes or breakage. It is not always an "
        "attack, but it can mean something is wrong or being tampered with.",
        "Read them with:  journalctl -k -p 3 -b   and search the first message online.", "\n".join(lines[:6]), ts)


def last_json_line(path, chunk=4_000_000):
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        n = min(size, chunk)
        f.seek(size - n)
        data = f.read(n)
    for ln in reversed(data.splitlines()):
        try:
            return json.loads(ln)
        except ValueError:
            continue
    return None


def poll_procs():
    while True:
        lst, ts, live = None, None, False
        try:
            if os.path.exists(PROC_LOG):
                snap = last_json_line(PROC_LOG)
                if snap and isinstance(snap.get("processes"), list):
                    t = dt.datetime.fromisoformat(snap["timestamp"]).timestamp()
                    if time.time() - t < 30:       # only trust a fresh snapshot
                        ts = t
                        lst = [{"name": p.get("name") or "?", "mem": p.get("memory_percent") or 0}
                               for p in snap["processes"] if isinstance(p, dict)]
        except Exception:
            pass
        if lst is None and psutil:
            lst, ts, live = [], time.time(), True
            for p in psutil.process_iter(["name", "memory_percent"]):
                lst.append({"name": p.info["name"] or "?", "mem": p.info["memory_percent"] or 0})
        with LOCK:
            PROCS.update(ts=ts, list=lst or [], live=live)
        time.sleep(3)


# ------------------------------------------------------------ snapshot for the browser
def buckets(evs, now, n, step):
    t0 = int(now // step) * step - (n - 1) * step
    s = [[0] * n for _ in range(3)]
    for e in evs:
        i = int((e["ts"] - t0) // step)
        if 0 <= i < n:
            s[min(e["sev"], 3) - 1][i] += 1
    return {"t0": t0, "step": step, "series": s}


def build():
    now = time.time()
    with LOCK:
        evs = list(EVENTS)
        items = [dict(v) for v in HARD["items"].values()]
        prot = []
        for key, _, name, desc in MONITORS:
            st, note = prot_state(key)
            prot.append({"key": key, "name": name, "desc": desc, "state": st, "note": note})
        plist = list(PROCS["list"])
    recent = [e for e in evs if e["ts"] > now - DAY]
    unseen = [e for e in recent if not e["seen"]]
    tips = [i for i in items if not i["ok"]]
    running = sum(1 for p in prot if p["state"] == "running")
    stopped = sum(1 for p in prot if p["state"] == "stopped")
    n3 = sum(1 for e in unseen if e["sev"] >= 3)
    n2 = sum(1 for e in unseen if e["sev"] == 2)
    extra = []
    if stopped:
        extra.append("%d protection%s not running (see Protection status)" % (stopped, " is" if stopped == 1 else "s are"))
    if tips:
        extra.append("%d security setting%s could be safer" % (len(tips), "" if len(tips) == 1 else "s"))
    tail = (" · " + " · ".join(extra)) if extra else ""
    if running == 0:
        bn = ("off", "Protection is not running", "Start the dashboard without --no-monitors, or fix the items under Protection status.")
    elif n3:
        bn = ("danger", "Something needs your attention",
              "%d serious alert%s - open them below, each one explains what it means.%s" % (n3, "" if n3 == 1 else "s", tail))
    elif n2 or stopped:
        bn = ("warn", "A few things to check",
              ("%d warning%s - often normal (updates, new hardware) but worth a look.%s" % (n2, "" if n2 == 1 else "s", tail)) if n2
              else tail.lstrip(" ·"))
    else:
        bn = ("ok", "Your system looks OK", "No new alerts. KernelSense is watching in the background." + tail)

    agg = {}
    for p in plist:
        agg[p["name"]] = agg.get(p["name"], 0.0) + float(p["mem"])
    top = [{"name": k, "mem": round(v, 1)} for k, v in sorted(agg.items(), key=lambda kv: -kv[1])[:5]]
    met = {}
    if psutil:
        met = {"cpu": psutil.cpu_percent(None), "mem": psutil.virtual_memory().percent,
               "disk": psutil.disk_usage("/").percent}
    return {
        "now": now, "host": socket.gethostname(),
        "banner": {"state": bn[0], "title": bn[1], "sub": bn[2], "unseen": len(unseen)},
        "c24": buckets(evs, now, 24, 3600), "c1": buckets(evs, now, 12, 300),
        "sec": {"total": len(items), "ok": len(items) - len(tips), "tips": tips},
        "metrics": met, "top": top, "prot": prot,
        "alerts": list(reversed(evs[-60:])),
    }


def publish():
    global SNAP, SNAP_SEQ
    p = json.dumps(build(), separators=(",", ":"))
    with COND:
        SNAP, SNAP_SEQ = p, SNAP_SEQ + 1
        COND.notify_all()


def builder():
    while True:
        try:
            publish()
        except Exception:
            pass
        time.sleep(1)


# ------------------------------------------------------------ demo
def demo():
    mods = ["vboxdrv", "vhost_net", "nf_tables", "uvcvideo", "btusb", "wireguard", "xt_conntrack"]
    hard = ["=== Hardening check (ubuntu) ===",
            "[OK] TCP SYN Cookies is already good (1)",
            "[FINDING] Reverse Path Filtering", "  Current : 2  (recommended: 1)",
            "  Benefit : Blocks spoofed packets", "  Trade-off: Can break asymmetric routing", "  Fix command:",
            "    sudo sysctl -w net.ipv4.conf.all.rp_filter=1",
            "    echo 'net.ipv4.conf.all.rp_filter = 1' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            "    sudo sysctl --system",
            "[OK] Ignore ICMP Redirects is already good (0)", "[OK] Do not send redirects is already good (0)",
            "[OK] IP Forwarding off is already good (0)", "[OK] ASLR full is already good (2)",
            "[FINDING] Hide kernel pointers", "  Current : 0  (recommended: 1)",
            "  Benefit : Harder for attackers to find kernel addresses", "  Trade-off: Some debugging tools need 0",
            "  Fix command:", "    sudo sysctl -w kernel.kptr_restrict=1",
            "    echo 'kernel.kptr_restrict = 1' | sudo tee -a /etc/sysctl.d/99-hardening.conf",
            "    sudo sysctl --system", "[OK] Protected symlinks is already good (1)"]
    for ln in hard:
        handle_line("hard", ln)

    def fake(ts):
        r = random.random()
        t = dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        if r < .25:
            return [("mod", "[ALERT] NEW MODULE LOADED: " + random.choice(mods))]
        if r < .35:
            return [("mod", "[ALERT] MODULE REMOVED: " + random.choice(mods))]
        if r < .6:
            return [("dir", "%s - INFO - %s file: %s" % (t, random.choice(["Created", "Modified", "Deleted", "Modified"]),
                    random.choice(["/etc/systemd/system/sshd.service", "/etc/systemd/system/helper-%d.service" % random.randint(1, 99),
                                   "/etc/init.d/cron", "/etc/systemd/system/apt-daily.timer", "/var/log/journal/x1/system.journal"])))]
        if r < .7:
            return [("priv", "Line added in ~/.bashrc: alias ll='ls -l'  # %d" % random.randint(1, 999))]
        if r < .76:
            x = "export PATH=/tmp/x%d:$PATH" % random.randint(1, 99)
            return [("priv", "Line added in ~/.bashrc: " + x), ("priv", "Suspicious change: " + x)]
        if r < .86:
            return [("priv", 'Possible priv-esc related: type=SYSCALL msg=audit(17000%05d.1:%d) comm="chmod" euid=0' % (random.randint(1, 99999), random.randint(1, 999)))]
        if r < .9:
            return [("priv", "Suspicious kernel access: type=PATH name=/proc/kallsyms id=%d" % random.randint(1, 999))]
        return [("proc", "Someone's running process utilities like top,htop... type=EXECVE a0=\"htop\" id=%d" % random.randint(1, 9999))]

    now = time.time()
    for ts in sorted(now - random.uniform(300, DAY - 600) for _ in range(40)):
        for k, l in fake(ts):
            handle_line(k, l, ts)
    klog_event(["Oct 25 09:12:01 pc kernel: nvme0n1: I/O error, dev nvme0n1, sector 4096"], now - 5400)
    while True:
        time.sleep(random.uniform(6, 20))
        for k, l in fake(time.time()):
            handle_line(k, l)


# ------------------------------------------------------------ http
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):
        pass

    def _host_ok(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        return ALLOW_ANY_HOST or host in ("127.0.0.1", "localhost", "::1")

    def _hdrs(self, ctype, extra=()):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()

    def do_POST(self):
        if not self._host_ok() or self.headers.get("X-KS") != "1" or self.path != "/api/ack":
            self.send_error(403)
            return
        with LOCK:
            for e in EVENTS:
                e["seen"] = True
        publish()
        self._hdrs("application/json")
        self.wfile.write(b"{}")

    def do_GET(self):
        if not self._host_ok():
            self.send_error(403)
            return
        path = self.path.split("?")[0]
        try:
            if path == "/":
                self._hdrs("text/html; charset=utf-8")
                self.wfile.write(HTML.encode())
            elif path == "/api/state":
                self._hdrs("application/json")
                self.wfile.write(SNAP.encode())
            elif path == "/stream":
                self._hdrs("text/event-stream", [("Connection", "keep-alive")])
                last = 0
                while True:
                    with COND:
                        COND.wait_for(lambda: SNAP_SEQ != last, timeout=15)
                        seq, payload = SNAP_SEQ, SNAP
                    if seq != last:
                        self.wfile.write(("data: %s\n\n" % payload).encode())
                        last = seq
                    else:
                        self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            else:
                self.send_error(404)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass


def main():
    global DEMO, NOMON, ALLOW_ANY_HOST
    ap = argparse.ArgumentParser(description="KernelSense dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8501)
    ap.add_argument("--demo", action="store_true", help="show fake data to preview the dashboard")
    ap.add_argument("--no-monitors", action="store_true", help="do not start the monitor scripts")
    a = ap.parse_args()
    DEMO, NOMON = a.demo, a.no_monitors
    ALLOW_ANY_HOST = a.host not in ("127.0.0.1", "localhost", "::1")
    if ALLOW_ANY_HOST:
        print("WARNING: there is no login - only use --host on a network you trust.")
    atexit.register(stop_monitors)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    threads = [poll_procs, builder] + ([demo] if DEMO else [tail_klog])
    if not DEMO and not NOMON:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print("Note: not running as root - the 'Admin access' and folder monitors may not start. Use sudo for full coverage.")
        start_monitors()
    for fn in threads:
        threading.Thread(target=fn, daemon=True).start()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.daemon_threads = True
    print("KernelSense dashboard: http://%s:%d   (Ctrl+C to stop everything)" % (a.host, a.port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        stop_monitors()


HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KernelSense</title>
<style>
:root{--bg:#f3f5f9;--bd:#e3e8ef;--tx:#1f2a44;--mut:#6b7794;--blue:#2563eb;--grn:#16a34a;--amb:#f59e0b;--red:#ef4444}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:14px}
.top{display:flex;align-items:center;gap:10px;padding:4px 2px 12px}
.logo{width:30px;height:30px;border-radius:8px;background:var(--blue);color:#fff;display:grid;place-items:center;font-weight:700}
.top b{font-size:17px}.sp{flex:1}
.live{display:flex;align-items:center;gap:6px;color:var(--mut);font-size:13px}
.dot{width:9px;height:9px;border-radius:50%;background:#9ca3af;flex:none}
.live.on .dot{background:var(--grn);animation:p 1.6s infinite}.live.off .dot{background:var(--red)}
@keyframes p{0%{box-shadow:0 0 0 0 rgba(22,163,74,.5)}100%{box-shadow:0 0 0 8px rgba(22,163,74,0)}}
.card{background:#fff;border:1px solid var(--bd);border-radius:14px;padding:16px 18px;min-width:0}
.card h3{margin:0 0 4px;font-size:16px}.sub{color:var(--mut);font-size:13px;margin:0 0 10px}
.row{display:grid;gap:12px;margin-top:12px;grid-template-columns:1fr 1fr}
@media(max-width:800px){.row{grid-template-columns:1fr}}
.bn{display:flex;align-items:center;gap:16px;border-left:8px solid var(--c);padding:18px}
.bn .ic{width:52px;height:52px;border-radius:50%;background:var(--c);color:#fff;font-size:28px;font-weight:700;display:grid;place-items:center;flex:none}
.bn h2{margin:0;font-size:21px}.bn p{margin:3px 0 0;color:var(--mut)}
.bn.ok{--c:var(--grn)}.bn.warn{--c:var(--amb)}.bn.danger{--c:var(--red)}.bn.off{--c:#9ca3af}
.bn .gr{flex:1}
button{font:inherit;border:1px solid var(--bd);background:#fff;border-radius:9px;padding:6px 12px;cursor:pointer;color:var(--tx)}
button:hover{background:#f3f6fb}button.on{background:#e8f0fe;border-color:#bfd2fb;color:#1e40af}
.leg{display:flex;gap:14px;flex-wrap:wrap;font-size:13px;color:var(--mut);margin-top:6px}
.leg i{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:5px}
.ax{font-size:10px;fill:#8a94ab}
.empty{color:var(--mut);padding:26px 8px;text-align:center}
.rings{display:flex;justify-content:space-around;gap:8px;text-align:center;margin:6px 0 14px}
.rings .cap{font-size:13px;color:var(--mut);margin-top:2px}
.pb{display:flex;align-items:center;gap:10px;margin:6px 0;font-size:14px}
.pb .nm{width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pb .tr{flex:1;height:10px;background:#eaeef5;border-radius:6px;overflow:hidden}.pb .tr i{display:block;height:100%;background:var(--blue);border-radius:6px}
.pb .v{width:56px;text-align:right;color:var(--mut);font-size:13px}
.pr{display:flex;gap:10px;padding:9px 0;border-bottom:1px solid #eef1f6}.pr:last-child{border:0}
.pr .st{margin-left:auto;font-size:13px;font-weight:600;white-space:nowrap}
.pr .d{color:var(--mut);font-size:13px}.pr .why{color:var(--red);font-size:13px;margin-top:2px}
.pr .dot{margin-top:6px}
.secw{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
details{border-top:1px solid #eef1f6}
details summary{cursor:pointer;padding:10px 2px;list-style:none;display:flex;gap:10px;align-items:center}
details summary::-webkit-details-marker{display:none}
details summary::after{content:"\25BE";margin-left:auto;color:var(--mut)}
details[open] summary::after{content:"\25B4"}
.bd{padding:0 2px 12px;color:#334155;font-size:14px}.bd p{margin:6px 0}
pre{background:#f3f5f9;border:1px solid var(--bd);border-radius:8px;padding:8px 10px;overflow:auto;font:12px/1.5 ui-monospace,Menlo,Consolas,monospace;margin:4px 0;white-space:pre-wrap;word-break:break-all}
.sv{color:#fff;border-radius:10px;font-size:12px;font-weight:600;padding:2px 10px;flex:none}
.ti{flex:1;font-weight:500}.when{color:var(--mut);font-size:12px;white-space:nowrap}
.al{border-left:4px solid var(--c);padding-left:10px;margin-top:6px;border-top:0;background:#fff}
.al.seen{opacity:.55}
.cp{font-size:12px;padding:3px 10px}
.hd{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
</style></head><body><div class="wrap">

<div class="top"><div class="logo">K</div><b>KernelSense</b><div class="sp"></div>
  <div class="live" id="live"><span class="dot"></span><span id="livet">connecting&hellip;</span></div>
  <span class="sub" style="margin:0" id="host"></span></div>

<div class="card bn off" id="bn"><div class="ic" id="bi">&ndash;</div>
  <div class="gr"><h2 id="bt">Loading&hellip;</h2><p id="bs"></p></div>
  <button id="ack" style="display:none">Mark all as seen</button></div>

<div class="row">
  <div class="card"><div class="hd"><h3>Alerts over time</h3><span class="sp"></span>
    <button data-r="24" class="rb on">24 hours</button><button data-r="1" class="rb">1 hour</button></div>
    <p class="sub">Each bar is how many alerts happened in that period.</p>
    <div id="chart"></div>
    <div class="leg"><span><i style="background:#3b82f6"></i>Info</span><span><i style="background:#f59e0b"></i>Warning</span><span><i style="background:#ef4444"></i>Danger</span></div></div>

  <div class="card"><h3>Security settings</h3><p class="sub">How safely your Linux is configured.</p>
    <div id="sec"></div></div>
</div>

<div class="row">
  <div class="card"><h3>Your computer right now</h3><p class="sub">Is anything using too much?</p>
    <div class="rings" id="rings"></div>
    <div class="sub" style="margin:0 0 4px"><b style="color:var(--tx)">Busiest programs</b> (share of memory)</div><div id="top"></div></div>

  <div class="card"><h3>Protection status</h3><p class="sub">The watchers KernelSense runs for you.</p><div id="prot"></div></div>
</div>

<div class="card" style="margin-top:12px"><div class="hd"><h3>Recent alerts</h3><span class="sp"></span>
  <button id="more" style="display:none"></button></div>
  <p class="sub">Tap an alert to see what it means and what you can do.</p><div id="alerts"></div></div>

</div>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const SEV={1:["Info","#3b82f6"],2:["Warning","#f59e0b"],3:["Danger","#ef4444"]};
const p2=n=>String(n).padStart(2,"0");
let D=null,range="24",showAll=false,sig={};const openA=new Set(),openT=new Set();
function ago(ts,now){const s=Math.max(0,now-ts);if(s<60)return"just now";if(s<3600)return Math.floor(s/60)+" min ago";if(s<86400)return Math.floor(s/3600)+" h ago";return Math.floor(s/86400)+" d ago"}
function niceStep(x){x=Math.max(x,1);const p=Math.pow(10,Math.floor(Math.log10(x))),f=x/p;return(f<=1?1:f<=2?2:f<=5?5:10)*p}
function chart(el,c,hourly){
  const n=c.series[0].length,tot=Array.from({length:n},(_,i)=>c.series[0][i]+c.series[1][i]+c.series[2][i]);
  if(!tot.some(v=>v>0)){el.innerHTML='<div class="empty">No alerts in this period. Good news.</div>';return}
  const W=el.clientWidth||460,H=190,L=26,R=4,T=8,B=22,iw=W-L-R,ih=H-T-B,mx=Math.max(...tot),st=niceStep(mx/4),ym=st*4,cw=iw/n,bw=cw*.7;
  let g="";for(let v=0;v<=ym;v+=st){const y=T+ih-ih*v/ym;g+=`<line x1="${L}" x2="${W-R}" y1="${y}" y2="${y}" stroke="#e8ecf3"/><text x="${L-5}" y="${y+3}" text-anchor="end" class="ax">${v}</text>`}
  for(let i=0;i<n;i++){let acc=0;const x=L+cw*i+(cw-bw)/2;
    [0,1,2].forEach(k=>{const v=c.series[k][i];if(!v)return;const h=ih*v/ym,y=T+ih-ih*acc/ym-h;acc+=v;
      g+=`<rect x="${x}" y="${y}" width="${bw}" height="${h}" rx="2" fill="${SEV[k+1][1]}"><title>${SEV[k+1][0]}: ${v}</title></rect>`});
    if(i%(hourly?4:2)==(hourly?3:1)){const d=new Date((c.t0+i*c.step)*1000);g+=`<text x="${L+cw*i+cw/2}" y="${H-6}" text-anchor="middle" class="ax">${p2(d.getHours())}:${hourly?"00":p2(d.getMinutes())}</text>`}}
  el.innerHTML=`<svg width="${W}" height="${H}">${g}</svg>`}
function ring(pct,big,cap,col){const R=32,C=2*Math.PI*R,l=C*Math.min(100,Math.max(0,pct))/100;
  return `<div><svg width="86" height="86" viewBox="0 0 86 86"><circle cx="43" cy="43" r="${R}" fill="none" stroke="#eaeef5" stroke-width="9"/><circle cx="43" cy="43" r="${R}" fill="none" stroke="${col}" stroke-width="9" stroke-linecap="round" stroke-dasharray="${l} ${C-l}" transform="rotate(-90 43 43)"/><text x="43" y="48" text-anchor="middle" style="font-size:17px;font-weight:600;fill:#1f2a44">${big}</text></svg><div class="cap">${cap}</div></div>`}
const loadCol=v=>v>90?"#ef4444":v>75?"#f59e0b":"#2563eb";
function renderSec(d){const s=d.sec,el=$("#sec");
  const key=JSON.stringify(s);if(sig.sec===key)return;sig.sec=key;
  if(!s.total){el.innerHTML='<div class="empty">First check is running&hellip; results appear within a minute.</div>';return}
  const pct=100*s.ok/s.total,col=pct==100?"#16a34a":pct>=60?"#f59e0b":"#ef4444";
  let h=`<div class="secw">${ring(pct,s.ok+"/"+s.total,"",col)}<div><b>${s.ok} of ${s.total} settings are safe</b><div class="sub" style="margin:2px 0 0">${s.tips.length?"Open a tip below to fix it.":"Nothing to fix. Nice."}</div></div></div>`;
  h+=s.tips.map((t,i)=>`<details data-tip="${esc(t.name)}" ${openT.has(t.name)?"open":""}><summary><span class="dot" style="background:#f59e0b"></span><span class="ti">${esc(t.name)}</span></summary><div class="bd"><p><b>Why it helps:</b> ${esc(t.benefit)}</p><p><b>Downside:</b> ${esc(t.tradeoff)}</p><p><b>Now:</b> ${esc(t.current)} &rarr; <b>safer:</b> ${esc(t.good)}</p><pre>${esc(t.cmds.join("\n"))}</pre><button class="cp" data-cmd="${encodeURIComponent(t.cmds.join("\n"))}">Copy commands</button></div></details>`).join("");
  el.innerHTML=h}
function render(d){
  D=d;const b=d.banner;$("#host").textContent=d.host;
  $("#bn").className="card bn "+b.state;$("#bi").textContent={ok:"\u2713",warn:"!",danger:"!",off:"\u2013"}[b.state];
  $("#bt").textContent=b.title;$("#bs").textContent=b.sub;$("#ack").style.display=b.unseen?"":"none";
  chart($("#chart"),range=="24"?d.c24:d.c1,range=="24");
  renderSec(d);
  const m=d.metrics;
  $("#rings").innerHTML=Object.keys(m).length?ring(m.cpu,Math.round(m.cpu)+"%","Processor busy",loadCol(m.cpu))+ring(m.mem,Math.round(m.mem)+"%","Memory used",loadCol(m.mem))+ring(m.disk,Math.round(m.disk)+"%","Disk space used",loadCol(m.disk)):'<div class="empty">Install psutil to see this.</div>';
  const mx=Math.max(1,...d.top.map(t=>t.mem));
  $("#top").innerHTML=d.top.length?d.top.map(t=>`<div class="pb"><span class="nm" title="${esc(t.name)}">${esc(t.name)}</span><span class="tr"><i style="width:${100*t.mem/mx}%"></i></span><span class="v">${t.mem}%</span></div>`).join(""):'<div class="empty">No data yet.</div>';
  $("#prot").innerHTML=d.prot.map(p=>{const c=p.state=="running"?"#16a34a":p.state=="stopped"?"#ef4444":"#9ca3af",t=p.state=="running"?"Working":p.state=="stopped"?"Not running":"Off";
    return `<div class="pr"><span class="dot" style="background:${c}"></span><div><div>${esc(p.name)}</div><div class="d">${esc(p.desc)}</div>${p.state=="stopped"&&p.note?`<div class="why">${esc(p.note)}</div>`:""}</div><span class="st" style="color:${c}">${t}</span></div>`}).join("");
  const list=showAll?d.alerts:d.alerts.slice(0,8),s=list.map(a=>a.id+(a.seen?"s":"u")+a.sev).join(",")+showAll+d.alerts.length;
  if(s!==sig.al){sig.al=s;
    $("#alerts").innerHTML=list.length?list.map(a=>`<details class="al ${a.seen?"seen":""}" data-id="${a.id}" style="--c:${SEV[a.sev][1]}" ${openA.has(a.id)?"open":""}><summary><span class="sv" style="background:${SEV[a.sev][1]}">${SEV[a.sev][0]}</span><span class="ti">${esc(a.title)}</span><span class="when" data-ts="${a.ts}"></span></summary><div class="bd"><p><b>What this means</b><br>${esc(a.why)}</p><p><b>What you can do</b><br>${esc(a.todo)}</p><p><b>Technical details</b> (from ${esc(a.srcname)})</p><pre>${esc(a.raw)}</pre></div></details>`).join(""):'<div class="empty">No alerts yet. When KernelSense notices something unusual it will appear here, explained in plain English.</div>';
    const mb=$("#more");mb.style.display=d.alerts.length>8?"":"none";mb.textContent=showAll?"Show fewer":"Show all ("+d.alerts.length+")"}
  document.querySelectorAll("[data-ts]").forEach(e=>e.textContent=ago(+e.dataset.ts,d.now))}
document.addEventListener("toggle",e=>{const t=e.target;if(t.dataset&&t.dataset.id){(t.open?openA.add(+t.dataset.id):openA.delete(+t.dataset.id))}else if(t.dataset&&t.dataset.tip){(t.open?openT.add(t.dataset.tip):openT.delete(t.dataset.tip))}},true);
document.addEventListener("click",e=>{const t=e.target;
  if(t.classList.contains("rb")){range=t.dataset.r;document.querySelectorAll(".rb").forEach(x=>x.classList.toggle("on",x===t));D&&render(D)}
  else if(t.id=="more"){showAll=!showAll;sig.al="";D&&render(D)}
  else if(t.id=="ack"){fetch("/api/ack",{method:"POST",headers:{"X-KS":"1"}})}
  else if(t.classList.contains("cp")){const txt=decodeURIComponent(t.dataset.cmd);
    const done=()=>{t.textContent="Copied!";setTimeout(()=>t.textContent="Copy commands",1500)};
    if(navigator.clipboard&&window.isSecureContext)navigator.clipboard.writeText(txt).then(done);
    else{const a=document.createElement("textarea");a.value=txt;document.body.appendChild(a);a.select();document.execCommand("copy");a.remove();done()}}});
function live(on){$("#live").className="live "+(on?"on":"off");$("#livet").textContent=on?"Live":"Reconnecting\u2026"}
const es=new EventSource("/stream");es.onopen=()=>live(true);es.onmessage=e=>{live(true);render(JSON.parse(e.data))};es.onerror=()=>live(false);
let rt;window.addEventListener("resize",()=>{clearTimeout(rt);rt=setTimeout(()=>D&&render(D),150)});
</script></body></html>
"""

if __name__ == "__main__":
    main()
