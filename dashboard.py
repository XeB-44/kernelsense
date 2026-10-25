#!/usr/bin/env python3
"""
KernelSense live dashboard - ONE file, no folders, no build step.

Run:   python3 dashboard.py              -> http://127.0.0.1:8501
Demo:  python3 dashboard.py --demo       (fake events, to preview the UI)

Reads (from the current directory, or KERNELSENSE_DATA_DIR):
  security_events.jsonl   alerts + heartbeats   (KERNELSENSE_EVENT_LOG)
  process_log.jsonl       process snapshots     (KERNELSENSE_PROCESS_LOG)
Needs: Python 3.8+. psutil is optional (host CPU/RAM/disk, live process fallback).
Live updates use Server-Sent Events, so the page never needs a refresh.
"""
import argparse, collections, datetime as dt, json, os, random, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import psutil
except ImportError:
    psutil = None

BASE = os.environ.get("KERNELSENSE_DATA_DIR") or os.getcwd()
EVENT_LOG = os.environ.get("KERNELSENSE_EVENT_LOG", os.path.join(BASE, "security_events.jsonl"))
PROC_LOG = os.environ.get("KERNELSENSE_PROCESS_LOG", os.path.join(BASE, "process_log.jsonl"))

LOCK = threading.Lock()
EVENTS = collections.deque(maxlen=5000)
HEART = {}
PROCS = {"ts": None, "list": [], "live": False}
TOTAL = 0
SEQ = 0
COND = threading.Condition()
SNAP, SNAP_SEQ = "{}", 0
ALLOW_ANY_HOST = False


# ----------------------------------------------------------------- parsing
def parse_ts(v):
    if v is None:
        return time.time()
    if isinstance(v, (int, float)):
        return float(v) / 1000 if v > 1e11 else float(v)
    try:
        return dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


def sev_rank(v):
    """-> 1 low, 2 medium, 3 high, 4 critical (accepts words or 0-15 levels)"""
    if isinstance(v, (int, float)):
        return 4 if v >= 12 else 3 if v >= 8 else 2 if v >= 4 else 1
    s = str(v or "").strip().lower()
    if s.isdigit():
        return sev_rank(int(s))
    if s in ("critical", "crit", "fatal", "emergency", "alert"):
        return 4
    if s in ("high", "error", "err", "severe"):
        return 3
    if s in ("medium", "warning", "warn", "moderate"):
        return 2
    return 1


def ingest(o):
    global TOTAL, SEQ
    if not isinstance(o, dict):
        return
    src = str(o.get("source") or o.get("monitor") or o.get("component") or o.get("worker") or "unknown")
    ts = parse_ts(o.get("timestamp") or o.get("ts") or o.get("time"))
    kind = str(o.get("type") or o.get("event_type") or o.get("kind") or "").lower()
    if "heartbeat" in kind or o.get("heartbeat"):
        with LOCK:
            HEART[src] = max(ts, HEART.get(src, 0))
        return
    msg = (o.get("message") or o.get("description") or o.get("msg") or o.get("title")
           or o.get("event") or json.dumps(o, default=str)[:200])
    sev = o.get("severity", o.get("level", o.get("priority")))
    detail = ", ".join("%s=%s" % (k, o[k]) for k in
                       ("path", "pid", "process", "name", "user", "module", "rule") if o.get(k) is not None)
    with LOCK:
        SEQ += 1
        TOTAL += 1
        EVENTS.append({"id": SEQ, "ts": ts, "src": src, "sev": sev_rank(sev),
                       "msg": str(msg)[:300], "detail": detail[:200]})


# ----------------------------------------------------------------- workers
def tail_events():
    pos, inode, first = 0, None, True
    while True:
        try:
            st = os.stat(EVENT_LOG)
            if st.st_size < pos or (inode is not None and st.st_ino != inode):
                pos = 0
            inode = st.st_ino
            if first:
                pos = max(0, st.st_size - 2_000_000)
            with open(EVENT_LOG, "rb") as f:
                f.seek(pos)
                if first and pos > 0:
                    f.readline()  # drop partial first line
                    pos = f.tell()
                while True:
                    line = f.readline()
                    if not line or not line.endswith(b"\n"):
                        break
                    pos = f.tell()
                    try:
                        ingest(json.loads(line))
                    except ValueError:
                        pass
            first = False
        except OSError:
            pass
        time.sleep(0.5)


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
                    ts = parse_ts(snap.get("timestamp"))
                    lst = [{"pid": p.get("pid"), "name": p.get("name") or "?",
                            "cpu": p.get("cpu_percent") or 0, "mem": p.get("memory_percent") or 0}
                           for p in snap["processes"] if isinstance(p, dict)]
        except Exception:
            pass
        if lst is None and psutil:
            lst, ts, live = [], time.time(), True
            for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                i = p.info
                lst.append({"pid": i["pid"], "name": i["name"] or "?",
                            "cpu": i["cpu_percent"] or 0, "mem": i["memory_percent"] or 0})
        with LOCK:
            PROCS.update(ts=ts, list=lst or [], live=live)
        time.sleep(3)


def build():
    now = time.time()
    with LOCK:
        evs, total, hb, pr = list(EVENTS), TOTAL, dict(HEART), dict(PROCS)
    N, step = 60, 60
    t0 = int(now // step) * step - (N - 1) * step
    SN, sstep = 12, 300
    s0 = int(now // sstep) * sstep - (SN - 1) * sstep
    counts = collections.Counter(e["src"] for e in evs)
    top = [s for s, _ in counts.most_common(5)]
    sb = {s: [0] * SN for s in top}
    tl = [[0] * N for _ in range(4)]
    sevc, seen = [0] * 5, {}
    for e in evs:
        sevc[e["sev"]] += 1
        seen[e["src"]] = max(seen.get(e["src"], 0), e["ts"])
        i = int((e["ts"] - t0) // step)
        if 0 <= i < N:
            tl[e["sev"] - 1][i] += 1
        j = int((e["ts"] - s0) // sstep)
        if e["src"] in sb and 0 <= j < SN:
            sb[e["src"]][j] += 1
    for s, t in hb.items():
        seen[s] = max(seen.get(s, 0), t)
    mons = [{"name": s, "age": int(now - t)} for s, t in sorted(seen.items())]

    agg = {}
    for p in pr["list"]:
        a = agg.setdefault(p["name"], [0.0, 0.0, 0])
        a[0] += float(p["mem"]); a[1] += float(p["cpu"]); a[2] += 1
    topp = sorted(agg.items(), key=lambda kv: -kv[1][0])[:5]

    m = {}
    if psutil:
        m = {"cpu": psutil.cpu_percent(None), "mem": psutil.virtual_memory().percent,
             "disk": psutil.disk_usage("/").percent}
    return {
        "now": now, "host": socket.gethostname(),
        "kpi": {"total": total, "high": sevc[3] + sevc[4], "sev": sevc[1:],
                "online": sum(1 for x in mons if x["age"] < 120), "monitors": len(mons),
                "procs": len(pr["list"])},
        "tl": {"t0": t0, "step": step, "series": tl},
        "by_src": [{"name": s, "value": c} for s, c in counts.most_common(6)],
        "src_time": {"t0": s0, "step": sstep, "series": [{"name": s, "vals": v} for s, v in sb.items()]},
        "top_procs": [{"name": n, "mem": round(a[0], 2), "cpu": round(a[1], 1), "n": a[2]} for n, a in topp],
        "procs_age": None if pr["ts"] is None else int(now - pr["ts"]),
        "procs_live": pr["live"],
        "mons": mons, "metrics": m,
        "alerts": [e for e in reversed(evs[-200:])],
    }


def builder():
    global SNAP, SNAP_SEQ
    while True:
        try:
            p = json.dumps(build(), separators=(",", ":"))
            with COND:
                SNAP, SNAP_SEQ = p, SNAP_SEQ + 1
                COND.notify_all()
        except Exception:
            pass
        time.sleep(1)


def demo():
    srcs = {
        "process-monitor": ["New process started from /tmp", "Process utility executed (top/htop)", "Sustained high CPU process"],
        "directory-monitor": ["File modified under /etc", "New executable dropped in /tmp", "Permissions changed on /etc/shadow"],
        "kernel-monitor": ["Kernel module loaded: nf_tables", "Unsigned kernel module load attempt", "Kernel log: segfault in user process"],
        "privilege-detector": ["SUID binary list changed", "sudoers file modified", "Possible privilege escalation attempt"],
    }
    sevs = ["low"] * 3 + ["medium"] * 3 + ["high"] * 2 + ["critical"]

    def fake(ts):
        s = random.choice(list(srcs))
        return {"timestamp": ts, "source": s, "severity": random.choice(sevs),
                "message": random.choice(srcs[s]), "pid": random.randint(300, 40000)}
    now = time.time()
    for ts in sorted(now - random.uniform(0, 3500) for _ in range(250)):
        ingest(fake(ts))
    while True:
        for s in srcs:
            ingest({"type": "heartbeat", "source": s})
        for _ in range(random.randint(0, 4)):
            ingest(fake(time.time()))
            time.sleep(random.uniform(0.2, 1.5))
        time.sleep(2)


# ----------------------------------------------------------------- http
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):
        pass

    def _hdrs(self, ctype, extra=()):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                         "connect-src 'self'; img-src data:")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        if not ALLOW_ANY_HOST and host not in ("127.0.0.1", "localhost", "::1"):
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
    global ALLOW_ANY_HOST
    ap = argparse.ArgumentParser(description="KernelSense live dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8501)
    ap.add_argument("--demo", action="store_true", help="feed fake events to preview the UI")
    a = ap.parse_args()
    ALLOW_ANY_HOST = a.host not in ("127.0.0.1", "localhost", "::1")
    if ALLOW_ANY_HOST:
        print("WARNING: no authentication - do not expose this beyond a trusted network.")
    for fn in (tail_events, poll_procs, builder) + ((demo,) if a.demo else ()):
        threading.Thread(target=fn, daemon=True).start()
    srv = ThreadingHTTPServer((a.host, a.port), H)
    srv.daemon_threads = True
    print("KernelSense dashboard: http://%s:%d   (events: %s)" % (a.host, a.port, EVENT_LOG))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KernelSense</title>
<style>
:root{--bg:#f3f5f9;--card:#fff;--bd:#e3e8ef;--tx:#1f2a44;--mut:#6b7794;--blue:#2563eb;--red:#dc2626;--grn:#16a34a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.4 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:16px}
.top{display:flex;align-items:center;gap:14px;flex-wrap:wrap;background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:10px 16px}
.logo{width:30px;height:30px;border-radius:8px;background:var(--blue);color:#fff;display:grid;place-items:center;font-weight:700}
.pill{background:#e8f0fe;color:#1e40af;border-radius:8px;padding:6px 16px;font-weight:600}
.sp{flex:1}
.live{display:flex;align-items:center;gap:6px;color:var(--mut);font-size:13px}
.dot{width:9px;height:9px;border-radius:50%;background:#9ca3af}
.live.on .dot{background:var(--grn);animation:p 1.6s infinite}
.live.off .dot{background:var(--red)}
@keyframes p{0%{box-shadow:0 0 0 0 rgba(22,163,74,.5)}100%{box-shadow:0 0 0 8px rgba(22,163,74,0)}}
.bar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:14px 2px 10px}
.tabs{display:flex;gap:22px}
.tab{padding:6px 2px;color:var(--mut);cursor:pointer;border-bottom:2px solid transparent;font-weight:500}
.tab.on{color:var(--blue);border-color:var(--blue)}
input,select{border:1px solid var(--bd);background:#fff;border-radius:8px;padding:7px 10px;font:inherit;color:var(--tx)}
input{width:230px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px 16px;min-width:0}
.card h3{margin:0 0 8px;font-size:14px;font-weight:600}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;text-align:center}
.kpi .n{font-size:34px;font-weight:600;color:var(--blue);letter-spacing:.5px}
.kpi.r .n{color:var(--red)}.kpi.g .n{color:var(--grn)}
.kpi .l{color:var(--mut);font-size:13px}
.g2{display:grid;gap:12px;margin-top:12px}
.a{grid-template-columns:2fr 1fr}.b{grid-template-columns:1fr 2fr}.c{grid-template-columns:1fr 1fr}
@media(max-width:900px){.a,.b,.c,.kpis{grid-template-columns:1fr 1fr}.a>*,.b>*,.c>*{grid-column:span 2}}
.ax{font-size:10px;fill:#8a94ab}
.dn{display:flex;align-items:center;gap:18px;flex-wrap:wrap;min-height:170px}
.legend{flex:1;min-width:120px}
.lg{display:flex;align-items:center;gap:8px;padding:3px 0;font-size:13px}
.lg i{width:10px;height:10px;border-radius:50%;flex:none}
.lg span{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lg b{font-weight:600;color:var(--mut)}
.meter{margin:10px 0}.meter .t{display:flex;justify-content:space-between;font-size:13px;color:var(--mut)}
.meter .m{height:8px;background:#eaeef5;border-radius:6px;overflow:hidden;margin-top:4px}
.meter .m i{display:block;height:100%;background:var(--blue);transition:width .6s}
.tw{overflow:auto;max-height:520px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{position:sticky;top:0;background:#fff;text-align:left;color:var(--mut);font-weight:600;padding:8px;border-bottom:1px solid var(--bd)}
td{padding:8px;border-bottom:1px solid #eef1f6;vertical-align:top}
tr.new td{animation:fl 2s}
@keyframes fl{from{background:#fff7d6}to{background:transparent}}
.bg{display:inline-block;padding:2px 9px;border-radius:10px;font-size:12px;font-weight:600;color:#fff}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--mut)}
.empty{color:var(--mut);padding:30px;text-align:center}
.ok{color:var(--grn)}.bad{color:var(--red)}
</style></head><body><div class="wrap">

<div class="top">
  <div class="logo">K</div><div class="pill">KernelSense &middot; Host Intrusion Detection</div>
  <div class="sp"></div>
  <div class="live" id="live"><span class="dot"></span><span id="livet">connecting&hellip;</span></div>
  <div class="mono" id="host"></div>
</div>

<div class="bar">
  <div class="tabs"><div class="tab on" data-t="dash">Dashboard</div><div class="tab" data-t="ev">Events</div></div>
  <div class="sp"></div>
  <input id="q" placeholder="Search alerts&hellip;" autocomplete="off">
  <select id="sev"><option value="0">All severities</option><option value="2">Medium+</option><option value="3">High+</option><option value="4">Critical</option></select>
</div>

<div id="dash">
  <div class="card kpis">
    <div class="kpi"><div class="n" id="k1">0</div><div class="l">Total alerts</div></div>
    <div class="kpi r"><div class="n" id="k2">0</div><div class="l">High / Critical</div></div>
    <div class="kpi g"><div class="n" id="k3">0</div><div class="l">Monitors online</div></div>
    <div class="kpi"><div class="n" id="k4">0</div><div class="l">Processes tracked</div></div>
  </div>

  <div class="g2 a">
    <div class="card"><h3>Alerts evolution (per minute, last hour)</h3><div id="c_tl"></div>
      <div class="lg" style="gap:16px" id="sevleg"></div></div>
    <div class="card"><h3>Alerts by source</h3><div id="c_src"></div></div>
  </div>

  <div class="g2 b">
    <div class="card"><h3>Top 5 processes by memory</h3><div id="c_proc"></div><div class="mono" id="pa"></div></div>
    <div class="card"><h3>Alerts evolution &ndash; top sources (per 5 min)</h3><div id="c_bar"></div><div id="barleg" class="lg" style="gap:16px;flex-wrap:wrap"></div></div>
  </div>

  <div class="g2 c">
    <div class="card"><h3>Host resources</h3><div id="meters"></div></div>
    <div class="card"><h3>Monitor health</h3><div id="mons"></div></div>
  </div>

  <div class="card" style="margin-top:12px"><h3>Security alerts</h3><div class="tw" id="t_recent"></div></div>
</div>

<div id="ev" style="display:none"><div class="card"><h3>Events <span class="mono" id="evc"></span></h3><div class="tw" style="max-height:78vh" id="t_all"></div></div></div>

</div>
<script>
const $=s=>document.querySelector(s);
const SEV=["","Low","Medium","High","Critical"],SC=["","#60a5fa","#f5b83d","#f08a24","#e5484d"];
const PAL=["#1d4ed8","#3b82f6","#93c5fd","#facc15","#14b8a6","#a78bfa"];
const esc=s=>String(s).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const p2=n=>String(n).padStart(2,"0");
function fmtT(ts,sec){const d=new Date(ts*1000);return p2(d.getHours())+":"+p2(d.getMinutes())+(sec?":"+p2(d.getSeconds()):"")}
function fmtD(ts){const d=new Date(ts*1000);return d.toLocaleDateString(undefined,{month:"short",day:"2-digit"})+" "+fmtT(ts,1)}
function niceStep(x){x=Math.max(x,1);const p=Math.pow(10,Math.floor(Math.log10(x))),f=x/p;return(f<=1?1:f<=2?2:f<=5?5:10)*p}
function axes(W,H,L,R,T,B,ym,st){let g="";const ih=H-T-B;
  for(let v=0;v<=ym;v+=st){const y=T+ih-ih*v/ym;g+=`<line x1="${L}" x2="${W-R}" y1="${y}" y2="${y}" stroke="#e5e9f0"/><text x="${L-6}" y="${y+3}" text-anchor="end" class="ax">${v}</text>`}return g}

function area(el,t0,step,series,cols){
  const W=el.clientWidth||600,H=220,L=34,R=8,T=8,B=22,iw=W-L-R,ih=H-T-B,n=series[0].length;
  const cum=series.map((_,k)=>series[0].map((_,i)=>{let s=0;for(let j=0;j<=k;j++)s+=series[j][i];return s}));
  const mx=Math.max(1,...cum[cum.length-1]),st=niceStep(mx/4),ym=st*4;
  const x=i=>L+iw*i/(n-1),y=v=>T+ih-ih*v/ym;
  let g=axes(W,H,L,R,T,B,ym,st);
  for(let i=0;i<n;i+=10)g+=`<text x="${x(i)}" y="${H-6}" text-anchor="middle" class="ax">${fmtT(t0+i*step)}</text>`;
  for(let k=series.length-1;k>=0;k--){let d=`M${x(0)},${y(0)}`;for(let i=0;i<n;i++)d+=` L${x(i).toFixed(1)},${y(cum[k][i]).toFixed(1)}`;
    g+=`<path d="${d} L${x(n-1)},${y(0)}Z" fill="${cols[k]}" fill-opacity=".92"/>`}
  el.innerHTML=`<svg width="${W}" height="${H}">${g}</svg>`}

function bars(el,t0,step,series,cols){
  const W=el.clientWidth||600,H=220,L=34,R=8,T=8,B=22,iw=W-L-R,ih=H-T-B,n=12;
  const tot=Array.from({length:n},(_,i)=>series.reduce((a,s)=>a+s.vals[i],0));
  const mx=Math.max(1,...tot),st=niceStep(mx/4),ym=st*4,cw=iw/n,bw=cw*.72;
  let g=axes(W,H,L,R,T,B,ym,st);
  for(let i=0;i<n;i++){let acc=0;
    series.forEach((s,k)=>{const v=s.vals[i];if(!v)return;const h=ih*v/ym,y=T+ih-ih*acc/ym-h;acc+=v;
      g+=`<rect x="${L+cw*i+(cw-bw)/2}" y="${y}" width="${bw}" height="${h}" fill="${cols[k%cols.length]}"><title>${esc(s.name)}: ${v}</title></rect>`});
    if(i%2==0)g+=`<text x="${L+cw*i+cw/2}" y="${H-6}" text-anchor="middle" class="ax">${fmtT(t0+i*step)}</text>`}
  el.innerHTML=`<svg width="${W}" height="${H}">${g}</svg>`}

function donut(el,items,cols,c1,c2){
  const tot=items.reduce((a,b)=>a+b.value,0),R=60,C=2*Math.PI*R;let off=0,seg=`<circle r="${R}" cx="80" cy="80" fill="none" stroke="#eaeef5" stroke-width="24"/>`;
  items.forEach((it,i)=>{const len=tot?C*it.value/tot:0;
    seg+=`<circle r="${R}" cx="80" cy="80" fill="none" stroke="${cols[i%cols.length]}" stroke-width="24" stroke-dasharray="${len} ${C-len}" stroke-dashoffset="${-off}" transform="rotate(-90 80 80)"><title>${esc(it.name)}: ${it.label||it.value}</title></circle>`;off+=len});
  const lg=items.map((it,i)=>`<div class="lg"><i style="background:${cols[i%cols.length]}"></i><span title="${esc(it.name)}">${esc(it.name)}</span><b>${esc(it.label||it.value)}</b></div>`).join("")||'<div class="empty">no data yet</div>';
  el.innerHTML=`<div class="dn"><svg viewBox="0 0 160 160" width="160" height="160">${seg}<text x="80" y="82" text-anchor="middle" style="font-size:20px;font-weight:600;fill:#1f2a44">${esc(c1)}</text><text x="80" y="98" text-anchor="middle" class="ax">${esc(c2)}</text></svg><div class="legend">${lg}</div></div>`}

function table(el,rows,q,minsev,limit,lastId){
  q=q.toLowerCase();
  rows=rows.filter(a=>a.sev>=minsev&&(!q||(a.src+" "+a.msg+" "+a.detail+" "+SEV[a.sev]).toLowerCase().includes(q)));
  const shown=rows.slice(0,limit);
  if(!shown.length){el.innerHTML='<div class="empty">No alerts match.</div>';return rows.length}
  el.innerHTML=`<table><thead><tr><th>Time</th><th>Source</th><th>Severity</th><th>Description</th><th>Details</th></tr></thead><tbody>`+
   shown.map(a=>`<tr class="${a.id>lastId?"new":""}"><td class="mono">${fmtD(a.ts)}</td><td>${esc(a.src)}</td><td><span class="bg" style="background:${SC[a.sev]}">${SEV[a.sev]}</span></td><td>${esc(a.msg)}</td><td class="mono">${esc(a.detail)}</td></tr>`).join("")+`</tbody></table>`;
  return rows.length}

let D=null,sig="",lastId=0,tab="dash";
function render(d){
  D=d;const k=d.kpi;
  $("#k1").textContent=k.total.toLocaleString();$("#k2").textContent=k.high.toLocaleString();
  $("#k3").textContent=k.online+" / "+k.monitors;$("#k4").textContent=k.procs.toLocaleString();
  $("#host").textContent=d.host;
  if(tab=="dash"){
    area($("#c_tl"),d.tl.t0,d.tl.step,d.tl.series,SC.slice(1));
    $("#sevleg").innerHTML=[1,2,3,4].map(i=>`<span class="lg"><i style="background:${SC[i]}"></i>${SEV[i]} <b>${k.sev[i-1]}</b></span>`).join("");
    donut($("#c_src"),d.by_src,PAL,String(d.by_src.reduce((a,b)=>a+b.value,0)),"alerts");
    const tp=d.top_procs.map(p=>({name:p.name,value:p.mem,label:p.mem.toFixed(1)+"%"}));
    donut($("#c_proc"),tp,PAL,tp.reduce((a,b)=>a+b.value,0).toFixed(1)+"%","RAM (top 5)");
    $("#pa").textContent=d.procs_age==null?"no process data (is process_log.jsonl being written?)":(d.procs_live?"live from psutil":"snapshot "+d.procs_age+"s ago");
    if(d.src_time.series.length){bars($("#c_bar"),d.src_time.t0,d.src_time.step,d.src_time.series,PAL);
      $("#barleg").innerHTML=d.src_time.series.map((s,i)=>`<span class="lg"><i style="background:${PAL[i%PAL.length]}"></i>${esc(s.name)}</span>`).join("")}
    else{$("#c_bar").innerHTML='<div class="empty">no alerts yet</div>';$("#barleg").innerHTML=""}
    const m=d.metrics;
    $("#meters").innerHTML=Object.keys(m).length?[["CPU","cpu"],["Memory","mem"],["Disk /","disk"]].map(([n,key])=>`<div class="meter"><div class="t"><span>${n}</span><span>${m[key].toFixed(0)}%</span></div><div class="m"><i style="width:${m[key]}%;${m[key]>85?"background:#dc2626":""}"></i></div></div>`).join(""):'<div class="empty">install psutil for host metrics</div>';
    $("#mons").innerHTML=d.mons.length?d.mons.map(x=>{const on=x.age<120;return `<div class="lg"><i style="background:${on?"#16a34a":"#dc2626"}"></i><span>${esc(x.name)}</span><b class="${on?"ok":"bad"}">${on?"online":"silent"} &middot; ${x.age}s ago</b></div>`}).join(""):'<div class="empty">no heartbeats / events seen yet</div>'}
  const q=$("#q").value,ms=+$("#sev").value,newest=d.alerts.length?d.alerts[0].id:0;
  const s=[tab,q,ms,newest,d.alerts.length].join("|");
  if(s!==sig){sig=s;
    if(tab=="dash")table($("#t_recent"),d.alerts,q,ms,10,lastId);
    else $("#evc").textContent="("+table($("#t_all"),d.alerts,q,ms,200,lastId)+")";
    lastId=newest}}

function live(on){$("#live").className="live "+(on?"on":"off");$("#livet").textContent=on?"Live":"Reconnecting\u2026"}
function connect(){const es=new EventSource("/stream");
  es.onopen=()=>live(true);es.onmessage=e=>{live(true);render(JSON.parse(e.data))};es.onerror=()=>live(false)}
document.querySelectorAll(".tab").forEach(t=>t.onclick=()=>{
  document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("on",x===t));tab=t.dataset.t;
  $("#dash").style.display=tab=="dash"?"":"none";$("#ev").style.display=tab=="ev"?"":"none";sig="";if(D)render(D)});
["q","sev"].forEach(i=>$("#"+i).addEventListener("input",()=>{sig="";if(D)render(D)}));
let rt;window.addEventListener("resize",()=>{clearTimeout(rt);rt=setTimeout(()=>D&&render(D),150)});
connect();
</script></body></html>
"""

if __name__ == "__main__":
    main()
