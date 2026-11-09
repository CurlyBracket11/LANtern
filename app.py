"""
LANtern - LAN Network Monitoring System
Computer Networks (B.Tech CST, Sem V) - Project Based Learning

CN concepts used:
  * ICMP Echo Request/Reply  -> reachability + RTT        (Network layer)
  * TCP 3-way handshake      -> service/port check        (Transport layer)
  * IP addressing & subnets  -> /24 ping-sweep discovery  (Network layer)
  * Client-Server model      -> Flask web dashboard       (Application layer, HTTP)
"""
import csv
import io
import ipaddress
import os
import platform
import re
import socket
import sqlite3
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime
from pathlib import Path

from flask import (Flask, Response, flash, jsonify, redirect,
                   render_template, request, url_for)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "lantern.db"
CHECK_INTERVAL = 10          # seconds between monitoring cycles
HISTORY_LIMIT = 1000         # rows of history kept
TCP_TIMEOUT = 1.5            # seconds

app = Flask(__name__)
app.secret_key = os.environ.get("LANTERN_SECRET", "change-this-local-demo-key")


# ---------------------------------------------------------------- database
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with closing(db()) as conn, conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT NOT NULL UNIQUE,
            port INTEGER,
            port_status TEXT,
            status TEXT NOT NULL DEFAULT 'Unknown',
            latency REAL,
            last_seen TEXT,
            updated_at TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            latency REAL,
            checked_at TEXT NOT NULL,
            FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
        )""")
        # Migration for databases created by the first version of LANtern
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(devices)")}
        if "port" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN port INTEGER")
        if "port_status" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN port_status TEXT")


# ---------------------------------------------------------- network checks
_RTT_RE = re.compile(r"time\s*[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


def ping_device(ip, timeout_s=2):
    """Send one ICMP Echo Request using the OS `ping`.
    Returns (reachable, rtt_ms). RTT is parsed from ping's own output; if that
    fails we fall back to wall-clock time (includes process start-up overhead)."""
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
    try:
        start = time.perf_counter()
        res = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout_s + 2)
        elapsed = (time.perf_counter() - start) * 1000
        if res.returncode == 0:
            m = _RTT_RE.search(res.stdout)
            return True, round(float(m.group(1)) if m else elapsed, 2)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return False, None


def tcp_check(ip, port, timeout=TCP_TIMEOUT):
    """Try a TCP 3-way handshake. Returns (open, connect_time_ms)."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    start = time.perf_counter()
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
        return True, round((time.perf_counter() - start) * 1000, 2)
    except OSError:
        return False, None


def check_device(dev):
    """Run ICMP (+ optional TCP) checks. A device is Online if it answers ping
    OR its TCP service is open (covers hosts whose firewall drops ICMP)."""
    icmp_ok, rtt = ping_device(dev["ip"])
    port_status, tcp_ms = None, None
    if dev["port"]:
        ok, tcp_ms = tcp_check(dev["ip"], dev["port"])
        port_status = "Open" if ok else "Closed"
    online = icmp_ok or port_status == "Open"
    latency = rtt if icmp_ok else tcp_ms
    return dev["id"], ("Online" if online else "Offline"), latency, port_status


def monitor_cycle():
    with closing(db()) as conn:
        devices = conn.execute("SELECT id, ip, port FROM devices").fetchall()
    if not devices:
        return
    with ThreadPoolExecutor(max_workers=16) as pool:      # check in parallel
        results = list(pool.map(check_device, devices))
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with closing(db()) as conn, conn:
        for dev_id, status, latency, port_status in results:
            conn.execute(
                "UPDATE devices SET status=?, latency=?, port_status=?, "
                "last_seen=CASE WHEN ?='Online' THEN ? ELSE last_seen END, "
                "updated_at=? WHERE id=?",
                (status, latency, port_status, status, now, now, dev_id))
            conn.execute(
                "INSERT INTO history(device_id,status,latency,checked_at) "
                "VALUES(?,?,?,?)", (dev_id, status, latency, now))
        conn.execute("DELETE FROM history WHERE id NOT IN "
                     "(SELECT id FROM history ORDER BY id DESC LIMIT ?)",
                     (HISTORY_LIMIT,))


def monitor_loop():
    while True:
        try:
            monitor_cycle()
        except Exception as exc:                          # keep thread alive
            print("Monitor cycle error:", exc)
        time.sleep(CHECK_INTERVAL)


def local_ip():
    """Find this machine's LAN IP (UDP connect sends no packet)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


# --------------------------------------------------------------- data views
def fetch_state():
    with closing(db()) as conn:
        devices = [dict(r) for r in conn.execute(
            "SELECT * FROM devices ORDER BY name COLLATE NOCASE")]
        uptime = {r["device_id"]: r for r in conn.execute(
            "SELECT device_id, COUNT(*) n, "
            "SUM(status='Online') up, AVG(latency) avg_ms "
            "FROM history GROUP BY device_id")}
        recent = [dict(r) for r in conn.execute(
            "SELECT h.status, h.latency, h.checked_at, d.name, d.ip "
            "FROM history h JOIN devices d ON d.id=h.device_id "
            "ORDER BY h.id DESC LIMIT 12")]
    for d in devices:
        u = uptime.get(d["id"])
        d["uptime"] = round(100 * u["up"] / u["n"], 1) if u else None
        d["avg_latency"] = round(u["avg_ms"], 2) if u and u["avg_ms"] else None
    summary = {
        "total": len(devices),
        "online": sum(d["status"] == "Online" for d in devices),
        "offline": sum(d["status"] == "Offline" for d in devices),
    }
    return devices, recent, summary


# ------------------------------------------------------------------- routes
@app.route("/")
def dashboard():
    devices, recent, summary = fetch_state()
    return render_template("index.html", devices=devices, recent=recent,
                           check_interval=CHECK_INTERVAL, **summary)


@app.post("/devices")
def add_device():
    name = request.form.get("name", "").strip()
    ip = request.form.get("ip", "").strip()
    port_raw = request.form.get("port", "").strip()
    if not name or not ip:
        flash("Please enter both a device name and IP address.", "error")
        return redirect(url_for("dashboard"))
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        flash("Please enter a valid IPv4 or IPv6 address.", "error")
        return redirect(url_for("dashboard"))
    port = None
    if port_raw:
        if not (port_raw.isdigit() and 1 <= int(port_raw) <= 65535):
            flash("TCP port must be a number between 1 and 65535.", "error")
            return redirect(url_for("dashboard"))
        port = int(port_raw)
    try:
        with closing(db()) as conn, conn:
            conn.execute("INSERT INTO devices(name,ip,port) VALUES(?,?,?)",
                         (name[:60], ip, port))
        flash(f"{name} added to monitoring.", "success")
    except sqlite3.IntegrityError:
        flash("That IP address is already being monitored.", "error")
    return redirect(url_for("dashboard"))


@app.post("/devices/<int:device_id>/delete")
def delete_device(device_id):
    with closing(db()) as conn, conn:
        conn.execute("DELETE FROM devices WHERE id=?", (device_id,))  # cascades
    flash("Device removed.", "success")
    return redirect(url_for("dashboard"))


@app.get("/api/status")
def api_status():
    devices, recent, summary = fetch_state()
    return jsonify(devices=devices, history=recent, summary=summary)


@app.get("/api/discover")
def api_discover():
    """Ping-sweep the /24 subnet this machine is on (private ranges only)."""
    me = local_ip()
    addr = ipaddress.ip_address(me)
    if not addr.is_private or addr.is_loopback:
        return jsonify(error="No private LAN address found on this machine."), 400
    net = ipaddress.ip_network(f"{me}/24", strict=False)
    with closing(db()) as conn:
        known = {r["ip"] for r in conn.execute("SELECT ip FROM devices")}
    hosts = [str(h) for h in net.hosts() if str(h) not in known]
    with ThreadPoolExecutor(max_workers=64) as pool:
        alive = list(pool.map(lambda h: (h, ping_device(h, 1)[0]), hosts))
    found = [h for h, ok in alive if ok]
    return jsonify(subnet=str(net), local_ip=me, scanned=len(hosts), found=found)


@app.get("/export/history.csv")
def export_history():
    with closing(db()) as conn:
        rows = conn.execute(
            "SELECT d.name, d.ip, h.status, h.latency, h.checked_at "
            "FROM history h JOIN devices d ON d.id=h.device_id "
            "ORDER BY h.id").fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["device", "ip", "status", "latency_ms", "checked_at"])
    w.writerows([tuple(r) for r in rows])
    return Response(buf.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": "attachment; filename=lantern_history.csv"})


if __name__ == "__main__":
    init_db()
    threading.Thread(target=monitor_loop, daemon=True).start()
    # Default is localhost only. Set LANTERN_HOST=0.0.0.0 to open the
    # dashboard to other machines on your LAN (e.g. for a demo).
    host = os.environ.get("LANTERN_HOST", "127.0.0.1")
    port = int(os.environ.get("LANTERN_PORT", "5000"))
    print(f"\nLANtern is running at http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)
