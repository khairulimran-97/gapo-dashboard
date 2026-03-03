#!/usr/bin/env python3
"""Gapo Tunnel Server Dashboard - Single-file web application."""

import hashlib
import hmac
import html
import json
import os
import re
import subprocess
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

# ── Configuration ────────────────────────────────────────────────────────────
USERNAME = os.environ.get("DASH_USER", "admin")
PASSWORD = os.environ.get("DASH_PASS", "changeme")
PORT = int(os.environ.get("DASH_PORT", "8080"))
SECRET = os.environ.get("DASH_SECRET", "default-secret-change-me").encode()
GAPO_TOKEN = os.environ.get("GAPO_TOKEN", "")
GAPO_DOMAIN = os.environ.get("GAPO_DOMAIN", "share.hostpanel.icu")
GAPO_TUNNEL = os.environ.get("GAPO_TUNNEL", "19443")

# Set timezone
os.environ["TZ"] = os.environ.get("DASH_TZ", "Asia/Kuala_Lumpur")
try:
    time.tzset()
except AttributeError:
    pass  # Windows

SESSION_MAX_AGE = 86400  # 24 hours


# ── Auth helpers ─────────────────────────────────────────────────────────────
def make_session_token(username: str) -> str:
    ts = str(int(time.time()))
    msg = f"{username}:{ts}".encode()
    sig = hmac.new(SECRET, msg, hashlib.sha256).hexdigest()
    return f"{username}:{ts}:{sig}"


def verify_session_token(token: str) -> bool:
    try:
        username, ts, sig = token.split(":", 2)
        msg = f"{username}:{ts}".encode()
        expected = hmac.new(SECRET, msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        if time.time() - int(ts) > SESSION_MAX_AGE:
            return False
        return username == USERNAME
    except Exception:
        return False


# ── Data collection ──────────────────────────────────────────────────────────
def run(cmd: str, timeout: int = 5) -> str:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except Exception as e:
        return f"Error: {e}"


def get_overview() -> dict:
    status_raw = run("systemctl is-active gapo-server")
    status = status_raw.strip()

    pid = ""
    mem = ""
    cpu = ""
    uptime = ""

    if status == "active":
        show = run("systemctl show gapo-server --property=MainPID,MemoryCurrent,CPUUsageNSec,ActiveEnterTimestamp")
        props = {}
        for line in show.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                props[k.strip()] = v.strip()

        pid = props.get("MainPID", "")

        mem_bytes = props.get("MemoryCurrent", "")
        if mem_bytes and mem_bytes != "[not set]":
            try:
                mb = int(mem_bytes) / (1024 * 1024)
                mem = f"{mb:.1f} MB"
            except ValueError:
                mem = mem_bytes

        cpu_ns = props.get("CPUUsageNSec", "")
        if cpu_ns and cpu_ns != "[not set]":
            try:
                cpu = f"{int(cpu_ns) / 1e9:.2f}s"
            except ValueError:
                cpu = cpu_ns

        ts = props.get("ActiveEnterTimestamp", "")
        if ts:
            uptime = ts

    version = run("/usr/local/bin/gapo-server --version 2>&1 || echo unknown")

    return {
        "status": status,
        "pid": pid,
        "memory": mem,
        "cpu_time": cpu,
        "uptime_since": uptime,
        "version": version,
        "token": GAPO_TOKEN,
    }


def get_tunnels() -> list:
    """Parse active tunnels from gapo-server logs (registered/closed events)."""
    logs = run("journalctl -u gapo-server --no-pager -n 500 --output=short-iso 2>/dev/null", timeout=10)
    # Track tunnel state: last "registered" without a subsequent "session closed" = active
    tunnels = {}  # subdomain -> {client, type, time}
    for line in logs.splitlines():
        # registered: dashboard.share.hostpanel.icu (127.0.0.1:45720) [http]
        m = re.search(r'tunnel: registered (\S+) \(([^)]+)\) \[(\w+)\]', line)
        if m:
            subdomain, client, ttype = m.group(1), m.group(2), m.group(3)
            # Extract timestamp from line start
            ts = line.split(" ", 1)[0] if line else ""
            tunnels[subdomain] = {
                "subdomain": subdomain,
                "client": client,
                "type": ttype,
                "time": ts,
                "active": True,
            }
            continue
        # session closed for dashboard.share.hostpanel.icu
        m = re.search(r'tunnel: session closed for (\S+)', line)
        if m:
            subdomain = m.group(1)
            if subdomain in tunnels:
                tunnels[subdomain]["active"] = False
    return list(tunnels.values())


def get_logs(lines: int = 80, filter_str: str = "") -> str:
    if filter_str:
        # Get more lines and grep for the filter, keeping last N matches
        return run(f"journalctl -u gapo-server --no-pager -n 2000 --output=short-iso 2>/dev/null | grep -i '{filter_str}' | tail -n {lines}", timeout=10) or "No matching log entries"
    return run(f"journalctl -u gapo-server --no-pager -n {lines} --output=short-iso 2>/dev/null || echo 'No logs available'", timeout=10)


def get_system() -> dict:
    # Load average
    load = ""
    try:
        with open("/proc/loadavg") as f:
            load = f.read().strip()
    except Exception:
        load = run("uptime")

    # Memory
    mem_info = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    mem_info[key] = int(parts[1])  # in kB
    except Exception:
        pass

    total_mb = mem_info.get("MemTotal", 0) / 1024
    avail_mb = mem_info.get("MemAvailable", 0) / 1024
    used_mb = total_mb - avail_mb

    # Disk
    disk = run("df -h / | tail -1")

    # System uptime
    sys_uptime = ""
    try:
        with open("/proc/uptime") as f:
            secs = float(f.read().split()[0])
            days = int(secs // 86400)
            hours = int((secs % 86400) // 3600)
            mins = int((secs % 3600) // 60)
            sys_uptime = f"{days}d {hours}h {mins}m"
    except Exception:
        sys_uptime = run("uptime -p")

    # CPU info
    cpu_count = os.cpu_count() or 0
    cpu_model = ""
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu_model = line.split(":", 1)[1].strip()
                    break
    except Exception:
        pass

    # Hostname
    hostname = run("hostname")

    return {
        "hostname": hostname,
        "load_average": load,
        "memory_total_mb": round(total_mb, 1),
        "memory_used_mb": round(used_mb, 1),
        "memory_avail_mb": round(avail_mb, 1),
        "memory_pct": round(used_mb / total_mb * 100, 1) if total_mb else 0,
        "disk": disk,
        "system_uptime": sys_uptime,
        "cpu_count": cpu_count,
        "cpu_model": cpu_model,
    }


# ── HTML Templates ───────────────────────────────────────────────────────────
CSS = """
:root {
    --bg: #0f1117;
    --surface: #1a1d27;
    --surface2: #232734;
    --border: #2e3348;
    --text: #e1e4ed;
    --text2: #8b90a5;
    --accent: #6c7bf7;
    --accent2: #4e5bcf;
    --green: #34d399;
    --red: #f87171;
    --yellow: #fbbf24;
    --orange: #fb923c;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Nav */
.nav {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 0 24px;
    display: flex;
    align-items: center;
    height: 56px;
    gap: 32px;
}
.nav-brand {
    font-size: 18px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: -0.5px;
}
.nav-links { display: flex; gap: 4px; flex: 1; }
.nav-links a {
    padding: 8px 16px;
    border-radius: 8px;
    color: var(--text2);
    font-size: 14px;
    font-weight: 500;
    transition: all 0.15s;
}
.nav-links a:hover { background: var(--surface2); color: var(--text); text-decoration: none; }
.nav-links a.active { background: var(--accent); color: #fff; }
.nav-right { font-size: 13px; color: var(--text2); display: flex; align-items: center; gap: 16px; }
.nav-right a { color: var(--text2); font-size: 13px; }
.nav-right a:hover { color: var(--red); }

/* Layout */
.container { max-width: 1200px; margin: 0 auto; padding: 24px; }

/* Cards */
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 24px; }
.card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
}
.card-title { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--text2); margin-bottom: 12px; }
.card-value { font-size: 28px; font-weight: 700; }
.card-sub { font-size: 13px; color: var(--text2); margin-top: 4px; }

/* Status badge */
.badge {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 600;
}
.badge-green { background: rgba(52,211,153,0.15); color: var(--green); }
.badge-red { background: rgba(248,113,113,0.15); color: var(--red); }

/* Table */
.table-wrap {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    margin-bottom: 24px;
}
.table-header { padding: 16px 20px; border-bottom: 1px solid var(--border); }
.table-header h2 { font-size: 16px; font-weight: 600; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; padding: 12px 20px; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--text2); border-bottom: 1px solid var(--border); }
td { padding: 12px 20px; font-size: 14px; border-bottom: 1px solid var(--border); }
tr:last-child td { border-bottom: none; }
tr:hover { background: var(--surface2); }

/* Logs */
.log-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
}
.log-box pre {
    padding: 16px 20px;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 12px;
    line-height: 1.6;
    overflow-x: auto;
    max-height: 600px;
    overflow-y: auto;
    color: var(--text2);
    white-space: pre-wrap;
    word-break: break-all;
}

/* Progress bar */
.progress-bar {
    height: 8px;
    background: var(--surface2);
    border-radius: 4px;
    overflow: hidden;
    margin-top: 8px;
}
.progress-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 0.3s;
}

/* Login */
.login-wrap {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
}
.login-box {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 40px;
    width: 380px;
}
.login-box h1 { font-size: 24px; margin-bottom: 8px; }
.login-box p { color: var(--text2); font-size: 14px; margin-bottom: 24px; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px; color: var(--text2); }
.form-group input {
    width: 100%;
    padding: 10px 14px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-size: 14px;
    outline: none;
}
.form-group input:focus { border-color: var(--accent); }
.btn {
    width: 100%;
    padding: 10px;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    margin-top: 8px;
}
.btn:hover { background: var(--accent2); }
.error-msg { color: var(--red); font-size: 13px; margin-top: 12px; text-align: center; }

/* Responsive */
@media (max-width: 768px) {
    .nav { padding: 0 12px; gap: 12px; }
    .nav-links a { padding: 6px 10px; font-size: 13px; }
    .container { padding: 16px; }
    .grid { grid-template-columns: 1fr; }
    .card-value { font-size: 22px; }
}

/* Refresh indicator */
.refresh-dot {
    width: 8px; height: 8px;
    background: var(--green);
    border-radius: 50%;
    display: inline-block;
    animation: pulse 2s infinite;
}
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
}

/* Setup page */
.setup-section {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 20px;
}
.setup-section h3 {
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.setup-section p { color: var(--text2); font-size: 14px; line-height: 1.6; margin-bottom: 12px; }
.code-block {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 18px;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 13px;
    line-height: 1.6;
    overflow-x: auto;
    color: var(--text);
    margin-bottom: 12px;
    position: relative;
}
.code-block .copy-btn {
    position: absolute;
    top: 8px;
    right: 8px;
    padding: 4px 10px;
    background: var(--surface2);
    color: var(--text2);
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
    font-size: 11px;
}
.code-block .copy-btn:hover { background: var(--accent); color: #fff; border-color: var(--accent); }
.tab-row { display: flex; gap: 4px; margin-bottom: 16px; }
.tab-btn {
    padding: 6px 16px;
    background: var(--surface2);
    color: var(--text2);
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
    font-size: 13px;
    font-weight: 500;
}
.tab-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
.tab-content { display: none; }
.tab-content.active { display: block; }
.step-num {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    background: var(--accent);
    color: #fff;
    border-radius: 50%;
    font-size: 13px;
    font-weight: 700;
}
"""

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gapo Dashboard - Login</title>
<style>{css}</style>
</head>
<body>
<div class="login-wrap">
<div class="login-box">
<h1>Gapo Dashboard</h1>
<p>Sign in to monitor your tunnel server</p>
<form method="POST" action="/login">
<div class="form-group">
<label>Username</label>
<input type="text" name="username" autocomplete="username" required autofocus>
</div>
<div class="form-group">
<label>Password</label>
<input type="password" name="password" autocomplete="current-password" required>
</div>
<button type="submit" class="btn">Sign In</button>
{error}
</form>
</div>
</div>
</body>
</html>"""

PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gapo Dashboard - {title}</title>
<style>{css}</style>
</head>
<body>
<nav class="nav">
<div class="nav-brand">Gapo Dashboard</div>
<div class="nav-links">
<a href="/setup" class="{active_setup}">Setup</a>
<a href="/" class="{active_overview}">Overview</a>
<a href="/tunnels" class="{active_tunnels}">Tunnels</a>
<a href="/logs" class="{active_logs}">Logs</a>
<a href="/system" class="{active_system}">System</a>
</div>
<div class="nav-right">
<span class="refresh-dot"></span> Auto-refresh
<a href="/logout">Logout</a>
</div>
</nav>
<div class="container">{content}</div>
<script>{js}</script>
</body>
</html>"""

JS_REFRESH = """
(function() {
    let countdown = 10;
    setInterval(function() {
        countdown--;
        if (countdown <= 0) {
            location.reload();
        }
    }, 1000);
})();
"""


def page(title, content, active=""):
    return PAGE_TEMPLATE.format(
        title=title,
        css=CSS,
        content=content,
        js=JS_REFRESH,
        active_overview="active" if active == "overview" else "",
        active_tunnels="active" if active == "tunnels" else "",
        active_logs="active" if active == "logs" else "",
        active_system="active" if active == "system" else "",
        active_setup="active" if active == "setup" else "",
    )


def render_overview():
    d = get_overview()
    status_badge = (
        '<span class="badge badge-green">Running</span>'
        if d["status"] == "active"
        else '<span class="badge badge-red">Stopped</span>'
    )
    return page("Overview", f"""
<h2 style="font-size:20px;margin-bottom:20px;">Server Overview</h2>
<div class="grid">
<div class="card">
<div class="card-title">Status</div>
<div class="card-value">{status_badge}</div>
<div class="card-sub">PID: {html.escape(d['pid'] or 'N/A')}</div>
</div>
<div class="card">
<div class="card-title">Active Since</div>
<div class="card-value" style="font-size:16px;">{html.escape(d['uptime_since'] or 'N/A')}</div>
</div>
<div class="card">
<div class="card-title">Memory Usage</div>
<div class="card-value">{html.escape(d['memory'] or 'N/A')}</div>
</div>
<div class="card">
<div class="card-title">CPU Time</div>
<div class="card-value">{html.escape(d['cpu_time'] or 'N/A')}</div>
</div>
</div>
<div class="grid">
<div class="card">
<div class="card-title">Version</div>
<div class="card-value" style="font-size:16px;">{html.escape(d['version'])}</div>
</div>
<div class="card" style="grid-column: span 2;">
<div class="card-title">Token</div>
<div style="display:flex;align-items:center;gap:10px;">
<code id="token-val" style="font-size:13px;background:var(--surface2);padding:8px 12px;border-radius:6px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{html.escape(d['token'] or 'N/A')}</code>
<button onclick="navigator.clipboard.writeText(document.getElementById('token-val').textContent).then(()=>this.textContent='Copied!').catch(()=>{{}})" style="padding:6px 14px;background:var(--accent);color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:12px;white-space:nowrap;">Copy</button>
</div>
</div>
</div>
""", active="overview")


def render_tunnels():
    tunnels = get_tunnels()
    active = [t for t in tunnels if t["active"]]
    inactive = [t for t in tunnels if not t["active"]]

    active_rows = ""
    if not active:
        active_rows = '<tr><td colspan="6" style="text-align:center;color:var(--text2);padding:32px;">No active tunnels</td></tr>'
    else:
        for t in active:
            url = f'https://{t["subdomain"]}'
            log_url = f'/logs?filter={urllib.parse.quote(t["subdomain"])}'
            active_rows += f"""<tr>
<td><span class="badge badge-green">Active</span></td>
<td><a href="{html.escape(url)}" target="_blank" style="color:var(--accent);">{html.escape(t['subdomain'])}</a></td>
<td><span class="badge" style="background:rgba(108,123,247,0.15);color:var(--accent);">{html.escape(t['type'].upper())}</span></td>
<td>{html.escape(t['client'])}</td>
<td style="font-size:12px;color:var(--text2);">{html.escape(t['time'])}</td>
<td><a href="{html.escape(log_url)}" style="font-size:12px;color:var(--accent);">View Logs</a></td>
</tr>"""

    recent_rows = ""
    if inactive:
        for t in inactive:
            log_url = f'/logs?filter={urllib.parse.quote(t["subdomain"])}'
            recent_rows += f"""<tr>
<td><span class="badge badge-red">Closed</span></td>
<td style="color:var(--text2);">{html.escape(t['subdomain'])}</td>
<td><span class="badge" style="background:var(--surface2);color:var(--text2);">{html.escape(t['type'].upper())}</span></td>
<td style="color:var(--text2);">{html.escape(t['client'])}</td>
<td style="font-size:12px;color:var(--text2);">{html.escape(t['time'])}</td>
<td><a href="{html.escape(log_url)}" style="font-size:12px;color:var(--accent);">View Logs</a></td>
</tr>"""

    recent_section = ""
    if inactive:
        recent_section = f"""
<div class="table-wrap">
<div class="table-header">
<h2>Recently Closed</h2>
</div>
<table>
<tr><th>Status</th><th>Subdomain</th><th>Type</th><th>Client</th><th>Registered</th><th></th></tr>
{recent_rows}
</table>
</div>"""

    return page("Tunnels", f"""
<div class="grid">
<div class="card">
<div class="card-title">Active Tunnels</div>
<div class="card-value">{len(active)}</div>
</div>
<div class="card">
<div class="card-title">Total Seen (This Session)</div>
<div class="card-value">{len(tunnels)}</div>
</div>
</div>
<div class="table-wrap">
<div class="table-header">
<h2>Active Tunnels</h2>
</div>
<table>
<tr><th>Status</th><th>Subdomain</th><th>Type</th><th>Client</th><th>Registered</th><th></th></tr>
{active_rows}
</table>
</div>
{recent_section}
""", active="tunnels")


def render_logs(filter_str: str = ""):
    logs = get_logs(filter_str=filter_str)
    safe_filter = html.escape(filter_str)

    filter_bar = ""
    if filter_str:
        filter_bar = f"""
<div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;">
<span style="font-size:13px;color:var(--text2);">Filtered by:</span>
<code style="background:var(--surface);padding:6px 12px;border-radius:6px;font-size:13px;border:1px solid var(--border);">{safe_filter}</code>
<a href="/logs" style="font-size:13px;color:var(--accent);">Clear filter</a>
</div>"""

    title = f"Logs — {safe_filter}" if filter_str else "Server Logs"
    subtitle = f"Matching entries for {safe_filter}" if filter_str else "Last 80 lines"

    return page("Logs", f"""
{filter_bar}
<div class="log-box">
<div class="table-header" style="display:flex;justify-content:space-between;align-items:center;">
<h2>{title}</h2>
<span style="font-size:12px;color:var(--text2);">{subtitle}</span>
</div>
<pre>{html.escape(logs)}</pre>
</div>
""", active="logs")


def render_system():
    s = get_system()
    mem_pct = s["memory_pct"]
    mem_color = "var(--green)" if mem_pct < 70 else "var(--yellow)" if mem_pct < 90 else "var(--red)"

    # Parse disk info
    disk_parts = s["disk"].split()
    disk_size = disk_parts[1] if len(disk_parts) > 1 else "?"
    disk_used = disk_parts[2] if len(disk_parts) > 2 else "?"
    disk_avail = disk_parts[3] if len(disk_parts) > 3 else "?"
    disk_pct_str = disk_parts[4] if len(disk_parts) > 4 else "0%"
    disk_pct = int(disk_pct_str.replace("%", "")) if "%" in disk_pct_str else 0
    disk_color = "var(--green)" if disk_pct < 70 else "var(--yellow)" if disk_pct < 90 else "var(--red)"

    return page("System", f"""
<h2 style="font-size:20px;margin-bottom:20px;">System Information</h2>
<div class="grid">
<div class="card">
<div class="card-title">Hostname</div>
<div class="card-value" style="font-size:18px;">{html.escape(s['hostname'])}</div>
</div>
<div class="card">
<div class="card-title">System Uptime</div>
<div class="card-value" style="font-size:18px;">{html.escape(s['system_uptime'])}</div>
</div>
<div class="card">
<div class="card-title">Load Average</div>
<div class="card-value" style="font-size:16px;">{html.escape(s['load_average'])}</div>
</div>
<div class="card">
<div class="card-title">CPU</div>
<div class="card-value">{s['cpu_count']} cores</div>
<div class="card-sub">{html.escape(s['cpu_model'])}</div>
</div>
</div>
<div class="grid">
<div class="card">
<div class="card-title">Memory</div>
<div class="card-value">{s['memory_used_mb']} MB <span style="font-size:14px;color:var(--text2);">/ {s['memory_total_mb']} MB</span></div>
<div class="card-sub">{s['memory_avail_mb']} MB available ({mem_pct}% used)</div>
<div class="progress-bar"><div class="progress-fill" style="width:{mem_pct}%;background:{mem_color};"></div></div>
</div>
<div class="card">
<div class="card-title">Disk (root)</div>
<div class="card-value">{html.escape(disk_used)} <span style="font-size:14px;color:var(--text2);">/ {html.escape(disk_size)}</span></div>
<div class="card-sub">{html.escape(disk_avail)} available ({disk_pct}% used)</div>
<div class="progress-bar"><div class="progress-fill" style="width:{disk_pct}%;background:{disk_color};"></div></div>
</div>
</div>
""", active="system")


def render_setup():
    server_addr = f"{GAPO_DOMAIN}:{GAPO_TUNNEL}"
    token = html.escape(GAPO_TOKEN)
    domain = html.escape(GAPO_DOMAIN)

    return page("Setup", f"""
<h2 style="font-size:20px;margin-bottom:20px;">Client Setup Guide</h2>

<div class="setup-section">
<h3><span class="step-num">1</span> Download Gapo Client</h3>
<p>Download the latest gapo client for your operating system from GitHub:</p>
<div class="tab-row">
<button class="tab-btn active" onclick="switchTab(event,'dl-linux')">Linux</button>
<button class="tab-btn" onclick="switchTab(event,'dl-mac')">macOS</button>
<button class="tab-btn" onclick="switchTab(event,'dl-win')">Windows</button>
</div>
<div id="dl-linux" class="tab-content active">
<div class="code-block"><button class="copy-btn" onclick="copyCode(this)">Copy</button>curl -L -o gapo.tar.gz https://github.com/ghostbirdme/gapo/releases/download/v1.0.1/gapo_1.0.1_linux_amd64.tar.gz
tar xzf gapo.tar.gz
sudo mv gapo /usr/local/bin/
chmod +x /usr/local/bin/gapo</div>
</div>
<div id="dl-mac" class="tab-content">
<p style="margin-bottom:8px;"><strong>Intel Mac:</strong></p>
<div class="code-block"><button class="copy-btn" onclick="copyCode(this)">Copy</button>curl -L -o gapo.tar.gz https://github.com/ghostbirdme/gapo/releases/download/v1.0.1/gapo_1.0.1_darwin_amd64.tar.gz
tar xzf gapo.tar.gz
sudo mv gapo /usr/local/bin/</div>
<p style="margin-bottom:8px;"><strong>Apple Silicon (M1/M2/M3):</strong></p>
<div class="code-block"><button class="copy-btn" onclick="copyCode(this)">Copy</button>curl -L -o gapo.tar.gz https://github.com/ghostbirdme/gapo/releases/download/v1.0.1/gapo_1.0.1_darwin_arm64.tar.gz
tar xzf gapo.tar.gz
sudo mv gapo /usr/local/bin/</div>
</div>
<div id="dl-win" class="tab-content">
<p>Download from <a href="https://github.com/ghostbirdme/gapo/releases/tag/v1.0.1" target="_blank" style="color:var(--accent);">GitHub Releases</a> and extract <code>gapo.exe</code> to a folder in your PATH.</p>
</div>
</div>

<div class="setup-section">
<h3><span class="step-num">2</span> Server Details</h3>
<p>Use these details to connect to this Gapo server:</p>
<table style="width:100%;">
<tr><td style="color:var(--text2);width:140px;padding:8px 0;">Server</td><td><code style="background:var(--bg);padding:4px 10px;border-radius:4px;">{html.escape(server_addr)}</code></td></tr>
<tr><td style="color:var(--text2);padding:8px 0;">Token</td><td><code id="setup-token" style="background:var(--bg);padding:4px 10px;border-radius:4px;word-break:break-all;">{token}</code> <button onclick="navigator.clipboard.writeText(document.getElementById('setup-token').textContent)" style="padding:2px 8px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:11px;margin-left:6px;">Copy</button></td></tr>
<tr><td style="color:var(--text2);padding:8px 0;">Domain</td><td><code style="background:var(--bg);padding:4px 10px;border-radius:4px;">{domain}</code></td></tr>
</table>
</div>

<div class="setup-section">
<h3><span class="step-num">3</span> Connect — HTTP Tunnel</h3>
<p>Expose a local web app (e.g. port 3000) to the internet:</p>
<div class="code-block"><button class="copy-btn" onclick="copyCode(this)">Copy</button>gapo --server {html.escape(server_addr)} --token {token} --http myapp 3000</div>
<p>Your app will be available at <code>https://myapp.{domain}</code></p>
<p style="color:var(--text2);font-size:13px;">Replace <code>myapp</code> with your desired subdomain and <code>3000</code> with your local port.</p>
</div>

<div class="setup-section">
<h3><span class="step-num">4</span> Connect — TCP Tunnel</h3>
<p>Expose a TCP service (SSH, database, etc.):</p>
<div class="code-block"><button class="copy-btn" onclick="copyCode(this)">Copy</button># SSH
gapo --server {html.escape(server_addr)} --token {token} --tcp ssh 22

# MySQL
gapo --server {html.escape(server_addr)} --token {token} --tcp mysql 3306

# PostgreSQL
gapo --server {html.escape(server_addr)} --token {token} --tcp postgres 5432</div>
<p style="color:var(--text2);font-size:13px;">The server will assign a public port (30000-39999) for your TCP tunnel.</p>
</div>

<div class="setup-section">
<h3><span class="step-num">5</span> Save Config (Skip Flags)</h3>
<p>Create <code>~/.gapo/config</code> to avoid repeating <code>--server</code> and <code>--token</code> every time:</p>
<div class="code-block"><button class="copy-btn" onclick="copyCode(this)">Copy</button>mkdir -p ~/.gapo
cat > ~/.gapo/config &lt;&lt; 'EOF'
GAPO_SERVER={html.escape(server_addr)}
GAPO_TOKEN={token}
EOF</div>
<p>Then simply run:</p>
<div class="code-block"><button class="copy-btn" onclick="copyCode(this)">Copy</button># HTTP tunnel
gapo --http myapp 3000

# TCP tunnel
gapo --tcp ssh 22</div>
<p style="margin-top:12px;"><strong>All config options:</strong></p>
<table style="width:100%;font-size:13px;">
<tr><th style="text-align:left;padding:6px 0;color:var(--text2);">Key</th><th style="text-align:left;padding:6px 0;color:var(--text2);">CLI Flag</th><th style="text-align:left;padding:6px 0;color:var(--text2);">Description</th></tr>
<tr><td><code>GAPO_SERVER</code></td><td><code>--server</code></td><td style="color:var(--text2);">Server address</td></tr>
<tr><td><code>GAPO_TOKEN</code></td><td><code>--token</code></td><td style="color:var(--text2);">Auth token</td></tr>
<tr><td><code>GAPO_TLS</code></td><td><code>--tls</code></td><td style="color:var(--text2);">Encrypt tunnel connection (true/false)</td></tr>
<tr><td><code>GAPO_INSECURE</code></td><td><code>--insecure</code></td><td style="color:var(--text2);">Allow self-signed certs (true/false)</td></tr>
</table>
<p style="color:var(--text2);font-size:13px;margin-top:8px;">CLI flags override config file values.</p>
</div>

<script>
function switchTab(e, id) {{
    var parent = e.target.closest('.setup-section');
    parent.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    parent.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    e.target.classList.add('active');
    document.getElementById(id).classList.add('active');
}}
function copyCode(btn) {{
    var block = btn.parentElement;
    var text = block.textContent.replace('Copy', '').trim();
    navigator.clipboard.writeText(text).then(() => {{
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy', 2000);
    }});
}}
</script>
""", active="setup")


# ── HTTP Handler ─────────────────────────────────────────────────────────────
class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default logging to stderr

    def _get_cookie(self, name: str) -> str:
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith(f"{name}="):
                return urllib.parse.unquote(part[len(name) + 1:])
        return ""

    def _is_authed(self) -> bool:
        token = self._get_cookie("session")
        return verify_session_token(token)

    def _send_html(self, code: int, body: str, headers: dict = None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, code: int, obj: dict):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location: str, headers: dict = None):
        self.send_response(302)
        self.send_header("Location", location)
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()

    def _parse_qs(self) -> dict:
        if "?" in self.path:
            return urllib.parse.parse_qs(self.path.split("?", 1)[1])
        return {}

    def do_GET(self):
        path = self.path.split("?")[0]

        # Login page
        if path == "/login":
            if self._is_authed():
                return self._redirect("/")
            return self._send_html(200, LOGIN_PAGE.format(css=CSS, error=""))

        # Logout
        if path == "/logout":
            return self._redirect("/login", {
                "Set-Cookie": "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            })

        # Auth check for all other routes
        if not self._is_authed():
            return self._redirect("/login")

        # API endpoints (for potential future AJAX use)
        if path == "/api/overview":
            return self._send_json(200, get_overview())
        if path == "/api/tunnels":
            return self._send_json(200, get_tunnels())
        if path == "/api/system":
            return self._send_json(200, get_system())
        if path == "/api/logs":
            return self._send_json(200, {"logs": get_logs()})

        # Pages
        if path == "/" or path == "/overview":
            return self._send_html(200, render_overview())
        if path == "/tunnels":
            return self._send_html(200, render_tunnels())
        if path == "/logs":
            qs = self._parse_qs()
            filter_str = qs.get("filter", [""])[0]
            return self._send_html(200, render_logs(filter_str=filter_str))
        if path == "/system":
            return self._send_html(200, render_system())
        if path == "/setup":
            return self._send_html(200, render_setup())

        # Favicon
        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        # 404
        self._send_html(404, page("Not Found", '<div style="text-align:center;padding:60px;"><h2>404 - Not Found</h2></div>'))

    def do_POST(self):
        path = self.path.split("?")[0]

        if path == "/login":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            params = urllib.parse.parse_qs(body)

            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            if hmac.compare_digest(username, USERNAME) and hmac.compare_digest(password, PASSWORD):
                token = make_session_token(username)
                cookie = f"session={urllib.parse.quote(token)}; Path=/; Max-Age={SESSION_MAX_AGE}; HttpOnly; SameSite=Lax"
                # Render dashboard directly with Set-Cookie instead of 302 redirect
                # (gapo tunnel follows redirects server-side, which loses the cookie)
                return self._send_html(200, render_overview(), {"Set-Cookie": cookie})
            else:
                return self._send_html(401, LOGIN_PAGE.format(
                    css=CSS,
                    error='<div class="error-msg">Invalid username or password</div>'
                ))

        self._send_html(405, "Method Not Allowed")

    def do_HEAD(self):
        self.do_GET()


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    server = HTTPServer(("0.0.0.0", PORT), DashboardHandler)
    print(f"Gapo Dashboard running on http://0.0.0.0:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    print("Dashboard stopped.")


if __name__ == "__main__":
    main()
