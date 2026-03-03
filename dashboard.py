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
    }


def get_tunnels() -> list:
    """Parse active tunnel connections from ss."""
    lines = run("ss -tnp state established '( sport = :443 or sport = :19443 )' 2>/dev/null || ss -tnp | grep -E ':443|:19443'")
    tunnels = []
    for line in lines.splitlines():
        line = line.strip()
        if not line or line.startswith("State") or line.startswith("Recv-Q"):
            continue
        parts = line.split()
        if len(parts) >= 4:
            tunnels.append({
                "state": parts[0] if not parts[0].isdigit() else "ESTAB",
                "local": parts[-3] if len(parts) >= 5 else parts[1],
                "peer": parts[-2] if len(parts) >= 5 else parts[2],
                "process": parts[-1] if len(parts) >= 5 else "",
            })
    return tunnels


def get_logs(lines: int = 80) -> str:
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
</div>
""", active="overview")


def render_tunnels():
    tunnels = get_tunnels()
    rows = ""
    if not tunnels:
        rows = '<tr><td colspan="4" style="text-align:center;color:var(--text2);padding:32px;">No active connections</td></tr>'
    else:
        for t in tunnels:
            rows += f"""<tr>
<td><span class="badge badge-green">{html.escape(t['state'])}</span></td>
<td>{html.escape(t['local'])}</td>
<td>{html.escape(t['peer'])}</td>
<td style="font-size:12px;color:var(--text2);">{html.escape(t['process'])}</td>
</tr>"""

    return page("Tunnels", f"""
<div class="table-wrap">
<div class="table-header">
<h2>Active Connections ({len(tunnels)})</h2>
</div>
<table>
<tr><th>State</th><th>Local</th><th>Peer</th><th>Process</th></tr>
{rows}
</table>
</div>
""", active="tunnels")


def render_logs():
    logs = get_logs()
    return page("Logs", f"""
<div class="log-box">
<div class="table-header" style="display:flex;justify-content:space-between;align-items:center;">
<h2>Server Logs</h2>
<span style="font-size:12px;color:var(--text2);">Last 80 lines</span>
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
            return self._send_html(200, render_logs())
        if path == "/system":
            return self._send_html(200, render_system())

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
