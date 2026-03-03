# Gapo Dashboard

A lightweight web dashboard for monitoring [Gapo](https://github.com/ghostbirdme/gapo) tunnel servers. Built with Python standard library only — no pip, no frameworks, no dependencies.

![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue)

## Features

- **Server Overview** — status, PID, memory, CPU time, uptime, version, token (with copy button)
- **Active Tunnels** — real-time connections via `ss`
- **Logs Viewer** — live `journalctl` output for gapo-server
- **System Metrics** — CPU, memory, disk usage with progress bars
- **Authentication** — HMAC-signed cookie-based login
- **Dark Theme** — modern UI with 10-second auto-refresh
- **Timezone Support** — configurable timezone (default: Asia/Kuala_Lumpur)
- **Single File** — entire app in one Python file, zero dependencies

## Architecture

```
Browser → https://dashboard.example.com
             ↓ (gapo tunnel)
         localhost:8080
             ↓
      Python dashboard (http.server)
             ↓
      systemctl / journalctl / /proc
```

## Quick Start (Local Development)

Run the dashboard locally for testing without systemd:

```bash
git clone https://github.com/khairulimran-97/gapo-dashboard.git
cd gapo-dashboard

# Set required environment variables
export DASH_USER=admin
export DASH_PASS=mypassword
export DASH_PORT=8080
export DASH_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export DASH_TZ=Asia/Kuala_Lumpur
export GAPO_TOKEN=your-gapo-token-here

# Run
python3 dashboard.py
```

Open `http://localhost:8080` in your browser and login with the credentials above.

> **Note:** Some features (systemd status, journalctl logs) require the gapo-server to be running on the same machine. On a local dev machine without gapo-server, those sections will show "N/A" or "inactive".

## Server Installation

### 1. Clone and place the dashboard

```bash
git clone https://github.com/khairulimran-97/gapo-dashboard.git
sudo mkdir -p /opt/gapo-dashboard
sudo cp gapo-dashboard/dashboard.py /opt/gapo-dashboard/
sudo chmod +x /opt/gapo-dashboard/dashboard.py
```

### 2. Create configuration

```bash
sudo mkdir -p /etc/gapo-dashboard
sudo cp gapo-dashboard/config.example /etc/gapo-dashboard/config
sudo chmod 600 /etc/gapo-dashboard/config
```

Edit `/etc/gapo-dashboard/config`:

```bash
DASH_USER=admin
DASH_PASS=your-secure-password
DASH_PORT=8080
DASH_SECRET=your-random-secret-for-cookie-signing
DASH_TZ=Asia/Kuala_Lumpur
```

Generate secure values:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(16))"   # password
python3 -c "import secrets; print(secrets.token_hex(32))"        # secret
```

### 3. Install systemd services

```bash
sudo cp gapo-dashboard/systemd/gapo-dashboard.service /etc/systemd/system/
sudo cp gapo-dashboard/systemd/gapo-client-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gapo-dashboard
sudo systemctl enable --now gapo-client-dashboard
```

### 4. Verify

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/
# Expected: 302 (redirect to login)

systemctl status gapo-dashboard gapo-client-dashboard
# Expected: both active
```

## Exposing via Gapo Tunnel

The `gapo-client-dashboard.service` runs the gapo client to expose the dashboard publicly:

```
gapo --server 127.0.0.1:19443 --token $GAPO_TOKEN --no-tui --http dashboard 8080
```

This registers `https://dashboard.<your-domain>` pointing to `localhost:8080`.

> **Note:** If running the gapo client on the same machine as the server, use `127.0.0.1:19443` instead of the public domain to avoid NAT hairpin issues.

## Configuration Reference

| Variable | Description | Default |
|---|---|---|
| `DASH_USER` | Login username | `admin` |
| `DASH_PASS` | Login password | `changeme` |
| `DASH_PORT` | Dashboard HTTP port | `8080` |
| `DASH_SECRET` | Secret key for cookie signing | - |
| `DASH_TZ` | Timezone for timestamps | `Asia/Kuala_Lumpur` |
| `GAPO_TOKEN` | Gapo server auth token (displayed on overview) | - |

The dashboard service loads two environment files:
- `/etc/gapo-dashboard/config` — dashboard credentials and settings
- `/etc/gapo/config` — gapo server config (provides `GAPO_TOKEN`)

## Firewall / Ports

The following ports **must be open** on your cloud provider's firewall (e.g. Tencent Cloud Lighthouse, AWS Security Group, etc.) for the gapo server and dashboard to work:

| Port | Protocol | Purpose | Who connects |
|---|---|---|---|
| **80** | TCP | ACME certificate challenges + HTTP→HTTPS redirect | Browsers, Let's Encrypt |
| **443** | TCP | HTTPS — serves tunneled sites to visitors | Browsers |
| **19443** | TCP | Tunnel control — gapo clients connect here | Gapo clients (laptops, servers) |

> **Important:** Without port **19443** open, external gapo clients will not be able to connect and register tunnels. If you only open 80 and 443, the dashboard will work but no one can create tunnels from their machines.

## Requirements

- Python 3.12+
- Gapo server running on the same host
- Gapo client binary at `/usr/local/bin/gapo`
- systemd (for service management and log access)

## File Structure

```
gapo-dashboard/
├── dashboard.py                          # Main application
├── config.example                        # Example configuration
├── systemd/
│   ├── gapo-dashboard.service            # Dashboard service
│   └── gapo-client-dashboard.service     # Tunnel client service
└── README.md
```

## License

MIT
