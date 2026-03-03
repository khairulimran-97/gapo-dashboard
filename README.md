# Gapo Dashboard

A lightweight web dashboard for monitoring [Gapo](https://github.com/ghostbirdme/gapo) tunnel servers. Built with Python standard library only — no pip, no frameworks, no dependencies.

![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue)

## Features

- **Server Overview** — status, PID, memory, CPU time, uptime, version
- **Active Tunnels** — real-time connections via `ss`
- **Logs Viewer** — live `journalctl` output for gapo-server
- **System Metrics** — CPU, memory, disk usage with progress bars
- **Authentication** — HMAC-signed cookie-based login
- **Dark Theme** — modern UI with 10-second auto-refresh
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

## Installation

### 1. Clone and place the dashboard

```bash
sudo mkdir -p /opt/gapo-dashboard
sudo cp dashboard.py /opt/gapo-dashboard/
sudo chmod +x /opt/gapo-dashboard/dashboard.py
```

### 2. Create configuration

```bash
sudo mkdir -p /etc/gapo-dashboard
sudo cp config.example /etc/gapo-dashboard/config
sudo chmod 600 /etc/gapo-dashboard/config
```

Edit `/etc/gapo-dashboard/config` with your credentials:

```
DASH_USER=admin
DASH_PASS=your-secure-password
DASH_PORT=8080
DASH_SECRET=your-random-secret-for-cookie-signing
```

Generate secure values:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(16))"   # password
python3 -c "import secrets; print(secrets.token_hex(32))"        # secret
```

### 3. Install systemd services

```bash
sudo cp systemd/gapo-dashboard.service /etc/systemd/system/
sudo cp systemd/gapo-client-dashboard.service /etc/systemd/system/
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
