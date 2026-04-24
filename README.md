# NETWATCH

![img](img.png)

**Real-time network security observability for macOS endpoints.**

NETWATCH is a terminal-based security monitoring tool that gives you continuous, live visibility into every active network connection on your machine — with automatic risk scoring, GeoIP intelligence, VPN status, process path validation, and new-connection alerting. Built for security-conscious individuals, developers, and teams who need to know exactly what their machine is talking to and why.

---

## Overview

Modern endpoints make hundreds of concurrent network connections. Most security tools surface this data only after an incident. NETWATCH surfaces it in real time — with enough context to act on it immediately.

Every second, NETWATCH:

- Enumerates all active TCP/UDP connections via the OS kernel
- Resolves the owning process and validates its executable path
- Scores each connection's risk level using a multi-factor algorithm
- Looks up the geographic origin of every external IP in the background
- Detects new connections the moment they appear
- Monitors VPN tunnel status and alerts when traffic is exposed

---

## Installation

**Requirements:** Python 3.10+, macOS (Linux compatible with minor limitations)

```bash
git clone https://github.com/kyegomez/netwatch
cd netwatch
pip install -r requirements.txt
```

## Usage

```bash
# Standard mode
python3 netwatch.py

# Full process visibility (recommended)
sudo python3 netwatch.py

# With DNS hostname resolution for remote IPs
sudo python3 netwatch.py --resolve
```

Press `Ctrl+C` to stop.

---

## Features

### System Dashboard
Live header panel showing the full network context of your machine, updated every second:

| Field | Description |
|-------|-------------|
| VPN Status | Detects active tunnel interfaces (`utun`, `tun`, `wg`, `ppp`, `ipsec`). Border turns red when no VPN is active. |
| Host / Local IP | Hostname and primary interface IP |
| Public IP | Your external IP, resolved via background fetch, cached for 60s |
| WiFi SSID | Active wireless network name (macOS) |
| Default Gateway | Network gateway IP |
| DNS Servers | Active nameservers from `/etc/resolv.conf` |
| Bytes Sent / Received | Cumulative throughput since boot |

### Connection Table
Live-updated table with one row per active connection:

| Column | Description |
|--------|-------------|
| FLAGS | `★` new connection (appeared within 6s), `⚠` suspicious process path |
| RISK | Three-tier risk rating: `HIGH`, `MED`, `LOW` — automatically calculated |
| PROTO | TCP or UDP |
| STATUS | Full TCP state (`ESTABLISHED`, `LISTEN`, `SYN_SENT`, `TIME_WAIT`, etc.) |
| LOCAL | Local address and port |
| REMOTE | Remote IP address |
| COUNTRY | GeoIP country lookup — resolved in background, cached per session |
| PORT | Port number with well-known service label |
| PROCESS | Owning process name. Red + `⚠` prefix if binary runs from a suspicious path |
| PID | Process ID |

### Automatic Risk Scoring

Each connection is scored across multiple dimensions:

**Port base score**

| Score | Ports |
|-------|-------|
| 4 | Telnet (23), FTP (21) — plaintext legacy protocols |
| 3 | RDP (3389) — remote desktop, high-value target |
| 2 | SSH (22), SMTP (25), MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379) |
| 1 | HTTP (80), HTTP-Alt (8080), unknown ports |
| 0 | HTTPS (443, 8443), DNS (53) |

**Modifier conditions**

| Condition | Score delta |
|-----------|-------------|
| External IP + `ESTABLISHED` | +1 |
| `LISTEN` on `0.0.0.0` or `::` (all interfaces) | +1 |
| `SYN_SENT` to external IP | +1 |
| Process binary in suspicious path | +2 |

**Rating thresholds:** `≥ 4` → `HIGH`, `≥ 2` → `MED`, `< 2` → `LOW`

### New Connection Detection
Every connection is tracked by a `(local_addr, remote_addr, pid)` key with a first-seen timestamp. Connections that appeared within the last 6 seconds are flagged with `★` and a highlighted row background. The highlight expires automatically.

### GeoIP Intelligence
Remote IP geographic lookups run in background threads via `ip-api.com` and are cached per session. Private/RFC 1918 addresses resolve immediately as `local`. Results appear in the COUNTRY column as they arrive.

### Process Path Validation
The full executable path of each process is inspected. Binaries making network connections from the following locations are flagged as suspicious and receive a +2 risk penalty:

- `/tmp/`, `/private/tmp/`, `/var/tmp/`
- `/var/folders/`
- `Downloads/`, `Desktop/`

Standard system paths (`/usr/`, `/System/`, `/Applications/`, `/Library/Application Support/`) are not flagged.

### VPN Status
Network interfaces are scanned each tick for active tunnel adapters. When no VPN is detected, the system panel border turns red and a warning is displayed inline. Detects WireGuard (`wg`), OpenVPN (`tun`), macOS VPN (`utun`), IPSec (`ipsec`), PPP, and TAP adapters.

### Statistics Panel
A live sidebar showing:
- Risk summary (HIGH / MED / LOW counts)
- Connection breakdown by TCP state
- Top 6 processes by connection count

---

## Requirements

- Python 3.10+
- macOS (Linux compatible with minor limitations — WiFi SSID and gateway detection use macOS-specific tooling)
- Root access recommended for full process visibility

**Dependencies:**
```
psutil>=5.9
rich>=13.0
```

---

## Display Reference

### Risk Indicators

| Symbol | Meaning |
|--------|---------|
| `● HIGH` | High-risk connection — immediate attention recommended |
| `◆ MED` | Medium-risk — monitor and investigate if unexpected |
| `○ LOW` | Low-risk — encrypted or local traffic |

### Flag Column

| Symbol | Meaning |
|--------|---------|
| `★` | New connection — appeared within the last 6 seconds |
| `⚠` | Suspicious process — binary executing from a high-risk path |

### VPN Border Color

| Color | Meaning |
|-------|---------|
| Cyan | VPN tunnel active — traffic is protected |
| Red | No VPN detected — traffic is exposed on current network |

### Connection Status Colors

| Color | States |
|-------|--------|
| Bold green | `ESTABLISHED` |
| Bold cyan | `LISTEN` |
| Bold magenta | `SYN_SENT` |
| Yellow | `TIME_WAIT`, `CLOSE_WAIT` |
| Dim | `FIN_WAIT`, `LAST_ACK`, `CLOSING`, `CLOSE` |

---

## Architecture

NETWATCH is a single-file Python script with no external services, no telemetry, and no persistent storage. All data is gathered locally from the OS kernel via `psutil`. The only outbound requests are:

1. **Public IP lookup** — one HTTPS request to `api.ipify.org` on startup, refreshed every 60 seconds
2. **GeoIP lookups** — one HTTP request to `ip-api.com` per unique external IP, cached for the session lifetime

All lookups run in daemon threads and never block the render loop. If either service is unavailable (e.g. on a restricted network), the tool degrades gracefully — displaying `unavailable` or `…` in the affected fields while all local monitoring continues uninterrupted.

---

## Threat Coverage

| Threat | Detection mechanism |
|--------|---------------------|
| Unencrypted outbound traffic | Port scoring — HTTP/FTP/Telnet flagged HIGH or MED |
| Exposed local services | LISTEN on `0.0.0.0` scored higher than localhost-bound services |
| Suspicious process origin | Binary path validation — temp/download directories flagged |
| Unexpected new connections | First-seen timestamp tracking with 6-second visual TTL |
| VPN tunnel failure | Interface scan every render tick |
| Remote desktop exposure | RDP (3389) port score = 3, external + established = HIGH |
| Database exposure | MySQL, PostgreSQL, MongoDB, Redis all scored MED minimum |
| Compromised process from temp | `/tmp` binary + external connection = HIGH |

---

## Limitations

- Per-connection bandwidth measurement is not currently implemented — total interface throughput is shown in the header
- GeoIP accuracy depends on `ip-api.com` data quality; CDN and VPN exit IPs may show unexpected countries
- WiFi SSID and gateway detection use macOS-specific commands (`airport`, `route`) and will not work on Linux without modification
- Full process visibility (executable paths, process names for all PIDs) requires root on macOS
- `ip-api.com` has a rate limit of 45 requests/minute on the free tier; sessions with many unique external IPs may see delayed GeoIP resolution

---

## Roadmap

- [ ] IP reputation lookup against AbuseIPDB / threat intel feeds
- [ ] Per-process bandwidth metering (KB/s per connection)
- [ ] Anomaly baseline — alert on first-ever outbound connection per process
- [ ] Port scan / sweep detection (multiple ports from same remote IP)
- [ ] DNS leak detection (DNS traffic bypassing VPN resolver)
- [ ] Connection history log (JSONL append with timestamp, risk, process)
- [ ] `--alert` mode — system notification on HIGH-risk connection
- [ ] Linux support (SSID via `iwgetid`, gateway via `ip route`)

---

## License

APACHE 2.0
