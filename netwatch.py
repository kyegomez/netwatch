#!/usr/bin/env python3
"""
NETWATCH v1.0 — Active Network Connection Monitor
Requires: pip install rich psutil
"""

import json
import os
import socket
import subprocess
import threading
import time
import sys
import urllib.request
from datetime import datetime
from typing import NamedTuple

try:
    import psutil
except ImportError:
    print("Missing dependency: pip install psutil rich")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.live import Live
    from rich.align import Align
    from rich import box
    from rich.console import Group
except ImportError:
    print("Missing dependency: pip install psutil rich")
    sys.exit(1)

console = Console()

BANNER = r"""
 ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
 ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
 ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
 ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
"""

STATUS_STYLE = {
    "ESTABLISHED": "bold green",
    "LISTEN":      "bold cyan",
    "TIME_WAIT":   "yellow",
    "CLOSE_WAIT":  "bold yellow",
    "SYN_SENT":    "bold magenta",
    "SYN_RECV":    "magenta",
    "FIN_WAIT1":   "dim yellow",
    "FIN_WAIT2":   "dim yellow",
    "LAST_ACK":    "dim red",
    "CLOSING":     "dim red",
    "CLOSE":       "dim white",
    "NONE":        "dim white",
}

RISK_PORTS = {
    21:    ("FTP",        "red"),
    22:    ("SSH",        "yellow"),
    23:    ("Telnet",     "bold red"),
    25:    ("SMTP",       "yellow"),
    53:    ("DNS",        "cyan"),
    80:    ("HTTP",       "white"),
    443:   ("HTTPS",      "green"),
    3306:  ("MySQL",      "bold yellow"),
    3389:  ("RDP",        "bold red"),
    5432:  ("PostgreSQL", "bold yellow"),
    8080:  ("HTTP-Alt",   "white"),
    8443:  ("HTTPS-Alt",  "green"),
    27017: ("MongoDB",    "bold yellow"),
    6379:  ("Redis",      "bold yellow"),
}


def resolve_host(ip: str, timeout: float = 0.4) -> str:
    if not ip or ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
        return ip
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def get_process_name(pid: int) -> str:
    if pid is None:
        return "—"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"[dim]pid:{pid}[/dim]"


def port_label(port: int) -> str:
    if port in RISK_PORTS:
        name, _ = RISK_PORTS[port]
        return f"{port} [dim]({name})[/dim]"
    return str(port) if port else "—"


def port_style(port: int) -> str:
    if port in RISK_PORTS:
        return RISK_PORTS[port][1]
    return "white"


# Base risk score per port (higher = more dangerous)
_PORT_SCORE: dict[int, int] = {
    23: 4, 21: 4,          # Telnet, FTP — plaintext & legacy
    3389: 3,               # RDP — remote desktop, high-value target
    22: 2, 25: 2,          # SSH, SMTP
    3306: 2, 5432: 2,      # MySQL, PostgreSQL
    27017: 2, 6379: 2,     # MongoDB, Redis
    80: 1, 8080: 1,        # HTTP — unencrypted
    443: 0, 8443: 0,       # HTTPS — encrypted
    53: 0,                 # DNS — normal
}

_PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.2", "172.3", "192.168.", "127.", "::1", "fe80")


def _is_external(ip: str) -> bool:
    if not ip or ip in ("0.0.0.0", "::"):
        return False
    return not any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def calc_risk(conn, suspicious_path: bool = False) -> tuple[str, str]:
    """Return (label, rich_style) — HIGH / MED / LOW."""
    rip    = conn.raddr.ip   if conn.raddr else ""
    rport  = conn.raddr.port if conn.raddr else 0
    laddr  = conn.laddr
    status = getattr(conn, "status", "NONE") or "NONE"

    effective_port = rport or (laddr.port if laddr else 0)
    score = _PORT_SCORE.get(effective_port, 1)

    if _is_external(rip) and status == "ESTABLISHED":
        score += 1
    if status == "LISTEN" and laddr and laddr.ip in ("0.0.0.0", "::"):
        score += 1
    if status == "SYN_SENT" and _is_external(rip):
        score += 1
    if suspicious_path:
        score += 2  # process running from temp/downloads dir is inherently suspicious

    if score >= 4:
        return "● HIGH", "bold red"
    if score >= 2:
        return "◆ MED", "bold yellow"
    return "○ LOW", "dim green"


## ── GeoIP ──────────────────────────────────────────────────────────────────

_geo_cache: dict[str, str] = {}
_geo_lock  = threading.Lock()


def _fetch_geo(ip: str) -> None:
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode"
        with urllib.request.urlopen(url, timeout=3) as r:
            d = json.loads(r.read())
            result = f"{d.get('countryCode','?')}  {d.get('country','?')}"
    except Exception:
        result = "?"
    with _geo_lock:
        _geo_cache[ip] = result


def get_geo(ip: str) -> str:
    if not ip or not _is_external(ip):
        return "[dim]local[/dim]"
    with _geo_lock:
        cached = _geo_cache.get(ip)
    if cached is not None:
        return cached
    with _geo_lock:
        _geo_cache[ip] = "…"
    threading.Thread(target=_fetch_geo, args=(ip,), daemon=True).start()
    return "…"


## ── VPN detection ──────────────────────────────────────────────────────────

def get_vpn_status() -> tuple[str, str]:
    ifaces = list(psutil.net_if_addrs().keys())
    active = [i for i in ifaces if i.startswith(("utun", "tun", "ppp", "tap", "ipsec", "wg"))]
    if active:
        return f"● ACTIVE  ({active[0]})", "bold green"
    return "✗ NONE", "bold red"


## ── Process path validation ────────────────────────────────────────────────

_SUSPICIOUS_PATHS = (
    "/tmp/", "/private/tmp/", "/var/tmp/",
    "/var/folders/",
    "Downloads/", "Desktop/",
)


def get_proc_info(pid: int) -> tuple[str, str, bool]:
    """Returns (display_name, exe_path, is_suspicious)."""
    if pid is None:
        return "—", "", False
    try:
        p   = psutil.Process(pid)
        exe = p.exe()
        suspicious = any(s in exe for s in _SUSPICIOUS_PATHS)
        return p.name(), exe, suspicious
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"pid:{pid}", "", False


## ── New-connection tracking ────────────────────────────────────────────────

_seen_conns: dict[tuple, float] = {}
_seen_lock  = threading.Lock()
_NEW_TTL    = 6.0  # seconds a connection stays flagged as NEW


def _conn_key(conn) -> tuple:
    la = (conn.laddr.ip, conn.laddr.port) if conn.laddr else None
    ra = (conn.raddr.ip, conn.raddr.port) if conn.raddr else None
    return (la, ra, conn.pid)


def update_seen(connections: list) -> set:
    """Maintain the seen-connections dict; return keys seen within _NEW_TTL."""
    now  = time.time()
    keys = {_conn_key(c) for c in connections}
    with _seen_lock:
        for k in keys:
            if k not in _seen_conns:
                _seen_conns[k] = now
        for k in list(_seen_conns):
            if k not in keys:
                del _seen_conns[k]
        return {k for k, ts in _seen_conns.items() if now - ts < _NEW_TTL}


class _Conn(NamedTuple):
    fd: int
    family: int
    type: int
    laddr: object
    raddr: object
    status: str
    pid: int | None


def get_connections() -> list:
    """Returns connections, falling back to per-process scan on permission error."""
    try:
        return psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        conns = []
        for proc in psutil.process_iter(["pid"]):
            try:
                for c in proc.net_connections(kind="inet"):
                    conns.append(_Conn(c.fd, c.family, c.type, c.laddr, c.raddr, c.status, proc.pid))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        return conns


def build_table(connections: list, resolve: bool = False, new_keys: set | None = None) -> Table:
    new_keys = new_keys or set()
    table = Table(
        box=box.HEAVY_HEAD,
        border_style="bright_black",
        header_style="bold bright_cyan",
        show_lines=True,
        title=f"[bold bright_cyan]ACTIVE CONNECTIONS[/]  [dim]{datetime.now().strftime('%H:%M:%S')}[/]",
        title_style="bold",
        caption=f"[dim]{len(connections)} connection(s) found[/]",
    )
    table.add_column("№",       style="dim",             width=4,  justify="right")
    table.add_column("FLAGS",                             width=5,  justify="center")
    table.add_column("RISK",                              width=8)
    table.add_column("PROTO",   style="bright_white",    width=6)
    table.add_column("STATUS",                            width=12)
    table.add_column("LOCAL",   style="bright_white",    min_width=20)
    table.add_column("REMOTE",                            min_width=24)
    table.add_column("COUNTRY",                           min_width=16)
    table.add_column("PORT",                              width=18)
    table.add_column("PROCESS",                           min_width=16)
    table.add_column("PID",     style="dim",              width=7,  justify="right")

    for i, conn in enumerate(connections, 1):
        laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "—"
        rip       = conn.raddr.ip   if conn.raddr else ""
        rport     = conn.raddr.port if conn.raddr else None

        if resolve and rip:
            rhost = resolve_host(rip)
            remote_display = f"{rhost}\n[dim]{rip}[/dim]" if rhost != rip else rip
        else:
            remote_display = rip or "[dim]—[/dim]"

        status     = getattr(conn, "status", "NONE") or "NONE"
        status_txt = Text(status, style=STATUS_STYLE.get(status, "white"))
        proto      = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        pid_str    = str(conn.pid) if conn.pid else "—"
        port_txt   = Text(port_label(rport), style=port_style(rport)) if rport else Text("—", style="dim")

        # Process info with path validation
        proc_name, _exe, suspicious = get_proc_info(conn.pid)
        proc_display = Text()
        if suspicious:
            proc_display.append("⚠ ", style="bold red")
        proc_display.append(proc_name, style="bold red" if suspicious else "bright_magenta")

        # GeoIP
        country     = get_geo(rip) if rip else "[dim]—[/dim]"
        country_txt = Text.from_markup(country)

        # Risk (elevated if suspicious path)
        risk_label, risk_style = calc_risk(conn, suspicious_path=suspicious)
        risk_txt = Text(risk_label, style=risk_style)

        # New-connection flag
        is_new  = _conn_key(conn) in new_keys
        flags   = Text()
        if is_new:
            flags.append("★", style="bold yellow")
        if suspicious:
            flags.append("⚠", style="bold red")

        row_style = "on grey7" if is_new else ""
        table.add_row(
            str(i), flags, risk_txt, proto, status_txt,
            laddr_str, remote_display, country_txt, port_txt, proc_display, pid_str,
            style=row_style,
        )

    return table


def build_stats(connections: list) -> Panel:
    status_counts: dict[str, int] = {}
    proc_counts:   dict[str, int] = {}
    risk_counts = {"HIGH": 0, "MED": 0, "LOW": 0}

    for c in connections:
        s = getattr(c, "status", "NONE") or "NONE"
        status_counts[s] = status_counts.get(s, 0) + 1
        name, _exe, suspicious = get_proc_info(c.pid)
        proc_counts[name] = proc_counts.get(name, 0) + 1
        label, _ = calc_risk(c, suspicious_path=suspicious)
        key = label.split()[-1]
        risk_counts[key] = risk_counts.get(key, 0) + 1

    status_lines = [
        f"  [{STATUS_STYLE.get(s, 'white')}]{s:<14}[/] [bold]{n:>3}[/]"
        for s, n in sorted(status_counts.items(), key=lambda x: -x[1])
    ]
    proc_lines = [
        f"  [bright_magenta]{name:<18}[/] [bold]{cnt:>3}[/]"
        for name, cnt in sorted(proc_counts.items(), key=lambda x: -x[1])[:6]
    ]
    risk_lines = [
        f"  [bold red]● HIGH          [/] [bold]{risk_counts['HIGH']:>3}[/]",
        f"  [bold yellow]◆ MED           [/] [bold]{risk_counts['MED']:>3}[/]",
        f"  [dim green]○ LOW           [/] [bold]{risk_counts['LOW']:>3}[/]",
    ]

    body = "\n".join([
        "[bold bright_cyan]RISK SUMMARY[/]", *risk_lines,
        "", "[bold bright_cyan]BY STATUS[/]", *status_lines,
        "", "[bold bright_cyan]TOP PROCESSES[/]", *proc_lines,
    ])
    return Panel(body, title="[bold bright_cyan]STATISTICS[/]", border_style="bright_black", padding=(0, 1))


## ── System info helpers ────────────────────────────────────────────────────

_pub_ip_cache: dict = {"value": "fetching...", "ts": 0.0}
_pub_ip_lock  = threading.Lock()


def _fetch_public_ip() -> None:
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=4) as r:
            ip = r.read().decode().strip()
    except Exception:
        ip = "unavailable"
    with _pub_ip_lock:
        _pub_ip_cache.update({"value": ip, "ts": time.time()})


def get_public_ip() -> str:
    now = time.time()
    with _pub_ip_lock:
        stale = now - _pub_ip_cache["ts"] > 60
    if stale:
        with _pub_ip_lock:
            _pub_ip_cache["ts"] = now  # prevent duplicate fetches
        threading.Thread(target=_fetch_public_ip, daemon=True).start()
    return _pub_ip_cache["value"]


def get_primary_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "unknown"
    finally:
        s.close()


def get_wifi_ssid() -> str:
    try:
        airport = (
            "/System/Library/PrivateFrameworks/Apple80211.framework"
            "/Versions/Current/Resources/airport"
        )
        out = subprocess.run([airport, "-I"], capture_output=True, text=True, timeout=2).stdout
        for line in out.splitlines():
            if " SSID:" in line:
                return line.split("SSID:")[1].strip()
    except Exception:
        pass
    return "—"


def get_default_gateway() -> str:
    try:
        out = subprocess.run(
            ["route", "get", "default"], capture_output=True, text=True, timeout=2
        ).stdout
        for line in out.splitlines():
            if "gateway:" in line:
                return line.split("gateway:")[1].strip()
    except Exception:
        pass
    return "—"


def get_dns_servers() -> str:
    try:
        servers: list[str] = []
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    servers.append(line.split()[1])
        return "  ".join(servers[:3]) if servers else "—"
    except Exception:
        return "—"


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n //= 1024
    return f"{n:.1f} TB"


def build_header() -> Panel:
    now      = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    hostname = socket.gethostname()
    local_ip = get_primary_ip()
    pub_ip   = get_public_ip()
    ssid     = get_wifi_ssid()
    gateway  = get_default_gateway()
    dns      = get_dns_servers()
    nio      = psutil.net_io_counters()

    vpn_label, vpn_style = get_vpn_status()

    def field(label: str, value: str, val_style: str = "white") -> str:
        return f"[bold bright_green]{label}[/]  [{val_style}]{value}[/]"

    # VPN banner — full width, colour-coded
    vpn_row = Align.center(
        f"[bold bright_green]VPN[/]  [{vpn_style}]{vpn_label}[/]"
        + ("   [dim](⚠ on public wifi without VPN your traffic is exposed)[/]" if "NONE" in vpn_label else "")
    )

    row1 = "   ".join([
        field("HOST",       hostname),
        field("LOCAL IP",   local_ip),
        field("PUBLIC IP",  pub_ip),
    ])
    row2 = "   ".join([
        field("WIFI",       ssid),
        field("GATEWAY",    gateway),
        field("DNS",        dns),
    ])
    row3 = "   ".join([
        field("TIME",       now),
        field("↑ SENT",     fmt_bytes(nio.bytes_sent)),
        field("↓ RECV",     fmt_bytes(nio.bytes_recv)),
    ])

    border = "bold red" if "NONE" in vpn_label else "bright_cyan"
    body   = "\n".join([str(vpn_row), row1, row2, row3])
    return Panel(Align.center(body), border_style=border, style="on black",
                 title="[bold bright_cyan]SYSTEM[/]")


def run(resolve: bool = False) -> None:
    is_root = os.geteuid() == 0

    console.print(Panel(
        Align.center(Text(BANNER, style="bold bright_cyan")),
        border_style="bright_cyan",
        subtitle="[dim]Network Connection Monitor  |  Ctrl+C to stop[/]",
        padding=(0, 0),
    ))

    if not is_root:
        console.print(Panel(
            "[yellow]Running without root — some processes may be hidden. "
            "For full visibility: [bold]sudo python3 netwatch.py[/bold][/]",
            border_style="yellow",
            padding=(0, 1),
        ))

    try:
        with Live(console=console, refresh_per_second=2, screen=False) as live:
            while True:
                connections = get_connections()
                new_keys    = update_seen(connections)
                live.update(Group(
                    build_header(),
                    build_table(connections, resolve=resolve, new_keys=new_keys),
                    build_stats(connections),
                ))
                time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[bold bright_cyan]Scan terminated.[/]")


if __name__ == "__main__":
    # Kick off public IP fetch immediately so it's ready on first render
    threading.Thread(target=_fetch_public_ip, daemon=True).start()
    run(resolve="--resolve" in sys.argv)
