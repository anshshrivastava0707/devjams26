"""
MCP server exposing local-network scanning tools.

Intended for scanning networks you own or are authorized to test
(home/office LAN, a lab environment, an authorized pentest engagement).
Do not point these tools at networks you don't have permission to scan.

Run with:
    .venv/bin/python server.py
or via the MCP CLI:
    .venv/bin/mcp dev server.py
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import platform
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import psutil
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("network-scanner")

NMAP_PATH = shutil.which("nmap")
DIG_PATH = shutil.which("dig")

CACHE_DIR = Path(__file__).parent / ".cache"

COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1723: "pptp",
    2049: "nfs",
    3000: "dev-http",
    3306: "mysql",
    3389: "rdp",
    5000: "dev-http",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

SECURITY_HEADERS: list[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

INFO_DISCLOSURE_HEADERS: list[str] = ["Server", "X-Powered-By", "X-AspNet-Version"]

SENSITIVE_PATHS: list[str] = [
    ".git/config",
    ".git/HEAD",
    ".env",
    ".svn/entries",
    ".DS_Store",
    "web.config",
    "docker-compose.yml",
    "backup.zip",
    ".well-known/security.txt",
]


def _run(cmd: list[str], timeout: int) -> str:
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )
    return result.stdout + result.stderr


def _scan_open_ports(
    ip: str, ports: list[int], timeout_seconds: float, max_workers: int
) -> list[dict[str, Any]]:
    """Check `ports` on `ip` via plain TCP connect attempts, returning open ones with a service name."""

    def check_port(port: int) -> tuple[int, bool]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout_seconds)
            result = sock.connect_ex((ip, port))
            return port, result == 0

    open_ports: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(check_port, p) for p in ports]
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = COMMON_PORTS.get(port, "unknown")
                open_ports.append({"port": port, "service": service})

    open_ports.sort(key=lambda p: p["port"])
    return open_ports


def _reverse_dns(ip: str) -> str | None:
    try:
        hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def _mac_vendor(mac: str) -> str | None:
    try:
        from scapy.all import conf
    except ImportError:
        return None
    try:
        _short, full = conf.manufdb.lookup(mac)
    except Exception:  # noqa: BLE001 - vendor DB lookups shouldn't fail discovery
        return None
    return full if full and full.lower() != mac.lower() else None


def _tls_context() -> ssl.SSLContext:
    """A context that completes the handshake and hands back the cert regardless of trust/hostname."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _http_get(host: str, port: int, path: str, tls: bool, timeout_seconds: float) -> tuple[int, dict[str, str]]:
    """Issue a single GET and return (status, headers). Raises OSError / http.client.HTTPException on failure."""
    conn: http.client.HTTPConnection
    if tls:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout_seconds, context=_tls_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout_seconds)
    try:
        conn.request("GET", path, headers={"User-Agent": "mcp-network-scanner/1.0", "Connection": "close"})
        response = conn.getresponse()
        headers = dict(response.getheaders())
        status = response.status
        response.read()  # drain the body so the connection closes cleanly
    finally:
        conn.close()
    return status, headers


def _http_get_with_body(
    host: str, port: int, path: str, tls: bool, timeout_seconds: float, max_bytes: int
) -> tuple[int, dict[str, str], bytes]:
    """Like _http_get, but also returns up to max_bytes of the response body."""
    conn: http.client.HTTPConnection
    if tls:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout_seconds, context=_tls_context())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout_seconds)
    try:
        conn.request("GET", path, headers={"User-Agent": "mcp-network-scanner/1.0", "Connection": "close"})
        response = conn.getresponse()
        headers = dict(response.getheaders())
        status = response.status
        body = response.read(max_bytes + 1)
    finally:
        conn.close()
    return status, headers, body[:max_bytes]


def _fetch_json(url: str, timeout_seconds: float) -> Any:
    """GET `url` and return the parsed JSON body."""
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-network-scanner/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        return json.loads(resp.read())


def _fetch_json_cached(url: str, cache_name: str, ttl_seconds: float, timeout_seconds: float) -> tuple[Any, dict[str, Any]]:
    """Fetch JSON from `url`, cached on disk under .cache/<cache_name> for ttl_seconds.

    Returns (parsed_json, meta) where meta reports whether this call hit the cache or the network.
    """
    cache_path = CACHE_DIR / cache_name
    if cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < ttl_seconds:
            try:
                return json.loads(cache_path.read_text()), {"source": "cache", "cache_age_seconds": round(age, 1)}
            except (OSError, json.JSONDecodeError):
                pass  # corrupt/unreadable cache - fall through and refetch

    req = urllib.request.Request(url, headers={"User-Agent": "mcp-network-scanner/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
        raw = resp.read()
    data = json.loads(raw)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path.write_bytes(raw)
    return data, {"source": "network", "cache_age_seconds": 0.0}


EPSS_API_URL = "https://api.first.org/data/v1/epss"


@mcp.tool()
def epss_lookup(cve_ids: list[str]) -> dict[str, Any]:
    """Look up the EPSS (Exploit Prediction Scoring System) score for one
    or more CVE IDs via FIRST.org's free public API - a 0-1 probability
    estimate of real-world exploitation in the next 30 days, plus its
    percentile rank against all other scored CVEs. No API key, no
    meaningful rate limit, one request regardless of how many CVE IDs
    are passed (they're sent as a single comma-separated query).
    A CVE with no EPSS record (too new, or not in NVD) is reported as
    such, not as an error. EPSS is a probability estimate, not a
    severity rating - a high score means "likely to be exploited soon",
    not "high impact if it is"; pair with kev_lookup (confirmed active
    exploitation) for the fuller picture."""
    if not cve_ids:
        return {"error": "cve_ids must be a non-empty list"}

    query = ",".join(cve_ids)
    try:
        body = _fetch_json(f"{EPSS_API_URL}?cve={query}", timeout_seconds=15.0)
    except (OSError, ValueError) as e:
        return {"error": f"EPSS request failed: {e}"}

    scored = {row["cve"]: row for row in body.get("data", [])}
    results = []
    for cve_id in cve_ids:
        row = scored.get(cve_id.upper()) or scored.get(cve_id)
        if row is None:
            results.append({"cve": cve_id, "scored": False})
        else:
            results.append(
                {
                    "cve": cve_id,
                    "scored": True,
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                    "date": row.get("date"),
                }
            )

    return {"results": results, "total_scored": body.get("total", 0)}


@mcp.tool()
def list_network_interfaces() -> dict[str, Any]:
    """List local network interfaces with their IPv4 addresses, netmasks,
    and derived CIDR subnets. Use this first to discover which local
    subnet(s) are available to scan (e.g. 192.168.1.0/24)."""
    interfaces: dict[str, Any] = {}
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for name, addr_list in addrs.items():
        entry: dict[str, Any] = {
            "up": stats[name].isup if name in stats else None,
            "addresses": [],
        }
        for addr in addr_list:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                cidr = None
                if addr.netmask:
                    try:
                        network = ipaddress.IPv4Network(
                            f"{addr.address}/{addr.netmask}", strict=False
                        )
                        cidr = str(network)
                    except ValueError:
                        cidr = None
                entry["addresses"].append(
                    {
                        "ip": addr.address,
                        "netmask": addr.netmask,
                        "cidr": cidr,
                    }
                )
        if entry["addresses"]:
            interfaces[name] = entry

    return {"interfaces": interfaces}


@mcp.tool()
def ping_host(host: str, count: int = 1, timeout_seconds: int = 2) -> dict[str, Any]:
    """Ping a single host to check if it's alive. Uses the system `ping`
    command (no special privileges required)."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(timeout_seconds * 1000), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(timeout_seconds), host]

    try:
        output = _run(cmd, timeout=timeout_seconds * count + 5)
    except subprocess.TimeoutExpired:
        return {"host": host, "alive": False, "error": "timeout"}

    alive = "0 received" not in output and (
        "bytes from" in output or "TTL=" in output or "ttl=" in output
    )
    return {"host": host, "alive": alive, "raw_output": output.strip()}


@mcp.tool()
def ping_sweep(subnet: str, max_workers: int = 64, timeout_seconds: int = 1) -> dict[str, Any]:
    """Discover live hosts on a subnet by pinging every address in it
    concurrently. `subnet` must be CIDR notation, e.g. '192.168.1.0/24'.
    Returns the list of hosts that responded. Best used on subnets no
    larger than /22 to keep scan time reasonable."""
    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError as e:
        return {"error": f"invalid subnet: {e}"}

    hosts = list(network.hosts())
    if len(hosts) > 4096:
        return {
            "error": f"subnet too large ({len(hosts)} hosts); "
            "use a smaller CIDR (e.g. /22 or smaller)"
        }

    system = platform.system().lower()

    def ping_one(ip: str) -> bool:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout_seconds * 1000), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout_seconds), ip]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_seconds + 2
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False

    alive_hosts: list[str] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(ping_one, str(ip)): str(ip) for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                alive_hosts.append(ip)

    alive_hosts.sort(key=lambda ip: tuple(int(o) for o in ip.split(".")))
    return {"subnet": subnet, "scanned": len(hosts), "alive_hosts": alive_hosts}


def _arp_discover(subnet: str, timeout_seconds: int) -> list[dict[str, str]] | dict[str, Any]:
    """Send an ARP request across `subnet`. Returns a list of {ip, mac}, or an {"error": ...} dict."""
    try:
        ipaddress.IPv4Network(subnet, strict=False)
    except ValueError as e:
        return {"error": f"invalid subnet: {e}"}

    try:
        from scapy.all import ARP, Ether, srp
    except ImportError as e:
        return {"error": f"scapy not available: {e}"}

    try:
        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request
        answered, _ = srp(packet, timeout=timeout_seconds, verbose=False)
    except PermissionError:
        return {
            "error": "permission denied sending raw ARP packets; "
            "run this process as root or grant CAP_NET_RAW "
            "(e.g. `sudo setcap cap_net_raw+ep $(readlink -f $(which python3))`)"
        }
    except Exception as e:  # noqa: BLE001 - scapy raises varied OS-level errors
        return {"error": str(e)}

    devices = [{"ip": received.psrc, "mac": received.hwsrc} for _sent, received in answered]
    devices.sort(key=lambda d: tuple(int(o) for o in d["ip"].split(".")))
    return devices


@mcp.tool()
def arp_scan(subnet: str, timeout_seconds: int = 3) -> dict[str, Any]:
    """Discover live hosts on the local subnet via ARP requests, returning
    IP and MAC address for each responder. More reliable than ping on a
    LAN since it works even when hosts block ICMP.
    Requires scapy and typically root/CAP_NET_RAW privileges to send raw
    ARP frames. `subnet` must be CIDR notation, e.g. '192.168.1.0/24'."""
    found = _arp_discover(subnet, timeout_seconds)
    if isinstance(found, dict):
        return found
    return {"subnet": subnet, "devices": found}


@mcp.tool()
def discover_devices(
    subnet: str,
    timeout_seconds: int = 3,
    probe_ports: bool = False,
    port_timeout_seconds: float = 0.5,
) -> dict[str, Any]:
    """Discover devices on the local subnet and enrich each one with
    whatever identifying info can be gathered: MAC address, vendor
    (looked up from the MAC's OUI), reverse-DNS hostname, and
    (optionally) a quick scan of common ports as a hint at the kind of
    device. Runs the same ARP scan as `arp_scan` under the hood, then
    does per-host lookups. `subnet` must be CIDR notation, e.g.
    '192.168.1.0/24'. Requires scapy and typically root/CAP_NET_RAW,
    same as arp_scan. Set `probe_ports=True` to also port-scan each
    device (slower on large subnets: it runs one host at a time).
    Only scan networks you own or are authorized to test."""
    found = _arp_discover(subnet, timeout_seconds)
    if isinstance(found, dict):
        return found

    devices: list[dict[str, Any]] = []
    for entry in found:
        ip = entry["ip"]
        mac = entry["mac"]
        device: dict[str, Any] = {
            "ip": ip,
            "mac": mac,
            "hostname": _reverse_dns(ip),
            "vendor": _mac_vendor(mac),
        }
        if probe_ports:
            device["open_ports"] = _scan_open_ports(
                ip, list(COMMON_PORTS.keys()), port_timeout_seconds, max_workers=len(COMMON_PORTS)
            )
        devices.append(device)

    return {
        "subnet": subnet,
        "device_count": len(devices),
        "probed_ports": probe_ports,
        "devices": devices,
    }


@mcp.tool()
def port_scan(
    host: str,
    ports: list[int] | None = None,
    timeout_seconds: float = 1.0,
    max_workers: int = 100,
) -> dict[str, Any]:
    """Scan a single host for open TCP ports using plain socket connect
    attempts (no special privileges needed). If `ports` is omitted, scans
    a curated list of common service ports. Returns open ports with best
    known service name."""
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return {"error": f"could not resolve host '{host}': {e}"}

    target_ports = ports if ports is not None else list(COMMON_PORTS.keys())
    open_ports = _scan_open_ports(resolved_ip, target_ports, timeout_seconds, max_workers)

    return {
        "host": host,
        "resolved_ip": resolved_ip,
        "scanned_ports": len(target_ports),
        "open_ports": open_ports,
    }


@mcp.tool()
def nmap_scan(
    target: str,
    arguments: str = "-sV -T4",
) -> dict[str, Any]:
    """Run an nmap scan against a host or subnet using the system nmap
    binary, and return the parsed results (host status, open ports,
    services, and version info where detected). `target` can be a single
    IP, hostname, or CIDR range. `arguments` are extra nmap flags
    (defaults to service/version detection at a fast timing template).
    Avoid flags requiring raw sockets (e.g. -sS, -O) unless this process
    has root/CAP_NET_RAW, or they will silently fall back / fail.
    Only scan networks/hosts you are authorized to scan."""
    if NMAP_PATH is None:
        return {"error": "nmap binary not found on PATH"}

    try:
        import nmap
    except ImportError as e:
        return {"error": f"python-nmap not available: {e}"}

    scanner = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))
    try:
        scanner.scan(hosts=target, arguments=arguments)
    except nmap.PortScannerError as e:
        return {"error": str(e)}

    results: dict[str, Any] = {}
    for host in scanner.all_hosts():
        host_info = scanner[host]
        ports: list[dict[str, Any]] = []
        for proto in host_info.all_protocols():
            for port, info in host_info[proto].items():
                ports.append(
                    {
                        "port": port,
                        "protocol": proto,
                        "state": info.get("state"),
                        "service": info.get("name"),
                        "product": info.get("product"),
                        "version": info.get("version"),
                    }
                )
        results[host] = {
            "state": host_info.state(),
            "hostnames": [h.get("name") for h in host_info.get("hostnames", [])],
            "ports": sorted(ports, key=lambda p: p["port"]),
        }

    return {"target": target, "arguments": arguments, "hosts": results}


@mcp.tool()
def nmap_os_scan(
    target: str,
    arguments: str = "-O",
) -> dict[str, Any]:
    """Run an nmap OS-detection scan against a host or subnet using the
    system nmap binary, and return the guessed OS matches per host
    (name, accuracy, OS class/family/generation). `target` can be a
    single IP, hostname, or CIDR range. `arguments` are extra nmap flags
    (defaults to just OS detection).
    OS detection sends raw packets and needs the *nmap binary itself* to
    run as root or have CAP_NET_RAW/CAP_NET_ADMIN (granting the calling
    Python process CAP_NET_RAW is not enough, since nmap runs as a
    separate subprocess); without that, nmap reports a permission error
    per host rather than failing the whole scan.
    Only scan networks/hosts you are authorized to scan."""
    if NMAP_PATH is None:
        return {"error": "nmap binary not found on PATH"}

    try:
        import nmap
    except ImportError as e:
        return {"error": f"python-nmap not available: {e}"}

    scanner = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))
    try:
        scanner.scan(hosts=target, arguments=arguments)
    except nmap.PortScannerError as e:
        return {"error": str(e)}

    results: dict[str, Any] = {}
    for host in scanner.all_hosts():
        host_info = scanner[host]
        osmatches: list[dict[str, Any]] = []
        for match in host_info.get("osmatch", []):
            osmatches.append(
                {
                    "name": match.get("name"),
                    "accuracy": match.get("accuracy"),
                    "osclass": [
                        {
                            "type": c.get("type"),
                            "vendor": c.get("vendor"),
                            "osfamily": c.get("osfamily"),
                            "osgen": c.get("osgen"),
                            "accuracy": c.get("accuracy"),
                        }
                        for c in match.get("osclass", [])
                    ],
                }
            )
        results[host] = {
            "state": host_info.state(),
            "hostnames": [h.get("name") for h in host_info.get("hostnames", [])],
            "osmatches": osmatches,
            "fingerprint": host_info.get("fingerprint"),
        }

    return {"target": target, "arguments": arguments, "hosts": results}


@mcp.tool()
def tls_scan(host: str, port: int = 443, timeout_seconds: float = 5.0) -> dict[str, Any]:
    """Connect to a TLS port and report the negotiated protocol/cipher and
    the peer certificate's details (subject, issuer, validity window,
    whether it's expired or self-signed). Does not validate the
    certificate against any trust store - it accepts anything so it can
    inspect certs that would normally be rejected (self-signed, expired,
    hostname-mismatched), which is the point of an audit tool.
    Only scan hosts you are authorized to test."""
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return {"error": f"could not resolve host '{host}': {e}"}

    try:
        with (
            socket.create_connection((resolved_ip, port), timeout=timeout_seconds) as sock,
            _tls_context().wrap_socket(sock, server_hostname=host) as tls_sock,
        ):
            protocol = tls_sock.version()
            cipher = tls_sock.cipher()
            der_cert = tls_sock.getpeercert(binary_form=True)
    except ssl.SSLError as e:
        return {"error": f"TLS handshake failed: {e}"}
    except OSError as e:
        return {"error": f"TLS connection failed: {e}"}

    cert_info: dict[str, Any] = {}
    if der_cert:
        try:
            from cryptography import x509

            cert = x509.load_der_x509_certificate(der_cert)
            now = datetime.now(UTC)
            not_after = cert.not_valid_after_utc
            not_before = cert.not_valid_before_utc
            cert_info = {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "expired": now > not_after,
                "not_yet_valid": now < not_before,
                "self_signed": cert.subject == cert.issuer,
                "days_until_expiry": (not_after - now).days,
                "signature_algorithm": (cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None),
            }
        except ImportError as e:
            cert_info = {"parse_error": f"cryptography not available: {e}"}
        except ValueError as e:
            cert_info = {"parse_error": str(e)}

    weak_protocol = protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")

    return {
        "host": host,
        "resolved_ip": resolved_ip,
        "port": port,
        "protocol": protocol,
        "weak_protocol": weak_protocol,
        "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None,
        "certificate": cert_info,
    }


@mcp.tool()
def http_header_audit(
    host: str,
    port: int = 80,
    path: str = "/",
    use_tls: bool | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Fetch a URL with a plain GET and audit the response headers: which
    common security headers (HSTS, CSP, X-Content-Type-Options,
    X-Frame-Options, Referrer-Policy, Permissions-Policy) are present vs
    missing, plus any headers that leak implementation details (Server,
    X-Powered-By). `use_tls` defaults to True for ports 443/8443 and
    False otherwise; pass it explicitly to override.
    Only scan hosts you are authorized to test."""
    tls = use_tls if use_tls is not None else port in (443, 8443)
    try:
        status, headers = _http_get(host, port, path, tls, timeout_seconds)
    except (OSError, http.client.HTTPException) as e:
        return {"error": f"HTTP request failed: {e}"}

    present_security_headers = {h: headers[h] for h in SECURITY_HEADERS if h in headers}
    missing_security_headers = [h for h in SECURITY_HEADERS if h not in headers]
    info_disclosure = {h: headers[h] for h in INFO_DISCLOSURE_HEADERS if h in headers}

    return {
        "host": host,
        "port": port,
        "path": path,
        "scheme": "https" if tls else "http",
        "status": status,
        "headers": headers,
        "present_security_headers": present_security_headers,
        "missing_security_headers": missing_security_headers,
        "info_disclosure_headers": info_disclosure,
    }


@mcp.tool()
def check_exposed_paths(
    host: str,
    port: int = 80,
    use_tls: bool | None = None,
    paths: list[str] | None = None,
    timeout_seconds: float = 5.0,
    fetch_body: bool = False,
    max_body_bytes: int = 8192,
) -> dict[str, Any]:
    """Probe a web server for common accidentally-exposed sensitive paths
    (.git/config, .env, .svn/entries, backup/config files, etc.) via
    plain GET requests. A path that answers 200 OK is flagged as likely
    exposed; anything else (404, 403, redirect) is not. Read-only - it
    only requests these paths, it never uploads, deletes, or exploits
    anything found. If `paths` is omitted, a built-in curated list is
    used. Set `fetch_body=True` to also capture up to `max_body_bytes`
    of raw content for anything exposed (200 OK) - the natural next
    step is feeding that content into secret_scan. Left off by default
    to keep responses small and avoid pulling content unnecessarily.
    Only scan hosts you are authorized to test."""
    tls = use_tls if use_tls is not None else port in (443, 8443)
    target_paths = paths if paths is not None else SENSITIVE_PATHS

    checked: list[dict[str, Any]] = []
    exposed: list[dict[str, Any]] = []
    for raw_path in target_paths:
        url_path = "/" + raw_path.lstrip("/")
        try:
            if fetch_body:
                status, _headers, body = _http_get_with_body(host, port, url_path, tls, timeout_seconds, max_body_bytes)
            else:
                status, _headers = _http_get(host, port, url_path, tls, timeout_seconds)
                body = None
        except (OSError, http.client.HTTPException) as e:
            checked.append({"path": url_path, "error": str(e)})
            continue
        entry: dict[str, Any] = {"path": url_path, "status": status}
        if body is not None and status == 200:
            entry["body"] = body.decode(errors="replace")
        checked.append(entry)
        if status == 200:
            exposed.append(entry)

    return {
        "host": host,
        "port": port,
        "scheme": "https" if tls else "http",
        "checked": checked,
        "exposed": exposed,
    }


def _probe_redis(ip: str, port: int, timeout_seconds: float) -> dict[str, Any]:
    try:
        with socket.create_connection((ip, port), timeout=timeout_seconds) as sock:
            sock.sendall(b"PING\r\n")
            data = sock.recv(256)
    except OSError as e:
        return {"service": "redis", "port": port, "reachable": False, "error": str(e)}

    if data.startswith(b"+PONG"):
        return {
            "service": "redis",
            "port": port,
            "reachable": True,
            "auth_required": False,
            "detail": "PING answered without authentication",
        }
    if b"NOAUTH" in data:
        return {"service": "redis", "port": port, "reachable": True, "auth_required": True, "detail": "server requires AUTH"}
    return {
        "service": "redis",
        "port": port,
        "reachable": True,
        "auth_required": None,
        "detail": f"unexpected response: {data[:100]!r}",
    }


def _probe_memcached(ip: str, port: int, timeout_seconds: float) -> dict[str, Any]:
    try:
        with socket.create_connection((ip, port), timeout=timeout_seconds) as sock:
            sock.sendall(b"version\r\n")
            data = sock.recv(256)
    except OSError as e:
        return {"service": "memcached", "port": port, "reachable": False, "error": str(e)}

    if data.startswith(b"VERSION"):
        return {
            "service": "memcached",
            "port": port,
            "reachable": True,
            "auth_required": False,
            "detail": "memcached's classic text protocol has no built-in auth; "
            f"version: {data.decode(errors='replace').strip()}",
        }
    return {
        "service": "memcached",
        "port": port,
        "reachable": True,
        "auth_required": None,
        "detail": f"unexpected response: {data[:100]!r}",
    }


def _probe_ftp(ip: str, port: int, timeout_seconds: float) -> dict[str, Any]:
    try:
        with socket.create_connection((ip, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            banner = sock.recv(256)
            sock.sendall(b"USER anonymous\r\n")
            sock.recv(256)
            sock.sendall(b"PASS anonymous@example.com\r\n")
            reply = sock.recv(256)
    except OSError as e:
        return {"service": "ftp", "port": port, "reachable": False, "error": str(e)}

    allowed = reply.startswith(b"230")
    return {
        "service": "ftp",
        "port": port,
        "reachable": True,
        "auth_required": not allowed,
        "detail": f"anonymous login {'succeeded' if allowed else 'rejected'}: {reply.decode(errors='replace').strip()}",
        "banner": banner.decode(errors="replace").strip(),
    }


def _probe_elasticsearch(ip: str, port: int, timeout_seconds: float) -> dict[str, Any]:
    try:
        status, _headers = _http_get(ip, port, "/", False, timeout_seconds)
    except (OSError, http.client.HTTPException) as e:
        return {"service": "elasticsearch", "port": port, "reachable": False, "error": str(e)}

    if status in (401, 403):
        return {"service": "elasticsearch", "port": port, "reachable": True, "auth_required": True, "detail": f"HTTP {status}"}
    if status == 200:
        return {
            "service": "elasticsearch",
            "port": port,
            "reachable": True,
            "auth_required": False,
            "detail": "cluster info endpoint answered without authentication",
        }
    return {"service": "elasticsearch", "port": port, "reachable": True, "auth_required": None, "detail": f"HTTP {status}"}


_SERVICE_PROBES: dict[int, Callable[[str, int, float], dict[str, Any]]] = {
    21: _probe_ftp,
    6379: _probe_redis,
    9200: _probe_elasticsearch,
    11211: _probe_memcached,
}


@mcp.tool()
def check_unauthenticated_services(
    host: str,
    ports: list[int] | None = None,
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    """Check a handful of commonly-unauthenticated-by-default services
    (Redis, FTP anonymous login, Elasticsearch, Memcached) for whether
    they answer without credentials. Only ports that match one of these
    four known services are actually probed - anything else in `ports`
    is skipped (reported separately), never blindly connected to. If
    `ports` is omitted, all four default service ports are checked.
    Every probe is a single read-only protocol handshake (PING,
    anonymous FTP login attempt, a plain GET, a version query) - nothing
    is written, deleted, or exploited.
    Only scan hosts you are authorized to test."""
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return {"error": f"could not resolve host '{host}': {e}"}

    target_ports = ports if ports is not None else list(_SERVICE_PROBES.keys())
    results: list[dict[str, Any]] = []
    skipped: list[int] = []
    for port in target_ports:
        probe = _SERVICE_PROBES.get(port)
        if probe is None:
            skipped.append(port)
            continue
        results.append(probe(resolved_ip, port, timeout_seconds))

    return {
        "host": host,
        "resolved_ip": resolved_ip,
        "checked": results,
        "skipped_ports_no_known_probe": skipped,
    }


def _check_telnet_port(ip: str, port: int, timeout_seconds: float) -> dict[str, Any] | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            banner = sock.recv(256)
    except OSError:
        return None
    return {
        "port": port,
        "protocol": "telnet",
        "issue": "Telnet is inherently cleartext; any credentials typed over it are sent unencrypted",
        "banner": banner.decode(errors="replace").strip(),
    }


def _check_ftp_cleartext(ip: str, port: int, timeout_seconds: float) -> dict[str, Any] | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            banner = sock.recv(256)
    except OSError:
        return None
    return {
        "port": port,
        "protocol": "ftp",
        "issue": "FTP authentication (USER/PASS) is sent in cleartext",
        "banner": banner.decode(errors="replace").strip(),
    }


def _check_http_basic_auth_cleartext(host: str, port: int, timeout_seconds: float) -> dict[str, Any] | None:
    try:
        status, headers = _http_get(host, port, "/", False, timeout_seconds)
    except (OSError, http.client.HTTPException):
        return None
    www_auth = headers.get("WWW-Authenticate", "")
    if status == 401 and "basic" in www_auth.lower():
        return {
            "port": port,
            "protocol": "http",
            "issue": "HTTP Basic Authentication offered over plaintext HTTP; credentials are only "
            "base64-encoded, trivially recoverable by anyone observing the traffic",
            "www_authenticate": www_auth,
        }
    return None


@mcp.tool()
def check_cleartext_auth(
    host: str,
    ports: list[int] | None = None,
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    """Flag exposure to cleartext (unencrypted) authentication: an open
    Telnet or FTP port (both transmit credentials in plaintext once
    authenticated) and HTTP endpoints offering HTTP Basic Authentication
    over plain HTTP instead of HTTPS (Basic Auth credentials are only
    base64-encoded, trivially recoverable by anyone observing the
    traffic). If `ports` is omitted, checks 21 (ftp), 23 (telnet), 80,
    and 8080. Port 23 is always treated as Telnet and 21 as FTP; any
    other port is probed as plain HTTP for a Basic-Auth challenge.
    Read-only: it connects and inspects banners/headers only - it never
    submits any credentials, guessed or otherwise.
    Only scan hosts you are authorized to test."""
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return {"error": f"could not resolve host '{host}': {e}"}

    target_ports = ports if ports is not None else [21, 23, 80, 8080]
    findings: list[dict[str, Any]] = []
    for port in target_ports:
        if port == 23:
            finding = _check_telnet_port(resolved_ip, port, timeout_seconds)
        elif port == 21:
            finding = _check_ftp_cleartext(resolved_ip, port, timeout_seconds)
        else:
            finding = _check_http_basic_auth_cleartext(host, port, timeout_seconds)
        if finding:
            findings.append(finding)

    return {
        "host": host,
        "resolved_ip": resolved_ip,
        "checked_ports": target_ports,
        "findings": findings,
    }


@mcp.tool()
def resolve_hostname(host: str) -> dict[str, Any]:
    """Resolve a hostname to its IP address(es), or reverse-resolve an
    IP address to a hostname (PTR lookup)."""
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        try:
            hostname, aliases, _ = socket.gethostbyaddr(host)
            return {"ip": host, "hostname": hostname, "aliases": aliases}
        except socket.herror as e:
            return {"ip": host, "error": f"no PTR record: {e}"}
    else:
        try:
            _, _, ip_list = socket.gethostbyname_ex(host)
            return {"hostname": host, "addresses": ip_list}
        except socket.gaierror as e:
            return {"hostname": host, "error": f"resolution failed: {e}"}


@mcp.tool()
def get_default_gateway() -> dict[str, Any]:
    """Return the system's default gateway IP and the interface it's
    reachable through, parsed from OS routing tables."""
    system = platform.system().lower()
    try:
        if system == "linux":
            output = _run(["ip", "route", "show", "default"], timeout=5)
            line = output.strip().splitlines()[0] if output.strip() else ""
            parts = line.split()
            gateway = parts[parts.index("via") + 1] if "via" in parts else None
            iface = parts[parts.index("dev") + 1] if "dev" in parts else None
            return {"gateway": gateway, "interface": iface, "raw": line}
        elif system == "darwin":
            output = _run(["route", "-n", "get", "default"], timeout=5)
            gateway = None
            iface = None
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("gateway:"):
                    gateway = line.split(":", 1)[1].strip()
                elif line.startswith("interface:"):
                    iface = line.split(":", 1)[1].strip()
            return {"gateway": gateway, "interface": iface}
        elif system == "windows":
            output = _run(["ipconfig"], timeout=5)
            return {"raw": output}
        else:
            return {"error": f"unsupported platform: {system}"}
    except (subprocess.TimeoutExpired, IndexError) as e:
        return {"error": str(e)}


KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_NAME = "cisa_kev.json"
KEV_CACHE_TTL_SECONDS = 24 * 60 * 60


@mcp.tool()
def kev_lookup(cve_ids: list[str]) -> dict[str, Any]:
    """Check whether one or more CVE IDs are in CISA's Known Exploited
    Vulnerabilities (KEV) catalog - i.e. CISA has confirmed real-world,
    active exploitation, not just theoretical risk.

    CISA publishes the whole catalog (~1700 entries) as one JSON file
    rather than a per-CVE API, so it's fetched once and cached locally
    for 24 hours (.cache/cisa_kev.json); most calls are served from that
    cache, not a fresh network request (the response's `cache` field
    says which happened). Presence in KEV is a strong signal to
    prioritize remediation; absence does NOT mean a CVE is safe to
    ignore, only that CISA hasn't flagged confirmed active exploitation
    of it (yet) - pair with epss_lookup for a probability estimate on
    CVEs that aren't (yet) in KEV."""
    if not cve_ids:
        return {"error": "cve_ids must be a non-empty list"}

    try:
        catalog, cache_meta = _fetch_json_cached(KEV_CATALOG_URL, KEV_CACHE_NAME, KEV_CACHE_TTL_SECONDS, timeout_seconds=20.0)
    except (OSError, ValueError) as e:
        return {"error": f"failed to fetch/parse CISA KEV catalog: {e}"}

    by_cve = {entry["cveID"]: entry for entry in catalog.get("vulnerabilities", [])}
    results = [
        {"cve": cve_id, "in_kev": (entry := by_cve.get(cve_id.upper())) is not None, "details": entry}
        for cve_id in cve_ids
    ]

    return {
        "results": results,
        "catalog_version": catalog.get("catalogVersion"),
        "catalog_date_released": catalog.get("dateReleased"),
        "catalog_total_entries": catalog.get("count"),
        "cache": cache_meta,
    }


_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")),
    (
        "Generic API Key/Secret Assignment",
        re.compile(r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"]?([A-Za-z0-9\-_/+=]{8,})['\"]?"),
    ),
]


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


@mcp.tool()
def secret_scan(text: str, reveal: bool = False, max_findings: int = 50) -> dict[str, Any]:
    """Scan a blob of text for likely-looking secrets: AWS access keys,
    private key headers, GitHub/Slack/Google/Stripe tokens, JWTs, and a
    generic "key/secret/token/password = value" assignment pattern.
    Intended as a followup to check_exposed_paths (call that with
    fetch_body=True on anything exposed, then feed the body here) or any
    other text you want checked.

    Pattern-based, not perfect: the generic assignment rule in
    particular can flag non-secrets (a config flag literally named
    "token" set to a placeholder) - treat findings as leads to verify,
    not confirmed secrets. `reveal=False` (default) returns each match
    redacted (first/last 4 characters only); set `reveal=True` only when
    you specifically need the full value, since it will then appear in
    this tool's output.
    Only scan text you are authorized to inspect."""
    findings: list[dict[str, Any]] = []
    for label, pattern in _SECRET_PATTERNS:
        if len(findings) >= max_findings:
            break
        for match in pattern.finditer(text):
            if len(findings) >= max_findings:
                break
            value = match.group(0)
            findings.append(
                {
                    "type": label,
                    "match": value if reveal else _redact(value),
                    "position": match.start(),
                }
            )

    return {
        "length_scanned": len(text),
        "finding_count": len(findings),
        "findings": findings,
        "reveal": reveal,
    }


def _dig_txt(name: str, timeout_seconds: float) -> list[str]:
    """Return TXT record strings for `name` via `dig`, quotes stripped and multi-segment records joined."""
    if DIG_PATH is None:
        return []
    try:
        output = _run([DIG_PATH, "+short", "TXT", name], timeout=int(timeout_seconds) + 2)
    except subprocess.TimeoutExpired:
        return []
    records: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        segments = re.findall(r'"((?:[^"\\]|\\.)*)"', line)
        records.append("".join(segments) if segments else line)
    return records


@mcp.tool()
def email_auth_audit(
    domain: str,
    dkim_selectors: list[str] | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Check a domain's anti-spoofing email authentication records: SPF,
    DMARC, and (best-effort) DKIM. Uses the system `dig` command for TXT
    lookups - these are read-only, public DNS queries, exactly what any
    receiving mail server does when your domain sends it mail.

    SPF and DMARC are fully deterministic (SPF is a TXT record on the
    domain itself; DMARC is a TXT record at _dmarc.<domain>). DKIM is
    NOT fully checkable from DNS alone: its selector (the DNS label a
    sender chose, e.g. "google" or "selector1") isn't discoverable
    without out-of-band knowledge (an email's DKIM-Signature header, or
    the provider's docs). Pass `dkim_selectors` if you know them;
    otherwise a handful of common defaults are guessed, and the result
    says explicitly that these are guesses - a "not found" result for
    every guessed selector does NOT mean DKIM is absent, only that none
    of the guessed selectors are in use.
    Only look up domains you are authorized to assess."""
    if DIG_PATH is None:
        return {"error": "dig binary not found on PATH"}

    spf_records = [r for r in _dig_txt(domain, timeout_seconds) if r.lower().startswith("v=spf1")]
    dmarc_records = [r for r in _dig_txt(f"_dmarc.{domain}", timeout_seconds) if r.lower().startswith("v=dmarc1")]

    dmarc_policy = None
    if dmarc_records:
        policy_match = re.search(r"(?i)\bp=([a-z]+)", dmarc_records[0])
        dmarc_policy = policy_match.group(1).lower() if policy_match else None

    selectors_checked = dkim_selectors if dkim_selectors else ["default", "google", "selector1", "selector2", "k1", "s1", "dkim"]
    dkim_found: list[dict[str, Any]] = []
    for selector in selectors_checked:
        records = _dig_txt(f"{selector}._domainkey.{domain}", timeout_seconds)
        matches = [r for r in records if "v=dkim1" in r.lower() or "p=" in r.lower()]
        if matches:
            dkim_found.append({"selector": selector, "record": matches[0]})

    return {
        "domain": domain,
        "spf": {"present": bool(spf_records), "records": spf_records},
        "dmarc": {
            "present": bool(dmarc_records),
            "records": dmarc_records,
            "policy": dmarc_policy,
            "note": (
                "p=none only monitors; it does not stop spoofed mail from being delivered. "
                "p=quarantine/p=reject actually enforce."
                if dmarc_policy
                else None
            ),
        },
        "dkim": {
            "selectors_checked": selectors_checked,
            "selectors_provided_by_caller": dkim_selectors is not None,
            "found": dkim_found,
            "note": "DKIM selectors aren't discoverable from DNS alone; an empty 'found' list means "
            "none of the checked selectors are in use, not that DKIM is absent.",
        },
    }


RETIRE_JS_URL = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json"
RETIRE_JS_CACHE_NAME = "retire_js_repository.json"
RETIRE_JS_CACHE_TTL_SECONDS = 24 * 60 * 60

_RETIRE_VERSION_TOKEN = "§§version§§"  # retire.js's placeholder for "the version goes here"
# Lazy quantifier: a greedy one swallows trailing optional groups in the surrounding pattern
# (e.g. "jquery-(version)(\.min)?\.js" against "jquery-4.0.0.min.js" would capture "4.0.0.min").
_RETIRE_VERSION_CHARS = r"[0-9][0-9A-Za-z_.\-]*?"


class _ScriptSrcParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.srcs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        for name, value in attrs:
            if name.lower() == "src" and value:
                self.srcs.append(value)


def _fetch_url(url: str, timeout_seconds: float, max_bytes: int) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-network-scanner/1.0"})
    context = ssl.create_default_context()  # real internet targets: validate normally, unlike the LAN tools
    with urllib.request.urlopen(req, timeout=timeout_seconds, context=context) as resp:
        status = resp.status
        body = resp.read(max_bytes + 1)
    return status, body[:max_bytes]


def _compile_retire_pattern(raw: str) -> re.Pattern[str] | None:
    wrapped = f"({_RETIRE_VERSION_TOKEN})"
    if wrapped in raw:
        pattern = raw.replace(wrapped, f"(?P<version>{_RETIRE_VERSION_CHARS})")
    elif _RETIRE_VERSION_TOKEN in raw:
        pattern = raw.replace(_RETIRE_VERSION_TOKEN, f"(?P<version>{_RETIRE_VERSION_CHARS})")
    else:
        return None
    try:
        return re.compile(pattern)
    except re.error:
        return None


def _version_tuple(v: str) -> tuple[int | str, ...]:
    return tuple(int(p) if p.isdigit() else p for p in re.findall(r"\d+|[A-Za-z]+", v))


def _version_in_range(version: str, below: str | None, at_or_above: str | None) -> bool | None:
    """True if `version` falls in [at_or_above, below). None if the strings aren't comparable."""
    try:
        v = _version_tuple(version)
        if below is not None and not v < _version_tuple(below):
            return False
        return at_or_above is None or v >= _version_tuple(at_or_above)
    except TypeError:
        return None


def _identify_library(url: str, repo: dict[str, Any], timeout_seconds: float, max_bytes: int) -> dict[str, Any] | None:
    filename = urlsplit(url).path.rsplit("/", 1)[-1]

    for lib_name, lib_data in repo.items():
        extractors = lib_data.get("extractors", {})
        for raw_pattern in extractors.get("filename", []):
            compiled = _compile_retire_pattern(raw_pattern)
            if compiled and (m := compiled.search(filename)):
                return {"library": lib_name, "version": m.group("version"), "matched_by": "filename"}
        for raw_pattern in extractors.get("uri", []):
            compiled = _compile_retire_pattern(raw_pattern)
            if compiled and (m := compiled.search(url)):
                return {"library": lib_name, "version": m.group("version"), "matched_by": "uri"}

    # Filename/URI alone didn't identify it - fall back to fetching content and matching version banners.
    try:
        _status, body = _fetch_url(url, timeout_seconds, max_bytes)
    except (OSError, ValueError):
        return None
    text = body.decode(errors="replace")

    for lib_name, lib_data in repo.items():
        for raw_pattern in lib_data.get("extractors", {}).get("filecontent", []):
            compiled = _compile_retire_pattern(raw_pattern)
            if compiled and (m := compiled.search(text)):
                return {"library": lib_name, "version": m.group("version"), "matched_by": "filecontent"}

    return None


@mcp.tool()
def js_library_audit(
    url: str,
    timeout_seconds: float = 10.0,
    max_scripts: int = 20,
    max_script_bytes: int = 2_000_000,
) -> dict[str, Any]:
    """Fetch a web page, find every JS library it loads via <script src>,
    identify each library's name and version, and check them against
    Retire.js's public vulnerability database (fetched once and cached
    locally for 24 hours at .cache/retire_js_repository.json).

    Identification tries the cheapest method first - the script's own
    filename/URL, e.g. "jquery-1.7.1.min.js" - and only downloads a
    script's content (capped at max_script_bytes) as a fallback, when
    the filename alone doesn't reveal a known library+version.
    Only checks the one page given - it does not crawl links, and it
    cannot reliably identify custom-bundled/minified app code that
    doesn't match a known open-source library's signature; those show
    up as identified=false, not as an error.
    Only scan pages you are authorized to assess."""
    try:
        status, body = _fetch_url(url, timeout_seconds, max_script_bytes)
    except (OSError, ValueError) as e:
        return {"error": f"failed to fetch page: {e}"}
    if status != 200:
        return {"error": f"page returned HTTP {status}"}

    parser = _ScriptSrcParser()
    parser.feed(body.decode(errors="replace"))

    script_urls: list[str] = []
    seen: set[str] = set()
    for src in parser.srcs:
        absolute = urljoin(url, src)
        if absolute not in seen:
            seen.add(absolute)
            script_urls.append(absolute)
        if len(script_urls) >= max_scripts:
            break

    try:
        repo, cache_meta = _fetch_json_cached(
            RETIRE_JS_URL, RETIRE_JS_CACHE_NAME, RETIRE_JS_CACHE_TTL_SECONDS, timeout_seconds=20.0
        )
    except (OSError, ValueError) as e:
        return {"error": f"failed to fetch/parse Retire.js vulnerability database: {e}"}

    results: list[dict[str, Any]] = []
    for script_url in script_urls:
        identified = _identify_library(script_url, repo, timeout_seconds, max_script_bytes)
        if identified is None:
            results.append({"script": script_url, "identified": False})
            continue

        vulns_found: list[dict[str, Any]] = []
        for vuln in repo.get(identified["library"], {}).get("vulnerabilities", []):
            if _version_in_range(identified["version"], vuln.get("below"), vuln.get("atOrAbove")):
                identifiers = vuln.get("identifiers", {})
                vulns_found.append(
                    {
                        "severity": vuln.get("severity"),
                        "summary": identifiers.get("summary"),
                        "cve": identifiers.get("CVE", []),
                        "below": vuln.get("below"),
                        "at_or_above": vuln.get("atOrAbove"),
                        "info": vuln.get("info", []),
                    }
                )

        results.append(
            {
                "script": script_url,
                "identified": True,
                "library": identified["library"],
                "version": identified["version"],
                "matched_by": identified["matched_by"],
                "vulnerabilities": vulns_found,
            }
        )

    return {
        "page": url,
        "scripts_found": len(parser.srcs),
        "scripts_checked": len(script_urls),
        "results": results,
        "retire_js_database": cache_meta,
    }


if __name__ == "__main__":
    mcp.run()
