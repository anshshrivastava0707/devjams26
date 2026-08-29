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

import ipaddress
import platform
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import psutil
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("network-scanner")

NMAP_PATH = shutil.which("nmap")

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


if __name__ == "__main__":
    mcp.run()
