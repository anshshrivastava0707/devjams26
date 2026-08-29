"""
Test client for the network-scanner MCP server (server.py).

Launches server.py as a subprocess over stdio, discovers every tool it
exposes, and calls each one against this machine's real local network
(gateway/subnet from list_network_interfaces / get_default_gateway).
Only scan networks you own or are authorized to test. Prints a PASS/FAIL
report per call and a final summary.

This script only *reports* failures — it does not attempt to fix the
server if a tool errors out.

Run with:
    .venv/bin/python client.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

SERVER_SCRIPT = Path(__file__).parent / "server.py"
PYTHON = sys.executable
OUTPUT_FILE = Path(__file__).parent / "client_output.txt"

# Real LAN target for this machine, confirmed with the user before scanning:
# gateway 172.18.224.1 on subnet 172.18.224.0/20 (from list_network_interfaces / get_default_gateway).
REAL_GATEWAY = "172.18.224.1"
REAL_SUBNET = "172.18.224.0/20"

# tool name -> list of (label, arguments) test cases to run against it.
# Subnet-discovery tools (ping_sweep, arp_scan) hit the full real LAN subnet.
# Single-host tools target the real gateway rather than a sweep, since running
# nmap's version detection across ~4094 hosts is impractically slow.
TEST_CASES: dict[str, list[tuple[str, dict[str, Any]]]] = {
    "list_network_interfaces": [("default", {})],
    "get_default_gateway": [("default", {})],
    "resolve_hostname": [
        ("forward (localhost)", {"host": "localhost"}),
        ("reverse (gateway)", {"host": REAL_GATEWAY}),
    ],
    "ping_host": [
        ("gateway", {"host": REAL_GATEWAY, "count": 1, "timeout_seconds": 2}),
    ],
    "ping_sweep": [
        ("real LAN subnet", {"subnet": REAL_SUBNET, "timeout_seconds": 1, "max_workers": 128}),
    ],
    "arp_scan": [
        ("real LAN subnet", {"subnet": REAL_SUBNET, "timeout_seconds": 3}),
    ],
    "discover_devices": [
        (
            "real LAN subnet, with port probe",
            {"subnet": REAL_SUBNET, "timeout_seconds": 3, "probe_ports": True, "port_timeout_seconds": 0.5},
        ),
    ],
    "port_scan": [
        ("gateway common ports", {"host": REAL_GATEWAY, "timeout_seconds": 1.0}),
    ],
    "nmap_scan": [
        ("gateway -sV -T4", {"target": REAL_GATEWAY, "arguments": "-sV -T4"}),
    ],
    "nmap_os_scan": [
        ("gateway -O", {"target": REAL_GATEWAY, "arguments": "-O"}),
    ],
}


@dataclass
class CaseResult:
    tool: str
    label: str
    ok: bool
    detail: str
    payload: Any = None
    arguments: dict[str, Any] = field(default_factory=dict)


def _extract_text(content: list[Any]) -> str:
    parts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str) and text:
            parts.append(text)
    return " | ".join(parts) or "<no text content>"


async def run_case(client: Client, tool: str, label: str, arguments: dict[str, Any]) -> CaseResult:
    try:
        result = await client.call_tool(tool, arguments)
    except Exception as exc:  # noqa: BLE001 - test harness must report any failure, not just expected ones
        return CaseResult(tool, label, False, f"exception raised while calling tool: {exc!r}", arguments=arguments)

    if result.is_error:
        return CaseResult(
            tool, label, False, f"tool returned isError=True: {_extract_text(result.content)}", arguments=arguments
        )

    payload = result.structured_content
    if isinstance(payload, dict) and "error" in payload:
        return CaseResult(
            tool, label, False, f"tool returned an error payload: {payload['error']}", arguments=arguments
        )

    return CaseResult(tool, label, True, "ok", payload, arguments=arguments)


def format_report(results: list[CaseResult]) -> str:
    lines: list[str] = [
        "MCP network-scanner tool test results",
        f"Generated: {datetime.now(UTC).isoformat()}",
        f"Server: {SERVER_SCRIPT}",
        f"Target: gateway={REAL_GATEWAY} subnet={REAL_SUBNET}",
        "",
    ]
    for r in results:
        lines.append("=" * 70)
        lines.append(f"tool:      {r.tool}")
        lines.append(f"case:      {r.label}")
        lines.append(f"arguments: {json.dumps(r.arguments, default=str)}")
        lines.append(f"status:    {'PASS' if r.ok else 'FAIL'}")
        if r.ok:
            lines.append("output:")
            lines.append(json.dumps(r.payload, indent=2, default=str))
        else:
            lines.append(f"failure detail: {r.detail}")
        lines.append("")

    passed = sum(1 for r in results if r.ok)
    lines.append("=" * 70)
    lines.append(f"SUMMARY: {passed}/{len(results)} passed")
    if passed < len(results):
        lines.append("Failing tools were left unfixed, per instructions:")
        for r in results:
            if not r.ok:
                lines.append(f"  - {r.tool} ({r.label}): {r.detail}")
    return "\n".join(lines)


async def main() -> int:
    params = StdioServerParameters(command=PYTHON, args=[str(SERVER_SCRIPT)])

    results: list[CaseResult] = []

    async with Client(params) as client:
        listing = await client.list_tools()
        server_tool_names = {t.name for t in listing.tools}
        print(f"Connected to server. Exposes {len(server_tool_names)} tools: {', '.join(sorted(server_tool_names))}\n")

        untested = server_tool_names - TEST_CASES.keys()
        if untested:
            print(f"WARNING: no test case defined for: {', '.join(sorted(untested))}\n")

        for tool in sorted(TEST_CASES):
            if tool not in server_tool_names:
                results.append(CaseResult(tool, "-", False, "tool not found on server (defined in TEST_CASES but not exposed)"))
                print(f"-> {tool}: NOT FOUND on server\n")
                continue

            for label, arguments in TEST_CASES[tool]:
                print(f"-> {tool} [{label}] args={arguments}")
                res = await run_case(client, tool, label, arguments)
                results.append(res)
                if res.ok:
                    print(f"   PASS: {json.dumps(res.payload, default=str)[:300]}")
                else:
                    print(f"   FAIL: {res.detail}")
                print()

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    passed = [r for r in results if r.ok]
    failed = [r for r in results if not r.ok]
    for r in results:
        status = "PASS" if r.ok else "FAIL"
        suffix = "" if r.ok else f" - {r.detail}"
        print(f"[{status}] {r.tool} ({r.label}){suffix}")

    print(f"\n{len(passed)}/{len(results)} test cases passed.")

    if failed:
        print(
            "\nThe following are NOT working. Per instructions, they have NOT been "
            "fixed — reporting only:"
        )
        for r in failed:
            print(f"  - {r.tool} ({r.label}): {r.detail}")

    OUTPUT_FILE.write_text(format_report(results) + "\n")
    print(f"\nFull, untruncated per-tool output written to {OUTPUT_FILE}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
