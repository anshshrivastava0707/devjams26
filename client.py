"""
Client for the network-scanner MCP server (server.py). Two modes:

  .venv/bin/python client.py            interactive LangChain agent chat,
                                         bound to every tool this server
                                         exposes (needs GOOGLE_API_KEY in .env)
  .venv/bin/python client.py --verify   fixed regression run: calls every
                                         tool with known-good arguments
                                         against this machine's real local
                                         network, writes client_output.txt

Only point either mode at networks/hosts you own or are authorized to test.
--verify only *reports* failures - it does not attempt to fix the server if
a tool errors out.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain_core.tools import StructuredTool
from langchain_google_genai import ChatGoogleGenerativeAI
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

load_dotenv(Path(__file__).parent / ".env")

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
    "tls_scan": [
        ("gateway :443", {"host": REAL_GATEWAY, "port": 443, "timeout_seconds": 5.0}),
    ],
    "http_header_audit": [
        ("gateway :80", {"host": REAL_GATEWAY, "port": 80, "timeout_seconds": 5.0}),
        ("gateway :443", {"host": REAL_GATEWAY, "port": 443, "timeout_seconds": 5.0}),
    ],
    "check_exposed_paths": [
        ("gateway :80", {"host": REAL_GATEWAY, "port": 80, "timeout_seconds": 5.0}),
    ],
    "check_unauthenticated_services": [
        (
            "gateway default probe ports",
            {"host": REAL_GATEWAY, "timeout_seconds": 3.0},
        ),
    ],
    "check_cleartext_auth": [
        (
            "gateway default probe ports",
            {"host": REAL_GATEWAY, "timeout_seconds": 3.0},
        ),
    ],
    "epss_lookup": [
        (
            "real CVEs: Log4Shell (high EPSS) + Apache 2.4.6 DoS (low EPSS)",
            {"cve_ids": ["CVE-2021-44228", "CVE-2013-4352"]},
        ),
    ],
    "kev_lookup": [
        (
            "real CVEs: Log4Shell (in KEV) + Apache 2.4.6 DoS (not in KEV)",
            {"cve_ids": ["CVE-2021-44228", "CVE-2013-4352"]},
        ),
    ],
    "secret_scan": [
        (
            "synthetic text blob with fake secrets",
            {
                "text": (
                    "config = {\n"
                    "  aws_key: 'AKIAABCDEFGHIJKLMNOP',\n"
                    "  api_token: 'sk_live_ABCDEFGHIJKLMNOPQRSTUVWX',\n"
                    "  jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',\n"
                    "  password: 'Sup3rSecretPass1234'\n"
                    "}\n"
                ),
            },
        ),
    ],
    # DNS TXT lookups are public by design (every receiving mail server does
    # this automatically) - no authorization concern, unlike LAN scanning.
    "email_auth_audit": [
        ("google.com", {"domain": "google.com", "timeout_seconds": 5.0}),
    ],
    # jquery.com's own homepage is a stable, genuinely public page that loads
    # jQuery via <script src> - a real end-to-end fetch/parse/identify test.
    "js_library_audit": [
        ("jquery.com homepage", {"url": "https://jquery.com/", "timeout_seconds": 10.0}),
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


async def run_verification() -> int:
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


AGENT_SYSTEM_PROMPT = (
    "You are a network security assistant with access to a set of local-network "
    "scanning and analysis tools over MCP. Each tool's own description documents "
    "specific safety constraints (e.g. 'use sparingly', 'only scan hosts you are "
    "authorized to test', rate limits) - follow them exactly, don't call a tool "
    "just because it exists. Before running any active scan (subnet sweeps, "
    "ARP/port/nmap scans, unauthenticated-service or cleartext-auth checks) "
    "against a target the user hasn't already named, confirm with the user that "
    "they own or are authorized to test it. Never guess or brute-force "
    "credentials. Prefer the least invasive tool that answers the question, and "
    "explain findings in plain language rather than dumping raw JSON.\n\n"
    "Users will describe what they want in everyday language, not tool names - "
    "translate intent to the right tool(s) yourself. Rough guide:\n"
    "- 'what's my network/subnet/IP' -> list_network_interfaces, get_default_gateway\n"
    "- 'what devices/hosts are on my network' -> ping_sweep or arp_scan (arp_scan is "
    "more reliable on a LAN); use discover_devices when they also want hostnames/"
    "vendor/device-type hints\n"
    "- 'is <host> up/reachable' -> ping_host; 'resolve/lookup this domain or IP' -> "
    "resolve_hostname\n"
    "- 'what ports/services are open on <host>' -> port_scan for a quick check, "
    "nmap_scan when they want service/version detail\n"
    "- 'what OS is <host> running' -> nmap_os_scan (warn them it needs root/"
    "CAP_NET_RAW and may fail without it)\n"
    "- 'is my site's SSL/TLS/certificate okay' -> tls_scan\n"
    "- 'are my security headers set up right' / 'is my site missing CSP/HSTS/etc' -> "
    "http_header_audit\n"
    "- 'do I have anything sensitive exposed' (.git, .env, backups, etc.) -> "
    "check_exposed_paths; if they want it checked for leaked keys/secrets too, "
    "call it with fetch_body=True and feed the body into secret_scan\n"
    "- 'is <text/config/file content> leaking any secrets or API keys' -> "
    "secret_scan\n"
    "- 'do I have any databases/caches open without a password' (Redis, "
    "Elasticsearch, Memcached, anonymous FTP) -> check_unauthenticated_services\n"
    "- 'are any of my services sending passwords in plaintext' (Telnet, FTP, HTTP "
    "Basic Auth over http) -> check_cleartext_auth\n"
    "- 'is my domain protected against email spoofing/phishing' (SPF/DMARC/DKIM) -> "
    "email_auth_audit\n"
    "- 'are the JS libraries on my site outdated/vulnerable' -> js_library_audit\n"
    "- 'is this CVE serious/likely to be exploited' -> epss_lookup (probability of "
    "exploitation) and kev_lookup (confirmed active exploitation); use both together "
    "for a fuller picture rather than either alone\n"
    "When a request is broad ('audit my network', 'check my site's security'), chain "
    "several of the above rather than picking just one, and say up front which "
    "checks you're about to run."
)


def build_langchain_tools(client: Client, mcp_tools: list[Any]) -> list[StructuredTool]:
    """Wrap each MCP tool as a LangChain StructuredTool that calls it over `client`.

    Each call's raw result is printed to the user as soon as it comes back, verbatim -
    that's the ground truth from the tool, not a paraphrase. The same raw result is also
    returned to the agent so it can still chain tool calls on precise data (e.g.
    check_exposed_paths' body -> secret_scan) and hold a conversation about it.
    """

    def make_coroutine(tool_name: str) -> Callable[..., Any]:
        async def _call(**kwargs: Any) -> Any:
            result = await client.call_tool(tool_name, kwargs)
            raw = {"error": _extract_text(result.content)} if result.is_error else result.structured_content
            print(f"\n[{tool_name}] {json.dumps(raw, indent=2, default=str)}\n")
            return raw

        return _call

    return [
        StructuredTool.from_function(
            coroutine=make_coroutine(tool.name),
            name=tool.name,
            description=tool.description or tool.name,
            args_schema=tool.input_schema,
        )
        for tool in mcp_tools
    ]


async def run_agent_chat() -> None:
    if not os.environ.get("GOOGLE_API_KEY"):
        print(
            "GOOGLE_API_KEY is not set. Add it to .env (copy .env.example) and re-run.\n"
            "The fixed regression run doesn't need it: .venv/bin/python client.py --verify"
        )
        return

    model_name = os.environ.get("GEMINI_MODEL") or "gemini-2.5-flash"
    params = StdioServerParameters(command=PYTHON, args=[str(SERVER_SCRIPT)])

    async with Client(params) as client:
        listing = await client.list_tools()
        model = ChatGoogleGenerativeAI(model=model_name)
        tools = build_langchain_tools(client, listing.tools)
        print(f"Connected to server. {len(tools)} tools available to the agent: {', '.join(t.name for t in tools)}\n")

        agent = create_agent(model, tools, system_prompt=AGENT_SYSTEM_PROMPT)

        print(f"Chatting with the agent (model={model_name}). Type 'exit' or Ctrl+D to quit.\n")
        messages: list[Any] = []
        while True:
            try:
                user_input = input("you> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not user_input:
                continue
            if user_input.lower() in {"exit", "quit"}:
                break

            messages.append({"role": "user", "content": user_input})
            try:
                result = await agent.ainvoke({"messages": messages})
            except Exception as exc:  # noqa: BLE001 - keep the chat loop alive on any agent-turn failure
                print(f"agent error: {exc!r}\n")
                messages.pop()
                continue

            messages = result["messages"]
            print(f"agent> {messages[-1].content}\n")


if __name__ == "__main__":
    if "--verify" in sys.argv[1:]:
        raise SystemExit(asyncio.run(run_verification()))
    asyncio.run(run_agent_chat())
