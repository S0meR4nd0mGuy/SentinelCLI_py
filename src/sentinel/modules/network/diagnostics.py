"""Network diagnostics and discovery operations."""

from __future__ import annotations

import json
import socket
import subprocess
import urllib.request
from dataclasses import asdict, dataclass

from ...core.common import ToolkitError, print_json, resolve_host


@dataclass
class PingResult:
    host: str
    reachable: bool
    latency_ms: float | None
    output: str


def ping_host(host: str, timeout: float = 2.0, count: int = 1) -> PingResult:
    if not host.strip():
        raise ToolkitError("Host is required.")
    count = max(1, min(count, 4))
    command = ["ping", "-n", str(count), "-w", str(max(100, int(timeout * 1000))), host]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=max(5.0, timeout * count + 2))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return PingResult(host, False, None, str(exc))
    output = (completed.stdout or completed.stderr).strip()
    latency_ms = None
    for token in output.replace("<", " ").split():
        if token.lower().endswith("ms"):
            try:
                latency_ms = float(token[:-2])
                break
            except ValueError:
                pass
    return PingResult(host, completed.returncode == 0, latency_ms, output)


def ping_command(args) -> int:
    result = asdict(ping_host(args.host, args.timeout, args.count))
    if args.json:
        print_json(result)
    else:
        print(f"{result['host']}: {'reachable' if result['reachable'] else 'unreachable'}")
        if result["latency_ms"] is not None:
            print(f"latency: {result['latency_ms']:.1f} ms")
        print(result["output"])
    return 0 if result["reachable"] else 1


def dns_audit(args) -> int:
    host = args.host.strip()
    records = {"host": host, "addresses": resolve_host(host)}
    if args.reverse:
        records["reverse"] = {address: socket.gethostbyaddr(address)[0] for address in records["addresses"]}
    if args.json:
        print_json(records)
    else:
        print(f"A records for {host}")
        for address in records["addresses"]:
            print(f"  {address}")
        for address, name in records.get("reverse", {}).items():
            print(f"  {address} -> {name}")
    return 0


def public_ip(args) -> int:
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=args.timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise ToolkitError(f"Public IP lookup failed: {exc}") from exc
    if args.json:
        print_json(result)
    else:
        print(result.get("ip", "unknown"))
    return 0
