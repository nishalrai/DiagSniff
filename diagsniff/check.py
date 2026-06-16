from __future__ import annotations

import shutil
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box

console = Console()
err     = Console(stderr=True)

# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class DepCheck:
    name:        str
    found:       bool
    path:        Optional[str] = None
    note:        Optional[str] = None


@dataclass
class DepReport:
    checks: list[DepCheck] = field(default_factory=list)

    @property
    def all_ok(self) -> bool:
        return all(c.found for c in self.checks)

    @property
    def critical_ok(self) -> bool:
        """True when the required items (text2pcap) are present."""
        return all(c.found for c in self.checks if c.name == "text2pcap")


@dataclass
class SSHCheckResult:
    host:          str
    port:          int
    success:       bool
    latency_ms:    float = 0.0
    error:         Optional[str] = None
    fingerprint:   Optional[str] = None
    server_banner: Optional[str] = None


# ── Dependency check ──────────────────────────────────────────────────────────

def check_dependencies() -> DepReport:
    checks: list[DepCheck] = []

    # ── External binaries ─────────────────────────────────────────────────────
    for binary, note in [
        ("text2pcap", "Required — converts raw sniffer text to .pcap"),
        ("tshark",    "Optional — used for pcap validation; install Wireshark"),
        ("wireshark", "Optional — GUI pcap viewer"),
    ]:
        path = shutil.which(binary)
        checks.append(DepCheck(
            name=binary,
            found=path is not None,
            path=path,
            note=note,
        ))

    # ── Python packages ───────────────────────────────────────────────────────
    for pkg, import_name, note in [
        ("paramiko",     "paramiko",     "SSH transport"),
        ("rich",         "rich",         "Terminal UI"),
        ("typer",        "typer",        "CLI framework"),
        ("pydantic",     "pydantic",     "Data validation"),
        ("keyring",      "keyring",      "OS credential store"),
        ("cryptography", "cryptography", "Fernet local credential fallback"),
    ]:
        try:
            __import__(import_name)
            checks.append(DepCheck(name=pkg, found=True, note=note))
        except ImportError:
            checks.append(DepCheck(name=pkg, found=False, note=note))

    return DepReport(checks=checks)


# ── SSH connectivity check ────────────────────────────────────────────────────

def check_ssh(
    host:     str,
    port:     int = 22,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout:  float = 10.0,
    save_key: bool = True,
) -> SSHCheckResult:
    import paramiko

    # ── Phase 1: TCP reachability ─────────────────────────────────────────────
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        return SSHCheckResult(
            host=host, port=port, success=False,
            error=f"TCP unreachable — {exc}",
        )
    latency_ms = (time.monotonic() - t0) * 1000

    # ── Phase 2: SSH session ──────────────────────────────────────────────────
    if username is None:
        return SSHCheckResult(
            host=host, port=port, success=True, latency_ms=latency_ms,
            note="TCP port open (no auth attempted — supply --auth user:pass to test login)",  # type: ignore[call-arg]
        )

    try:
        from .ssh_client import DiagSSHClient
        from .models import DeviceProfile

        profile = DeviceProfile(
            name        = "__check__",
            device_type = "fortigate",
            host        = host,
            port        = port,
            username    = username,
            auth_method = "password" if password else "key",
        )

        with DiagSSHClient() as ssh:
            ssh.connect(profile, password=password)
            transport = ssh._client.get_transport()
            banner    = transport.remote_version if transport else None

        return SSHCheckResult(
            host=host, port=port, success=True,
            latency_ms=latency_ms,
            server_banner=banner,
        )

    except Exception as exc:
        return SSHCheckResult(
            host=host, port=port, success=False,
            latency_ms=latency_ms,
            error=str(exc),
        )



def print_dep_report(report: DepReport) -> None:
    """Render dependency check results as a Rich table."""
    console.print()
    console.print(Rule("[bold cyan] ◉  DiagSniff — Dependency Check [/bold cyan]", style="cyan"))

    table = Table(box=box.ROUNDED, show_lines=True, padding=(0, 1))
    table.add_column("Dependency",   style="bold white",  width=16)
    table.add_column("Status",       width=10)
    table.add_column("Path / Note",  style="dim")

    for c in report.checks:
        status = "[green]✔  found[/green]" if c.found else "[red]✗  missing[/red]"
        detail = c.path or c.note or ""
        table.add_row(c.name, status, detail)

    console.print(table)

    if report.all_ok:
        console.print("[green]✔  All dependencies satisfied.[/green]\n")
    elif report.critical_ok:
        console.print(
            "[yellow]⚠  Core dependencies OK.  "
            "Optional tools (tshark/wireshark) enhance pcap validation.[/yellow]\n"
        )
    else:
        console.print(
            "[red]✗  Required dependencies missing.  "
            "Install Wireshark (provides text2pcap) and re-run.[/red]\n"
        )


def print_ssh_report(result: SSHCheckResult, assumed_port: bool = False) -> None:
    console.print()
    port_note = "  [dim](port 22 assumed — not explicitly provided)[/dim]" if assumed_port else ""

    if result.success:
        body = (
            f"  [bold green]✔  Connection successful[/bold green]{port_note}\n\n"
            f"  [bold]Host[/bold]      [dim]›[/dim]  {result.host}:{result.port}\n"
            f"  [bold]Latency[/bold]   [dim]›[/dim]  {result.latency_ms:.1f} ms\n"
        )
        if result.server_banner:
            body += f"  [bold]Banner[/bold]    [dim]›[/dim]  {result.server_banner}\n"
        console.print(Panel(
            body,
            title="[bold bright_green]■  SSH Check[/bold bright_green]",
            title_align="left",
            border_style="bright_green",
            padding=(0, 2),
        ))
    else:
        tips = _troubleshoot_ssh(result)
        body = (
            f"  [bold red]✗  Connection failed[/bold red]{port_note}\n\n"
            f"  [bold]Host[/bold]      [dim]›[/dim]  {result.host}:{result.port}\n"
            f"  [bold]Error[/bold]     [dim]›[/dim]  [red]{result.error}[/red]\n"
        )
        if result.latency_ms > 0:
            body += f"  [bold]Latency[/bold]   [dim]›[/dim]  {result.latency_ms:.1f} ms\n"
        if tips:
            body += "\n  [bold yellow]Troubleshooting:[/bold yellow]\n"
            for tip in tips:
                body += f"  [dim]•  {tip}[/dim]\n"
        console.print(Panel(
            body,
            title="[bold red]■  SSH Check[/bold red]",
            title_align="left",
            border_style="red",
            padding=(0, 2),
        ))


def _troubleshoot_ssh(result: SSHCheckResult) -> list[str]:
    err_lower = (result.error or "").lower()
    tips: list[str] = []

    if "tcp unreachable" in err_lower or "connection refused" in err_lower:
        tips += [
            f"Check that SSH is enabled on the device at port {result.port}.",
            "Verify network routing / firewall rules allow port " + str(result.port) + " from this host.",
            f"Test manually:  ssh {result.host} -p {result.port}",
        ]
    elif "authentication" in err_lower or "auth" in err_lower:
        tips += [
            "Verify username and password are correct.",
            "Ensure the account has SSH / admin-login permissions on the device.",
            "Try:  diagsniff auth test <profile>",
        ]
    elif "timeout" in err_lower:
        tips += [
            "The host is not responding — check IP address, routing, and firewall.",
            f"Increase timeout if the device is slow to respond.",
        ]
    elif "host key" in err_lower or "mismatch" in err_lower:
        tips += [
            "The device's SSH host key changed since last connection.",
            "If the device was re-imaged, remove the old key:",
            "  Edit ~/.diagsniff/known_hosts.json and delete the matching entry.",
        ]
    else:
        tips += [
            "Run with --verbose for detailed SSH debug output.",
            f"Test network reach:  ping {result.host}",
        ]

    return tips
