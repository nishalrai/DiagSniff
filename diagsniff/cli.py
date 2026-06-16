from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.rule import Rule
from rich.spinner import Spinner
from rich.table import Table
from rich import box

from . import __version__
from .capture import run_capture
from .check import (
    check_dependencies,
    check_ssh,
    print_dep_report,
    print_ssh_report,
)
from .config import profile_manager
from .credentials import (
    delete_password,
    get_password,
    has_stored_password,
    save_password,
)
from .models import CaptureConfig, DeviceProfile, SnifferSession, TLSDebugConfig
from .platform_utils import (
    get_default_output_dir,
    get_common_ssh_key_paths,
    get_pcap_dir,
    suggest_capture_stem,
)

# ── App setup ─────────────────────────────────────────────────────────────────

_APP_HELP = """\
[bold cyan]DiagSniff[/bold cyan] — SSH-based packet capture for FortiGate / FortiWeb.

[bold]Quick examples:[/bold]

  [dim]# Dependency check[/dim]
  diagsniff check

  [dim]# Connectivity check (port 22 assumed if omitted)[/dim]
  diagsniff check 192.168.1.1 --auth admin:password

  [dim]# Check connectivity using a saved profile[/dim]
  diagsniff profile check appsec

  [dim]# Interactive capture (Ctrl+C to stop)[/dim]
  diagsniff capture --profile appsec --iface port1 --filter "host 192.168.190.96" --interactive

  [dim]# Interactive capture with TLS key extraction[/dim]
  diagsniff capture --profile appsec --iface port1 --filter "host 192.168.190.96" --interactive --tls

  [dim]# Bounded capture, 200 packets[/dim]
  diagsniff capture --profile appsec --iface any --count 200

  [dim]# Offline convert a saved sniffer .txt to .pcap[/dim]
  diagsniff convert --file ./capture.txt

  [dim]# Offline convert with explicit output path[/dim]
  diagsniff convert --file ./capture.txt --output ./pcap/session1.pcap
"""

app         = typer.Typer(
    name="diagsniff",
    help=_APP_HELP,
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=True,
)
profile_app = typer.Typer(
    help="Manage saved device profiles.\n\n"
         "  diagsniff profile add <name>       Create a new profile\n"
         "  diagsniff profile list             List all profiles\n"
         "  diagsniff profile show <name>      Show profile JSON\n"
         "  diagsniff profile check <name>     Test SSH connectivity\n"
         "  diagsniff profile delete <name>    Remove a profile\n",
    rich_markup_mode="rich",
)
auth_app    = typer.Typer(
    help="Manage stored credentials.\n\n"
         "  diagsniff auth save <name>    Store / update password\n"
         "  diagsniff auth clear <name>   Remove stored password\n"
         "  diagsniff auth test <name>    Verify credentials via SSH\n",
    rich_markup_mode="rich",
)

app.add_typer(profile_app, name="profile")
app.add_typer(auth_app,    name="auth")

console = Console()
err     = Console(stderr=True)

# ── Startup banner ──────────────────────────────────────────────────────────
# ANSI-shadow wordmark; rendered only on bare invocation so it never pollutes
# command output or piped JSON. Uses Rich (already a dependency) for colour.

_BANNER_ART = r"""
██████╗ ██╗ █████╗  ██████╗ ███████╗███╗   ██╗██╗███████╗███████╗
██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝████╗  ██║██║██╔════╝██╔════╝
██║  ██║██║███████║██║  ███╗███████╗██╔██╗ ██║██║█████╗  █████╗
██║  ██║██║██╔══██║██║   ██║╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝
██████╔╝██║██║  ██║╚██████╔╝███████║██║ ╚████║██║██║     ██║
╚═════╝ ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝"""


def _print_banner() -> None:
    """Print the DiagSniff startup banner with version and tagline."""
    console.print(f"[bold bright_cyan]{_BANNER_ART}[/bold bright_cyan]")
    console.print(
        f"  [bold]SSH packet capture for FortiGate / FortiWeb[/bold]"
        f"   [dim]·  v{__version__}[/dim]\n"
    )


# Auto-exit countdown helper
_AUTO_EXIT_INTERVAL = 0.25  # seconds between countdown ticks


def _auto_exit(seconds: int, message: str = "Auto-exit in {n}s…") -> None:
    """Count down *seconds* then exit, updating the line in-place."""
    for remaining in range(seconds, 0, -1):
        console.print(
            f"  [dim]{message.format(n=remaining)}[/dim]",
            end="\r",
        )
        time.sleep(1)
    console.print()  # newline after countdown


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(format="%(levelname)s %(name)s: %(message)s", level=level)



@app.command("check")
def check(
    target: Optional[str] = typer.Argument(
        None,
        help="[host] or [host:port] to test SSH connectivity. "
             "Omit to run a dependency-only check.",
        metavar="[HOST[:PORT]]",
    ),
    auth: Optional[str] = typer.Option(
        None, "--auth",
        help="Credentials for SSH test in [bold]user:password[/bold] format.",
        metavar="USER:PASS",
    ),
    timeout: float = typer.Option(10.0, "--timeout", help="TCP connect timeout in seconds."),
    verbose: bool  = typer.Option(False, "--verbose"),
) -> None:
    
    _setup_logging(verbose)

    # ── Always run dependency check ───────────────────────────────────────────
    report = check_dependencies()
    print_dep_report(report)

    if target is None:
        raise typer.Exit(0 if report.critical_ok else 1)

    # ── Parse target ──────────────────────────────────────────────────────────
    assumed_port = False
    if ":" in target:
        raw_host, raw_port = target.rsplit(":", 1)
        try:
            resolved_port = int(raw_port)
        except ValueError:
            err.print(f"[red]Invalid port in target: {raw_port!r}[/red]")
            raise typer.Exit(1)
    else:
        raw_host      = target
        resolved_port = 22
        assumed_port  = True

    # ── Parse auth ────────────────────────────────────────────────────────────
    resolved_user: Optional[str] = None
    resolved_pass: Optional[str] = None
    if auth:
        if ":" not in auth:
            err.print("[red]--auth must be in user:password format.[/red]")
            raise typer.Exit(1)
        resolved_user, resolved_pass = auth.split(":", 1)

    console.print(
        f"[dim]Testing SSH connectivity to [bold]{raw_host}:{resolved_port}[/bold]…[/dim]"
    )
    result = check_ssh(
        host=raw_host,
        port=resolved_port,
        username=resolved_user,
        password=resolved_pass,
        timeout=timeout,
    )
    print_ssh_report(result, assumed_port=assumed_port)

    if result.success:
        _auto_exit(5, "Auto-exit in {n}s…")
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


# ── capture ───────────────────────────────────────────────────────────────────

@app.command()
def capture(
    # ── Connection ────────────────────────────────────────────────────────────
    profile_name: Optional[str] = typer.Option(
        None, "--profile", "-p",
        help="Use a saved profile (skips individual host/user prompts).",
    ),
    host:     Optional[str] = typer.Option(None, "--host", "-H", help="Device IP or hostname."),
    port:     int           = typer.Option(22,   "--port",       help="SSH port."),
    username: Optional[str] = typer.Option(None, "--user", "-u", help="SSH username."),
    device_type: Optional[str] = typer.Option(
        None, "--device", "-d",
        help="Device type: [bold]fortigate[/bold] or [bold]fortiweb[/bold].",
    ),
    # ── Sniffer ───────────────────────────────────────────────────────────────
    interface:   str = typer.Option("any",  "--iface",     "-i", help="Sniffer interface."),
    filter_expr: str = typer.Option("none", "--filter",    "-f", help="BPF-style filter expression."),
    verbosity:   int = typer.Option(3,      "--verbosity", "-v", help="Output verbosity 1–6 (default 3 = hex dump required for pcap conversion).", min=1, max=6),
    count:       int = typer.Option(100,    "--count",     "-c", help="Packets to capture (0=interactive).", min=0, max=10_000),
    interactive: bool = typer.Option(False, "--interactive", "-I", help="Run until Ctrl+C."),
    filename: Optional[str] = typer.Option(
        None, "--filename",
        help="Base filename stem (default: yyyy-mm-dd-HHMMSS). Raw .txt and .pcap share the same stem in <project>/pcap/.",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Full output file path (overrides --filename and default pcap/ location).",
    ),
    # ── Auth ──────────────────────────────────────────────────────────────────
    key_path: Optional[Path] = typer.Option(None, "--key",      "-k", help="Path to SSH private key."),
    password: Optional[str]  = typer.Option(
        None, "--password",
        help="Password (prefer stored credentials or keyring).",
        envvar="DIAGSNIFF_PASSWORD",
    ),
    # ── TLS debug (FortiWeb only) ─────────────────────────────────────────────
    tls_debug: bool = typer.Option(
        False, "--tls-debug/--no-tls-debug", "--tls/--no-tls",
        help="[bold yellow](FortiWeb only)[/bold yellow] Enable TLS debug key capture (broad mode, no IP filters). "
             "[dim]Shorthand: --tls[/dim]",
    ),
    tls_strict: bool = typer.Option(
        False, "--tls-strict",
        help="[bold yellow](FortiWeb only)[/bold yellow] Strict TLS debug mode with IP filter prompts. "
             "Prompts for client-ip and server-ip for precise flow filtering.",
    ),
    tls_keylog: Optional[Path] = typer.Option(
        None, "--tls-keylog",
        help="Path for the session key log file  [default: <stem>-sessionkey.log].",
    ),
    tls_level: int = typer.Option(
        255, "--tls-level",
        help="FortiWeb SSL debug verbosity level 0–255.",
        min=0, max=255,
    ),
    tls_min_entries: int = typer.Option(
        0, "--tls-min-entries",
        help="Warn if fewer than N TLS key entries are extracted.",
        min=0,
    ),
    tls_drain: float = typer.Option(
        3.0, "--tls-drain",
        help="Seconds to drain TLS debug output after capture ends.",
    ),
    tls_client_ip: Optional[str] = typer.Option(
        None, "--tls-client-ip",
        help="[bold yellow](--tls-strict)[/bold yellow] Frontend client IP address for flow filter.",
    ),
    tls_server_ip: Optional[str] = typer.Option(
        None, "--tls-server-ip",
        help="[bold yellow](--tls-strict)[/bold yellow] FortiWeb VIP address for flow filter.",
    ),
    tls_pserver_ip: Optional[str] = typer.Option(
        None, "--tls-pserver-ip",
        help="[bold yellow](--tls-strict)[/bold yellow] Backend real server IP for flow filter (RP mode).",
    ),
    # ── General ───────────────────────────────────────────────────────────────
    keep_txt: bool = typer.Option(
        False, "--keep-txt",
        help="Keep the raw .txt sniffer file after successful .pcap conversion. "
             "Default: delete .txt after successful conversion.",
    ),
    verbose: bool = typer.Option(False, "--verbose", help="Enable debug logging."),
) -> None:

    _setup_logging(verbose)

    # ── Resolve profile ───────────────────────────────────────────────────────
    prof: Optional[DeviceProfile] = None
    if profile_name:
        prof = profile_manager.get(profile_name)
        if prof is None:
            err.print(f"[red]Profile not found: {profile_name!r}[/red]")
            raise typer.Exit(1)

    # ── Prompt for missing required fields ────────────────────────────────────
    resolved_host     = (prof.host        if prof else host)     or Prompt.ask("Device IP/hostname")
    resolved_user     = (prof.username    if prof else username) or Prompt.ask("Username")
    resolved_dtype    = (prof.device_type if prof else device_type) or \
                        Prompt.ask("Device type", choices=["fortigate", "fortiweb"], default="fortigate")
    resolved_port     = prof.port       if prof else port
    resolved_auth     = prof.auth_method if prof else ("key" if key_path else "password")
    resolved_key_path = prof.key_path   if prof else key_path

    # ── Build and validate profile ────────────────────────────────────────────
    try:
        active_profile = DeviceProfile(
            name        = profile_name or "__adhoc__",
            device_type = resolved_dtype,
            host        = resolved_host,
            port        = resolved_port,
            username    = resolved_user,
            auth_method = resolved_auth,
            key_path    = resolved_key_path,
        )
    except Exception as exc:
        err.print(f"[red]Invalid profile parameters: {exc}[/red]")
        raise typer.Exit(1)

    # ── Resolve password ──────────────────────────────────────────────────────
    resolved_password: Optional[str] = None
    if active_profile.auth_method == "password":
        resolved_password = password or get_password(
            active_profile.credential_service, active_profile.username
        )
        if resolved_password is None:
            import getpass
            resolved_password = getpass.getpass(
                f"Password for {active_profile.username}@{active_profile.host}: "
            )

    # ── Build capture config ──────────────────────────────────────────────────
    effective_interactive = interactive or (count == 0)
    try:
        capture_cfg = CaptureConfig(
            interface   = interface,
            filter_expr = filter_expr,
            verbosity   = verbosity,
            count       = count,
            interactive = effective_interactive,
        )
    except Exception as exc:
        err.print(f"[red]Invalid capture parameters: {exc}[/red]")
        raise typer.Exit(1)

    # ── Build TLS debug config ────────────────────────────────────────────────
    # --tls-strict implies --tls
    tls_enabled = tls_debug or tls_strict
    tls_strict_mode = tls_strict
    
    resolved_tls_client_ip  = tls_client_ip
    resolved_tls_server_ip  = tls_server_ip
    resolved_tls_pserver_ip = tls_pserver_ip
    
    # --tls-strict mode: prompt for IP filters for precise flow filtering
    if tls_strict_mode and resolved_dtype == "fortiweb":
        console.print("\n[bold yellow]Strict TLS Debug Mode[/bold yellow]")
        console.print("[dim]Using exact IP filters for precise TLS key extraction.[/dim]")
        console.print("[dim]  • client-ip:  Frontend client IP (client → FortiWeb VIP)[/dim]")
        console.print("[dim]  • server-ip:  FortiWeb VIP address[/dim]")
        console.print("[dim]  • pserver-ip: Backend real server (use --tls-pserver-ip flag)[/dim]\n")
        
        if not resolved_tls_client_ip:
            resolved_tls_client_ip = Prompt.ask(
                "[cyan]Client IP[/cyan] (frontend client address, e.g., 192.168.1.10)",
                default="",
            ).strip() or None
        
        if not resolved_tls_server_ip:
            resolved_tls_server_ip = Prompt.ask(
                "[cyan]Server IP[/cyan] (FortiWeb VIP, e.g., 10.0.0.1)",
                default="",
            ).strip() or None
        
        # pserver-ip is NOT prompted — use --tls-pserver-ip if needed
        # (Not all FortiWeb versions support this filter)
        
        if not any([resolved_tls_client_ip, resolved_tls_server_ip]):
            console.print("[yellow]⚠  No IP filters provided — consider using --tls for broad mode instead.[/yellow]\n")
        else:
            console.print()  # blank line after prompts
    
    tls_cfg = TLSDebugConfig(
        enabled              = tls_enabled,
        strict_mode          = tls_strict_mode,
        ssl_debug_level      = tls_level,
        keylog_path          = tls_keylog,
        save_raw_debug       = True,  # Always save initially; deleted on success
        raw_debug_path       = None,  # Auto-generated
        drain_timeout        = tls_drain,
        min_expected_entries = tls_min_entries,
        client_ip            = resolved_tls_client_ip,
        server_ip            = resolved_tls_server_ip,
        pserver_ip           = resolved_tls_pserver_ip,
    )

    # ── Resolve output path ───────────────────────────────────────────────────
    # Raw capture is saved as .txt; fgt2eth.py converts it to .pcap afterwards.
    if output is None:
        if filename:
            # Strip any extension the user may have included
            stem = filename
            for ext in (".pcap", ".txt"):
                if stem.lower().endswith(ext):
                    stem = stem[: -len(ext)]
                    break
        else:
            stem = suggest_capture_stem()
        output = get_pcap_dir() / (stem + ".txt")
    elif output.suffix.lower() == ".pcap":
        # If the user explicitly asked for .pcap, store raw as sibling .txt
        output = output.with_suffix(".txt")
    output.parent.mkdir(parents=True, exist_ok=True)

    session = SnifferSession(
        profile     = active_profile,
        capture     = capture_cfg,
        output_path = output,
        tls_debug   = tls_cfg,
    )

    try:
        run_capture(session, password=resolved_password, keep_txt=keep_txt)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
    except Exception as exc:
        err.print(f"\n[red]Capture failed: {exc}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        raise typer.Exit(1)


# ── tls-session ───────────────────────────────────────────────────────────────

@app.command("tls-session")
def tls_session(
    profile_name: Optional[str] = typer.Option(
        None, "--profile", "-p", help="Use a saved profile."),
    host:     Optional[str] = typer.Option(None, "--host",   "-H", help="FortiWeb IP/hostname."),
    port:     int           = typer.Option(22,   "--port",         help="SSH port."),
    username: Optional[str] = typer.Option(None, "--user",   "-u", help="SSH username."),
    password: Optional[str] = typer.Option(
        None, "--password", envvar="DIAGSNIFF_PASSWORD", help="SSH password."),
    key_path: Optional[Path] = typer.Option(None, "--key",   "-k", help="SSH private key path."),
    duration: int  = typer.Option(60,  "--duration", help="Seconds to collect debug output.", min=1, max=3600),
    tls_level: int = typer.Option(255, "--tls-level", help="FortiWeb SSL debug verbosity 0–255.", min=0, max=255),
    keylog:   Optional[Path] = typer.Option(
        None, "--keylog", "-o", help="NSS key log output path  [default: auto-named in pcap/]."),
    save_raw: bool = typer.Option(False, "--save-raw", help="Save the raw FortiWeb debug stream."),
    raw_path: Optional[Path] = typer.Option(
        None, "--raw-path", help="Path for raw debug stream  [default: <keylog>.tlsdebug.txt]."),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    
    _setup_logging(verbose)

    # ── Resolve connection params ─────────────────────────────────────────────
    prof: Optional[DeviceProfile] = None
    if profile_name:
        prof = profile_manager.get(profile_name)
        if prof is None:
            err.print(f"[red]Profile not found: {profile_name!r}[/red]")
            raise typer.Exit(1)

    resolved_host = (prof.host     if prof else host)     or Prompt.ask("FortiWeb IP/hostname")
    resolved_user = (prof.username if prof else username) or Prompt.ask("Username")
    resolved_port = prof.port      if prof else port
    resolved_auth = prof.auth_method if prof else ("key" if key_path else "password")
    resolved_key  = prof.key_path    if prof else key_path

    try:
        active_profile = DeviceProfile(
            name        = profile_name or "__adhoc__",
            device_type = "fortiweb",
            host        = resolved_host,
            port        = resolved_port,
            username    = resolved_user,
            auth_method = resolved_auth,
            key_path    = resolved_key,
        )
    except Exception as exc:
        err.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    resolved_password: Optional[str] = None
    if active_profile.auth_method == "password":
        resolved_password = password or get_password(
            active_profile.credential_service, active_profile.username
        )
        if resolved_password is None:
            import getpass
            resolved_password = getpass.getpass(
                f"Password for {resolved_user}@{resolved_host}: "
            )

    tls_cfg = TLSDebugConfig(
        enabled         = True,
        ssl_debug_level = tls_level,
        keylog_path     = keylog,
        save_raw_debug  = save_raw,
        raw_debug_path  = raw_path,
        drain_timeout   = 2.0,
    )

    # ── Run debug-only session ────────────────────────────────────────────────
    console.print(
        Panel(
            f"[bold]Device[/bold]     : FortiWeb [cyan]{resolved_host}:{resolved_port}[/cyan]\n"
            f"[bold]Duration[/bold]   : {duration}s\n"
            f"[bold]SSL level[/bold]  : {tls_level}\n"
            f"[bold]Key log[/bold]    : {keylog or '<auto>'}",
            title="[bold yellow]DiagSniff — TLS Debug Session[/bold yellow]",
            border_style="yellow",
        )
    )

    from .ssh_client import DiagSSHClient
    from .tls_debug import TLSDebugOrchestrator, run_tls_debug_postprocess

    dummy_output = get_default_output_dir() / f"tlsdebug_{resolved_host}_{duration}s.txt"

    with DiagSSHClient() as ssh:
        with Live(Spinner("dots", text="Connecting…"), console=console, transient=True):
            ssh.connect(active_profile, password=resolved_password)
        console.print("[green]✓[/green] Connected.\n")

        orch = TLSDebugOrchestrator()
        orch.start(ssh, tls_cfg)
        console.print(
            f"[yellow]⚡[/yellow] TLS debug running. Collecting for [bold]{duration}[/bold]s… "
            "(press Ctrl+C to stop early)\n"
        )

        import signal as _signal

        _stopped = False
        def _handle(s: int, f: object) -> None:
            nonlocal _stopped; _stopped = True
        orig = _signal.getsignal(_signal.SIGINT)
        _signal.signal(_signal.SIGINT, _handle)

        try:
            for remaining in range(duration, 0, -1):
                if _stopped:
                    break
                console.print(
                    f"  [dim]{remaining:>4}s remaining…[/dim]",
                    end="\r",
                )
                time.sleep(1)
        finally:
            _signal.signal(_signal.SIGINT, orig)

        console.print("\n[yellow]Stopping TLS debug…[/yellow]")
        raw_lines = orch.stop(drain_timeout=tls_cfg.drain_timeout)

    result = run_tls_debug_postprocess(raw_lines, tls_cfg, dummy_output)
    _print_tls_result(result)


def _print_tls_result(result: "TLSKeyLogResult") -> None:
    from .models import TLSKeyLogResult
    if result.success:
        console.print(
            Panel(
                f"[bold green]TLS key log written[/bold green]\n\n"
                f"  Entries   : {result.entry_count} "
                f"(TLS 1.2: {result.tls12_count}, TLS 1.3: {result.tls13_count})\n"
                f"  Key log   : [cyan]{result.keylog_path}[/cyan]"
                + (f"\n  Raw debug : [cyan]{result.raw_debug_path}[/cyan]" if result.raw_debug_path else ""),
                border_style="yellow",
            )
        )
    else:
        console.print("[yellow]No TLS key entries were extracted.[/yellow]")
    for w in result.warnings:
        console.print(f"[yellow]⚠  {w}[/yellow]")


# ── tls-parse (offline) ───────────────────────────────────────────────────────

@app.command("tls-parse")
def tls_parse(
    input_file:  Path = typer.Argument(..., help="Saved FortiWeb debug output file to parse."),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="NSS key log output path."),
    show_entries: bool = typer.Option(False, "--show", "-s", help="Print extracted key entries to terminal."),
    verbose:     bool = typer.Option(False, "--verbose"),
) -> None:
 
    _setup_logging(verbose)

    if not input_file.exists():
        err.print(f"[red]File not found: {input_file}[/red]")
        raise typer.Exit(1)

    from .tls_debug import orchestrate_fortiweb_tls_debug, TLSKeyParser

    out = output_file or input_file.with_suffix(".keylog")
    out.parent.mkdir(parents=True, exist_ok=True)

    # Parse for rich terminal display if --show or --verbose requested
    parser = None
    session = None
    if show_entries or verbose:
        with input_file.open(encoding="utf-8", errors="replace") as fh:
            parser = TLSKeyParser()
            session = parser.parse(fh.read())

        if show_entries:
            if not session.entries:
                console.print("[yellow]No TLS key entries found in the input file.[/yellow]")
            else:
                table = Table(
                    title=f"TLS Key Entries — {input_file.name}",
                    box=box.ROUNDED,
                    show_lines=True,
                )
                table.add_column("Label",         style="bold cyan",  no_wrap=True)
                table.add_column("TLS",           style="green",      width=4)
                table.add_column("Client Random", style="dim",        no_wrap=True)
                table.add_column("Secret (first 32 hex)", style="dim")

                for e in session.entries:
                    table.add_row(
                        e.label,
                        e.tls_version,
                        e.client_random[:16] + "…",
                        e.secret[:32] + "…",
                    )
                console.print(table)
        
        # Show verbose parse statistics
        if verbose and parser:
            stats = parser.stats
            console.print()
            console.print(Panel(
                f"[bold]Parse Statistics[/bold]\n\n"
                f"  Total lines:          {stats.total_lines:,}\n"
                f"  Candidate TLS lines:  {stats.candidate_lines:,}\n"
                f"  Secret-like lines:    {stats.secret_candidate_lines:,}\n"
                f"  Matched entries:      {stats.matched_entries:,}\n"
                f"  Unique entries:       {stats.unique_entries:,}\n\n"
                f"[bold]Content Analysis[/bold]\n\n"
                f"  Flow trace detected:   {'[green]Yes[/green]' if stats.has_flow_trace else '[red]No[/red]'}\n"
                f"  SSL/TLS content:       {'[green]Yes[/green]' if stats.has_ssl_content else '[red]No[/red]'}\n"
                f"  Handshake indicators:  {'[green]Yes[/green]' if stats.has_handshake_indicators else '[yellow]No[/yellow]'}",
                title="[bold cyan]Debug Analysis[/bold cyan]",
                border_style="cyan",
            ))
            
            if stats.unmatched_samples:
                console.print()
                console.print("[yellow]Sample unmatched secret-like lines:[/yellow]")
                for sample in stats.unmatched_samples:
                    console.print(f"  [dim]→ {sample}[/dim]")

    count, _ = orchestrate_fortiweb_tls_debug(input_file, out, verbose=False)

    if count == 0:
        # Check if file looks like a sniffer capture instead of TLS debug output
        is_sniffer = False
        is_empty = False
        has_command_errors = False
        try:
            with input_file.open(encoding="utf-8", errors="replace") as fh:
                content = fh.read(5000)  # Read first 5KB
                if not content.strip():
                    is_empty = True
                elif "0x0000" in content or "DiagSniff capture" in content:
                    is_sniffer = True
                elif "Parsing error" in content or "Command fail" in content:
                    has_command_errors = True
        except Exception:
            pass

        if is_empty:
            console.print(
                "[red]✗  Input file is empty.[/red]\n\n"
                "[yellow]The TLS debug channel did not produce any output.\n"
                "Possible causes:\n"
                "  • FortiWeb TLS debug commands failed to execute.\n"
                "  • Connection was interrupted before data was collected.\n"
                "  • FortiWeb shell did not respond to debug commands.[/yellow]"
            )
        elif is_sniffer:
            console.print(
                "[red]✗  This appears to be a sniffer capture file, NOT a TLS debug file.[/red]\n\n"
                "[yellow]The tls-parse command expects a TLS debug stream (*.tlsdebug.txt)\n"
                "from FortiWeb's [bold]diagnose debug flow trace[/bold] command.\n\n"
                "To get TLS debug output, run a capture with:[/yellow]\n"
                "  [cyan]diagsniff capture --tls ...[/cyan]\n\n"
                "[dim]This runs flow trace alongside packet capture and saves *.tlsdebug.txt[/dim]"
            )
        elif has_command_errors:
            console.print(
                "[red]✗  TLS debug commands failed on the FortiWeb device.[/red]\n\n"
                "[yellow]The raw debug file contains command errors.\n"
                "FortiWeb 8.x uses [bold]diagnose debug flow trace[/bold] instead of\n"
                "[bold]diagnose debug application SSL[/bold].\n\n"
                "DiagSniff will use the correct command flow automatically.\n"
                "Ensure your FortiWeb is running a supported firmware version.[/yellow]"
            )
        else:
            console.print(
                "[yellow]No TLS key entries found in the input file.[/yellow]\n"
            )
            if verbose and parser and parser.stats.total_lines > 0:
                console.print(
                    "[dim]See the Debug Analysis panel above for details.[/dim]\n"
                )
            console.print(
                "[yellow]Possible causes:\n"
                "  • No fresh TLS handshake occurred during capture.\n"
                "  • Traffic filter excluded the TLS session.\n"
                "  • FortiWeb firmware outputs secrets in unknown format.\n"
                "  • diagnose debug flow filter flow-detail was < 4.\n\n"
                "Troubleshooting:\n"
                "  1. Ensure packet capture + flow trace run simultaneously.\n"
                "  2. Generate fresh TLS traffic (e.g., new browser session).\n"
                "  3. Check IP filters (client-ip, server-ip, pserver-ip).\n"
                "  4. Review the raw *.tlsdebug.txt file for debug output.[/yellow]"
            )
    else:
        console.print(
            f"[green]✓[/green] {count} key entr{'y' if count == 1 else 'ies'} written "
            f"to [cyan]{out}[/cyan] (mode 600).\n"
            "[dim]Load in Wireshark: Edit → Preferences → Protocols → TLS → "
            "(Pre)-Master-Secret log filename[/dim]"
        )


# ── convert (offline TXT → PCAP) ─────────────────────────────────────────────

@app.command("convert")
def convert(
    file: Path = typer.Option(
        ..., "--file", "-f",
        help="Raw Fortinet/FortiWeb sniffer .txt file to convert.",
        metavar="FILE",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output .pcap path. Defaults to [bold]pcap/<timestamp>.pcap[/bold].",
        metavar="FILE",
    ),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
 
    _setup_logging(verbose)

    from .converter import ConvertError, ConvertErrorCode, offline_convert

    # ── Validate file argument ────────────────────────────────────────────────
    if not file.exists():
        err.print(
            f"[red]File not found:[/red] {file}\n"
            "[dim]Check the path and try again.[/dim]"
        )
        raise typer.Exit(1)

    if not file.is_file():
        err.print(f"[red]Not a regular file:[/red] {file}")
        raise typer.Exit(1)

    if file.suffix.lower() != ".txt":
        err.print(
            f"[red]Invalid file extension:[/red] [bold]{file.suffix or '(none)'}[/bold]\n"
            f"  Expected a [bold].txt[/bold] sniffer output file, got: [bold]{file.name}[/bold]\n"
            "[dim]  Tip: raw sniffer output is saved as .txt before PCAP conversion.[/dim]"
        )
        raise typer.Exit(1)

    # ── Resolve output path ───────────────────────────────────────────────────
    if output is None:
        stem = file.stem
        output = get_pcap_dir() / f"converted-{stem}.pcap"
    else:
        # Ensure output has .pcap extension
        if output.suffix.lower() != ".pcap":
            output = output.with_suffix(".pcap")
        output.parent.mkdir(parents=True, exist_ok=True)

    # ── Run conversion ────────────────────────────────────────────────────────
    console.print()
    console.print(Rule("[bold green] ◉  DiagSniff Convert [/bold green]", style="green"))
    console.print(
        Panel(
            f"  [bold]Input[/bold]   [dim]›[/dim]  [cyan]{file}[/cyan]\n"
            f"  [bold]Output[/bold]  [dim]›[/dim]  [cyan]{output}[/cyan]",
            title="[bold bright_green]▶  Offline PCAP Conversion[/bold bright_green]",
            subtitle="[dim]by Nitratic[/dim]",
            subtitle_align="right",
            title_align="left",
            border_style="bright_green",
            padding=(1, 2),
        )
    )

    try:
        result = offline_convert(file, output, debug=verbose)
    except ConvertError as exc:
        _code_label = {
            ConvertErrorCode.NOT_TXT:         "Invalid file type",
            ConvertErrorCode.NOT_FOUND:       "File not found",
            ConvertErrorCode.NOT_READABLE:    "File not readable",
            ConvertErrorCode.EMPTY:           "File is empty",
            ConvertErrorCode.NO_PACKETS:      "No sniffer packets detected",
            ConvertErrorCode.MALFORMED:       "Malformed capture data",
            ConvertErrorCode.UNSUPPORTED_FMT: "Unsupported file format",
        }.get(exc.code, "Conversion error")

        console.print(
            Panel(
                f"[bold red]✗  {_code_label}[/bold red]\n\n"
                f"[red]{exc.message}[/red]\n\n"
                "[dim]Correct the source file and try again.[/dim]",
                title="[bold red]Conversion Failed[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(1)

    if not result.success:
        console.print(
            Panel(
                f"[bold red]✗  Conversion failed[/bold red]\n\n"
                f"[red]{result.error or 'Unknown error'}[/red]\n\n"
                "[dim]Correct the source file and try again.[/dim]",
                title="[bold red]Conversion Failed[/bold red]",
                border_style="red",
                padding=(1, 2),
            )
        )
        raise typer.Exit(1)

    console.print(
        Panel(
            f"[bold green]✔  Conversion successful[/bold green]\n\n"
            f"  [bold]Packets[/bold]  [dim]›[/dim]  {result.packets_written:,}\n"
            f"  [bold]Input[/bold]    [dim]›[/dim]  [cyan]{result.txt_path}[/cyan]\n"
            f"  [bold]PCAP[/bold]     [dim]›[/dim]  [cyan]{result.pcap_path}[/cyan]\n\n"
            "[dim]Open in Wireshark or tshark to inspect packets.[/dim]",
            title="[bold green]Conversion Complete[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )


# ── profile sub-commands ──────────────────────────────────────────────────────

@profile_app.command("add")
def profile_add(
    name: str = typer.Argument(..., help="Unique profile name (alphanumeric + hyphens)."),
) -> None:
    """Interactively create and save a device profile."""
    if profile_manager.exists(name):
        if not Confirm.ask(f"Profile {name!r} already exists. Overwrite?", default=False):
            raise typer.Exit()

    device_type = Prompt.ask("Device type", choices=["fortigate", "fortiweb"], default="fortigate")
    host        = Prompt.ask("Host / IP")
    port        = int(Prompt.ask("SSH port", default="22"))
    username    = Prompt.ask("Username")

    # Explicit numbered menu avoids the common mistake of typing a password
    # at the auth-method prompt (which Rich silently re-prompts for anyway,
    # but wastes a keystroke and is confusing).
    console.print("Auth method:")
    console.print("  [bold cyan]1[/bold cyan] — password  (default)")
    console.print("  [bold cyan]2[/bold cyan] — SSH key")
    _auth_raw = Prompt.ask("Select", choices=["1", "2", "password", "key"], default="1")
    auth_method = "key" if _auth_raw in ("2", "key") else "password"
    console.print(f"  → using [bold]{auth_method}[/bold] authentication")

    key_path: Optional[Path] = None
    if auth_method == "key":
        suggestions = get_common_ssh_key_paths()
        default_key = str(suggestions[0]) if suggestions else ""
        raw_key     = Prompt.ask("Path to SSH private key", default=default_key)
        key_path    = Path(raw_key).expanduser()

    try:
        prof = DeviceProfile(
            name        = name,
            device_type = device_type,  # type: ignore[arg-type]
            host        = host,
            port        = port,
            username    = username,
            auth_method = auth_method,  # type: ignore[arg-type]
            key_path    = key_path,
        )
    except Exception as exc:
        err.print(f"[red]Validation error: {exc}[/red]")
        raise typer.Exit(1)

    profile_manager.save(prof)
    console.print(f"[green]✓[/green] Profile [bold]{name}[/bold] saved.")

    if auth_method == "password":
        if Confirm.ask("Store password now?", default=True):
            import getpass
            pw      = getpass.getpass(f"Password for {username}@{host}: ")
            backend = save_password(prof.credential_service, username, pw)
            console.print(f"[green]✓[/green] Password stored via [bold]{backend}[/bold].")


@profile_app.command("check")
def profile_check(
    name:    str   = typer.Argument(..., help="Profile name to test."),
    timeout: float = typer.Option(10.0, "--timeout", help="TCP connect timeout in seconds."),
    verbose: bool  = typer.Option(False, "--verbose"),
) -> None:

    _setup_logging(verbose)

    prof = profile_manager.get(name)
    if prof is None:
        err.print(f"[red]Profile not found: {name!r}[/red]")
        raise typer.Exit(1)

    password: Optional[str] = None
    if prof.auth_method == "password":
        password = get_password(prof.credential_service, prof.username)
        if password is None:
            import getpass
            password = getpass.getpass(f"Password for {prof.username}@{prof.host}: ")

    console.print(
        f"[dim]Testing profile [bold]{name}[/bold] → {prof.host}:{prof.port}…[/dim]"
    )
    result = check_ssh(
        host=prof.host,
        port=prof.port,
        username=prof.username,
        password=password,
        timeout=timeout,
    )
    print_ssh_report(result)

    if result.success:
        console.print("[dim]Press Ctrl+C to exit early.[/dim]")
        try:
            _auto_exit(15, "Auto-exit in {n}s…")
        except KeyboardInterrupt:
            console.print()
        raise typer.Exit(0)
    else:
        raise typer.Exit(1)


@profile_app.command("list")
def profile_list() -> None:
    """List all saved profiles."""
    profiles = profile_manager.list_all()
    if not profiles:
        console.print("[yellow]No profiles saved yet. Use [bold]diagsniff profile add[/bold].[/yellow]")
        return

    table = Table(title="Saved Profiles", box=box.ROUNDED, show_lines=True)
    table.add_column("Name",        style="bold cyan")
    table.add_column("Type",        style="green")
    table.add_column("Host",        style="white")
    table.add_column("Port",        style="dim")
    table.add_column("User",        style="white")
    table.add_column("Auth",        style="dim")
    table.add_column("Credentials", style="yellow")

    for p in profiles:
        cred_status = "✓ stored" if has_stored_password(p.credential_service, p.username) \
                      else "— none"
        table.add_row(
            p.name, p.device_type, p.host, str(p.port),
            p.username, p.auth_method,
            cred_status if p.auth_method == "password" else "key file",
        )
    console.print(table)


@profile_app.command("show")
def profile_show(name: str = typer.Argument(...)) -> None:
    """Show details of a single profile."""
    prof = profile_manager.get(name)
    if prof is None:
        err.print(f"[red]Profile not found: {name!r}[/red]")
        raise typer.Exit(1)
    console.print(prof.model_dump_json(indent=2))


@profile_app.command("delete")
def profile_delete(
    name:  str  = typer.Argument(...),
    force: bool = typer.Option(False, "--force", "-y"),
) -> None:
    """Remove a saved profile (and optionally its stored credentials)."""
    if not profile_manager.exists(name):
        err.print(f"[red]Profile not found: {name!r}[/red]")
        raise typer.Exit(1)

    if not force and not Confirm.ask(f"Delete profile {name!r}?", default=False):
        raise typer.Exit()

    prof = profile_manager.get(name)
    profile_manager.delete(name)
    console.print(f"[green]✓[/green] Profile [bold]{name}[/bold] deleted.")

    if prof and Confirm.ask("Also remove stored credentials?", default=True):
        delete_password(prof.credential_service, prof.username)
        console.print("[green]✓[/green] Credentials removed.")


# ── auth sub-commands ─────────────────────────────────────────────────────────

@auth_app.command("save")
def auth_save(name: str = typer.Argument(...)) -> None:
    """Store or update the password for a profile."""
    prof = profile_manager.get(name)
    if prof is None:
        err.print(f"[red]Profile not found: {name!r}[/red]")
        raise typer.Exit(1)
    if prof.auth_method != "password":
        err.print(f"[yellow]Profile {name!r} uses key auth — no password to store.[/yellow]")
        raise typer.Exit()

    import getpass
    pw      = getpass.getpass(f"Password for {prof.username}@{prof.host}: ")
    backend = save_password(prof.credential_service, prof.username, pw)
    console.print(f"[green]✓[/green] Password stored via [bold]{backend}[/bold].")


@auth_app.command("clear")
def auth_clear(name: str = typer.Argument(...)) -> None:
    """Remove stored credentials for a profile."""
    prof = profile_manager.get(name)
    if prof is None:
        err.print(f"[red]Profile not found: {name!r}[/red]")
        raise typer.Exit(1)
    removed = delete_password(prof.credential_service, prof.username)
    if removed:
        console.print(f"[green]✓[/green] Credentials removed for [bold]{name}[/bold].")
    else:
        console.print(f"[yellow]No credentials found for [bold]{name}[/bold].[/yellow]")


@auth_app.command("test")
def auth_test(
    name:    str  = typer.Argument(...),
    verbose: bool = typer.Option(False, "--verbose"),
) -> None:
    """Open an SSH connection to verify stored credentials."""
    _setup_logging(verbose)
    prof = profile_manager.get(name)
    if prof is None:
        err.print(f"[red]Profile not found: {name!r}[/red]")
        raise typer.Exit(1)

    password = get_password(prof.credential_service, prof.username) \
               if prof.auth_method == "password" else None
    if prof.auth_method == "password" and password is None:
        import getpass
        password = getpass.getpass(f"Password for {prof.username}@{prof.host}: ")

    from .ssh_client import DiagSSHClient
    try:
        with DiagSSHClient() as ssh:
            ssh.connect(prof, password=password)
            console.print(f"[green]✓[/green] Auth test passed for [bold]{name}[/bold].")
    except Exception as exc:
        err.print(f"[red]Auth test FAILED: {exc}[/red]")
        raise typer.Exit(1)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    # Show the banner on bare invocation (before Typer renders the help screen).
    if len(sys.argv) == 1:
        _print_banner()
    app()


if __name__ == "__main__":
    main()
