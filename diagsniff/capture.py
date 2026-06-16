from __future__ import annotations

import signal
import socket
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.rule import Rule

if TYPE_CHECKING:
    from .fgt2eth import ConversionResult

from .commands import build_sniffer_command
from .credentials import get_password
from .models import SnifferSession, TLSKeyLogResult
from .output import OutputWriter
from .ssh_client import DiagSSHClient

console = Console()


# ── Session header ────────────────────────────────────────────────────────────

def _write_session_header(writer: OutputWriter, session: SnifferSession, command: str) -> None:
    tls_note = (
        "\n# TLS debug  : ENABLED (key log will be written alongside capture)"
        if session.tls_debug.enabled else ""
    )
    writer.write_header(
        f"# DiagSniff capture\n"
        f"# Device      : {session.profile.device_type} @ {session.profile.host}:{session.profile.port}\n"
        f"# Interface   : {session.capture.interface}\n"
        f"# Filter      : {session.capture.filter_expr}\n"
        f"# Verbosity   : {session.capture.verbosity}\n"
        f"# Count       : {'∞ (interactive)' if session.capture.interactive else session.capture.count}\n"
        f"# Command     : {command}\n"
        f"# Started     : {session.timestamp.isoformat()}\n"
        f"# Output file : {session.output_path}"
        f"{tls_note}\n"
        f"{'#' * 72}\n"
    )


# ── Main entry point ──────────────────────────────────────────────────────────

def run_capture(
    session:  SnifferSession,
    password: Optional[str] = None,
    keep_txt: bool = False,
) -> tuple[int, Optional[TLSKeyLogResult]]:
    profile = session.profile
    command = build_sniffer_command(profile.device_type, session.capture)

    # ── Resolve credential ────────────────────────────────────────────────────
    if profile.auth_method == "password" and password is None:
        password = get_password(profile.credential_service, profile.username)

    # ── TLS debug eligibility check ───────────────────────────────────────────
    tls_enabled = session.tls_debug.enabled
    if tls_enabled and profile.device_type != "fortiweb":
        console.print(
            "[yellow]⚠  TLS debug is only supported on FortiWeb devices. "
            "Ignoring --tls-debug for this FortiGate session.[/yellow]"
        )
        tls_enabled = False

    # ── Session summary panel ─────────────────────────────────────────────────
    tls_mode_label = "STRICT" if session.tls_debug.strict_mode else "ENABLED"
    tls_line = (
        f"\n  [bold]TLS debug[/bold]  [dim]›[/dim] [yellow]{tls_mode_label}[/yellow] "
        f"(SSL level {session.tls_debug.ssl_debug_level})"
        if tls_enabled else ""
    )
    console.print()
    console.print(Rule("[bold green] ◉  DiagSniff [/bold green]", style="green"))
    console.print(
        Panel(
            f"  [bold]Device[/bold]     [dim]›[/dim] {profile.device_type.upper()} "
            f"[cyan]{profile.host}:{profile.port}[/cyan]\n"
            f"  [bold]Interface[/bold]  [dim]›[/dim] {session.capture.interface}\n"
            f"  [bold]Filter[/bold]     [dim]›[/dim] {session.capture.filter_expr}\n"
            f"  [bold]Verbosity[/bold]  [dim]›[/dim] {session.capture.verbosity}\n"
            f"  [bold]Count[/bold]      [dim]›[/dim] "
            f"{'[italic]∞  — interactive  (Ctrl+C to stop)[/italic]' if session.capture.interactive else str(session.capture.count)}\n"
            f"  [bold]PCAP output[/bold][dim]›[/dim] [cyan]{session.output_path.with_suffix('.pcap')}[/cyan]\n"
            f"  [bold]Command[/bold]    [dim]›[/dim] [dim]{command}[/dim]"
            f"{tls_line}",
            title="[bold bright_green]▶  Starting Packet Capture[/bold bright_green]",
            subtitle="[dim]by Nitratic[/dim]",
            subtitle_align="right",
            title_align="left",
            border_style="bright_green",
            padding=(1, 2),
        )
    )

    tls_result: Optional[TLSKeyLogResult] = None

    with DiagSSHClient() as ssh:
        console.print(f"[dim]Connecting to {profile.host}:{profile.port}…[/dim]")
        ssh.connect(profile, password=password)
        console.print("[green]✓[/green] Connected. Streaming output…\n")

        # ── Start TLS debug side-channel (FortiWeb only) ──────────────────────
        tls_orchestrator = None
        if tls_enabled:
            from .tls_debug import TLSDebugOrchestrator
            tls_orchestrator = TLSDebugOrchestrator()
            try:
                tls_orchestrator.start(ssh, session.tls_debug)
                console.print(
                    "[yellow]⚡[/yellow] TLS debug channel opened — "
                    "key material will be extracted after capture completes.\n"
                )
            except Exception as exc:
                console.print(f"[red]TLS debug channel failed to open: {exc}[/red]")
                tls_orchestrator = None

        # ── Run sniffer ───────────────────────────────────────────────────────
        with OutputWriter(session.output_path) as writer:
            _write_session_header(writer, session, command)

            if session.capture.interactive:
                lines_written = _run_interactive(ssh, command, writer)
            else:
                lines_written = _run_bounded(ssh, command, writer)

        # ── Stop TLS debug and post-process ───────────────────────────────────
        # Temporarily ignore Ctrl+C during post-capture processing so the user
        # doesn't accidentally abort conversion or TLS key extraction.
        _original_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        if tls_orchestrator is not None:
            console.print("[yellow]⟳  Stopping TLS debug channel…[/yellow]")
            try:
                raw_lines = tls_orchestrator.stop(drain_timeout=session.tls_debug.drain_timeout)
                console.print(f"[dim]   Collected {len(raw_lines):,} raw debug lines[/dim]")
            except Exception as exc:
                console.print(f"[red]⚠  TLS debug drain error: {exc}[/red]")
                raw_lines = []

            console.print("[yellow]⟳  Extracting TLS key material…[/yellow]")
            try:
                from .tls_debug import run_tls_debug_postprocess
                tls_result = run_tls_debug_postprocess(
                    raw_lines    = raw_lines,
                    debug_config = session.tls_debug,
                    capture_path = session.output_path,
                )
            except Exception as exc:
                console.print(f"[red]⚠  TLS postprocess error: {exc}[/red]")
                tls_result = None

    # ── Post-capture pipeline ─────────────────────────────────────────────────
    # Keep SIGINT ignored during conversion
    console.print("[dim]Processing capture — please wait…[/dim]")

    # Stage 1: Convert raw .txt → Wireshark-compatible .pcap
    pcap_path = session.output_path.with_suffix(".pcap")
    conversion_result = _run_conversion(session.output_path, pcap_path)

    # Stage 2: Delete raw .txt after successful conversion (unless keep_txt)
    if not keep_txt and conversion_result and conversion_result.success:
        try:
            session.output_path.unlink(missing_ok=True)
        except OSError:
            pass  # Non-fatal; the .pcap is what matters

    # Stage 3: Handle TLS key log and cleanup
    if tls_result is not None and tls_result.success:
        # Ensure TLS key log sits beside the .pcap in pcap/ with -sessionkey.log suffix
        stem = pcap_path.stem
        keylog_target = pcap_path.parent / f"{stem}SessionKey.log"
        if tls_result.keylog_path and tls_result.keylog_path != keylog_target:
            try:
                import shutil as _shutil
                _shutil.copy2(str(tls_result.keylog_path), str(keylog_target))
                # Remove the original if it was a temp file
                if tls_result.keylog_path.exists() and tls_result.keylog_path != keylog_target:
                    try:
                        tls_result.keylog_path.unlink(missing_ok=True)
                    except OSError:
                        pass
                tls_result = tls_result.model_copy(
                    update={"keylog_path": keylog_target}
                )
                console.print(f"[green]✓[/green]  TLS session key → [cyan]{keylog_target}[/cyan]")
            except Exception as exc:
                console.print(
                    f"[yellow]⚠  Could not move keylog to pcap/: {exc}\n"
                    f"   Keylog remains at {tls_result.keylog_path}[/yellow]"
                )
        
        # Auto-delete raw TLS debug file after successful extraction
        if tls_result.raw_debug_path and tls_result.raw_debug_path.exists():
            try:
                tls_result.raw_debug_path.unlink(missing_ok=True)
                console.print(f"[dim]   Cleaned up temporary TLS debug file[/dim]")
            except OSError:
                pass  # Non-fatal; extraction succeeded

    # Restore normal Ctrl+C handling after post-capture processing
    signal.signal(signal.SIGINT, _original_sigint)

    _print_summary(
        txt_path=session.output_path,
        pcap_path=pcap_path,
        lines=lines_written,
        tls_result=tls_result,
        conversion_result=conversion_result,
        keep_txt=keep_txt,
    )
    return lines_written, tls_result


# ── PCAP conversion ───────────────────────────────────────────────────────────

_CONVERSION_STAGES = [
    "Checking prerequisites",
    "Parsing raw sniffer output",
    "Running text2pcap",
    "Validating output",
]


def _stage_panel(
    current_idx: int,
    result: Optional["ConversionResult"] = None,
    error: Optional[str] = None,
) -> Panel:
    """Render the live conversion progress panel."""
    lines = []
    finished = result is not None
    for i, stage in enumerate(_CONVERSION_STAGES):
        if finished and result.success:
            lines.append(f"  [green]✔[/green]  {stage}")
        elif finished and not result.success:
            if i < current_idx:
                lines.append(f"  [green]✔[/green]  {stage}")
            elif i == current_idx:
                lines.append(f"  [red]✗[/red]  [bold]{stage}[/bold]")
            else:
                lines.append(f"  [dim]○  {stage}[/dim]")
        else:
            if i < current_idx:
                lines.append(f"  [green]✔[/green]  {stage}")
            elif i == current_idx:
                lines.append(f"  [yellow]●[/yellow]  [bold]{stage}[/bold]…")
            else:
                lines.append(f"  [dim]○  {stage}[/dim]")

    footer = ""
    if result is not None:
        if result.success:
            footer = (
                f"\n\n  [bold green]✔  Conversion successful[/bold green]\n"
                f"  [bold]Packets[/bold]  [dim]›[/dim]  {result.packets_written:,}\n"
                f"  [bold]PCAP[/bold]     [dim]›[/dim]  [cyan]{result.pcap_path}[/cyan]"
            )
        else:
            footer = (
                f"\n\n  [bold red]✗  Conversion failed[/bold red]\n"
                f"  [red]{result.error or error or 'Unknown error'}[/red]"
            )
    elif error:
        footer = f"\n\n  [bold red]✗  Error:[/bold red]  [red]{error}[/red]"

    return Panel(
        "\n".join(lines) + footer,
        title="[bold yellow]⟳  Converting to PCAP[/bold yellow]",
        title_align="left",
        border_style="yellow",
        padding=(1, 2),
    )


def _run_conversion(txt_path: Path, pcap_path: Path) -> Optional["ConversionResult"]:
    from .fgt2eth import ConversionResult, convert_to_pcap

    current_stage: list[int] = [0]
    live_ref: list[Optional[Live]] = [None]
    conversion_error: list[Optional[str]] = [None]

    def on_stage(name: str, idx: int) -> None:
        current_stage[0] = idx
        if live_ref[0] is not None:
            try:
                live_ref[0].update(_stage_panel(idx))
            except Exception:
                pass

    console.print()
    console.print(Rule("[bold yellow] ⟳  DiagSniff — Post-Capture Processing [/bold yellow]", style="yellow"))

    result: Optional[ConversionResult] = None
    try:
        with Live(
            _stage_panel(0),
            refresh_per_second=10,
            console=console,
            transient=True,   # clear on exit; we print final state manually
        ) as live:
            live_ref[0] = live
            try:
                result = convert_to_pcap(
                    txt_path=txt_path,
                    pcap_path=pcap_path,
                    on_stage=on_stage,
                )
            except Exception as exc:
                conversion_error[0] = str(exc)
                result = ConversionResult(
                    success=False,
                    txt_path=txt_path,
                    pcap_path=None,
                    packets_written=0,
                    error=f"Unexpected converter error: {exc}",
                )
            finally:
                try:
                    live.update(_stage_panel(current_stage[0], result=result,
                                             error=conversion_error[0]))
                except Exception:
                    pass

    except Exception as live_exc:
        # Live display itself failed — print result plainly
        console.print(f"[red]Display error: {live_exc}[/red]")
        if result is None:
            console.print("[red]PCAP conversion could not be started.[/red]")
        elif not result.success:
            console.print(f"[red]✗  Conversion failed: {result.error}[/red]")
        else:
            console.print(f"[green]✓  PCAP written: {result.pcap_path}[/green]")
    else:
        # Print final conversion state as static panel (Live was transient=True)
        console.print(_stage_panel(current_stage[0], result=result, error=conversion_error[0]))

    # Always surface errors visibly, never swallow them
    if result is not None and not result.success:
        console.print(f"\n[red]✗  Conversion failed:[/red] {result.error}")
        if not txt_path.exists():
            console.print(
                "[red]✗  Raw .txt file is also missing — no capture data saved![/red]"
            )
        elif txt_path.stat().st_size == 0:
            console.print(
                "[yellow]⚠  Raw .txt file is empty — capture produced no output.\n"
                "   Check verbosity (must be ≥ 3), interface name, and filter expression.[/yellow]"
            )

    return result


# ── Bounded capture ───────────────────────────────────────────────────────────

def _run_bounded(ssh: DiagSSHClient, command: str, writer: OutputWriter) -> int:
    for line in ssh.stream_command(command):
        writer.write_line(line)
    return writer.line_count


# ── Interactive capture (Ctrl+C to stop) ──────────────────────────────────────

def _run_interactive(ssh: DiagSSHClient, command: str, writer: OutputWriter) -> int:
    transport = ssh._client.get_transport()
    if transport is None:
        raise RuntimeError("SSH transport lost before interactive capture.")

    channel = transport.open_session()
    channel.set_combine_stderr(True)
    channel.exec_command(command)

    _stop_requested = False

    def _signal_handler(sig: int, frame: object) -> None:
        nonlocal _stop_requested
        _stop_requested = True

    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _signal_handler)

    buf = b""
    packet_count = 0
    start_time = time.time()

    def _make_counter_panel() -> Panel:
        elapsed = time.time() - start_time
        mins, secs = divmod(int(elapsed), 60)
        rate = packet_count / elapsed if elapsed > 0 else 0.0
        return Panel(
            f"  [bold cyan]Packets captured[/bold cyan]  [dim]›[/dim]  "
            f"[bold white]{packet_count:,}[/bold white]\n"
            f"  [bold]Elapsed[/bold]           [dim]›[/dim]  {mins:02d}:{secs:02d}\n"
            f"  [bold]Rate[/bold]              [dim]›[/dim]  {rate:.1f} pkt/s\n\n"
            f"  [dim italic]Press Ctrl+C to stop and save[/dim italic]",
            title="[bold bright_green]● LIVE CAPTURE[/bold bright_green]",
            title_align="left",
            border_style="bright_green",
            padding=(0, 2),
        )

    # 65 536-byte receive window reduces syscall overhead for high-throughput captures.
    _RECV_CHUNK = 65_536

    stream_error: Optional[str] = None
    try:
        with Live(
            _make_counter_panel(),
            refresh_per_second=4,
            console=console,
            transient=True,   # clear panel on exit; we print summary manually
        ) as live:
            while not _stop_requested:
                if channel.recv_ready():
                    chunk = channel.recv(_RECV_CHUNK)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        decoded = line.decode(errors="replace")
                        writer.write_line_silent(decoded)
                        stripped = decoded.strip()
                        # Count data lines only — skip headers and summary lines
                        if (stripped
                                and not stripped.startswith("#")
                                and not stripped.startswith("--")
                                and not stripped.startswith("interfaces=")
                                and not stripped.startswith("filters=")):
                            packet_count += 1
                        live.update(_make_counter_panel())

                if channel.exit_status_ready():
                    break

                time.sleep(0.05)

    except Exception as exc:
        stream_error = str(exc)

    if stream_error:
        console.print(f"\n[red]⚠  Stream error: {stream_error}[/red]")

    if _stop_requested:
        console.print("\n[yellow]Ctrl+C received — stopping sniffer…[/yellow]")
        try:
            # Set channel timeout to prevent blocking forever
            channel.settimeout(2.0)
            channel.send(b"\x03")  # Send Ctrl+C as bytes
            time.sleep(0.3)
            # Drain any final device output (summary line etc.) with timeout
            drain_deadline = time.time() + 2.0
            while time.time() < drain_deadline:
                if channel.recv_ready():
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                else:
                    # No data ready — wait briefly then check again
                    time.sleep(0.05)
                    if not channel.recv_ready():
                        break  # No more data coming
        except socket.timeout:
            console.print("[dim]Channel drain timed out[/dim]")
        except Exception as exc:
            console.print(f"[dim]Drain warning: {exc}[/dim]")

    if buf.strip():
        writer.write_line_silent(buf.decode(errors="replace"))

    try:
        channel.close()
    except Exception:
        pass  # Channel may already be closed or in bad state

    # Restore original SIGINT handler AFTER cleanup completes
    signal.signal(signal.SIGINT, original_sigint)

    # Print final capture stats as a static panel (Live was transient=True)
    elapsed = time.time() - start_time
    mins, secs = divmod(int(elapsed), 60)
    rate = packet_count / elapsed if elapsed > 0 else 0.0
    console.print(
        Panel(
            f"  [bold cyan]Packets captured[/bold cyan]  [dim]›[/dim]  "
            f"[bold white]{packet_count:,}[/bold white]\n"
            f"  [bold]Elapsed[/bold]           [dim]›[/dim]  {mins:02d}:{secs:02d}\n"
            f"  [bold]Rate[/bold]              [dim]›[/dim]  {rate:.1f} pkt/s",
            title="[bold bright_green]■ CAPTURE COMPLETE[/bold bright_green]",
            title_align="left",
            border_style="bright_green",
            padding=(0, 2),
        )
    )

    return writer.line_count


def _print_summary(
    txt_path:          Path,
    pcap_path:         Path,
    lines:             int,
    tls_result:        Optional[TLSKeyLogResult],
    conversion_result: Optional["ConversionResult"] = None,
    keep_txt:          bool = False,
) -> None:
    # ── PCAP conversion section ───────────────────────────────────────────────
    pcap_section = ""
    if conversion_result is not None:
        if conversion_result.success and conversion_result.pcap_path:
            pcap_size_kb = (
                conversion_result.pcap_path.stat().st_size / 1024
                if conversion_result.pcap_path.exists() else 0
            )
            pcap_section = (
                f"\n\n  [bold]PCAP (Wireshark)[/bold]  [dim]›[/dim]  "
                f"[cyan]{conversion_result.pcap_path}[/cyan]  "
                f"[dim]({pcap_size_kb:.1f} KB)[/dim]"
            )
        else:
            pcap_section = (
                f"\n\n  [yellow]⚠  PCAP conversion failed:[/yellow]  "
                f"{conversion_result.error or 'unknown error'}\n"
                f"  [dim]Raw .txt preserved — install text2pcap (Wireshark) to convert.[/dim]"
            )

    # ── Raw txt section (only shown if kept) ─────────────────────────────────
    txt_section = ""
    if keep_txt and txt_path.exists():
        txt_size_kb = txt_path.stat().st_size / 1024
        txt_section = (
            f"\n  [bold]Raw text[/bold]          [dim]›[/dim]  [dim]{txt_path}[/dim]  "
            f"[dim]({txt_size_kb:.1f} KB)[/dim]"
        )
    elif not (conversion_result and conversion_result.success):
        # Conversion failed — show txt even if keep_txt=False
        if txt_path.exists():
            txt_size_kb = txt_path.stat().st_size / 1024
            txt_section = (
                f"\n  [bold]Raw text[/bold]          [dim]›[/dim]  [yellow]{txt_path}[/yellow]  "
                f"[dim]({txt_size_kb:.1f} KB)[/dim]"
            )

    # ── TLS key log section ───────────────────────────────────────────────────
    tls_section = ""
    if tls_result is not None:
        if tls_result.success:
            tls_section = (
                f"\n\n  [bold]TLS Session Key[/bold]   [dim]›[/dim]  "
                f"[cyan]{tls_result.keylog_path}[/cyan]\n"
                f"  [bold]TLS entries[/bold]       [dim]›[/dim]  {tls_result.entry_count} "
                f"(TLS 1.2: {tls_result.tls12_count}, TLS 1.3: {tls_result.tls13_count})"
            )
            # Note: raw debug path is not shown; file is auto-deleted on success
        else:
            tls_section = "\n\n  [yellow]⚠  TLS key log: no entries extracted[/yellow]"

        for w in (tls_result.warnings or []):
            # Indent multi-line warnings properly
            w_indented = w.replace("\n", "\n  ")
            tls_section += f"\n  [yellow]⚠  {w_indented}[/yellow]"

    console.print()
    console.print(Rule("[bold green] ◉  DiagSniff [/bold green]", style="green"))
    console.print(
        Panel(
            f"  [bold green]✔[/bold green]  Capture complete\n\n"
            f"  [bold]Packets recorded[/bold]  [dim]›[/dim]  [white]{lines:,}[/white]"
            f"{pcap_section}"
            f"{txt_section}"
            f"{tls_section}",
            title="[bold bright_green]■  Session Summary[/bold bright_green]",
            subtitle="[dim]by Nitratic[/dim]",
            subtitle_align="right",
            title_align="left",
            border_style="bright_green",
            padding=(1, 2),
        )
    )
