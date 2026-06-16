
from __future__ import annotations

import io
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_SHELL_TIMEOUT   = 10.0   # seconds to wait for shell prompt on connect
_DRAIN_CHUNK     = 4096
_POLL_INTERVAL   = 0.05   # seconds between channel polls in background thread
_PROMPT_MARKERS  = (b"$ ", b"# ", b"> ", b"FortiWeb")  # shell-ready indicators

# TLS 1.3 NSS label set (all labels that appear in a key log)
_TLS13_LABELS = {
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EARLY_EXPORTER_SECRET",
    "EXPORTER_SECRET",
}


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class TLSKeyEntry:
    """
    One row in the NSS Key Log file.

    label          — NSS label (e.g. CLIENT_RANDOM, CLIENT_HANDSHAKE_TRAFFIC_SECRET)
    client_random  — 64 hex chars (32 bytes) identifying the TLS session
    secret         — hex-encoded key material (length varies by label / TLS version)
    """
    label:         str
    client_random: str
    secret:        str
    tls_version:   str = "unknown"  # "1.2" or "1.3"

    def to_keylog_line(self) -> str:
        return f"{self.label} {self.client_random} {self.secret}"

    def is_tls13(self) -> bool:
        return self.label in _TLS13_LABELS


@dataclass
class TLSDebugSession:
    """Accumulated key entries from one FortiWeb TLS debug capture."""

    entries: list[TLSKeyEntry] = field(default_factory=list)

    def add(self, entry: TLSKeyEntry) -> None:
        self.entries.append(entry)

    @property
    def tls12_count(self) -> int:
        return sum(1 for e in self.entries if not e.is_tls13())

    @property
    def tls13_count(self) -> int:
        return sum(1 for e in self.entries if e.is_tls13())

    def to_keylog(self) -> str:
        """Render the full NSS Key Log string."""
        lines: list[str] = [
            "# DiagSniff TLS key log",
            "# Load in Wireshark: Edit → Preferences → Protocols → TLS",
            "#   → (Pre)-Master-Secret log filename",
            "#",
            "# ⚠ SENSITIVE — delete this file after your debug session.",
            "#",
        ]
        seen: set[str] = set()
        for e in self.entries:
            row = e.to_keylog_line()
            if row not in seen:   # deduplicate exact duplicates
                lines.append(row)
                seen.add(row)
        return "\n".join(lines) + "\n"

    def save_keylog(self, path: Path) -> int:
        """
        Write NSS Key Log file with restrictive permissions.
        Returns the number of unique entries written.
        NEVER write this to a shared or world-readable location.
        """
        content = self.to_keylog()
        path.write_text(content, encoding="utf-8")
        try:
            path.chmod(0o600)
        except (NotImplementedError, OSError):
            pass  # Windows: rely on NTFS ACLs
        unique_entries = len([l for l in content.splitlines() if not l.startswith("#") and l.strip()])
        return unique_entries

    def save_raw_debug(self, raw_lines: list[str], path: Path) -> None:
        """Persist the unfiltered FortiWeb debug stream for offline re-parsing."""
        path.write_text("\n".join(raw_lines) + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except (NotImplementedError, OSError):
            pass


# ── Multi-format TLS key parser ───────────────────────────────────────────────
#
# FortiWeb 8.x TLS Secret Extraction
# ──────────────────────────────────
# FortiWeb 8 outputs TLS secrets via `diagnose debug flow trace` at detail level 4.
# The output format varies by firmware version and TLS version being used:
#
# Possible formats:
#   [timestamp] [flow] ... CLIENT_RANDOM <hex64> <hex96>
#   [timestamp] [flow] ... client_random=<hex64> master_secret=<hex96>
#   [timestamp] ... ssl_keylog: CLIENT_RANDOM <hex64> <hex96>
#   Multiple lines with client_random on one line and master_secret nearby
#   TLS 1.3: <LABEL> <hex64> <hex64>  where LABEL is CLIENT_HANDSHAKE_TRAFFIC_SECRET etc.
#
# The parser uses a multi-stage approach:
#   1. Candidate detection: Find lines containing TLS-related keywords
#   2. Pattern matching: Apply multiple regex patterns
#   3. Context window: For multi-line secrets, look ahead/behind
#   4. Deduplication: Remove exact duplicate entries
#

@dataclass
class TLSParseStats:
    """Statistics from TLS key parsing for diagnostics."""
    total_lines: int = 0
    candidate_lines: int = 0
    secret_candidate_lines: int = 0
    matched_entries: int = 0
    command_failures: int = 0  # "Parsing error" or "Command fail" lines
    unique_entries: int = 0
    unmatched_samples: list[str] = field(default_factory=list)
    has_flow_trace: bool = False
    has_ssl_content: bool = False
    has_handshake_indicators: bool = False


class TLSKeyParser:
    """
    Applies a bank of regex patterns to raw FortiWeb debug output and
    extracts NSS Key Log entries.

    Supports FortiWeb 8.x flow trace format as well as older debug formats.

    Pattern bank covers:
      • TLS 1.2 — FortiWeb inline format:  client_random=<hex64> master_key=<hex96>
      • TLS 1.2 — OpenSSL-style label:     CLIENT_RANDOM <hex64> <hex96>
      • TLS 1.2 — multi-line format:       client_random: <hex64> ... master_secret: <hex96>
      • TLS 1.2 — flow trace embedded:     [flow] ... CLIENT_RANDOM <hex64> <hex96>
      • TLS 1.3 — NSS-style labels:        CLIENT_HANDSHAKE_TRAFFIC_SECRET <hex64> <hex64>
      • TLS 1.3 — verbose prefix format:   [SSL] LABEL: <hex64> <hex64>
      • TLS 1.3 — flow trace embedded:     [flow] ... <TLS13_LABEL> <hex64> <hex64>

    All patterns lower-case their captures before returning.
    """

    # ── Candidate detection keywords (case-insensitive) ───────────────────────
    _CANDIDATE_KEYWORDS = {
        'ssl', 'tls', 'secret', 'master', 'random', 'client', 'handshake',
        'traffic', 'pre_master', 'premaster', 'key_log', 'keylog',
        'client_random', 'master_secret', 'master_key',
    }
    
    # Keywords that suggest TLS handshake activity
    _HANDSHAKE_KEYWORDS = {
        'clienthello', 'serverhello', 'certificate', 'keyexchange',
        'changecipherspec', 'finished', 'handshake', 'ssl_accept',
        'ssl_connect', 'tls_accept', 'tls_connect',
    }

    # ── Pattern definitions ───────────────────────────────────────────────────

    # TLS 1.2 — key=value on one line (most common FortiWeb inline format)
    # Handles: client_random=X...master_secret=Y, client random: X ... master key: Y
    # NOTE: No DOTALL - must be on same line. Multi-line handled separately with blank line reset.
    _P_TLS12_INLINE = re.compile(
        r"client[_\-\s]*random[=:\s]+(?P<cr>[0-9a-fA-F]{64})"
        r"[^\n]*?master[_\-\s]*(?:key|secret)[=:\s]+(?P<ms>[0-9a-fA-F]{96})",
        re.IGNORECASE,
    )

    # TLS 1.2 — OpenSSL / NSS key log format (standalone or embedded in flow trace)
    # Handles: CLIENT_RANDOM <hex64> <hex96>
    # Also handles: [timestamp] [flow] CLIENT_RANDOM <hex64> <hex96>
    _P_TLS12_NSS = re.compile(
        r"CLIENT_RANDOM\s+(?P<cr>[0-9a-fA-F]{64})\s+(?P<ms>[0-9a-fA-F]{96})",
        re.IGNORECASE,
    )

    # TLS 1.2 — ssl_keylog style: ssl_keylog: CLIENT_RANDOM X Y
    _P_TLS12_KEYLOG = re.compile(
        r"(?:ssl_keylog|keylog|key_log)[:\s]+CLIENT_RANDOM\s+"
        r"(?P<cr>[0-9a-fA-F]{64})\s+(?P<ms>[0-9a-fA-F]{96})",
        re.IGNORECASE,
    )

    # TLS 1.3 — NSS-style multi-label (any position in line)
    _P_TLS13_NSS = re.compile(
        r"(?P<label>" + "|".join(re.escape(l) for l in _TLS13_LABELS) + r")"
        r"\s+(?P<cr>[0-9a-fA-F]{64})\s+(?P<secret>[0-9a-fA-F]{32,128})",
        re.IGNORECASE,
    )

    # TLS 1.3 — verbose prefix: [SSL] LABEL: random secret or [flow] LABEL random secret
    _P_TLS13_VERBOSE = re.compile(
        r"\[(?:SSL|TLS|ssl|tls|flow|FLOW)\][:\s]*"
        r"(?P<label>" + "|".join(re.escape(l) for l in _TLS13_LABELS) + r")"
        r"[:\s]+(?P<cr>[0-9a-fA-F]{64})\s+(?P<secret>[0-9a-fA-F]{32,128})",
        re.IGNORECASE,
    )

    # TLS 1.2 multi-line detection patterns
    _P_TLS12_CR_LINE = re.compile(
        r"client[_\-\s]*random[:\s=]+([0-9a-fA-F]{64})", re.IGNORECASE
    )
    _P_TLS12_MS_LINE = re.compile(
        r"master[_\-\s]*(?:key|secret)[:\s=]+([0-9a-fA-F]{96})", re.IGNORECASE
    )
    
    # Generic hex blob finder for multi-line correlation
    _P_HEX64 = re.compile(r'\b([0-9a-fA-F]{64})\b')
    _P_HEX96 = re.compile(r'\b([0-9a-fA-F]{96})\b')

    def __init__(self) -> None:
        self.stats = TLSParseStats()

    def _is_candidate_line(self, line: str) -> bool:
        """Check if line contains TLS-related keywords."""
        line_lower = line.lower()
        return any(kw in line_lower for kw in self._CANDIDATE_KEYWORDS)

    def _is_secret_candidate(self, line: str) -> bool:
        """Check if line looks like it might contain secret material."""
        line_lower = line.lower()
        # Must have both a random indicator AND a secret indicator
        has_random = 'random' in line_lower or 'client' in line_lower
        has_secret = 'secret' in line_lower or 'master' in line_lower or 'key' in line_lower
        # Or must be an NSS-style label
        has_nss_label = any(label.lower() in line_lower for label in _TLS13_LABELS)
        has_nss_label = has_nss_label or 'client_random' in line_lower
        return (has_random and has_secret) or has_nss_label

    def _detect_content_type(self, lines: list[str]) -> None:
        """Analyze raw lines to detect what kind of content we have."""
        for line in lines:
            line_lower = line.lower()
            # Check for flow trace markers
            if 'diagnose debug flow' in line_lower or '[flow]' in line_lower:
                self.stats.has_flow_trace = True
            # Check for SSL/TLS content
            if 'ssl' in line_lower or 'tls' in line_lower:
                self.stats.has_ssl_content = True
            # Check for handshake indicators
            if any(kw in line_lower for kw in self._HANDSHAKE_KEYWORDS):
                self.stats.has_handshake_indicators = True
            # Check for command failures
            if 'parsing error' in line_lower or 'command fail' in line_lower:
                self.stats.command_failures += 1

    def parse(self, raw_text: str) -> TLSDebugSession:
        """
        Parse raw debug output and extract TLS key entries.
        
        Also populates self.stats with diagnostic information.
        """
        session = TLSDebugSession()
        lines = raw_text.splitlines()
        self.stats = TLSParseStats(total_lines=len(lines))
        
        # Analyze content type
        self._detect_content_type(lines)
        
        # Count candidate lines
        candidate_lines = []
        for line in lines:
            if self._is_candidate_line(line):
                self.stats.candidate_lines += 1
                candidate_lines.append(line)
                if self._is_secret_candidate(line):
                    self.stats.secret_candidate_lines += 1

        # ── Single-pass full-text patterns ────────────────────────────────────

        # TLS 1.2 inline (client_random=X...master_secret=Y on same line)
        for m in self._P_TLS12_INLINE.finditer(raw_text):
            session.add(TLSKeyEntry(
                label         = "CLIENT_RANDOM",
                client_random = m.group("cr").lower(),
                secret        = m.group("ms").lower(),
                tls_version   = "1.2",
            ))
            self.stats.matched_entries += 1

        # TLS 1.2 NSS format (CLIENT_RANDOM X Y)
        for m in self._P_TLS12_NSS.finditer(raw_text):
            session.add(TLSKeyEntry(
                label         = "CLIENT_RANDOM",
                client_random = m.group("cr").lower(),
                secret        = m.group("ms").lower(),
                tls_version   = "1.2",
            ))
            self.stats.matched_entries += 1

        # TLS 1.2 keylog style (ssl_keylog: CLIENT_RANDOM X Y)
        for m in self._P_TLS12_KEYLOG.finditer(raw_text):
            session.add(TLSKeyEntry(
                label         = "CLIENT_RANDOM",
                client_random = m.group("cr").lower(),
                secret        = m.group("ms").lower(),
                tls_version   = "1.2",
            ))
            self.stats.matched_entries += 1

        # TLS 1.3 NSS format
        for m in self._P_TLS13_NSS.finditer(raw_text):
            session.add(TLSKeyEntry(
                label         = m.group("label").upper(),
                client_random = m.group("cr").lower(),
                secret        = m.group("secret").lower(),
                tls_version   = "1.3",
            ))
            self.stats.matched_entries += 1

        # TLS 1.3 verbose format
        for m in self._P_TLS13_VERBOSE.finditer(raw_text):
            session.add(TLSKeyEntry(
                label         = m.group("label").upper(),
                client_random = m.group("cr").lower(),
                secret        = m.group("secret").lower(),
                tls_version   = "1.3",
            ))
            self.stats.matched_entries += 1

        # ── Line-pair scan for split multi-line format ────────────────────────
        # Look for client_random on one line and master_secret within next 5 lines
        # Blank lines reset the pending state
        pending_cr: Optional[str] = None
        pending_line_idx: int = -1
        
        for idx, line in enumerate(lines):
            # Blank lines reset pending state
            if not line.strip():
                pending_cr = None
                pending_line_idx = -1
                continue
            
            cr_m = self._P_TLS12_CR_LINE.search(line)
            ms_m = self._P_TLS12_MS_LINE.search(line)

            if cr_m:
                pending_cr = cr_m.group(1).lower()
                pending_line_idx = idx
            elif ms_m and pending_cr is not None:
                # Check if within context window (5 lines)
                if idx - pending_line_idx <= 5:
                    session.add(TLSKeyEntry(
                        label         = "CLIENT_RANDOM",
                        client_random = pending_cr,
                        secret        = ms_m.group(1).lower(),
                        tls_version   = "1.2",
                    ))
                    self.stats.matched_entries += 1
                pending_cr = None
                pending_line_idx = -1

        # ── Collect unmatched samples for diagnostics ─────────────────────────
        if self.stats.matched_entries == 0 and self.stats.secret_candidate_lines > 0:
            # Collect up to 5 samples of lines that looked like they might have secrets
            for line in candidate_lines:
                if self._is_secret_candidate(line):
                    # Truncate for display
                    sample = line[:200] + "..." if len(line) > 200 else line
                    self.stats.unmatched_samples.append(sample.strip())
                    if len(self.stats.unmatched_samples) >= 5:
                        break

        # Deduplicate entries
        seen: set[str] = set()
        unique_entries: list[TLSKeyEntry] = []
        for entry in session.entries:
            key = entry.to_keylog_line()
            if key not in seen:
                seen.add(key)
                unique_entries.append(entry)
        
        session.entries = unique_entries
        self.stats.unique_entries = len(unique_entries)

        return session


# ── SSH debug-channel orchestrator ────────────────────────────────────────────

class TLSDebugOrchestrator:
    """
    Manages a second SSH shell session to a FortiWeb device that runs
    concurrently with the packet sniffer channel.

    Lifecycle
    ---------
    1. start(ssh_client, debug_config)
       → Opens an invoke_shell channel, waits for prompt, sends enable commands.
       → Launches a background collector thread.

    2. The calling code runs the sniffer capture on the primary channel.

    3. stop()
       → Sends disable commands to the shell.
       → Waits up to drain_timeout seconds for remaining output.
       → Stops the collector thread.
       → Returns all collected raw lines.

    The orchestrator does NOT parse key material — that is the caller's job
    (via TLSKeyParser) so the two concerns remain independently testable.
    """

    def __init__(self) -> None:
        self._channel            = None
        self._thread: Optional[threading.Thread] = None
        self._raw_lines: list[str] = []
        self._lock               = threading.Lock()
        self._stop_event         = threading.Event()
        self._ssh_client         = None   # holds reference to DiagSSHClient

    def start(
        self,
        ssh_client:   "DiagSSHClient",  # type: ignore[name-defined]  # avoid circular
        debug_config: "TLSDebugConfig",  # type: ignore[name-defined]
    ) -> None:
        """Open the debug shell channel and begin collecting output in a thread."""
        from .commands import build_fortiweb_tls_debug_enable

        self._ssh_client = ssh_client
        transport = ssh_client._client.get_transport()
        if transport is None or not transport.is_active():
            raise RuntimeError("Cannot open TLS debug channel: SSH transport not active.")

        self._channel = transport.open_session()
        self._channel.get_pty()         # FortiWeb debug requires a PTY
        self._channel.invoke_shell()

        # Set a timeout on the channel to prevent indefinite blocking
        self._channel.settimeout(5.0)

        # Wait for the shell to become ready
        self._wait_for_prompt(timeout=_SHELL_TIMEOUT)

        # Send debug enable commands, one per line
        # Pass IP filters from config to command builder
        for cmd in build_fortiweb_tls_debug_enable(
            ssl_debug_level=debug_config.ssl_debug_level,
            client_ip=debug_config.client_ip,
            server_ip=debug_config.server_ip,
            pserver_ip=debug_config.pserver_ip,
        ):
            self._channel.send((cmd + "\n").encode())
            time.sleep(0.1)   # brief pause so the device processes each command

        # Log active filters for debugging
        filters = []
        if debug_config.client_ip:
            filters.append(f"client-ip={debug_config.client_ip}")
        if debug_config.server_ip:
            filters.append(f"server-ip={debug_config.server_ip}")
        if debug_config.pserver_ip:
            filters.append(f"pserver-ip={debug_config.pserver_ip}")
        filter_str = ", ".join(filters) if filters else "none"
        log.info("TLS debug channel opened; flow-detail=4, filters: %s", filter_str)

        # Start background collector thread
        self._stop_event.clear()
        self._thread = threading.Thread(
            target  = self._collect_loop,
            name    = "tls-debug-collector",
            daemon  = True,
        )
        self._thread.start()

    def stop(self, drain_timeout: float = 3.0) -> list[str]:
        """
        Gracefully stop the debug session.
        Returns all raw lines collected (including prompts and command echoes).
        """
        from .commands import build_fortiweb_tls_debug_disable

        if self._channel is None:
            return []

        # Signal the collector thread to stop FIRST so it doesn't interfere
        # with our disable commands
        self._stop_event.set()

        try:
            # Set a timeout so we don't block forever
            self._channel.settimeout(2.0)
            for cmd in build_fortiweb_tls_debug_disable():
                self._channel.send((cmd + "\n").encode())
                time.sleep(0.1)
            # Brief wait for device to process disable commands
            time.sleep(min(drain_timeout, 1.0))
        except Exception as exc:
            log.warning("Error sending debug-disable commands: %s", exc)

        # Wait for collector thread to finish
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=drain_timeout)
            if self._thread.is_alive():
                log.warning("TLS debug collector thread did not stop within timeout")

        try:
            self._channel.close()
        except Exception:
            pass

        with self._lock:
            return list(self._raw_lines)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _wait_for_prompt(self, timeout: float) -> None:
        """Block until the shell emits a known prompt marker or timeout expires."""
        deadline = time.monotonic() + timeout
        buf      = b""
        while time.monotonic() < deadline:
            if self._channel.recv_ready():
                buf += self._channel.recv(_DRAIN_CHUNK)
                if any(m in buf for m in _PROMPT_MARKERS):
                    return
            time.sleep(_POLL_INTERVAL)
        log.warning("TLS debug shell: prompt not detected within %.1f s — continuing anyway.", timeout)

    def _collect_loop(self) -> None:
        """Background thread: drain channel bytes into self._raw_lines."""
        buf = b""
        while not self._stop_event.is_set():
            try:
                if self._channel and self._channel.recv_ready():
                    chunk = self._channel.recv(_DRAIN_CHUNK)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        decoded = line.decode(errors="replace").rstrip("\r")
                        with self._lock:
                            self._raw_lines.append(decoded)
                elif self._channel and self._channel.exit_status_ready():
                    break
                else:
                    time.sleep(_POLL_INTERVAL)
            except Exception as exc:
                log.debug("TLS debug collector: %s", exc)
                break

        # Drain any trailing bytes
        if buf.strip():
            with self._lock:
                self._raw_lines.append(buf.decode(errors="replace").rstrip("\r"))


# ── Public entry-points ───────────────────────────────────────────────────────

def parse_raw_debug_lines(
    lines: Iterator[str],
    return_stats: bool = False,
) -> TLSDebugSession | tuple[TLSDebugSession, TLSParseStats]:
    """
    Parse a sequence of raw FortiWeb debug output lines.

    This is the pure-logic path used by both the live orchestrator
    (after stop() returns) and the offline `diagsniff tls-parse` command.
    
    Parameters
    ----------
    lines : Iterator[str]
        Raw debug output lines from FortiWeb flow trace.
    return_stats : bool
        If True, returns (session, stats) tuple for diagnostics.
    
    Returns
    -------
    TLSDebugSession or tuple[TLSDebugSession, TLSParseStats]
    """
    raw_text = "\n".join(lines)
    parser = TLSKeyParser()
    session = parser.parse(raw_text)
    
    if return_stats:
        return session, parser.stats
    return session


def parse_fortiweb_tls_debug(raw_lines: Iterator[str]) -> TLSDebugSession:
    """Backward-compatible alias for parse_raw_debug_lines."""
    return parse_raw_debug_lines(raw_lines)


def run_tls_debug_postprocess(
    raw_lines:    list[str],
    debug_config: "TLSDebugConfig",  # type: ignore[name-defined]
    capture_path: Path,
) -> "TLSKeyLogResult":
    """
    Post-process collected debug lines into a TLSKeyLogResult.

    Called by capture.py after the sniffer session ends.
    Handles:
      • Parsing key material from raw_lines.
      • Writing the NSS Key Log file.
      • Optionally saving the raw debug stream.
      • Generating warnings for missing/unexpected state.
    
    FortiWeb 8.x Notes:
      • TLS secrets come from `diagnose debug flow trace` at detail level 4.
      • Both packet capture AND flow trace must run simultaneously.
      • A fresh TLS handshake must occur during capture for secrets to appear.
      • Use client-ip/server-ip/pserver-ip filters to reduce noise.
    """
    # Avoid circular import — models imported at call time
    from .models import TLSKeyLogResult

    warnings: list[str] = []
    
    # Parse with statistics
    session, stats = parse_raw_debug_lines(iter(raw_lines), return_stats=True)

    # ── Determine key log output path ─────────────────────────────────────────
    # Session key log: <stem>SessionKey.log
    keylog_path = debug_config.keylog_path
    if keylog_path is None:
        stem = capture_path.stem
        keylog_path = capture_path.parent / f"{stem}SessionKey.log"

    keylog_path.parent.mkdir(parents=True, exist_ok=True)
    session.save_keylog(keylog_path)

    # ── Optionally save raw debug stream ──────────────────────────────────────
    raw_debug_path: Optional[Path] = None
    if debug_config.save_raw_debug:
        raw_debug_path = debug_config.raw_debug_path or capture_path.with_suffix(".tlsdebug.txt")
        raw_debug_path.parent.mkdir(parents=True, exist_ok=True)
        session.save_raw_debug(raw_lines, raw_debug_path)

    # ── Detailed diagnostic warnings ──────────────────────────────────────────
    if stats.total_lines == 0:
        warnings.append(
            "TLS debug channel returned no output.\n"
            "Possible causes:\n"
            "  • FortiWeb shell session was not established.\n"
            "  • diagnose debug flow commands failed to execute.\n"
            "  • Connection was interrupted before data could be collected."
        )
    elif not stats.has_flow_trace and not stats.has_ssl_content:
        warnings.append(
            f"Collected {stats.total_lines:,} lines but no flow trace or SSL content detected.\n"
            "The debug output may be from the wrong command or capture session.\n"
            "FortiWeb 8.x requires: diagnose debug flow trace start"
        )
    elif session.tls12_count == 0 and session.tls13_count == 0:
        # Detailed failure analysis
        diagnostic = f"Parsed {stats.total_lines:,} debug lines:\n"
        diagnostic += f"  • Candidate TLS lines: {stats.candidate_lines:,}\n"
        diagnostic += f"  • Secret-like lines: {stats.secret_candidate_lines:,}\n"
        diagnostic += f"  • Flow trace detected: {'Yes' if stats.has_flow_trace else 'No'}\n"
        diagnostic += f"  • SSL/TLS content: {'Yes' if stats.has_ssl_content else 'No'}\n"
        diagnostic += f"  • Handshake indicators: {'Yes' if stats.has_handshake_indicators else 'No'}\n"
        
        if stats.command_failures > 0:
            diagnostic += f"  • Command failures: {stats.command_failures}\n"
            diagnostic += "\nSome debug commands failed on this FortiWeb version."
        
        if stats.secret_candidate_lines > 0:
            diagnostic += "\nFound secret-like patterns but regex extraction failed.\n"
            diagnostic += "This may indicate an unsupported FortiWeb output format."
            if stats.unmatched_samples:
                diagnostic += "\nSample unmatched lines (check for format variations):"
                for sample in stats.unmatched_samples[:3]:
                    diagnostic += f"\n  → {sample}"
        elif stats.has_flow_trace and stats.has_ssl_content and stats.has_handshake_indicators:
            # This is the case the user is hitting - everything looks right but no keys
            diagnostic += "\n⚠  Flow trace active with SSL traffic but NO TLS secrets found.\n"
            diagnostic += "\nThis FortiWeb version may not export TLS session keys via CLI.\n"
            diagnostic += "Possible solutions:\n"
            diagnostic += "  • Check FortiWeb GUI for 'SSL Keylog' or 'Debug' options.\n"
            diagnostic += "  • Try FortiWeb firmware that supports TLS key export.\n"
            diagnostic += "  • Use browser-side keylogging (SSLKEYLOGFILE env var).\n"
            diagnostic += "  • Contact Fortinet support for TLS debugging options.\n"
            diagnostic += "\nAlternative: Set SSLKEYLOGFILE in your browser/client:\n"
            diagnostic += "  Windows: set SSLKEYLOGFILE=C:\\path\\to\\keylog.txt\n"
            diagnostic += "  Linux:   export SSLKEYLOGFILE=/path/to/keylog.txt"
        elif stats.has_ssl_content and not stats.has_handshake_indicators:
            diagnostic += "\nSSL content found but no handshake detected.\n"
            diagnostic += "A fresh TLS handshake must occur during capture."
        else:
            diagnostic += "\nPossible causes:\n"
            diagnostic += "  • No HTTPS/TLS traffic during capture (check filter).\n"
            diagnostic += "  • No fresh TLS handshake (cached sessions reuse keys).\n"
            diagnostic += "  • FortiWeb firmware doesn't export TLS secrets via CLI.\n"
            diagnostic += "  • Flow trace detail level < 4 (need flow-detail 4)."
        
        warnings.append(diagnostic)
    
    if debug_config.min_expected_entries > 0 and len(session.entries) < debug_config.min_expected_entries:
        warnings.append(
            f"Expected at least {debug_config.min_expected_entries} key entries "
            f"but found only {len(session.entries)}."
        )

    return TLSKeyLogResult(
        keylog_path    = keylog_path,
        raw_debug_path = raw_debug_path,
        entry_count    = len(session.entries),
        tls12_count    = session.tls12_count,
        tls13_count    = session.tls13_count,
        warnings       = warnings,
    )


def orchestrate_fortiweb_tls_debug(
    raw_output_path:    Path,
    keylog_output_path: Path,
    verbose: bool = False,
) -> tuple[int, Optional[TLSParseStats]]:
   
    with raw_output_path.open(encoding="utf-8", errors="replace") as fh:
        session, stats = parse_raw_debug_lines(iter(fh), return_stats=True)
    count = session.save_keylog(keylog_output_path)
    
    if verbose:
        return count, stats
    return count, None
