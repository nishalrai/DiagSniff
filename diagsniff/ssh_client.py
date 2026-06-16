
from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Iterator, Optional

import paramiko
import paramiko.hostkeys
from rich.console import Console
from rich.prompt import Confirm
from rich.panel import Panel

from .models import DeviceProfile, HostKeyRecord, HostKeyStore
from .platform_utils import get_app_dir

log     = logging.getLogger(__name__)
console = Console(stderr=True)

_KNOWN_HOSTS_FILE = "known_hosts.json"
_RECV_CHUNK       = 4096
_POLL_INTERVAL    = 0.05  # seconds between channel polls


# ── Known-hosts persistence ───────────────────────────────────────────────────

class KnownHostsManager:
    def __init__(self) -> None:
        self._path: Path = get_app_dir() / _KNOWN_HOSTS_FILE

    def _load(self) -> HostKeyStore:
        if not self._path.exists():
            return HostKeyStore()
        try:
            return HostKeyStore.model_validate(
                json.loads(self._path.read_text(encoding="utf-8"))
            )
        except Exception:
            return HostKeyStore()

    def _save(self, store: HostKeyStore) -> None:
        self._path.write_text(store.model_dump_json(indent=2), encoding="utf-8")

    def lookup(self, hostname: str, port: int, key_type: str) -> Optional[HostKeyRecord]:
        k = HostKeyStore.record_key(hostname, port, key_type)
        return self._load().host_keys.get(k)

    def trust(self, hostname: str, port: int, key_type: str, fingerprint: str) -> None:
        store = self._load()
        k     = HostKeyStore.record_key(hostname, port, key_type)
        store.host_keys[k] = HostKeyRecord(
            hostname=hostname, port=port,
            key_type=key_type, fingerprint=fingerprint,
            trusted=True,
        )
        self._save(store)


_known_hosts = KnownHostsManager()


# ── TOFU host-key policy ──────────────────────────────────────────────────────

class TOFUPolicy(paramiko.MissingHostKeyPolicy):
    """
    Trust-On-First-Use policy.

    • Unknown host  → show fingerprint, prompt user, store if accepted.
    • Known host, fingerprint matches → silently allow.
    • Known host, fingerprint CHANGED → raise unconditionally (potential MITM).
    """

    def missing_host_key(
        self,
        client: paramiko.SSHClient,
        hostname: str,
        key: paramiko.PKey,
    ) -> None:
        port        = client.get_transport().getpeername()[1] if client.get_transport() else 22
        key_type    = key.get_name()
        fingerprint = _sha256_fingerprint(key)
        existing    = _known_hosts.lookup(hostname, port, key_type)

        if existing is not None:
            if existing.fingerprint == fingerprint:
                return  # Trusted, all good
            # Fingerprint mismatch — HARD FAIL
            console.print(
                Panel(
                    f"[bold red]⛔  HOST KEY MISMATCH[/bold red]\n\n"
                    f"The host key for [bold]{hostname}:{port}[/bold] has changed!\n\n"
                    f"  Stored :  {existing.fingerprint}\n"
                    f"  Received: {fingerprint}\n\n"
                    "This could indicate a [bold red]man-in-the-middle attack[/bold red].\n"
                    "Remove the stored key from ~/.diagsniff/known_hosts.json to proceed.",
                    title="Security Alert",
                    border_style="red",
                )
            )
            raise paramiko.BadHostKeyException(hostname, key, None)

        # ── First-time onboarding ─────────────────────────────────────────────
        # Print a blank line first so the panel is visually separated from
        # any "Connecting..." status line above it.
        console.print()
        console.print(
            Panel(
                f"[bold yellow]🔑  New host key — ACTION REQUIRED[/bold yellow]\n\n"
                f"  Host     : [bold]{hostname}:{port}[/bold]\n"
                f"  Key type : {key_type}\n"
                f"  SHA-256  : [cyan]{fingerprint}[/cyan]\n\n"
                "[bold]Verify this fingerprint matches what is shown on the device[/bold]\n"
                "before typing [bold green]y[/bold green].\n\n"
                "FortiGate  : [dim]get system ssh-server[/dim]\n"
                "FortiWeb   : [dim]get system global | grep ssh[/dim]",
                title="[bold yellow]⚠  First-Time Connection[/bold yellow]",
                border_style="yellow",
            )
        )
        # Use console.print to force-flush before Confirm.ask reads stdin.
        # This ensures the prompt is visible even in piped or WSL terminals.
        console.print("[bold yellow]?[/bold yellow] Do you trust this host key and want to save it? "
                      "[[bold green]y[/bold green]/[bold red]N[/bold red]] ", end="")
        try:
            answer = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        trust = answer in ("y", "yes")
        if not trust:
            console.print("[red]✗[/red] Host key rejected — connection aborted.")
            raise paramiko.AuthenticationException(
                f"User declined host key for {hostname}:{port}"
            )
        _known_hosts.trust(hostname, port, key_type, fingerprint)
        console.print(f"[green]✓[/green] Host key saved to ~/.diagsniff/known_hosts.json")
        console.print()


def _sha256_fingerprint(key: paramiko.PKey) -> str:
    import base64
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


# ── SSH Client wrapper ────────────────────────────────────────────────────────

class DiagSSHClient:
    """Manages a single Paramiko SSH session to a FortiGate/FortiWeb device."""

    def __init__(self) -> None:
        self._client: paramiko.SSHClient = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(TOFUPolicy())

    def connect(
        self,
        profile:  DeviceProfile,
        password: Optional[str] = None,
    ) -> None:
        """
        Open SSH connection using either password or key-based auth.
        Raises on auth failure or host-key rejection.
        """
        common = dict(
            hostname = profile.host,
            port     = profile.port,
            username = profile.username,
            timeout  = 15,
            # Disable Paramiko's own known_hosts so only our TOFU store is used
            look_for_keys    = False,
            allow_agent      = False,
        )

        if profile.auth_method == "key":
            if profile.key_path is None or not profile.key_path.exists():
                raise FileNotFoundError(f"SSH key not found: {profile.key_path}")
            self._client.connect(key_filename=str(profile.key_path), **common)
        else:
            if not password:
                raise ValueError("Password is required for password-based auth.")
            self._client.connect(password=password, **common)

        log.info(
            "SSH connected to %s:%s as %s",
            profile.host, profile.port, profile.username,
        )

    def stream_command(self, command: str) -> Iterator[str]:
        """
        Execute *command* and yield decoded output lines as they arrive.

        Uses exec_command (not invoke_shell) so only the command output is
        captured — no login banner, no prompt echoes.

        The caller must handle KeyboardInterrupt to stop infinite captures.
        """
        transport = self._client.get_transport()
        if transport is None or not transport.is_active():
            raise RuntimeError("SSH transport is not active.")

        # Open a dedicated channel per command
        channel = transport.open_session()
        channel.set_combine_stderr(True)   # merge stderr → cleaner output
        channel.exec_command(command)

        buf = b""
        try:
            while True:
                if channel.recv_ready():
                    chunk = channel.recv(_RECV_CHUNK)
                    if not chunk:
                        break
                    buf += chunk
                    # Yield complete lines; hold partial line in buffer
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        yield line.decode(errors="replace")

                elif channel.exit_status_ready():
                    # Drain any remaining data
                    while channel.recv_ready():
                        buf += channel.recv(_RECV_CHUNK)
                    break
                else:
                    time.sleep(_POLL_INTERVAL)

            # Yield any trailing partial line (FortiOS sometimes omits final \n)
            if buf.strip():
                yield buf.decode(errors="replace")

        finally:
            channel.close()

    def close(self) -> None:
        self._client.close()
        log.debug("SSH connection closed.")

    # Context manager support
    def __enter__(self) -> "DiagSSHClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
