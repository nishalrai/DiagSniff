from __future__ import annotations

import hashlib
import platform
import sys
from pathlib import Path
from typing import Optional


def get_os() -> str:
    """Return a normalised OS label: 'windows', 'linux', or 'darwin'."""
    return platform.system().lower()


def get_app_dir() -> Path:
    """~/.diagsniff/ — the single config root, cross-platform."""
    d = Path.home() / ".diagsniff"
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_default_output_dir() -> Path:
    """Resolve Desktop → Documents → Home, in that priority order."""
    home = Path.home()
    candidates = [
        home / "Desktop",
        home / "Documents",
        home,
    ]
    for p in candidates:
        if p.exists() and p.is_dir():
            return p
    return home  # guaranteed fallback


def get_common_ssh_key_paths() -> list[Path]:
    """Return candidate private-key locations for the current user."""
    ssh_dir = Path.home() / ".ssh"
    names   = ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"]
    return [ssh_dir / n for n in names if (ssh_dir / n).exists()]


# ── Machine ID (used as entropy source for local credential encryption) ───────

def get_machine_id() -> str:
    """
    Return a stable, per-machine identifier without elevated privileges.

    Priority:
      Linux  → /etc/machine-id
      Windows → MachineGuid registry key
      Fallback → username + node name hash (not truly unique but stable)
    """
    os_name = get_os()

    if os_name == "linux":
        mid_path = Path("/etc/machine-id")
        if mid_path.exists():
            return mid_path.read_text().strip()

    if os_name == "windows":
        try:
            import winreg  # type: ignore[import]
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            )
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            winreg.CloseKey(key)
            return str(value)
        except Exception:
            pass

    # Stable-ish fallback — not hardware-unique but reproducible per user
    import getpass
    raw = f"{getpass.getuser()}@{platform.node()}:{sys.platform}"
    return hashlib.sha256(raw.encode()).hexdigest()


def suggest_output_filename(device_type: str, host: str, interface: str) -> str:
    """Build a sensible default filename for a capture output file."""
    from datetime import datetime
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Sanitise host: strip characters that are invalid in filenames
    safe_host = "".join(c if c.isalnum() or c in "-_." else "_" for c in host)
    return f"capture_{device_type}_{safe_host}_{interface}_{ts}.txt"


def get_pcap_dir() -> Path:
    """Return the project-local pcap/ directory, creating it if needed.

    Resolves to <project_root>/pcap/ where project root is the parent of the
    diagsniff package directory (i.e., two levels above this file).
    """
    pcap_dir = Path(__file__).parent.parent / "pcap"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    return pcap_dir


def suggest_pcap_filename() -> str:
    """Return a default .pcap filename in yyyyMMdd-HHmmssSSS.pcap format.

    Example: 20260419-182100123.pcap
    """
    from datetime import datetime
    now = datetime.now()
    ts = now.strftime("%Y%m%d-%H%M%S")
    ms = f"{now.microsecond // 1000:03d}"
    return f"{ts}{ms}.pcap"


def suggest_capture_stem() -> str:
    """Return a timestamped stem (no extension) in yyyyMMdd-HHmmssSSS format.

    Example: 20260419-182100123

    Used to derive paired raw-text and converted-pcap filenames:
      stem + '.txt'           → raw sniffer output
      stem + '.pcap'          → Wireshark-compatible converted file
      stem + 'SessionKey.log' → TLS session key log
    """
    from datetime import datetime
    now = datetime.now()
    ts = now.strftime("%Y%m%d-%H%M%S")
    ms = f"{now.microsecond // 1000:03d}"
    return f"{ts}{ms}"
