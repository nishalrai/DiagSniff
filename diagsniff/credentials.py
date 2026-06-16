
from __future__ import annotations

import base64
import hashlib
import json
import logging
from pathlib import Path
from typing import Optional

from .platform_utils import get_app_dir, get_machine_id

log = logging.getLogger(__name__)

# ── Key derivation ────────────────────────────────────────────────────────────

_KDF_SALT      = b"diagsniff-credential-store-v1"
_KDF_ITERS     = 200_000
_CREDS_FILENAME = ".creds.enc"


def _derive_fernet_key(machine_id: str) -> bytes:
    raw = hashlib.pbkdf2_hmac(
        "sha256",
        machine_id.encode(),
        _KDF_SALT,
        iterations=_KDF_ITERS,
    )
    return base64.urlsafe_b64encode(raw[:32])


def _get_fernet():
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise RuntimeError(
            "The 'cryptography' package is required for local credential storage. "
            "Run: pip install cryptography"
        ) from exc
    return Fernet(_derive_fernet_key(get_machine_id()))


# ── Encrypted local store ─────────────────────────────────────────────────────

class _LocalCredentialStore:
    """JSON dict encrypted on disk.  Thread-safe via read-modify-write."""

    def __init__(self) -> None:
        self._path: Path = get_app_dir() / _CREDS_FILENAME

    def _load(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        try:
            fernet = _get_fernet()
            cipher = self._path.read_bytes()
            plain  = fernet.decrypt(cipher)
            return json.loads(plain)
        except Exception:
            log.warning("Could not decrypt local credential store — returning empty.")
            return {}

    def _save(self, data: dict[str, str]) -> None:
        fernet = _get_fernet()
        cipher = fernet.encrypt(json.dumps(data).encode())
        # Restrict permissions on POSIX; Windows ACLs managed by file system
        self._path.write_bytes(cipher)
        try:
            self._path.chmod(0o600)
        except NotImplementedError:
            pass

    def get(self, service: str, username: str) -> Optional[str]:
        key  = f"{service}::{username}"
        return self._load().get(key)

    def set(self, service: str, username: str, password: str) -> None:
        key   = f"{service}::{username}"
        data  = self._load()
        data[key] = password
        self._save(data)

    def delete(self, service: str, username: str) -> bool:
        key  = f"{service}::{username}"
        data = self._load()
        if key not in data:
            return False
        del data[key]
        self._save(data)
        return True


_local_store = _LocalCredentialStore()


# ── Public API ────────────────────────────────────────────────────────────────

def save_password(service: str, username: str, password: str) -> str:
    try:
        import keyring
        keyring.set_password(service, username, password)
        log.debug("Credential saved to system keyring: %s / %s", service, username)
        return "keyring"
    except Exception as exc:
        log.info("Keyring unavailable (%s); falling back to local store.", exc)
        _local_store.set(service, username, password)
        return "local"


def get_password(service: str, username: str) -> Optional[str]:
    """Retrieve a password, trying keyring first then local fallback."""
    try:
        import keyring
        pw = keyring.get_password(service, username)
        if pw is not None:
            return pw
    except Exception as exc:
        log.debug("Keyring get failed (%s); trying local store.", exc)
    return _local_store.get(service, username)


def delete_password(service: str, username: str) -> bool:
    """Remove a credential from both keyring and local store."""
    removed = False
    try:
        import keyring
        keyring.delete_password(service, username)
        removed = True
    except Exception:
        pass
    if _local_store.delete(service, username):
        removed = True
    return removed


def has_stored_password(service: str, username: str) -> bool:
    return get_password(service, username) is not None
