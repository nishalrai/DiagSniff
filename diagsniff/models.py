from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# ── Type aliases ──────────────────────────────────────────────────────────────
DeviceType     = Literal["fortigate", "fortiweb"]
AuthMethod     = Literal["password", "key"]
VerbosityLevel = Annotated[int, Field(ge=1, le=6)]
# count=0 means "run forever until Ctrl+C"; hard upper bound prevents runaway captures
CaptureCount   = Annotated[int, Field(ge=0, le=10_000)]


class DeviceProfile(BaseModel):
    name:        str        = Field(..., min_length=1, max_length=64, pattern=r"^[\w\-]+$")
    device_type: DeviceType = "fortigate"
    host:        str        = Field(..., min_length=1)
    port:        int        = Field(default=22, ge=1, le=65535)
    username:    str        = Field(..., min_length=1)
    auth_method: AuthMethod = "password"
    key_path:    Optional[Path] = None

    @field_validator("key_path", mode="before")
    @classmethod
    def _expand_key_path(cls, v: Optional[str | Path]) -> Optional[Path]:
        return Path(v).expanduser() if v else None

    @model_validator(mode="after")
    def _key_required_for_key_auth(self) -> "DeviceProfile":
        if self.auth_method == "key" and self.key_path is None:
            raise ValueError("key_path must be provided when auth_method='key'")
        return self

    @property
    def credential_service(self) -> str:
        return f"diagsniff::{self.name}::{self.host}"


class CaptureConfig(BaseModel):
    """Parameters that drive the sniffer command."""

    interface:   str           = Field(default="any",  min_length=1, max_length=32)
    filter_expr: str           = Field(default="none", max_length=512)
    verbosity:   VerbosityLevel = 3   # verbose 3 = hex dump, required for pcap conversion
    count:       CaptureCount   = 100
    # interactive=True → count is ignored; run until Ctrl+C
    interactive: bool           = False

    @field_validator("filter_expr", mode="before")
    @classmethod
    def _sanitize_filter(cls, v: str) -> str:
        """Strip stray quotes a user might include; empty → 'none'."""
        v = v.strip().strip("'\"")
        return v if v else "none"



class TLSDebugConfig(BaseModel):
    enabled:              bool           = False
    strict_mode:          bool           = False  # --tls-strict uses exact IP filters
    ssl_debug_level:      int            = Field(default=255, ge=0, le=255)
    # Where to write the Wireshark-compatible NSS Key Log file
    keylog_path:          Optional[Path] = None
    # Optionally save the raw FortiWeb debug stream for offline re-parsing
    save_raw_debug:       bool           = True   # Default on; deleted on success
    raw_debug_path:       Optional[Path] = None
    # Seconds to keep draining debug output after the sniffer channel closes
    drain_timeout:        float          = Field(default=3.0, ge=0.0, le=30.0)
    # Emit a warning when fewer than this many key entries are found
    min_expected_entries: int            = Field(default=0, ge=0)

    client_ip:  Optional[str] = None
    server_ip:  Optional[str] = None
    pserver_ip: Optional[str] = None

    @field_validator("keylog_path", "raw_debug_path", mode="before")
    @classmethod
    def _expand(cls, v: Optional[str | Path]) -> Optional[Path]:
        return Path(v).expanduser() if v else None


class TLSKeyLogResult(BaseModel):
    keylog_path:    Path
    raw_debug_path: Optional[Path] = None
    entry_count:    int            = 0
    tls12_count:    int            = 0
    tls13_count:    int            = 0
    warnings:       list[str]      = Field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.entry_count > 0



class SnifferSession(BaseModel):
    profile:     DeviceProfile
    capture:     CaptureConfig
    output_path: Path
    tls_debug:   TLSDebugConfig = Field(default_factory=TLSDebugConfig)
    timestamp:   datetime       = Field(default_factory=datetime.now)


# ── Host-key persistence ──────────────────────────────────────────────────────

class HostKeyRecord(BaseModel):

    hostname:    str
    port:        int
    key_type:    str
    fingerprint: str           # SHA-256 hex
    added_at:    datetime = Field(default_factory=datetime.now)
    trusted:     bool     = False


class ProfileStore(BaseModel):

    version:  int                      = 1
    profiles: dict[str, DeviceProfile] = Field(default_factory=dict)


class HostKeyStore(BaseModel):

    version:   int                       = 1
    host_keys: dict[str, HostKeyRecord]  = Field(default_factory=dict)

    @staticmethod
    def record_key(hostname: str, port: int, key_type: str) -> str:
        return f"{hostname}:{port}:{key_type}"
