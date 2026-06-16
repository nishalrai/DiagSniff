from __future__ import annotations

import os
import re
import tempfile
from enum import Enum
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .fgt2eth import ConversionResult

# ── Detection patterns ────────────────────────────────────────────────────────

# Relative timestamp: "0.531555 port1 in …"
_RE_TS_REL = re.compile(r'^\d+\.\d+\s')

# Absolute timestamp: "2025-01-24 11:37:36.123456 port1 in …"
_RE_TS_ABS = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\s')

# Hex dump line: "0x0000  45 00 …"
_RE_HEX = re.compile(r'^0x[0-9a-fA-F]+[\s\t\xa0]')

# DiagSniff metadata header comment: "# DiagSniff capture", "# Started : …"
_RE_FS_HEADER = re.compile(
    r'^#\s*(?:DiagSniff|Started|Device|Interface|Filter|Command|Verbosity|Count|Output)\b',
    re.IGNORECASE,
)

# ANSI terminal escape sequences
_RE_ANSI = re.compile(r'\x1b\[[0-9;]*[mABCDHJKSTfsu]')

# Lines that are clearly shell / terminal noise (matched against stripped line)
_RE_NOISE = re.compile(
    r'^(?:'
    r'diagnose\s+network\s+sniffer'   # copied sniffer command
    r'|diagnose\s+sniffer\s+packet'   # FortiGate variant
    r'|(?:\w[\w@.\-]*\s*[#$>]\s*)'    # shell prompt  (admin@fw # ...)
    r'|\-{5,}'                         # horizontal rules -----
    r'|={5,}'                          # horizontal rules =====
    r'|Press\s+CTRL'                   # "Press CTRL+C to stop"
    r'|Ctrl\+C'
    r'|pcap_lookupdev'                 # libpcap error noise
    r'|Using\s+interface\s+'           # tcpdump header line
    r'|listening\s+on\s+'             # tcpdump header
    r')',
    re.IGNORECASE,
)


# ── Error model ───────────────────────────────────────────────────────────────

class ConvertErrorCode(str, Enum):
    NOT_TXT         = "not_txt"
    NOT_FOUND       = "not_found"
    NOT_READABLE    = "not_readable"
    EMPTY           = "empty"
    NO_PACKETS      = "no_packets"
    MALFORMED       = "malformed"
    UNSUPPORTED_FMT = "unsupported_format"


class ConvertError(Exception):
    def __init__(self, code: ConvertErrorCode, message: str) -> None:
        super().__init__(message)
        self.code    = code
        self.message = message


# ── Sanitization ──────────────────────────────────────────────────────────────

def sanitize_sniffer_content(content: str) -> str:

    from datetime import datetime

    lines   = content.splitlines()
    cleaned: list[str] = []
    in_body = False   # True once the first packet timestamp is seen
    has_started_header = False

    for raw_line in lines:
        # Phase 1: strip ANSI codes
        line = _RE_ANSI.sub("", raw_line)

        if not in_body:
            # Phase 2: pre-packet region ──────────────────────────────────────

            # Always keep DiagSniff metadata header comments
            if _RE_FS_HEADER.match(line):
                cleaned.append(line)
                # Check if this is the Started header
                if line.strip().startswith("# Started"):
                    has_started_header = True
                continue

            # Detect start of packet data
            if _RE_TS_REL.match(line) or _RE_TS_ABS.match(line):
                in_body = True
                # Phase 4: Inject Started header if missing (for relative timestamps)
                if not has_started_header:
                    now_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")
                    cleaned.insert(0, f"# Started     : {now_iso}")
                    has_started_header = True
                cleaned.append(line)
                continue

            # Skip everything else before the first packet
            continue

        # Phase 3: packet-body region ─────────────────────────────────────────

        # Hex dump lines — always keep
        if _RE_HEX.match(line):
            cleaned.append(line)
            continue

        # Next packet timestamp — always keep
        if _RE_TS_REL.match(line) or _RE_TS_ABS.match(line):
            cleaned.append(line)
            continue

        # Blank lines between packets — keep (part of packet structure)
        if not line.strip():
            cleaned.append(line)
            continue

        # Filter obvious noise; silently drop noisy lines
        stripped = line.strip()
        if _RE_NOISE.match(stripped):
            continue

        # Otherwise keep (unknown non-noise lines — let the parser decide)
        cleaned.append(line)

    return "\n".join(cleaned)


# ── Validation ────────────────────────────────────────────────────────────────

def validate_sniffer_content(original: str, sanitized: str) -> None:
   
    if not original.strip():
        raise ConvertError(
            ConvertErrorCode.EMPTY,
            "Input file is empty — nothing to convert.\n"
            "  Ensure the file contains sniffer output, then retry.",
        )

    san_lines = sanitized.splitlines()
    ts_lines  = [l for l in san_lines if _RE_TS_REL.match(l) or _RE_TS_ABS.match(l)]
    hex_lines = [l for l in san_lines if _RE_HEX.match(l)]

    if not ts_lines:
        # Give a more specific reason when possible
        has_hex_in_original = bool(_RE_HEX.search(original))
        orig_lower          = original.lower()
        is_sniffer_command  = "sniffer" in orig_lower or "diagnose network" in orig_lower
        is_pcap_file        = original[:4] in ("\xd4\xc3\xb2\xa1", "\xa1\xb2\xc3\xd4",
                                                "\x0a\x0d\x0d\x0a")

        if is_pcap_file:
            raise ConvertError(
                ConvertErrorCode.UNSUPPORTED_FMT,
                "Input looks like a binary .pcap file, not a sniffer text output.\n"
                "  Provide a raw text file from 'diagnose network sniffer' (verbosity ≥ 3).",
            )
        if has_hex_in_original and not is_sniffer_command:
            raise ConvertError(
                ConvertErrorCode.MALFORMED,
                "Hex dump data found but no valid packet timestamp lines detected.\n"
                "  Ensure verbosity ≥ 3 was used — timestamps must precede each hex block.\n"
                "  FortiGate: diagnose sniffer packet <iface> '<filter>' 3\n"
                "  FortiWeb:  diagnose network sniffer <iface> '<filter>' 3",
            )
        if is_sniffer_command:
            raise ConvertError(
                ConvertErrorCode.NO_PACKETS,
                "Sniffer command reference found but no packet data detected.\n"
                "  The file may be a copied command, not capture output.\n"
                "  Run the sniffer with verbosity ≥ 3 and capture live traffic.",
            )
        raise ConvertError(
            ConvertErrorCode.NO_PACKETS,
            "No Fortinet/FortiWeb sniffer packet lines detected.\n"
            "  Expected format: '<timestamp> <iface> in|out <flags>\\n0x0000 <hex>…'\n"
            "  Ensure this is a raw sniffer output file captured at verbosity ≥ 3.",
        )

    if not hex_lines:
        raise ConvertError(
            ConvertErrorCode.NO_PACKETS,
            f"Found {len(ts_lines)} timestamp line(s) but no hex dump data.\n"
            "  Hex body data is required for PCAP conversion.\n"
            "  Re-capture with verbosity ≥ 3 to include packet hex dumps.",
        )


# ── Public conversion API ─────────────────────────────────────────────────────

def offline_convert(
    input_file:  Path,
    output_file: Path,
    debug:       bool = False,
) -> "ConversionResult":
   
    from .fgt2eth import ConversionResult, convert_to_pcap

    input_file  = Path(input_file)
    output_file = Path(output_file)

    # ── Read ─────────────────────────────────────────────────────────────────
    try:
        content = input_file.read_text(encoding="utf-8", errors="replace")
    except PermissionError as exc:
        raise ConvertError(
            ConvertErrorCode.NOT_READABLE,
            f"Cannot read '{input_file.name}': {exc}\n"
            "  Check file permissions and try again.",
        )
    except OSError as exc:
        raise ConvertError(
            ConvertErrorCode.NOT_READABLE,
            f"I/O error reading '{input_file.name}': {exc}",
        )

    # ── Sanitize ─────────────────────────────────────────────────────────────
    sanitized = sanitize_sniffer_content(content)

    # ── Validate ─────────────────────────────────────────────────────────────
    validate_sniffer_content(content, sanitized)

    # ── Convert via temp file ─────────────────────────────────────────────────
    tmp_path: Optional[Path] = None
    try:
        fd, tmp_name = tempfile.mkstemp(suffix=".txt", prefix="diagsniff_convert_")
        tmp_path = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(sanitized)

        result = convert_to_pcap(tmp_path, output_file, debug=debug)

        # Re-attach the original input path so callers see the real source file
        return ConversionResult(
            success         = result.success,
            txt_path        = input_file,
            pcap_path       = result.pcap_path,
            packets_written = result.packets_written,
            error           = result.error,
        )

    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass
