#!/usr/bin/env python3


import sys
import re
import os
import argparse
import subprocess
import time
import shutil
import platform
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Callable, Optional
import io

DEFAULT_YEAR = datetime.now().year


# ── Public conversion result ──────────────────────────────────────────────────

@dataclass
class ConversionResult:
    success:         bool
    txt_path:        Path
    pcap_path:       Optional[Path]
    packets_written: int
    error:           Optional[str] = None

@lru_cache(maxsize=1)
def get_platform_paths():
    text2pcap_cmd = "text2pcap"
    wireshark_cmd = "wireshark"

    system = platform.system()
    
    # Common paths to search
    search_paths = []
    
    if system == "Darwin": # macOS
        search_paths = [
            "/Applications/Wireshark.app/Contents/MacOS",
            "/usr/local/bin",
            "/opt/homebrew/bin"
        ]
    elif system == "Windows":
        search_paths = [
            r"C:\Program Files\Wireshark",
            r"C:\Program Files (x86)\Wireshark"
        ]

    # Helper to find executable
    def find_exe(cmd):
        # Check PATH first
        if shutil.which(cmd):
            return cmd
            
        # Check specific paths
        for path in search_paths:
            full_path = os.path.join(path, cmd)
            if system == "Windows" and not full_path.lower().endswith(".exe"):
                full_path += ".exe"
            
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                return full_path
        return None

    t2p = find_exe("text2pcap")
    ws = find_exe("wireshark")

    return t2p, ws

class PacketProcessor:
    def __init__(self, infile, outfile, lines_limit=None, demux=False, debug=False, pipe_mode=False):
        self.infile = infile
        self.outfile = outfile
        self.lines_limit = lines_limit
        self.demux = demux
        self.debug = debug
        self.pipe_mode = pipe_mode
        
        self.packet_array = []
        self.eth0_count = 0
        self.skip_packet = False
        self.line_count = 0
        self.file_handlers = {} # For demux map: interface -> (filename, file_handle)
        self.temp_files = []

        # Capture start time parsed from DiagSniff header (for relative timestamps)
        self.capture_start_time: Optional[datetime] = None

        # Regex patterns
        self.re_hex = re.compile(r'^(0x[0-9a-f]+[ \t\xa0]+)', re.IGNORECASE)
        self.re_timestamp_rel = re.compile(r'^([0-9]+)\.([0-9]+)\s')
        self.re_timestamp_abs = re.compile(r'^(\d+-\d+-\d+ \d+:\d+:\d+\.\d+)\s')
        self.re_interface = re.compile(r' (\S+) (?:out|in) ')
        self.re_truncated = re.compile(r'truncated-ip - [0-9]+ bytes missing!')
        # DiagSniff header: # Started     : 2026-04-19T17:19:02.276888
        self.re_started_header = re.compile(r'^#\s*Started\s*:\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)')

    def log(self, msg):
        if self.debug:
            sys.stderr.write(f"[DEBUG] {msg}\n")

    def get_output_handler(self, current_line):
        """Determines where to write the processed hex dump."""
        if not self.demux:
            # If piping to stdout (wireshark), use stdout
            if self.outfile == '-':
                return sys.stdout
            
            # Otherwise use the main temporary file
            if 'main' not in self.file_handlers:
                # If outfile is specified as 'capture.pcap', we write temp to 'capture.pcap.tmp'
                # If outfile is None (input file based), we use 'inputfile.pcap.tmp'
                base_name = self.infile if self.infile else "capture"
                if self.outfile and self.outfile != '-':
                    base_name = self.outfile
                
                # Strip extension if needed
                if base_name.lower().endswith('.pcap'):
                    base_name = base_name[:-5]
                elif base_name.lower().endswith('.zip'):
                    base_name = base_name[:-4]
                
                tmp_name = f"{base_name}.tmp"
                self.temp_files.append((tmp_name, f"{base_name}.pcap"))
                # 256 KB write buffer reduces syscall overhead for large captures
                self.file_handlers['main'] = open(tmp_name, 'w', buffering=262_144)
            return self.file_handlers['main']

        # Demux logic
        match = self.re_interface.search(current_line)
        intf = match.group(1) if match else "[noIntf]"
        
        if intf not in self.file_handlers:
            base_name = self.infile if self.infile else "capture"
            if self.outfile and self.outfile != '-':
                base_name = self.outfile
            
            clean_intf = intf.replace('/', '-')
            tmp_name = f"{base_name}.{clean_intf}.tmp"
            final_name = f"{base_name}.{clean_intf}.pcap"
            
            self.temp_files.append((tmp_name, final_name))
            self.file_handlers[intf] = open(tmp_name, 'w')
            
        return self.file_handlers[intf]

    def convert_timestamp(self, line, fh):
        if self.re_truncated.search(line):
            return True  # Skip truncated packets

        # Relative timestamp: 123.456789 (seconds.microseconds since capture start)
        match_rel = self.re_timestamp_rel.match(line)
        if match_rel:
            secs = int(match_rel.group(1))
            usecs = match_rel.group(2)
            
            # If we have the actual capture start time, compute real timestamp
            if self.capture_start_time is not None:
                # Parse microseconds properly (may have varying precision)
                usecs_padded = usecs.ljust(6, '0')[:6]  # Ensure 6 digits
                offset_seconds = secs + int(usecs_padded) / 1_000_000
                actual_time = self.capture_start_time + timedelta(seconds=offset_seconds)
                # Format: DD/MM/YYYY HH:MM:SS.usec
                formatted = actual_time.strftime("%d/%m/%Y %H:%M:%S")
                fh.write(f"{formatted}.{usecs_padded}\n")
            else:
                # Legacy fallback: convert relative seconds to pseudo-date
                # This produces timestamps like 01/01/YEAR which are not accurate
                # but allow the pcap to be processed
                days = secs // 86400
                secs %= 86400
                hours = secs // 3600
                secs %= 3600
                mins = secs // 60
                secs %= 60
                usecs_padded = usecs.ljust(6, '0')[:6]
                formatted_date = f"01/{days+1:02d}/{DEFAULT_YEAR} {hours:02d}:{mins:02d}:{secs:02d}.{usecs_padded}"
                fh.write(f"{formatted_date}\n")
            return False

        # Absolute timestamp: 2025-01-24 11:37:36.123456
        match_abs = self.re_timestamp_abs.match(line)
        if match_abs:
            ts_str = match_abs.group(1)
            try:
                # FGT format: YYYY-MM-DD HH:MM:SS.usec
                parts = ts_str.split(' ')
                date_parts = parts[0].split('-')  # [YYYY, MM, DD]
                time_part = parts[1]
                # Ensure microseconds have 6 digits
                if '.' in time_part:
                    time_base, usec = time_part.split('.', 1)
                    usec = usec.ljust(6, '0')[:6]
                    time_part = f"{time_base}.{usec}"
                else:
                    time_part = f"{time_part}.000000"
                # Output: DD/MM/YYYY HH:MM:SS.usec
                new_date = f"{date_parts[2]}/{date_parts[1]}/{date_parts[0]}"
                fh.write(f"{new_date} {time_part}\n")
            except Exception:
                fh.write(f"{ts_str}\n")
            return False
            
        return False

    def build_packet_array(self, line, file_obj):
        self.packet_array = []
        _re_hex_token = re.compile(r'^[0-9a-fA-F]{2,4}$')

        while line:
            # Clean the line
            line = line.strip()
            if not line:
                break

            # Check if it looks like hex data "0x0000"
            if not line.startswith("0x"):
                break

            # Split: parts[0] = "0x0000", parts[1] = rest
            parts = line.split(maxsplit=1)
            if len(parts) > 1:
                # Walk tokens; stop at the first non-hex token (ASCII column)
                hex_bytes: list[str] = []
                for token in parts[1].split():
                    if _re_hex_token.match(token):
                        t = token.lower()
                        if len(t) == 2:
                            hex_bytes.append(t)
                        else:                      # 4-char group → 2 bytes
                            hex_bytes.append(t[:2])
                            hex_bytes.append(t[2:])
                    else:
                        # First non-hex token signals the ASCII column; stop
                        break
                # Clamp to 16 bytes (one text2pcap row)
                self.packet_array.extend(hex_bytes[:16])

            pos = file_obj.tell()
            line = file_obj.readline()
            if not line:
                break
            # If next line is a timestamp, we went too far
            if self.re_timestamp_rel.match(line) or self.re_timestamp_abs.match(line):
                file_obj.seek(pos)
                break
                
    def strip_bytes(self, start, count):
        """Removes 'count' bytes starting at index 'start'."""
        if start < len(self.packet_array):
            del self.packet_array[start:start+count]

    def adjust_packet(self):
        """Port of the Perl adjustPacket logic."""
        def get_bytes(start, length):
            if start + length <= len(self.packet_array):
                return "".join(self.packet_array[start:start+length])
            return ""

        # Logic 1: Remove bytes if bytes 14-15 are 0800 or 8893
        chk = get_bytes(14, 2)
        if chk == "0800" or chk == "8893":
            self.strip_bytes(12, 2)

        # Logic 2: Add Ethernet Header if raw IP (starts with 4500/4510)
        chk = get_bytes(0, 2)
        if chk.startswith("4500") or chk.startswith("4510"):
            prefix = ["00"] * 12 + ["08", "00"]
            self.packet_array = prefix + self.packet_array

        # Logic 3: Fix specific internal FGT types
        chk = get_bytes(12, 2)
        if chk == "8890" or chk == "8891":
            self.packet_array[12] = "08"
            self.packet_array[13] = "00"

    def write_packet(self, fh):
        """Writes the packet array to the file handle in text2pcap format."""
        offset = 0
        for i, byte in enumerate(self.packet_array):
            if i % 16 == 0:
                fh.write(f"{offset:06x} ")
            fh.write(f" {byte}")
            offset += 1
            if (i + 1) % 16 == 0:
                fh.write("\n")
        
        if len(self.packet_array) % 16 != 0:
            fh.write("\n")
            
        self.line_count += 1

    def _parse_diagsniff_header(self, f) -> None:
        header_lines = []
        pos = f.tell()
        
        # Read up to 20 lines looking for header
        for _ in range(20):
            line = f.readline()
            if not line:
                break
            header_lines.append(line)
            
            # Check for DiagSniff "Started" header
            match = self.re_started_header.match(line)
            if match:
                ts_str = match.group(1)
                try:
                    # Parse ISO format: 2026-04-19T17:19:02.276888
                    if '.' in ts_str:
                        self.capture_start_time = datetime.strptime(
                            ts_str, "%Y-%m-%dT%H:%M:%S.%f"
                        )
                    else:
                        self.capture_start_time = datetime.strptime(
                            ts_str, "%Y-%m-%dT%H:%M:%S"
                        )
                    self.log(f"Parsed capture start time: {self.capture_start_time}")
                except ValueError as e:
                    self.log(f"Failed to parse start time '{ts_str}': {e}")
            
            # Stop scanning once we hit actual packet data
            if self.re_timestamp_rel.match(line) or self.re_timestamp_abs.match(line):
                break
            if line.startswith("0x"):
                break
        
        # Rewind to beginning for actual processing
        f.seek(pos)

    def run(self):
        if self.infile:
            # 1 MB read buffer reduces I/O overhead for large capture files
            f = open(self.infile, 'r', errors='replace', buffering=1_048_576)
        else:
            f = sys.stdin

        try:
            # Parse DiagSniff header for capture start time
            if self.infile:
                self._parse_diagsniff_header(f)
            
            current_fh = None
            
            while True:
                line = f.readline()
                if not line:
                    break

                if self.re_timestamp_rel.match(line) or self.re_timestamp_abs.match(line):
                    self.skip_packet = False
                    
                    # Demux check
                    if not self.demux and 'eth0' in line:
                        self.eth0_count += 1
                        self.skip_packet = True
                    
                    # Get file handler for this packet
                    current_fh = self.get_output_handler(line)
                    
                    # Process timestamp
                    should_skip = self.convert_timestamp(line, current_fh)
                    if should_skip:
                        self.skip_packet = True
                        
                elif self.re_hex.match(line) and not self.skip_packet:
                    # Found packet data
                    self.build_packet_array(line, f)
                    self.adjust_packet()
                    if current_fh:
                        self.write_packet(current_fh)
                        current_fh.flush() 
                    
                    if self.lines_limit and self.line_count >= self.lines_limit:
                        print("Reached max lines.")
                        break
        finally:
            if self.infile:
                f.close()
            # Close all temp output files
            for fh in self.file_handlers.values():
                if fh != sys.stdout:
                    fh.close()

        if self.eth0_count > 0:
            sys.stderr.write(f"** Skipped {self.eth0_count} packets captured on eth0\n")

        return self.temp_files

# ── Public Python API ─────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def check_text2pcap() -> Optional[str]:
    """Return the path to the text2pcap binary, or None if not found (cached)."""
    t2p, _ = get_platform_paths()
    return t2p


def convert_to_pcap(
    txt_path: Path,
    pcap_path: Path,
    debug: bool = False,
    on_stage: Optional[Callable[[str, int], None]] = None,
) -> ConversionResult:

    txt_path  = Path(txt_path)
    pcap_path = Path(pcap_path)

    def _notify(name: str, idx: int) -> None:
        if on_stage is not None:
            on_stage(name, idx)

    # ── Stage 0: prerequisites ────────────────────────────────────────────────
    _notify("Checking prerequisites", 0)

    t2p_bin = check_text2pcap()
    if not t2p_bin:
        return ConversionResult(
            success=False, txt_path=txt_path, pcap_path=None,
            packets_written=0,
            error="text2pcap not found — install Wireshark (or tshark) and add it to PATH",
        )

    if not txt_path.exists():
        return ConversionResult(
            success=False, txt_path=txt_path, pcap_path=None,
            packets_written=0,
            error=f"Input file not found: {txt_path}",
        )

    if txt_path.stat().st_size == 0:
        return ConversionResult(
            success=False, txt_path=txt_path, pcap_path=pcap_path,
            packets_written=0,
            error="Input file is empty — no packets were captured",
        )

    # ── Stage 1: parse raw sniffer output ────────────────────────────────────
    _notify("Parsing raw sniffer output", 1)

    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    processor = PacketProcessor(
        infile=str(txt_path),
        outfile=str(pcap_path),
        debug=debug,
    )

    try:
        temp_files = processor.run()
    except Exception as exc:
        return ConversionResult(
            success=False, txt_path=txt_path, pcap_path=pcap_path,
            packets_written=0,
            error=f"Parsing failed: {exc}",
        )

    if not temp_files:
        return ConversionResult(
            success=False, txt_path=txt_path, pcap_path=pcap_path,
            packets_written=processor.line_count,
            error="No packets were parsed from the capture file",
        )

    if processor.line_count == 0:
        # Clean up any empty temp files
        for tmp_f, _ in temp_files:
            if os.path.exists(tmp_f):
                os.remove(tmp_f)
        return ConversionResult(
            success=False, txt_path=txt_path, pcap_path=pcap_path,
            packets_written=0,
            error="No parsable packets found — check verbosity level (needs ≥ 3 for hex output)",
        )

    # ── Stage 2: run text2pcap ────────────────────────────────────────────────
    _notify("Running text2pcap", 2)

    final_pcap: Optional[Path] = None
    for tmp_f, final_f in temp_files:
        cmd = [t2p_bin, "-q", "-t", "%d/%m/%Y %H:%M:%S.", tmp_f, final_f]
        if debug:
            sys.stderr.write(f"[DEBUG] Running: {' '.join(cmd)}\n")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return ConversionResult(
                success=False, txt_path=txt_path, pcap_path=Path(final_f),
                packets_written=processor.line_count,
                error="text2pcap timed out after 60 seconds",
            )
        finally:
            if os.path.exists(tmp_f):
                try:
                    os.remove(tmp_f)
                except OSError:
                    pass

        if proc.returncode != 0:
            err_msg = proc.stderr.decode(errors="replace").strip()
            return ConversionResult(
                success=False, txt_path=txt_path, pcap_path=Path(final_f),
                packets_written=processor.line_count,
                error=f"text2pcap exited {proc.returncode}: {err_msg}",
            )

        final_pcap = Path(final_f)

    # ── Stage 3: validate output ──────────────────────────────────────────────
    _notify("Validating output", 3)

    if final_pcap is None or not final_pcap.exists():
        return ConversionResult(
            success=False, txt_path=txt_path, pcap_path=final_pcap,
            packets_written=processor.line_count,
            error="text2pcap produced no output file",
        )

    if final_pcap.stat().st_size < 24:  # pcap global header is 24 bytes
        return ConversionResult(
            success=False, txt_path=txt_path, pcap_path=final_pcap,
            packets_written=processor.line_count,
            error=f"Output file too small ({final_pcap.stat().st_size} bytes) — likely empty capture",
        )

    return ConversionResult(
        success=True,
        txt_path=txt_path,
        pcap_path=final_pcap,
        packets_written=processor.line_count,
    )


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Convert FortiGate sniffer output to PCAP")
    parser.add_argument("-in", dest="infile", required=False, help="Input file (FGT verbose 3 text)")
    parser.add_argument("-out", dest="outfile", help="Output file (.pcap) or '-' for Wireshark pipe")
    parser.add_argument("-lines", type=int, dest="lines_limit", help="Stop after N lines")
    parser.add_argument("-demux", action="store_true", help="Create one pcap per interface")
    parser.add_argument("-debug", action="store_true", help="Enable debug output")
    
    args = parser.parse_args()

    if not args.infile:
        # Check if piping into stdin
        if not sys.stdin.isatty():
            args.infile = None # Use stdin
        else:
            parser.print_help()
            sys.exit(1)

    t2p_bin, ws_bin = get_platform_paths()
    if not t2p_bin:
        sys.stderr.write("Error: 'text2pcap' not found. Install Wireshark.\n")
        sys.exit(1)

    # If piping to wireshark
    pipe_mode = (args.outfile == '-')

    if pipe_mode and not ws_bin:
        sys.stderr.write("Error: 'wireshark' not found. Cannot pipe output.\n")
        sys.exit(1)

    processor = PacketProcessor(args.infile, args.outfile, args.lines_limit, args.demux, args.debug, pipe_mode)

    if pipe_mode:
        t2p_cmd = [t2p_bin, "-q", "-t", "%d/%m/%Y %H:%M:%S.", "-", "-"]
        ws_cmd = [ws_bin, "-k", "-i", "-"]

        if args.debug:
            print(f"Executing: {' '.join(t2p_cmd)} | {' '.join(ws_cmd)}")

        try:
            p_ws = subprocess.Popen(ws_cmd, stdin=subprocess.PIPE)
            p_t2p = subprocess.Popen(t2p_cmd, stdin=subprocess.PIPE, stdout=p_ws.stdin)
            
            if args.demux:
                sys.stderr.write("Warning: demux ignored in pipe mode.\n")
            
            # We force the processor to write to the pipe
            processor.demux = False 
            
            # Python 3 Popen stdin expects bytes. TextIOWrapper can wrap it.
            text_wrapper = io.TextIOWrapper(p_t2p.stdin, encoding='utf-8', line_buffering=True)
            processor.file_handlers['main'] = text_wrapper
            
            processor.run()
            
            text_wrapper.close()
            p_t2p.wait()
            p_ws.wait()

        except KeyboardInterrupt:
            pass
        except BrokenPipeError:
            pass
    else:
        # File based mode
        temp_files = processor.run()
        
        # Convert all temp files to pcap
        for tmp_file, final_file in temp_files:
            if args.debug:
                print(f"Converting {tmp_file} to {final_file}...")
            
            cmd = [t2p_bin, "-q", "-t", "%d/%m/%Y %H:%M:%S.", tmp_file, final_file]
            subprocess.call(cmd)
            
            if os.path.exists(tmp_file):
                os.remove(tmp_file)
            
            if args.debug:
                print(f"Created {final_file}")

if __name__ == "__main__":
    main()