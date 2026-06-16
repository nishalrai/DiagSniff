from __future__ import annotations

import io
from pathlib import Path
from typing import Iterator

from rich.console import Console
from rich.text import Text

console = Console()


class OutputWriter:

    def __init__(self, output_path: Path) -> None:
        self.path = output_path
        # Open in text mode; 'a' so accidental double-open appends rather than truncates
        self._fh: io.TextIOWrapper = output_path.open("a", encoding="utf-8")
        self._line_count = 0

    def write_line(self, line: str) -> None:
        # Colour FortiOS sniffer output: packets lines in default, headers dim
        styled = _colour_line(line)
        console.print(styled, highlight=False)
        self._fh.write(line + "\n")
        self._fh.flush()
        self._line_count += 1

    def write_line_silent(self, line: str) -> None:
        self._fh.write(line + "\n")
        self._fh.flush()
        self._line_count += 1

    def write_header(self, header: str) -> None:
        self._fh.write(header + "\n")
        self._fh.flush()

    @property
    def line_count(self) -> int:
        return self._line_count

    def close(self) -> None:
        self._fh.flush()
        self._fh.close()

    def __enter__(self) -> "OutputWriter":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _colour_line(line: str) -> Text:
    t = Text(line)
    ls = line.strip()
    if ls.startswith("interfaces=") or ls.startswith("filters="):
        t.stylize("dim cyan")
    elif " -> " in ls or " ARP " in ls:
        t.stylize("green")
    elif "ICMP" in ls:
        t.stylize("yellow")
    elif "TCP" in ls and ("SYN" in ls or "FIN" in ls or "RST" in ls):
        t.stylize("magenta")
    elif ls.startswith("##") or ls.startswith("--"):
        t.stylize("dim")
    return t


def stream_to_output(
    lines:  Iterator[str],
    writer: OutputWriter,
) -> int:
    for line in lines:
        writer.write_line(line)
    return writer.line_count
