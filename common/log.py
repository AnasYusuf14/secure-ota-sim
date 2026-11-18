"""
Colored, timestamped logging for the OTA simulation (no external dependencies).

Every log line looks like this:

    [12:01:03] [OTA] Signature verified ✔
    [12:01:03] [OTA] REJECTED: signature invalid ✘

The text inside the second pair of brackets is a *tag* that tells you which part
of the system is talking (OTA client, BOOTloader, SERVER, ATTACKer, ...).

Colors use plain ANSI escape codes. On Windows 10+ we switch the console into
"virtual terminal" mode so the codes are understood. Colors are turned off
automatically when output is redirected to a file or when NO_COLOR is set.

Log lines can additionally be copied (without colors) into one or more files
by calling add_file_sink(); the demo uses this to write results/demo_log.txt.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import TextIO

RESET = "\033[0m"

_COLOR_CODES = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "gray": "\033[90m",
    "bold": "\033[1m",
}

# Which color each component's tag is printed in.
TAG_COLORS = {
    "OTA": "cyan",
    "BOOT": "magenta",
    "APP": "green",
    "SERVER": "blue",
    "ATTACK": "red",
    "FLASH": "gray",
    "DEVICE": "cyan",
    "DEMO": "yellow",
    "TOOLS": "blue",
}

# Levels change the color of the message and append a symbol.
LEVEL_COLORS = {"info": None, "ok": "green", "fail": "red", "warn": "yellow"}
LEVEL_SYMBOLS = {"info": "", "ok": " ✔", "fail": " ✘", "warn": " ⚠"}

_lock = threading.Lock()          # the server thread and the device both log
_file_sinks: list[TextIO] = []    # extra files that receive every log line


def _enable_windows_ansi() -> bool:
    """Turn on ANSI escape-code processing in the Windows console.

    Returns True if it worked (so colors can be used), False otherwise.
    """
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # -11 = STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    except Exception:
        return False


def _prepare_console() -> bool:
    """Make the console able to print UTF-8 symbols and decide whether to use colors."""
    # Make sure symbols like ✔ and ✘ do not crash on consoles using a legacy code page.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass

    if os.environ.get("NO_COLOR"):
        return False
    if not (hasattr(sys.stdout, "isatty") and sys.stdout.isatty()):
        return False
    if os.name == "nt":
        return _enable_windows_ansi()
    return True


_use_color = _prepare_console()


def _paint(text: str, color: str | None) -> str:
    """Wrap `text` in ANSI color codes (only if colors are enabled)."""
    if not _use_color or color is None:
        return text
    return f"{_COLOR_CODES[color]}{text}{RESET}"


def log(tag: str, message: str, level: str = "info") -> None:
    """Print one timestamped log line.

    Args:
        tag:     component name, e.g. "OTA", "BOOT", "SERVER".
        message: the text to print.
        level:   "info", "ok" (adds ✔), "fail" (adds ✘) or "warn" (adds ⚠).
    """
    timestamp = time.strftime("%H:%M:%S")
    symbol = LEVEL_SYMBOLS.get(level, "")
    plain = f"[{timestamp}] [{tag}] {message}{symbol}"
    colored = (
        _paint(f"[{timestamp}]", "gray")
        + " "
        + _paint(f"[{tag}]", TAG_COLORS.get(tag))
        + " "
        + _paint(f"{message}{symbol}", LEVEL_COLORS.get(level))
    )
    with _lock:
        print(colored, flush=True)
        for sink in _file_sinks:
            sink.write(plain + "\n")
            sink.flush()


def ok(tag: str, message: str) -> None:
    """Log a success line (green, with ✔)."""
    log(tag, message, "ok")


def fail(tag: str, message: str) -> None:
    """Log a failure / rejection line (red, with ✘)."""
    log(tag, message, "fail")


def warn(tag: str, message: str) -> None:
    """Log a warning line (yellow, with ⚠)."""
    log(tag, message, "warn")


def banner(title: str) -> None:
    """Print a big separator line, used between demo scenarios."""
    line = "=" * 78
    with _lock:
        print(_paint(line, "bold"), flush=True)
        print(_paint(f"  {title}", "bold"), flush=True)
        print(_paint(line, "bold"), flush=True)
        for sink in _file_sinks:
            sink.write(f"{line}\n  {title}\n{line}\n")
            sink.flush()


def raw(text: str) -> None:
    """Print text exactly as given (also copied to file sinks). Used for tables."""
    with _lock:
        print(text, flush=True)
        for sink in _file_sinks:
            sink.write(text + "\n")
            sink.flush()


def add_file_sink(path: Path, mode: str = "w") -> TextIO:
    """Copy every following log line (without colors) into the file at `path`.

    Returns the open file so it can later be passed to remove_file_sink().
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    sink = open(path, mode, encoding="utf-8")
    with _lock:
        _file_sinks.append(sink)
    return sink


def remove_file_sink(sink: TextIO) -> None:
    """Stop copying log lines into `sink` and close it."""
    with _lock:
        if sink in _file_sinks:
            _file_sinks.remove(sink)
    sink.close()
