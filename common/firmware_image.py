"""
The (simulated) firmware image format.

An image is a single binary blob:

    {"name": "SmartSensor", "version": "1.1.0", "build_date": "...", "behavior": "ok", "blink_ms": 500}\\n
    <random padding bytes ...>

* The first line is a JSON header describing the build.
* The rest is random padding so the image is ~64 KB, which makes the chunked
  download (4 KB at a time) realistic. Random bytes also mean every build has
  a different hash, like real compiled firmware.

"behavior" decides what the firmware does on its first boot after an update:
    "ok"            -> self-test passes
    "fail_selftest" -> self-test returns False   (e.g. a sensor driver bug)
    "crash"         -> raises an exception while booting (e.g. a null pointer)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from common.version import parse_version

IMAGE_SIZE = 64 * 1024           # 65536 bytes
BEHAVIORS = ("ok", "fail_selftest", "crash")
DEFAULT_PRODUCT = "SmartSensor"


class ImageError(ValueError):
    """Raised when bytes in a flash slot are not a valid firmware image."""


def default_blink_ms(version: str) -> int:
    """Pick an LED blink period from the version so versions look different in the demo."""
    _major, minor, patch = parse_version(version)
    return max(50, 1000 // (minor + 1) - 10 * patch)


def build_image(
    name: str,
    version: str,
    behavior: str = "ok",
    size: int = IMAGE_SIZE,
    blink_ms: int | None = None,
    build_date: str | None = None,
) -> bytes:
    """Create a firmware image (header line + random padding) of exactly `size` bytes."""
    parse_version(version)
    if behavior not in BEHAVIORS:
        raise ValueError(f"behavior must be one of {BEHAVIORS}, got {behavior!r}")
    header = {
        "name": name,
        "version": version,
        "build_date": build_date or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "behavior": behavior,
        "blink_ms": blink_ms if blink_ms is not None else default_blink_ms(version),
    }
    header_bytes = (json.dumps(header) + "\n").encode("utf-8")
    if len(header_bytes) > size:
        raise ValueError("image size too small for the header")
    padding = os.urandom(size - len(header_bytes))
    return header_bytes + padding


def parse_header(image: bytes) -> dict[str, Any]:
    """Read the JSON header line at the start of a firmware image.

    Raises ImageError if the image is empty or the header is unreadable.
    """
    if not image:
        raise ImageError("image is empty")
    newline = image.find(b"\n")
    if newline == -1:
        raise ImageError("image has no header line")
    try:
        header = json.loads(image[:newline].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImageError(f"bad image header: {exc}") from exc
    if not isinstance(header, dict) or "version" not in header or "name" not in header:
        raise ImageError("image header lacks name/version")
    return header
