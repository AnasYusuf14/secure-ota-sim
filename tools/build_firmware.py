"""
"Compile" a firmware image for a given version and behavior.

    python tools/build_firmware.py --version 1.1.0
    python tools/build_firmware.py --version 1.2.0 --behavior fail_selftest
    python tools/build_firmware.py --version 1.2.1 --behavior crash --out build/bad.bin

The output is an UNSIGNED image. Use tools/sign_release.py to sign it and
turn it into a release the server can publish.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common import log  # noqa: E402
from common.firmware_image import BEHAVIORS, DEFAULT_PRODUCT, IMAGE_SIZE, build_image  # noqa: E402
from common.paths import BUILD_DIR  # noqa: E402


def build_firmware_file(
    version: str,
    behavior: str = "ok",
    out_path: Path | None = None,
    name: str = DEFAULT_PRODUCT,
    size: int = IMAGE_SIZE,
    blink_ms: int | None = None,
) -> Path:
    """Build an image and write it to disk. Returns the path of the written file."""
    image = build_image(name, version, behavior, size=size, blink_ms=blink_ms)
    out_path = Path(out_path) if out_path else BUILD_DIR / f"{name}-{version}.bin"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(image)
    log.ok("TOOLS", f"Built {name} v{version} (behavior={behavior}, {len(image)} bytes) -> {out_path}")
    return out_path


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Build a simulated firmware image.")
    parser.add_argument("--version", required=True, help='firmware version, e.g. "1.1.0"')
    parser.add_argument("--behavior", default="ok", choices=BEHAVIORS, help="what happens on first boot")
    parser.add_argument("--name", default=DEFAULT_PRODUCT, help="product name")
    parser.add_argument("--size", type=int, default=IMAGE_SIZE, help="image size in bytes")
    parser.add_argument("--blink-ms", type=int, default=None, help="LED blink period shown when running")
    parser.add_argument("--out", type=Path, default=None, help="output file (default: build/<name>-<version>.bin)")
    args = parser.parse_args(argv)
    build_firmware_file(args.version, args.behavior, args.out, args.name, args.size, args.blink_ms)
    return 0


if __name__ == "__main__":
    sys.exit(main())
