"""
Sign a firmware image and produce a release folder (runs on the offline signing machine).

    # sign an image built earlier with build_firmware.py
    python tools/sign_release.py --image build/SmartSensor-1.1.0.bin

    # or build + sign in one step
    python tools/sign_release.py --version 1.1.0 --behavior ok

Result:
    releases/<version>/firmware.bin
    releases/<version>/manifest.json   (name, version, size, sha256, signature)

Only these two PUBLIC files go to the update server. The private key is read
here and never written anywhere else.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common import log  # noqa: E402
from common.crypto_utils import load_private_key  # noqa: E402
from common.firmware_image import BEHAVIORS, DEFAULT_PRODUCT, build_image, parse_header  # noqa: E402
from common.manifest import build_manifest, manifest_to_json  # noqa: E402
from common.paths import KEYS_DIR, PRIVATE_KEY_NAME, RELEASES_DIR  # noqa: E402


def sign_release(image: bytes, private_key, releases_dir: Path) -> Path:
    """Sign `image` and write firmware.bin + manifest.json into releases_dir/<version>/.

    The product name and version are read from the image's own header, so the
    manifest always describes the firmware it ships with.
    Returns the release directory.
    """
    header = parse_header(image)
    manifest = build_manifest(header["name"], header["version"], image, private_key)

    release_dir = Path(releases_dir) / header["version"]
    release_dir.mkdir(parents=True, exist_ok=True)
    (release_dir / "firmware.bin").write_bytes(image)
    (release_dir / "manifest.json").write_text(manifest_to_json(manifest), encoding="utf-8")
    log.ok("TOOLS", f"Signed release {header['name']} v{header['version']} -> {release_dir}")
    return release_dir


def make_release(
    version: str,
    behavior: str,
    private_key_path: Path,
    releases_dir: Path,
    name: str = DEFAULT_PRODUCT,
    blink_ms: int | None = None,
) -> Path:
    """Build a fresh image for `version`/`behavior` and sign it. Returns the release dir."""
    image = build_image(name, version, behavior, blink_ms=blink_ms)
    return sign_release(image, load_private_key(private_key_path), releases_dir)


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Sign a firmware image into a release.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--image", type=Path, help="existing image built with build_firmware.py")
    source.add_argument("--version", help="build a new image with this version, then sign it")
    parser.add_argument("--behavior", default="ok", choices=BEHAVIORS, help="(with --version) boot behavior")
    parser.add_argument("--name", default=DEFAULT_PRODUCT, help="(with --version) product name")
    parser.add_argument("--key", type=Path, default=KEYS_DIR / PRIVATE_KEY_NAME, help="private key PEM")
    parser.add_argument("--releases", type=Path, default=RELEASES_DIR, help="releases directory")
    args = parser.parse_args(argv)

    if not args.key.exists():
        log.fail("TOOLS", f"private key {args.key} not found - run: python tools/keygen.py")
        return 1
    if args.image:
        sign_release(args.image.read_bytes(), load_private_key(args.key), args.releases)
    else:
        make_release(args.version, args.behavior, args.key, args.releases, name=args.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
