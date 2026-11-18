"""
Generate the vendor's signing key pair (runs on the offline signing machine).

    python tools/keygen.py            # writes keys/private_key.pem + keys/public_key.pem
    python tools/keygen.py --force    # overwrite existing keys

* private_key.pem stays on the signing machine. It is NEVER copied to the
  update server or the device. (keys/ is listed in .gitignore.)
* public_key.pem is copied into the device at "factory" time
  (see `python device/device.py factory-reset`).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from common import log  # noqa: E402
from common.crypto_utils import generate_private_key, save_private_key, save_public_key  # noqa: E402
from common.paths import KEYS_DIR, PRIVATE_KEY_NAME, PUBLIC_KEY_NAME  # noqa: E402


def generate_keys(keys_dir: Path, force: bool = False) -> tuple[Path, Path]:
    """Create a new P-256 key pair in `keys_dir`.

    Returns (private_key_path, public_key_path).
    Raises FileExistsError if keys already exist and `force` is False, so a
    working key is never destroyed by accident (devices in the field trust it!).
    """
    keys_dir = Path(keys_dir)
    private_path = keys_dir / PRIVATE_KEY_NAME
    public_path = keys_dir / PUBLIC_KEY_NAME
    if private_path.exists() and not force:
        raise FileExistsError(f"{private_path} already exists (use --force to overwrite)")

    private_key = generate_private_key()
    save_private_key(private_key, private_path)
    save_public_key(private_key.public_key(), public_path)
    log.ok("TOOLS", f"Generated ECDSA P-256 key pair in {keys_dir}")
    return private_path, public_path


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Generate the firmware signing key pair.")
    parser.add_argument("--out", type=Path, default=KEYS_DIR, help="output directory (default: keys/)")
    parser.add_argument("--force", action="store_true", help="overwrite existing keys")
    args = parser.parse_args(argv)
    try:
        private_path, public_path = generate_keys(args.out, args.force)
    except FileExistsError as exc:
        log.warn("TOOLS", str(exc))
        return 1
    log.log("TOOLS", f"  private key: {private_path}   (keep secret, never upload)")
    log.log("TOOLS", f"  public key : {public_path}   (embedded in the device at factory reset)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
