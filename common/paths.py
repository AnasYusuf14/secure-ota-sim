"""
Default locations of every directory used by the simulation.

All paths are built with pathlib relative to the project root, so the project
works from any current directory and on Windows, Linux and macOS.
"""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

KEYS_DIR = PROJECT_ROOT / "keys"                 # offline signing machine (secret!)
RELEASES_DIR = PROJECT_ROOT / "releases"         # signed releases, published to the server
FIRMWARE_SRC_DIR = PROJECT_ROOT / "firmware_src"  # definitions of the sample builds
BUILD_DIR = PROJECT_ROOT / "build"               # unsigned images from build_firmware.py
DEVICE_FLASH_DIR = PROJECT_ROOT / "device_flash"  # the device's virtual flash chip
TRUSTED_KEY_PATH = PROJECT_ROOT / "device" / "trusted_key.pem"  # key "burned in" at the factory
RESULTS_DIR = PROJECT_ROOT / "results"

PRIVATE_KEY_NAME = "private_key.pem"
PUBLIC_KEY_NAME = "public_key.pem"
