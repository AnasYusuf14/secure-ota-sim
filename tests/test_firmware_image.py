"""Unit tests for common/firmware_image.py."""

import pytest

from common.firmware_image import IMAGE_SIZE, ImageError, build_image, parse_header


def test_image_size_and_header():
    """Image is exactly 64 KB and its header can be read back."""
    image = build_image("SmartSensor", "1.1.0", "ok", blink_ms=500)
    assert len(image) == IMAGE_SIZE
    header = parse_header(image)
    assert header["version"] == "1.1.0"
    assert header["behavior"] == "ok"
    assert header["blink_ms"] == 500


def test_images_differ():
    """Random padding makes each build unique (different hash)."""
    assert build_image("S", "1.0.0") != build_image("S", "1.0.0")


def test_invalid_behavior():
    """Unknown behaviors are refused."""
    with pytest.raises(ValueError):
        build_image("S", "1.0.0", "explode")


@pytest.mark.parametrize("bad", [b"", b"no newline here", b"{not json}\n..."])
def test_parse_header_errors(bad):
    """Garbage in a slot is detected."""
    with pytest.raises(ImageError):
        parse_header(bad)
