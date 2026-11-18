"""Unit tests for common/version.py."""

import pytest

from common.version import compare_versions, is_at_least, is_newer, parse_version


def test_parse_valid():
    """Well-formed versions parse into integer tuples."""
    assert parse_version("1.2.0") == (1, 2, 0)
    assert parse_version("0.0.0") == (0, 0, 0)
    assert parse_version("10.20.30") == (10, 20, 30)


@pytest.mark.parametrize("bad", ["1.2", "1.2.3.4", "v1.2.3", "1.2.x", "", "01.2.3", "1.2.3-beta", " 1.2.3"])
def test_parse_invalid(bad):
    """Anything that is not exactly MAJOR.MINOR.PATCH is rejected."""
    with pytest.raises(ValueError):
        parse_version(bad)


def test_parse_non_string():
    """Non-string input (e.g. a number from forged JSON) is rejected."""
    with pytest.raises(ValueError):
        parse_version(1.2)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("1.0.0", "1.0.0", 0),
        ("1.1.0", "1.0.0", 1),
        ("1.0.0", "1.1.0", -1),
        ("2.0.0", "1.99.99", 1),
        ("1.0.10", "1.0.9", 1),
        ("1.10.0", "1.9.0", 1),   # would be wrong with string comparison!
    ],
)
def test_compare(a, b, expected):
    """Comparison is numeric per component."""
    assert compare_versions(a, b) == expected


def test_is_newer_and_at_least():
    """Helpers built on compare_versions."""
    assert is_newer("1.1.0", "1.0.0")
    assert not is_newer("1.0.0", "1.0.0")
    assert is_at_least("1.0.0", "1.0.0")
    assert not is_at_least("0.9.0", "1.0.0")
