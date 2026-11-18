"""
Semantic version helpers ("MAJOR.MINOR.PATCH", e.g. "1.2.0").

Versions are compared as tuples of integers, NOT as strings. Comparing strings
would be a security bug: as text, "1.10.0" < "1.9.0", which would let an old
firmware look newer than a new one.
"""

from __future__ import annotations

import re

_VERSION_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def parse_version(text: str) -> tuple[int, int, int]:
    """Turn "1.2.0" into the tuple (1, 2, 0).

    Raises ValueError for anything that is not exactly three dot-separated
    non-negative integers (no "v" prefix, no leading zeros, no suffixes).
    """
    if not isinstance(text, str):
        raise ValueError(f"version must be a string, got {type(text).__name__}")
    match = _VERSION_RE.match(text)
    if not match:
        raise ValueError(f"invalid version {text!r} (expected MAJOR.MINOR.PATCH)")
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def compare_versions(a: str, b: str) -> int:
    """Compare two version strings.

    Returns -1 if a < b, 0 if a == b, +1 if a > b.
    """
    va, vb = parse_version(a), parse_version(b)
    return (va > vb) - (va < vb)


def is_newer(candidate: str, current: str) -> bool:
    """Return True if `candidate` is strictly newer than `current`."""
    return compare_versions(candidate, current) > 0


def is_at_least(candidate: str, minimum: str) -> bool:
    """Return True if `candidate` >= `minimum`."""
    return compare_versions(candidate, minimum) >= 0
