"""Shannon entropy analysis for detecting high-randomness strings."""

import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string. Range: 0.0 (uniform) to log2(n) (random)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


# Character sets used for high-entropy string detection
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS    = "0123456789abcdefABCDEF"


def _find_high_entropy_strings(line: str, charset: str, threshold: float, min_length: int = 20) -> list[str]:
    """Extract substrings from a line that exceed the entropy threshold."""
    words = line.split()
    findings = []
    for word in words:
        # Strip common surrounding characters
        word = word.strip("'\",;:()[]{}\\")
        if len(word) < min_length:
            continue
        # Only look at words composed mostly of the charset
        filtered = "".join(c for c in word if c in charset)
        if len(filtered) < min_length:
            continue
        ent = shannon_entropy(filtered)
        if ent >= threshold:
            findings.append(filtered)
    return findings


def find_high_entropy_base64(line: str, threshold: float = 4.5) -> list[str]:
    return _find_high_entropy_strings(line, BASE64_CHARS, threshold)


def find_high_entropy_hex(line: str, threshold: float = 3.0) -> list[str]:
    return _find_high_entropy_strings(line, HEX_CHARS, threshold, min_length=16)


def is_high_entropy(value: str, threshold: float = 3.5) -> bool:
    """Quick check — is this string suspiciously random?"""
    return shannon_entropy(value) >= threshold
