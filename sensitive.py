"""OWASP LLM02 helper: find secrets and card numbers in text, and redact them.

Used in two places: the detector blocks prompts that contain them, and the
gateway redacts them before anything is written to the audit log (otherwise the
log itself would become a leak).

Scope: well-known token formats and Luhn-valid card numbers. It does not try to
find emails, phone numbers, names or free-form passwords.
"""
from __future__ import annotations

import re

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "openai_style_key": re.compile(r"\bsk-(?:proj-|live-|ant-)?[A-Za-z0-9_-]{20,}"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "private_key_block": re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}

# 13-19 digits, optionally separated by single spaces or dashes.
_CARD_RE = re.compile(r"(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _looks_like_card(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    return (
        13 <= len(digits) <= 19
        and digits[0] in "3456"
        and len(set(digits)) > 1
        and _luhn_ok(digits)
    )


def find_sensitive(text: str) -> list[tuple[str, int, int]]:
    """Return (kind, start, end) for every secret or card number found."""
    found: list[tuple[str, int, int]] = []
    for kind, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            found.append((kind, m.start(), m.end()))
    for m in _CARD_RE.finditer(text):
        if _looks_like_card(m.group()):
            found.append(("card_number", m.start(), m.end()))
    return found


def redact(text: str) -> tuple[str, list[str]]:
    """Replace every finding with [REDACTED:kind]. Returns (text, kinds)."""
    spans = sorted(find_sensitive(text), key=lambda s: s[1])
    out: list[str] = []
    kinds: list[str] = []
    pos = 0
    for kind, start, end in spans:
        if start < pos:  # overlaps a span we already replaced
            continue
        out.append(text[pos:start])
        out.append(f"[REDACTED:{kind}]")
        kinds.append(kind)
        pos = end
    out.append(text[pos:])
    return "".join(out), kinds
