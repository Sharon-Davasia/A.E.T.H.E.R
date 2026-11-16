"""Sensitive-data redaction for logs and events (Phase 0).

Spec refs: Observability, Audit trail, Configuration and secrets.
Redacts API keys, bearer tokens, passwords, and SECRET-class fields
before they reach logs. Phase 0: pattern-based, no real secrets handled.
"""

from __future__ import annotations

import re
from typing import Any

_REDACTED = "[REDACTED]"

# Patterns for common secret shapes (synthetic-test only; no real data).
_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(bearer\s+)\S+"),
    re.compile(r"(?i)(password\s*[:=]\s*)\S+"),
    re.compile(r"(?i)(secret\s*[:=]\s*)\S+"),
    re.compile(r"sk-[A-Za-z0-9\-_]{10,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
]

_SENSITIVE_KEYS = frozenset(
    {"api_key", "apikey", "password", "secret", "token", "authorization", "credential"}
)


def redact_text(text: str) -> str:
    """Redact secret patterns from free text."""
    out = text
    for pat in _PATTERNS:
        out = pat.sub(lambda m: f"{m.group(1)}{_REDACTED}" if m.lastindex else _REDACTED, out)
    return out


def redact_value(value: Any) -> Any:
    """Recursively redact sensitive values in dicts/lists/strings."""
    if isinstance(value, dict):
        return {
            k: (_REDACTED if str(k).lower() in _SENSITIVE_KEYS else redact_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
