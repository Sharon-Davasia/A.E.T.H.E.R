"""Content classification for filesystem reads.

Reading a file is *not* automatically safe because it does not modify bytes.
The Master Specification classifies access sensitivity and effect risk
separately. This module supplies the sensitivity half for reads:

* a binary sniff, because handing binary bytes to a text pipeline is a content
  -handling error rather than a convenience;
* strict UTF-8 decoding with no lossy fallback;
* a secret-content screen so a mis-named file cannot smuggle credentials into
  model context.

Nothing here decides authorization. It classifies content that policy has
already allowed, and can only ever *deny*.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from aether.core.fs import errors
from aether.core.fs.limits import BINARY_SNIFF_BYTES

# Filenames that are secrets by name. The registry's ``is_protected_path``
# already rejects these for ordinary roots; this is the second, independent
# screen applied to the resolved leaf name so a future registry change cannot
# silently widen read scope.
_SECRET_NAME = re.compile(
    r"""^(?:
        \.env(?:\..*)? |
        \.netrc |
        \.pgpass |
        \.npmrc |
        \.pypirc |
        credentials(?:\.json)? |
        secrets?(?:\.json|\.ya?ml|\.toml)? |
        id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)? |
        .*\.(?:pem|key|p12|pfx|kdbx|jks|keystore) |
        .*\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\b.*
    )$""",
    re.IGNORECASE | re.VERBOSE,
)

# Content that looks like an inline credential assignment. Deliberately narrow
# and high-precision: a false positive denies a legitimate read (the user can
# re-request explicitly), a false negative would leak a secret into context.
_SECRET_CONTENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),  # GitHub tokens
    re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),  # generic API secret key
    re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|password)\b\s*[:=]\s*"
        r"['\"]?[A-Za-z0-9/+=_\-]{16,}['\"]?"
    ),
)

_TEXT_CONTROL_ALLOWED: Final = frozenset({"\t", "\n", "\r", "\f", "\v"})


@dataclass(frozen=True, slots=True)
class TextContent:
    """Decoded, screened text plus the facts needed to report it honestly."""

    text: str
    encoding: str
    total_bytes: int
    returned_bytes: int
    truncated: bool

    @property
    def complete(self) -> bool:
        return not self.truncated


def is_secret_filename(name: str) -> bool:
    """Return True when a leaf filename is a secret by name."""

    return _SECRET_NAME.match(name) is not None


def looks_binary(data: bytes) -> bool:
    """Conservative binary sniff over the leading window.

    A NUL byte, or an unusually high share of non-text control bytes, marks the
    payload as binary. Erring toward "binary" is safe: it denies a read rather
    than returning undecodable bytes as if they were text.
    """

    window = data[:BINARY_SNIFF_BYTES]
    if not window:
        return False
    if b"\x00" in window:
        return True
    control = sum(
        1
        for byte in window
        if (byte < 0x20 and chr(byte) not in _TEXT_CONTROL_ALLOWED) or byte == 0x7F
    )
    return control / len(window) > 0.10


def contains_secret_material(text: str) -> bool:
    """Return True when text appears to embed credential material."""

    sample = text[:1_048_576]
    return any(pattern.search(sample) is not None for pattern in _SECRET_CONTENT_PATTERNS)


def decode_text(
    data: bytes,
    *,
    total_bytes: int | None = None,
) -> TextContent:
    """Strictly decode ``data`` as UTF-8, refusing binary or sensitive payloads.

    Raises :class:`FileCapabilityError`-compatible reason codes via the
    caller-supplied error type; this function raises ``ValueError`` subclasses
    through :func:`raise_for_content` instead so it stays dependency-free.
    """

    total = len(data) if total_bytes is None else total_bytes
    if looks_binary(data):
        raise ContentRejected(errors.BINARY_CONTENT_DENIED, "payload is not text")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A read may legitimately end mid-codepoint when truncated. Only that
        # exact case is tolerated; otherwise refuse rather than mangling text.
        if len(data) < total:
            text = _decode_truncated_utf8(data)
        else:
            raise ContentRejected(errors.INVALID_ENCODING, "payload is not valid UTF-8") from exc
    if contains_secret_material(text):
        raise ContentRejected(
            errors.SENSITIVE_CONTENT_DENIED, "content contains credential material"
        )
    return TextContent(
        text=text,
        encoding="utf-8",
        total_bytes=total,
        returned_bytes=len(data),
        truncated=len(data) < total,
    )


def _decode_truncated_utf8(data: bytes) -> str:
    """Decode a prefix that may split a multi-byte sequence at the very end."""

    for trim in range(1, 4):
        try:
            return data[:-trim].decode("utf-8")
        except UnicodeDecodeError:
            continue
    raise ContentRejected(errors.INVALID_ENCODING, "payload is not valid UTF-8")


class ContentRejected(Exception):
    """Content is unsafe or undecodable; ``reason_code`` is authoritative."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


__all__ = [
    "ContentRejected",
    "TextContent",
    "contains_secret_material",
    "decode_text",
    "is_secret_filename",
    "looks_binary",
]
