"""Hard bounds for every filesystem capability.

The Master Specification requires bounded files, directories, recursion depth
and total search output. These are deliberately small enough that a hostile or
merely enormous tree cannot exhaust the process, and large enough that ordinary
project inspection is not obstructive.

Bounds live here rather than at call sites so a caller cannot raise them by
choosing different arguments: capability argument models *narrow* these values,
never widen them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

# --- Reads ---------------------------------------------------------------
MAX_READ_BYTES: Final = 1_048_576  # 1 MiB hard ceiling for one read
DEFAULT_READ_BYTES: Final = 131_072  # 128 KiB default

# Content at or above this byte count that decodes as UTF-8 is still returned,
# but the caller must treat it as truncated unless it asked for the full size.
MAX_TEXT_CHARS: Final = 4_000_000

# --- Listing ------------------------------------------------------------
MAX_DIRECTORY_ENTRIES: Final = 5_000
MAX_DIRECTORY_DEPTH: Final = 32

# --- Search -------------------------------------------------------------
MAX_SEARCH_QUERY_CHARS: Final = 512
MAX_SEARCH_RESULTS: Final = 100
MAX_SEARCH_FILES_SCANNED: Final = 5_000
MAX_SEARCH_DEPTH: Final = 32
MAX_SEARCH_MATCHES_PER_FILE: Final = 50
MAX_SEARCH_OUTPUT_CHARS: Final = 262_144  # 256 KiB of match context total
MAX_SEARCH_FILE_BYTES: Final = 1_048_576  # skip larger files, report as skipped

# --- Time ---------------------------------------------------------------
DEFAULT_SEARCH_TIMEOUT_SECONDS: Final = 10.0
MAX_SEARCH_TIMEOUT_SECONDS: Final = 60.0
MAX_LISTING_TIMEOUT_SECONDS: Final = 30.0

# --- Content sniffing ---------------------------------------------------
# A NUL byte in the leading window is the conservative signal that a file is
# binary rather than text. This is intentionally simple and conservative: a
# false positive denies a read (safe), a false negative would return binary
# bytes as text (unsafe), so the window is generous.
BINARY_SNIFF_BYTES: Final = 8_192


@dataclass(frozen=True, slots=True)
class ReadBounds:
    """Resolved, validated bounds for one read."""

    max_bytes: int = DEFAULT_READ_BYTES

    def __post_init__(self) -> None:
        if not 1 <= self.max_bytes <= MAX_READ_BYTES:
            raise ValueError("read byte bound outside the permitted range")

    @classmethod
    def clamp(cls, requested: int | None) -> ReadBounds:
        if requested is None:
            return cls()
        return cls(max_bytes=max(1, min(int(requested), MAX_READ_BYTES)))


@dataclass(frozen=True, slots=True)
class SearchBounds:
    """Resolved, validated bounds for one search."""

    max_results: int = 25
    max_depth: int = 16
    timeout_seconds: float = DEFAULT_SEARCH_TIMEOUT_SECONDS
    max_files_scanned: int = MAX_SEARCH_FILES_SCANNED
    max_matches_per_file: int = MAX_SEARCH_MATCHES_PER_FILE
    max_output_chars: int = MAX_SEARCH_OUTPUT_CHARS

    def __post_init__(self) -> None:
        if not 1 <= self.max_results <= MAX_SEARCH_RESULTS:
            raise ValueError("search result bound outside the permitted range")
        if not 0 <= self.max_depth <= MAX_SEARCH_DEPTH:
            raise ValueError("search depth bound outside the permitted range")
        if not 0.0 < self.timeout_seconds <= MAX_SEARCH_TIMEOUT_SECONDS:
            raise ValueError("search timeout outside the permitted range")
        if not 1 <= self.max_files_scanned <= MAX_SEARCH_FILES_SCANNED:
            raise ValueError("search file bound outside the permitted range")
        if not 1 <= self.max_matches_per_file <= MAX_SEARCH_MATCHES_PER_FILE:
            raise ValueError("search match bound outside the permitted range")
        if not 1 <= self.max_output_chars <= MAX_SEARCH_OUTPUT_CHARS:
            raise ValueError("search output bound outside the permitted range")


__all__ = [
    "BINARY_SNIFF_BYTES",
    "DEFAULT_READ_BYTES",
    "DEFAULT_SEARCH_TIMEOUT_SECONDS",
    "MAX_DIRECTORY_DEPTH",
    "MAX_DIRECTORY_ENTRIES",
    "MAX_LISTING_TIMEOUT_SECONDS",
    "MAX_READ_BYTES",
    "MAX_SEARCH_DEPTH",
    "MAX_SEARCH_FILES_SCANNED",
    "MAX_SEARCH_MATCHES_PER_FILE",
    "MAX_SEARCH_OUTPUT_CHARS",
    "MAX_SEARCH_QUERY_CHARS",
    "MAX_SEARCH_RESULTS",
    "MAX_SEARCH_TIMEOUT_SECONDS",
    "MAX_TEXT_CHARS",
    "ReadBounds",
    "SearchBounds",
]
