"""Exact pre/post diff rendering for approval previews (S14-1).

The review found that the planner produced ``full_diff=()`` for edits, so the
human approved a *description* rather than the bytes. This module renders the
exact change as a unified diff and, just as importantly, derives the digest that
the plan, the preview and the grant all bind to.

Two properties matter and are both enforced here:

* **Determinism.** The same pre-image and post-image always produce byte-identical
  diff text, so a digest computed at planning time still verifies at execution
  time. No timestamps, no locale-dependent formatting, no context lines that
  depend on surrounding content outside the two images.
* **Boundedness.** A preview is rendered for a human and stored in a database, so
  the diff is capped in both line count and byte size. An over-large change is
  *refused* rather than truncated: a truncated diff would let a user approve one
  thing while a different thing executed, which is the exact failure this exists
  to prevent.
"""

from __future__ import annotations

import difflib
import hashlib
from dataclasses import dataclass

MAX_DIFF_BYTES = 64_000
MAX_DIFF_LINES = 4_000
MAX_DIFF_INPUT_BYTES = 4 * 1024 * 1024
_CONTEXT_LINES = 3


class DiffError(Exception):
    """The diff cannot be rendered safely; ``reason_code`` is authoritative."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


@dataclass(frozen=True, slots=True)
class ExactDiff:
    """A deterministic unified diff plus the digests that bind approval to bytes."""

    unified_diff: str
    pre_sha256: str
    post_sha256: str
    pre_bytes: int
    post_bytes: int
    added_lines: int
    removed_lines: int

    @property
    def diff_sha256(self) -> str:
        return hashlib.sha256(self.unified_diff.encode("utf-8")).hexdigest()

    @property
    def effect_sha256(self) -> str:
        """The digest a grant binds as ``expected_effect_sha256``.

        It covers the pre-image, the post-image *and* the rendered diff, so a
        grant cannot be satisfied by a different post-image that happens to
        arrive with the same pre-image. Binding only the pre-image is precisely
        the substitution the review rejected.
        """

        material = (
            f"aether-effect-v1\n{self.pre_sha256}\n{self.post_sha256}\n{self.diff_sha256}\n"
        ).encode()
        return hashlib.sha256(material).hexdigest()


def _eof_state(raw: bytes) -> str:
    """The final-newline state of one image, derived only from its raw bytes."""

    if raw == b"":
        return "empty"
    return "newline" if raw.endswith(b"\n") else "no-newline"


def _decode(raw: bytes) -> list[str]:
    """Decode to text for diffing, refusing what cannot be shown faithfully.

    Binary content is refused rather than mojibake'd: a human cannot meaningfully
    approve a diff of bytes they cannot read, and a lossy decode could render two
    different post-images as the same text.
    """

    if len(raw) > MAX_DIFF_INPUT_BYTES:
        raise DiffError("diff_input_too_large", "the content exceeds the diff input bound")
    if b"\x00" in raw:
        raise DiffError("diff_binary_content", "binary content cannot be previewed as text")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DiffError(
            "diff_invalid_utf8", "content that is not valid UTF-8 cannot be previewed"
        ) from exc
    # ``splitlines`` would silently normalise CRLF and trailing-newline presence,
    # which changes what the user is agreeing to. Split on "\n" only.
    return text.split("\n")


def render_exact_diff(
    *,
    pre_image: bytes,
    post_image: bytes,
    display_name: str,
) -> ExactDiff:
    """Render the exact change from ``pre_image`` to ``post_image``."""

    # A lone final carriage return cannot be represented faithfully: its
    # fragment would look exactly like a CRLF-terminated line once joined, and
    # appending the EOF trailer after it would form a spurious CRLF pair.
    # Refuse explicitly rather than render misleading evidence.
    if pre_image.endswith(b"\r") or post_image.endswith(b"\r"):
        raise DiffError(
            "diff_final_cr_unsupported",
            "content ending in a lone carriage return cannot be previewed exactly",
        )
    pre_lines = _decode(pre_image)
    post_lines = _decode(post_image)
    if pre_image == post_image:
        raise DiffError(
            "diff_no_change", "the proposed content is identical to the current content"
        )

    unified = list(
        difflib.unified_diff(
            pre_lines,
            post_lines,
            fromfile=f"a/{display_name}",
            tofile=f"b/{display_name}",
            n=_CONTEXT_LINES,
            lineterm="",
        )
    )
    if not unified:
        raise DiffError("diff_empty", "the change produced no diff")
    # The canonical EOF trailer (aether-diff-v2) records both images' final-
    # newline states, derived exclusively from the raw bytes above. Splitting
    # on "\n" turns a trailing newline into an empty sentinel element, which
    # renders as a bare +/- line indistinguishable from a trailing blank
    # line; the trailer is what makes that evidence unambiguous. It is part
    # of the canonical text, so every digest computed over the diff binds it.
    trailer = (
        f"\\ aether-diff-v2 eof: original={_eof_state(pre_image)} "
        f"replacement={_eof_state(post_image)}"
    )
    unified = [*unified, trailer]
    if len(unified) > MAX_DIFF_LINES:
        raise DiffError(
            "diff_too_large",
            "the change is too large to preview exactly; it must be split into smaller edits",
        )
    text = "\n".join(unified)
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_DIFF_BYTES:
        raise DiffError(
            "diff_too_large",
            "the rendered diff exceeds the preview bound; it must be split into smaller edits",
        )
    added = sum(1 for line in unified if line.startswith("+") and not line.startswith("+++"))
    removed = sum(1 for line in unified if line.startswith("-") and not line.startswith("---"))
    return ExactDiff(
        unified_diff=text,
        pre_sha256=hashlib.sha256(pre_image).hexdigest(),
        post_sha256=hashlib.sha256(post_image).hexdigest(),
        pre_bytes=len(pre_image),
        post_bytes=len(post_image),
        added_lines=added,
        removed_lines=removed,
    )


__all__ = [
    "MAX_DIFF_BYTES",
    "MAX_DIFF_INPUT_BYTES",
    "MAX_DIFF_LINES",
    "DiffError",
    "ExactDiff",
    "render_exact_diff",
]
