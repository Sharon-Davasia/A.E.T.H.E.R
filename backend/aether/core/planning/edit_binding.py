"""The approved post-image binding (S14-1).

Before this module, an edit's authorization proved only that the *pre-image* was
unchanged. Everything downstream then trusted whatever bytes the caller supplied
as ``proposed_content``. That is a substitution hole: approving "fix the typo in
README.md" would authorize any README.md content that replaced the same
pre-image, because nothing in the plan, preview or grant named the result.

The binding closes it. ``ApprovedEdit`` carries the pre-image digest, the
post-image digest and the diff digest, and:

* the planner writes it into the immutable plan step;
* the preview authority renders the exact diff and binds the same digests, so the
  human sees precisely the bytes they are approving;
* the executor recomputes the post-image digest from the bytes it is about to
  write and refuses unless it matches the binding that the grant covers.

The effect digest deliberately includes the *rendered diff* as well as both
images. A post-image digest alone would still allow a grant to be satisfied by a
different rendering of the change, and the user approves the rendering.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from aether.core.planning.exact_diff import DiffError, ExactDiff, render_exact_diff

_MAX_EDIT_BYTES = 4 * 1024 * 1024


class EditBindingError(Exception):
    """The proposed bytes are not the approved bytes; ``reason_code`` is set."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"{reason_code}: {message}")


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class ApprovedEdit:
    """Exactly which bytes were approved, and how the approval is proven.

    This object is the single source of truth shared by the plan step, the
    preview and the executor. It is immutable so a caller cannot adjust it after
    the user has seen the preview.
    """

    resource_id: str
    steps: int
    detected_changes: int
    pre_sha256: str
    post_sha256: str
    diff_sha256: str
    effect_sha256: str
    post_bytes: int
    unified_diff: str

    @classmethod
    def build(
        cls,
        *,
        resource_id: str,
        pre_image: bytes,
        post_image: bytes,
        display_name: str,
    ) -> ApprovedEdit:
        """Derive the binding, refusing anything that cannot be shown exactly."""

        if len(post_image) > _MAX_EDIT_BYTES:
            raise EditBindingError("edit_too_large", "proposed content exceeds the edit bound")
        if len(pre_image) > _MAX_EDIT_BYTES:
            raise EditBindingError("edit_too_large", "the current file exceeds the edit bound")
        try:
            rendered = render_exact_diff(
                pre_image=pre_image, post_image=post_image, display_name=display_name
            )
        except DiffError as exc:
            raise EditBindingError(exc.reason_code, str(exc)) from exc
        return cls.from_rendered(resource_id=resource_id, rendered=rendered)

    @classmethod
    def from_rendered(cls, *, resource_id: str, rendered: ExactDiff) -> ApprovedEdit:
        return cls(
            resource_id=resource_id,
            steps=1,
            detected_changes=rendered.added_lines + rendered.removed_lines,
            pre_sha256=rendered.pre_sha256,
            post_sha256=rendered.post_sha256,
            diff_sha256=rendered.diff_sha256,
            effect_sha256=rendered.effect_sha256,
            post_bytes=rendered.post_bytes,
            unified_diff=rendered.unified_diff,
        )

    def to_step_arguments(self) -> dict[str, object]:
        """The immutable facts written into the plan step's expected effect.

        These are persisted with the plan and are therefore covered by the plan
        hash, so a later revision cannot quietly change the approved bytes.
        """

        return {
            # Digest-only on purpose: the persisted plan must never carry the
            # document text, and the plan-field validator forbids content-like
            # key names. The rendered diff is shown in the preview but is not
            # persisted with the plan.
            "approved_source_digest": self.pre_sha256,
            "approved_result_digest": self.post_sha256,
            "approved_rendering_digest": self.diff_sha256,
            "approved_effect_digest": self.effect_sha256,
            "approved_result_bytes": self.post_bytes,
        }

    @classmethod
    def from_step_arguments(cls, *, resource_id: str, values: dict[str, object]) -> ApprovedEdit:
        """Rebuild the binding from a persisted step, or refuse a malformed one."""

        post_bytes = values.get("approved_result_bytes")
        if not isinstance(post_bytes, int) or isinstance(post_bytes, bool):
            raise EditBindingError(
                "approved_binding_malformed",
                "the persisted approval binding is incomplete",
            )
        try:
            return cls(
                resource_id=resource_id,
                steps=1,
                detected_changes=0,
                pre_sha256=str(values["approved_source_digest"]),
                post_sha256=str(values["approved_result_digest"]),
                diff_sha256=str(values["approved_rendering_digest"]),
                effect_sha256=str(values["approved_effect_digest"]),
                post_bytes=post_bytes,
                unified_diff=str(values.get("approved_unified_diff", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise EditBindingError(
                "approved_binding_malformed",
                "the persisted approval binding is incomplete",
            ) from exc

    def verify_proposed(self, *, proposed_content: bytes, current_pre_image: bytes) -> None:
        """Prove the bytes about to be written are the bytes the user approved.

        Both halves are checked. A matching pre-image with a different post-image
        is the substitution this exists to reject.
        """

        if sha256_hex(current_pre_image) != self.pre_sha256:
            raise EditBindingError(
                "post_image_binding_pre_mismatch",
                "the current file is not the pre-image the user approved",
            )
        actual_post = sha256_hex(proposed_content)
        if actual_post != self.post_sha256:
            raise EditBindingError(
                "approved_post_image_mismatch",
                "the content to be written is not the content the user approved",
            )
        if len(proposed_content) != self.post_bytes:
            raise EditBindingError(
                "approved_post_image_size_mismatch",
                "the content to be written has a different size than the approved content",
            )


__all__ = ["ApprovedEdit", "EditBindingError", "sha256_hex"]
