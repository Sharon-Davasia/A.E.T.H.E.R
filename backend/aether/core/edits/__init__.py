"""Phase 2D verified file edits, durable receipts and restored undo.

Mutation is the highest-risk surface in Phase 2, so the ordering here is
deliberate and enforced by one code path (:mod:`aether.core.edits.executor`):

1. verify the exact grant covers this action *now*;
2. re-inspect the target and refuse if it changed since preview;
3. capture and verify a pre-image into the Undo Vault;
4. replace atomically on the same volume;
5. re-read and verify the resulting bytes and hash;
6. persist a durable receipt that links action, grant and snapshot.

A step that cannot be completed with verification is reported ``UNVERIFIED`` or
``FAILED`` — never ``SUCCEEDED``. There is no generic shell and no unrestricted
filesystem adapter in this package.
"""

from __future__ import annotations

__all__ = ["executor", "receipts"]
