"""Typed filesystem capability execution (Phase 2C).

This package implements the *real* read/inspect/search/open capabilities behind
the existing ``ResourceRegistry`` and deterministic ``PolicyBroker``. It is a
deliberately narrow surface:

* every operation takes a broker-resolved resource reference, never a raw path;
* every operation re-derives identity and version from the filesystem
  *immediately* before acting (TOCTOU reduction, not elimination — see
  :mod:`aether.core.fs.executor`);
* every operation is bounded by count/size/time limits and reports honest
  partial results;
* nothing here writes user files. T2 mutation lives in
  :mod:`aether.core.edits` and requires an exact consumed grant.

Missing capability is denied, never approximated: if a guarantee cannot be met
for a path, file type or filesystem, the operation fails closed with a typed
reason code instead of degrading silently.
"""

from __future__ import annotations

__all__ = ["content", "errors", "executor", "limits", "search"]
