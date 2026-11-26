"""Phase 3 application registry and alias resolution (CP2)."""

from aether.core.apps.registry import (
    ApplicationRegistryError,
    InMemoryApplicationRegistry,
)
from aether.core.apps.resolution import (
    ResolutionKind,
    ResolutionOutcome,
    resolve_application,
)

__all__ = [
    "ApplicationRegistryError",
    "InMemoryApplicationRegistry",
    "ResolutionKind",
    "ResolutionOutcome",
    "resolve_application",
]
