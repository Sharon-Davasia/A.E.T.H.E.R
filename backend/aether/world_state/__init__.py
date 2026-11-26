"""Phase 3 WorldState foundation (CP1): observer + privacy + in-memory state.

Native observation is disabled by default and is never enabled by an
ordinary launch in this checkpoint. The native Windows observer source
exists behind explicit platform+activation guards and is not wired
into the running application.
"""

from aether.world_state.observer import (
    FakeWindowEventSource,
    ObserverService,
    ObserverUnavailable,
    WindowEvent,
    WindowEventKind,
)
from aether.world_state.privacy import (
    ContextClassification,
    ObservationPolicy,
    PrivacyMode,
    collect_permitted,
)
from aether.world_state.service import InMemoryWorldState

__all__ = [
    "ContextClassification",
    "FakeWindowEventSource",
    "InMemoryWorldState",
    "ObservationPolicy",
    "ObserverService",
    "ObserverUnavailable",
    "PrivacyMode",
    "WindowEvent",
    "WindowEventKind",
    "collect_permitted",
]
