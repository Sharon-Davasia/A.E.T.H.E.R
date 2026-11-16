"""Structured logging configuration with redaction (Phase 0).

Spec refs: Observability, Audit trail.

Redaction scope: only structlog events processed through the configured
processor chain are redacted. Standard-library ``logging`` output that
bypasses structlog is NOT automatically redacted. Callers must use the
structlog logger from ``get_logger()`` for sensitive-adjacent data, or
redact values before passing them to stdlib logging.
"""

from __future__ import annotations

import logging
import sys
from typing import Any, cast

import structlog

from aether.core.security.redaction import redact_value


def configure_logging(level: str = "INFO") -> None:
    """Configure structlog with a redaction processor.

    The redaction processor runs on every structlog event dict before
    JSON rendering. It does not intercept stdlib ``logging`` records.
    """
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            lambda _l, _m, event_dict: redact_value(event_dict),
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.PrintLoggerFactory(sys.stderr),
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO))


def get_logger(name: str = "aether") -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger.

    ``structlog.get_logger`` returns a lazy proxy (``BoundLoggerLazyProxy``)
    until first use. We cast to ``BoundLogger`` for typing; the proxy
    resolves to a real bound logger on first log call.
    """
    return cast("structlog.stdlib.BoundLogger", structlog.get_logger(name))


def _redact_event_dict(event_dict: dict[str, Any]) -> dict[str, Any]:
    """Apply redaction to an event dict (exposed for testing)."""
    result = redact_value(event_dict)
    assert isinstance(result, dict)
    return result
