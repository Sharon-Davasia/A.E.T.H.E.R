"""Structured logging tests (Phase 0).

Covers logger creation, structured output, and redaction.
Redaction applies to structlog events only, not stdlib logging.
"""

from __future__ import annotations

import json

import structlog

from aether.observability.logging import _redact_event_dict, configure_logging, get_logger


def test_get_logger_returns_usable_logger() -> None:
    configure_logging()
    logger = get_logger("test-aether")
    assert logger is not None
    # Must support standard structlog methods without error.
    logger.info("test message", key="value")


def test_get_logger_default_name() -> None:
    configure_logging()
    logger = get_logger()
    assert logger is not None


def test_redact_event_dict_redacts_sensitive_keys() -> None:
    event = {"event": "test", "api_key": "supersecret", "safe": "hello"}
    out = _redact_event_dict(event)
    assert out["api_key"] == "[REDACTED]"
    assert out["safe"] == "hello"


def test_redact_event_dict_redacts_nested() -> None:
    event = {"event": "test", "context": {"password": "hunter2", "user": "alice"}}
    out = _redact_event_dict(event)
    assert out["context"]["password"] == "[REDACTED]"
    assert out["context"]["user"] == "alice"


def test_structured_output_is_json(capsys) -> None:  # type: ignore[no-untyped-def]
    """Structlog output with JSONRenderer is valid JSON per line."""
    configure_logging()
    logger = get_logger("test-json")
    logger.info("hello", answer=42)
    captured = capsys.readouterr()
    # PrintLoggerFactory writes to stderr.
    lines = [ln for ln in captured.err.splitlines() if ln.strip().startswith("{")]
    assert len(lines) >= 1
    parsed = json.loads(lines[-1])
    assert parsed["event"] == "hello"
    assert parsed["answer"] == 42


def test_structured_output_redacts_secrets(capsys) -> None:  # type: ignore[no-untyped-def]
    """Sensitive values are redacted in structured output."""
    configure_logging()
    logger = get_logger("test-redact")
    logger.info("login attempt", api_key="supersecret123", user="alice")
    captured = capsys.readouterr()
    lines = [ln for ln in captured.err.splitlines() if ln.strip().startswith("{")]
    assert len(lines) >= 1
    assert "supersecret123" not in lines[-1]
    assert "[REDACTED]" in lines[-1]
    assert "alice" in lines[-1]


def test_stdlib_logging_not_automatically_redacted() -> None:
    """Document the boundary: stdlib logging bypasses structlog redaction.

    This test asserts the documented limitation — stdlib records are
    not intercepted. Callers must use structlog for redacted output.
    """
    # configure_logging sets up structlog processors only; it does not
    # install a stdlib logging filter. Verify no stdlib filter is added.
    import logging

    configure_logging()
    root = logging.getLogger()
    # No AETHER-specific filter should be present on the root logger.
    filter_names = [type(f).__name__ for f in root.filters]
    assert "AetherRedactFilter" not in filter_names
    # structlog is configured (sanity check that configure ran).
    assert structlog.get_config() is not None
