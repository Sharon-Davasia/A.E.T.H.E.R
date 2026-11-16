"""Redaction tests (Phase 0, synthetic secrets only)."""

from __future__ import annotations

from aether.core.security.redaction import redact_text, redact_value


def test_redacts_api_key_assignment() -> None:
    out = redact_text("api_key=supersecret123")
    assert "supersecret123" not in out
    assert "[REDACTED]" in out


def test_redacts_bearer_token() -> None:
    out = redact_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz")
    assert "abcdefghijklmnopqrstuvwxyz" not in out


def test_redacts_dict_sensitive_keys() -> None:
    out = redact_value({"api_key": "abc", "safe": "hello"})
    assert out["api_key"] == "[REDACTED]"
    assert out["safe"] == "hello"


def test_preserves_non_sensitive() -> None:
    assert redact_text("hello world") == "hello world"
