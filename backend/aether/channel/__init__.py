"""Authenticated backend-hosted channel services.

These services speak the same authenticated, per-launch HMAC-SHA256 wire
protocol as the Stage 1 synthetic child (``apps/desktop/backend/channel_child.py``)
but are hosted inside the trusted backend package so that review operations can
reuse the single authoritative implementation of preview construction and
verification (``aether.core.approval_review``). The Stage 1 stdlib-only child is
kept unchanged; it remains the reference for the isolated synthetic ping path.
"""
