"""Ephemeral bearer authentication and exact Origin checks for local APIs."""

from __future__ import annotations

import secrets
from hmac import compare_digest

from fastapi import HTTPException, Request, status


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def require_local_session(request: Request) -> None:
    token = request.app.state.session_token
    authorization = request.headers.get("authorization", "")
    scheme, _, supplied = authorization.partition(" ")
    if scheme.casefold() != "bearer" or not supplied or not compare_digest(supplied, token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "LOCAL_SESSION_REQUIRED"},
            headers={"WWW-Authenticate": "Bearer"},
        )
    origin = request.headers.get("origin")
    allowed_origins: frozenset[str] = request.app.state.allowed_origins
    if origin is not None and origin not in allowed_origins:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "ORIGIN_NOT_ALLOWED"},
        )
