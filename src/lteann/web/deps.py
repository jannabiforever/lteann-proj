"""Request-scoped helpers: cookies and the signed-in user. No business rules here."""

from __future__ import annotations

from datetime import timedelta

from fastapi import HTTPException, Request, Response

from ..config import Settings
from ..domain import User
from ..service import Service


def service_of(request: Request) -> Service:
    return request.app.state.service


def settings_of(request: Request) -> Settings:
    return request.app.state.settings


def cookie_name(settings: Settings, base: str) -> str:
    # __Host- binds the cookie to this exact origin; browsers only accept it over HTTPS.
    return f"__Host-{base}" if settings.secure_cookies else base


def set_cookie(
    response: Response, settings: Settings, base: str, value: str, ttl: timedelta
) -> None:
    response.set_cookie(
        cookie_name(settings, base),
        value,
        max_age=int(ttl.total_seconds()),
        path="/",
        secure=settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )


def clear_cookie(response: Response, settings: Settings, base: str) -> None:
    response.delete_cookie(
        cookie_name(settings, base),
        path="/",
        secure=settings.secure_cookies,
        httponly=True,
        samesite="lax",
    )


def session_token(request: Request) -> str | None:
    return request.cookies.get(cookie_name(settings_of(request), "lteann_session"))


def current_user(request: Request) -> User:
    """401 unless the session cookie maps to a live user; re-verifies stale memberships."""
    service = service_of(request)
    user = service.current_user(session_token(request))
    if user is None:
        raise HTTPException(401, "sign in required")
    service.ensure_fresh_memberships(user.id)  # AccessDenied -> 401 via the exception table
    return user
