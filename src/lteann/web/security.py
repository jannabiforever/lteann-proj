"""One ASGI boundary: canonical host, bounded bodies, conservative browser headers."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

MAX_BODY = 256 * 1024  # all bodies are small JSON; images never come through the browser
HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
}


class SecurityBoundary(BaseHTTPMiddleware):
    def __init__(self, app, host: str):
        super().__init__(app)
        self.host = host

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.url.hostname != self.host:
            return JSONResponse({"detail": "unknown host"}, status_code=421)
        length = request.headers.get("content-length")
        if length and int(length) > MAX_BODY:
            return JSONResponse({"detail": "body too large"}, status_code=413)
        response = await call_next(request)
        for name, value in HEADERS.items():
            response.headers.setdefault(name, value)
        return response
