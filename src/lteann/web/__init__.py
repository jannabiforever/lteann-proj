"""FastAPI assembly. Knows HTTP; the service knows the rules."""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..adapters.repo import Conflict
from ..config import Settings
from ..ports import AccessDenied, AuthError, Unavailable
from ..service import NotFound, Service
from .routes import router
from .security import SecurityBoundary

log = logging.getLogger(__name__)

# The whole error contract. Bodies carry only the kind; details go to the log.
STATUS: dict[type[Exception], tuple[int, str]] = {
    NotFound: (404, "not found"),
    Conflict: (409, "stale version; reload and retry"),
    AccessDenied: (401, "sign in again"),
    AuthError: (400, "sign-in failed; start again"),
    Unavailable: (503, "provider unavailable; try later"),
}


def create_app(
    service: Service,
    settings: Settings,
    lifespan: Callable[[FastAPI], AbstractAsyncContextManager[None]] | None = None,
) -> FastAPI:
    app = FastAPI(title="lteann", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.service = service
    app.state.settings = settings
    app.add_middleware(SecurityBoundary, host=settings.host)
    app.include_router(router)

    for exc_type, (status, detail) in STATUS.items():

        def handler(
            request: Request, exc: Exception, status: int = status, detail: str = detail
        ) -> JSONResponse:
            log.info("%s %s -> %s: %s", request.method, request.url.path, status, exc)
            return JSONResponse({"detail": detail}, status_code=status)

        app.add_exception_handler(exc_type, handler)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app
