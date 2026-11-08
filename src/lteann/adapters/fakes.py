"""In-memory implementations of every port, for tests and the demo server."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from ..domain import Event, EventDraft, Notice, Scope
from ..ports import AccessDenied, AuthError, Blob, Flow, Grant, Principal

FAR_FUTURE = datetime(2100, 1, 1, tzinfo=UTC)


class FakeIdentity:
    """Signs in whoever `principal` says, after a round trip that checks state."""

    def __init__(self, principal: Principal):
        self.principal = principal

    def begin(self, redirect_url: str) -> tuple[str, Flow]:
        state = secrets.token_urlsafe(16)
        return f"{redirect_url}?state={state}&code=ok", {"state": state}

    def finish(self, flow: Flow, query: dict[str, str]) -> tuple[Principal, Grant]:
        if query.get("state") != flow.get("state") or query.get("code") != "ok":
            raise AuthError("state or code mismatch")
        blob: Blob = {"subject": self.principal.subject}
        return self.principal, Grant(f"token:{self.principal.subject}", FAR_FUTURE, blob)


class FakeCredentials:
    def __init__(self, now: Callable[[], datetime] | None = None):
        self.revoked: set[str] = set()
        self.now = now or (lambda: datetime.now(UTC))

    def refresh(self, blob: Blob) -> Grant:
        subject = blob.get("subject")
        if not subject or subject in self.revoked:
            raise AccessDenied("revoked")
        return Grant(f"token:{subject}", self.now() + timedelta(hours=1), blob)


class FakeSource:
    """`access` maps token -> readable scope ids; `posts` maps scope id -> notices."""

    provider = "fake"

    def __init__(self):
        self.access: dict[str, set[str]] = {}
        self.scopes_by_id: dict[str, Scope] = {}
        self.posts: dict[str, list[Notice]] = {}
        self.images: dict[str, bytes] = {}

    def grant(self, token: str, scope: Scope) -> None:
        self.scopes_by_id[scope.id] = scope
        self.access.setdefault(token, set()).add(scope.id)

    def scopes(self, access_token: str) -> list[Scope]:
        if access_token not in self.access:
            raise AccessDenied("unknown token")
        return [self.scopes_by_id[s] for s in sorted(self.access[access_token])]

    def notices(self, access_token: str, scope: Scope) -> list[Notice]:
        if scope.id not in self.access.get(access_token, ()):
            raise AccessDenied("not a member")
        return list(self.posts.get(scope.id, []))

    def image(self, access_token: str, notice: Notice, image_id: str) -> bytes:
        return self.images[image_id]


class FakeExtractor:
    """Scripted: `drafts[notice.id]` is returned verbatim; unknown notices yield nothing."""

    def __init__(self, drafts: dict[str, list[EventDraft]] | None = None):
        self.drafts = drafts or {}
        self.calls: list[str] = []

    def extract(
        self, notice: Notice, images: list[bytes], previous: list[Event]
    ) -> list[EventDraft]:
        self.calls.append(notice.id)
        return list(self.drafts.get(notice.id, []))
