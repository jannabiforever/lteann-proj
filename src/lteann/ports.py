"""The four seams that have a second (fake) implementation. Nothing else is a port.

One class may implement several of these: the Microsoft adapter is Identity,
Credentials and Source at once. A later Google adapter is Credentials and Source
only, because sign-in stays with the school tenant.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from .domain import Event, EventDraft, Notice, Scope

Flow = dict[str, object]  # opaque, server-side only; never sent to the browser
Blob = dict[str, object]  # opaque provider credential; the repository stores it encrypted


class AuthError(Exception):
    """The sign-in or token exchange was rejected. Start over."""


class AccessDenied(Exception):
    """The provider no longer honours this credential. The user must sign in again."""


class Unavailable(Exception):
    """Transient provider failure. Retry later; keep the credential."""


@dataclass(frozen=True, slots=True)
class Principal:
    issuer: str
    subject: str
    name: str
    email: str


@dataclass(frozen=True, slots=True)
class Grant:
    access_token: str
    expires_at: datetime
    blob: Blob  # what Credentials needs to refresh later


class Identity(Protocol):
    def begin(self, redirect_url: str) -> tuple[str, Flow]:
        """Return (url to send the browser to, flow to keep server-side)."""
        ...

    def finish(self, flow: Flow, query: dict[str, str]) -> tuple[Principal, Grant]:
        """Validate the callback against the stored flow. Raises AuthError."""
        ...


class Credentials(Protocol):
    def refresh(self, blob: Blob) -> Grant:
        """Raises AccessDenied (re-login) or Unavailable (retry)."""
        ...


class Source(Protocol):
    provider: str

    def scopes(self, access_token: str) -> list[Scope]:
        """Scopes this token can read right now. This is the membership proof."""
        ...

    def notices(self, access_token: str, scope: Scope) -> list[Notice]: ...

    def image(self, access_token: str, notice: Notice, image_id: str) -> bytes: ...


class Extractor(Protocol):
    def extract(
        self, notice: Notice, images: list[bytes], previous: list[Event]
    ) -> list[EventDraft]:
        """Turn one notice into drafts. `previous` lets it propose matches."""
        ...
