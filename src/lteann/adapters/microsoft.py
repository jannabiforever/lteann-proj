"""Microsoft adapter: Entra sign-in (Identity, Credentials) and Teams reads (Source).

Delegated permissions only. Every Graph call carries the signed-in student's own
token; a channel appears in `scopes()` only after a real read of it succeeds.
Scope ids are "<team uuid>/<channel id>" because Graph paths need both.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from typing import Any, Protocol
from urllib.parse import quote, urlsplit
from uuid import UUID

import httpx
from msal import ConfidentialClientApplication, SerializableTokenCache

from ..domain import Notice, Scope
from ..ports import AccessDenied, AuthError, Blob, Flow, Grant, Principal, Unavailable

log = logging.getLogger(__name__)

PROVIDER = "microsoft"
SCOPES = ["User.Read", "Team.ReadBasic.All", "Channel.ReadBasic.All", "ChannelMessage.Read.All"]
GRAPH = "https://graph.microsoft.com/v1.0"
IMAGE_TYPES = {"image/png", "image/jpeg", "image/webp", "image/gif"}
MAX_IMAGE_BYTES = 3_000_000
MAX_TEXT = 16_000
MAX_IMAGES = 3
TRANSIENT = {"temporarily_unavailable", "server_error"}


class _NoAccess(Exception):
    """403/404 from Graph: the token cannot read this resource. Not a provider failure."""


class TokenApp(Protocol):
    """The four MSAL calls we make. ConfidentialClientApplication satisfies this; tests fake it.

    Positional-only (`/`) where we pass positionally, so MSAL's own parameter
    names don't matter; keyword names match MSAL's where we pass keywords.
    """

    def initiate_auth_code_flow(
        self, scopes: list[str], /, *, redirect_uri: str, prompt: str
    ) -> dict[str, Any]: ...
    def acquire_token_by_auth_code_flow(
        self, flow: dict[str, Any], query: dict[str, str], /
    ) -> dict[str, Any]: ...
    def get_accounts(self) -> list[dict[str, Any]]: ...
    def acquire_token_silent_with_error(
        self, scopes: list[str], /, *, account: dict[str, Any]
    ) -> dict[str, Any] | None: ...


class _Text(HTMLParser):
    BLOCKS = frozenset({"p", "br", "div", "li", "tr", "h1", "h2", "h3", "h4"})

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.images: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.BLOCKS:
            self.parts.append("\n")
        if tag == "img":
            self.images.append(dict(attrs).get("src") or "")

    def handle_data(self, data: str) -> None:
        self.parts.append(data)


def parse_html(html: str) -> tuple[str, list[str]]:
    """(plain text, img src list). Whitespace collapsed per line."""
    p = _Text()
    p.feed(html or "")
    lines = (" ".join(line.split()) for line in "".join(p.parts).splitlines())
    return "\n".join(line for line in lines if line), p.images


class MicrosoftAdapter:
    provider = PROVIDER

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        *,
        transport: httpx.BaseTransport | None = None,
        msal_app: Callable[[SerializableTokenCache | None], TokenApp] | None = None,  # test seam
        now: Callable[[], datetime] | None = None,
    ):
        self.tenant_id, self.client_id = str(UUID(tenant_id)), str(UUID(client_id))
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self.issuer = self.authority + "/v2.0"
        self._secret = client_secret
        self._msal_app = msal_app
        self.now = now or (lambda: datetime.now(UTC))
        self.http = httpx.Client(timeout=10, trust_env=False, transport=transport)

    # --- MSAL -----------------------------------------------------------------

    def _app(self, cache: SerializableTokenCache | None = None) -> TokenApp:
        if self._msal_app is not None:
            return self._msal_app(cache)
        return ConfidentialClientApplication(
            self.client_id,
            client_credential=self._secret,
            authority=self.authority,
            token_cache=cache,
            timeout=10,
        )

    @staticmethod
    def _cache(serialized: str | None = None) -> SerializableTokenCache:
        cache = SerializableTokenCache()
        if serialized:
            cache.deserialize(serialized)
        return cache

    def _grant(self, result: dict[str, Any], cache: SerializableTokenCache, oid: str) -> Grant:
        granted = {
            s.lower().removeprefix("https://graph.microsoft.com/")
            for s in result.get("scope", "").split()
        }
        if not {s.lower() for s in SCOPES} <= granted:
            raise AccessDenied("school permissions not granted")
        lifetime = min(int(result.get("expires_in", 0)), 3600)
        if lifetime < 60:
            raise Unavailable("token lifetime too short")
        return Grant(
            result["access_token"],
            self.now() + timedelta(seconds=lifetime),
            {"cache": cache.serialize(), "oid": oid},
        )

    def _validate_claims(self, claims: dict[str, Any]) -> str:
        """Our own checks on top of MSAL's; returns the object id (lower-case uuid)."""
        try:
            tenant, oid = str(UUID(claims.get("tid", ""))), str(UUID(claims.get("oid", "")))
        except ValueError:
            raise AuthError("missing tenant or object id") from None
        if tenant != self.tenant_id or claims.get("iss") != self.issuer:
            raise AuthError("wrong tenant")
        if claims.get("aud") != self.client_id:
            raise AuthError("wrong audience")
        if claims.get("acct") == 1:
            raise AuthError("guest accounts are not allowed")
        exp = claims.get("exp")
        if not isinstance(exp, int | float) or exp <= self.now().timestamp():
            raise AuthError("expired identity")
        return oid

    # --- Identity -------------------------------------------------------------

    def begin(self, redirect_url: str) -> tuple[str, Flow]:
        flow = self._app().initiate_auth_code_flow(
            SCOPES, redirect_uri=redirect_url, prompt="select_account"
        )
        if not flow.get("auth_uri") or not flow.get("state"):
            raise Unavailable("MSAL could not start a sign-in")
        return flow["auth_uri"], flow

    def finish(self, flow: Flow, query: dict[str, str]) -> tuple[Principal, Grant]:
        cache = self._cache()
        try:
            result = self._app(cache).acquire_token_by_auth_code_flow(flow, query)
        except ValueError as error:  # MSAL: state mismatch or malformed response
            raise AuthError(str(error)) from None
        if "access_token" not in result:
            raise AuthError(result.get("error", "no token"))
        oid = self._validate_claims(result.get("id_token_claims") or {})
        grant = self._grant(result, cache, oid)
        me = self._get(
            grant.access_token, GRAPH + "/me?$select=id,userType,displayName,mail,userPrincipalName"
        )
        if str(me.get("id", "")).lower() != oid or me.get("userType") != "Member":
            raise AuthError("not a member of the school tenant")
        name = str(me.get("displayName") or "")[:200]
        email = str(me.get("mail") or me.get("userPrincipalName") or "")[:320]
        return Principal(self.issuer, oid, name, email), grant

    # --- Credentials ----------------------------------------------------------

    def refresh(self, blob: Blob) -> Grant:
        oid = str(blob.get("oid", ""))
        serialized = blob.get("cache")
        cache = self._cache(serialized if isinstance(serialized, str) else None)
        app = self._app(cache)
        accounts = [
            a for a in app.get_accounts() if str(a.get("local_account_id", "")).lower() == oid
        ]
        if len(accounts) != 1:
            raise AccessDenied("no cached account")
        result = app.acquire_token_silent_with_error(SCOPES, account=accounts[0]) or {}
        if "access_token" not in result:
            if result.get("error") in TRANSIENT:
                raise Unavailable(result["error"])
            raise AccessDenied(result.get("error", "refresh failed"))
        return self._grant(result, cache, oid)

    # --- Graph plumbing -------------------------------------------------------

    def _get(self, token: str, url: str, *, allow_missing: bool = False) -> dict[str, Any]:
        try:
            r = self.http.get(url, headers={"Authorization": "Bearer " + token})
        except httpx.HTTPError as error:
            raise Unavailable(type(error).__name__) from None
        if r.status_code == 401:
            raise AccessDenied("graph 401")
        if r.status_code in (403, 404):
            raise _NoAccess(r.status_code)
        if r.status_code != 200:
            raise Unavailable(f"graph {r.status_code}")
        data = r.json()
        if not isinstance(data, dict):
            raise Unavailable("graph returned a non-object")
        return data

    def _pages(self, token: str, url: str, limit: int = 20) -> list[dict[str, Any]]:
        path = urlsplit(url).path
        items: list[dict[str, Any]] = []
        for _ in range(limit):
            data = self._get(token, url)
            items.extend(v for v in data.get("value", []) if isinstance(v, dict))
            url = data.get("@odata.nextLink") or ""
            if not url:
                return items
            if urlsplit(url).netloc != "graph.microsoft.com" or urlsplit(url).path != path:
                raise Unavailable("suspicious pagination link")
        raise Unavailable("too many pages")

    @staticmethod
    def _messages_url(scope_id: str) -> str:
        team_id, _, channel_id = scope_id.partition("/")
        return f"{GRAPH}/teams/{quote(team_id, safe='')}/channels/{quote(channel_id, safe='')}/messages"

    # --- Source ---------------------------------------------------------------

    def scopes(self, access_token: str) -> list[Scope]:
        """Teams channels this token can actually read. A listing alone is not proof."""
        scopes: list[Scope] = []
        for team in self._pages(access_token, GRAPH + "/me/joinedTeams?$select=id,displayName"):
            team_id = str(UUID(team["id"]))
            team_name = str(team.get("displayName") or "").strip()
            channels_url = f"{GRAPH}/teams/{team_id}/allChannels?$select=id,displayName,membershipType,tenantId"
            for ch in self._pages(access_token, channels_url):
                channel_id = str(ch.get("id") or "")
                if (
                    not channel_id
                    or "/" in channel_id
                    or ch.get("tenantId") not in (None, self.tenant_id)
                ):
                    continue  # cross-tenant shared channels are deliberately excluded
                scope_id = f"{team_id}/{channel_id}"
                try:
                    self._get(access_token, self._messages_url(scope_id) + "?$top=1")
                except _NoAccess:
                    continue
                channel_name = str(ch.get("displayName") or "").strip() or "Teams"
                name = f"{team_name} · {channel_name}" if team_name else channel_name
                scopes.append(Scope(scope_id, PROVIDER, name[:200]))
        # ponytail: probes run sequentially; use a small ThreadPoolExecutor if sign-in gets slow.
        return scopes

    def notices(self, access_token: str, scope: Scope) -> list[Notice]:
        try:
            data = self._get(
                access_token, self._messages_url(scope.id) + "?$top=50&$expand=replies"
            )
        except _NoAccess:
            raise AccessDenied("channel no longer readable") from None
        notices = []
        for m in data.get("value", []):
            if m.get("deletedDateTime") or m.get("messageType") != "message":
                continue
            text, images = self._notice_content(m, scope.id)
            stamp = m.get("lastModifiedDateTime") or m.get("createdDateTime")
            posted = datetime.fromisoformat(stamp) if stamp else self.now()
            notices.append(
                Notice(str(m["id"]), scope.id, text, tuple(images), posted, m.get("webUrl"))
            )
        return notices

    def _notice_content(self, m: dict[str, Any], scope_id: str) -> tuple[str, list[str]]:
        body, images = parse_html((m.get("body") or {}).get("content", ""))
        parts = [f"제목: {m.get('subject') or ''}".rstrip(": "), body]
        # ponytail: $expand=replies returns the first page only; deeper threads are not analysed.
        for reply in m.get("replies") or []:
            reply_text, _ = parse_html((reply.get("body") or {}).get("content", ""))
            if reply_text:
                parts.append("답글: " + reply_text)
        text = "\n".join(p for p in parts if p)
        if len(text) > MAX_TEXT:
            text = text[:MAX_TEXT] + "\n[이하 생략]"
        prefix = self._messages_url(scope_id) + f"/{quote(str(m['id']), safe='')}/hostedContents/"
        hosted = [u for u in images if u.startswith(prefix) and u.endswith("/$value")]
        return text, hosted[:MAX_IMAGES]

    def image(self, access_token: str, notice: Notice, image_id: str) -> bytes:
        prefix = (
            self._messages_url(notice.scope_id) + f"/{quote(notice.id, safe='')}/hostedContents/"
        )
        if not image_id.startswith(prefix) or not image_id.endswith("/$value"):
            raise Unavailable("image url does not belong to this notice")
        try:
            r = self.http.get(image_id, headers={"Authorization": "Bearer " + access_token})
        except httpx.HTTPError as error:
            raise Unavailable(type(error).__name__) from None
        if r.status_code == 401:
            raise AccessDenied("graph 401")
        if r.status_code != 200:
            raise Unavailable(f"image {r.status_code}")
        if r.headers.get("content-type", "").split(";")[0] not in IMAGE_TYPES:
            raise Unavailable("not an image")
        if len(r.content) > MAX_IMAGE_BYTES:
            raise Unavailable("image too large")
        return r.content
