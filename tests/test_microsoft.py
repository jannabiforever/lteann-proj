"""Microsoft adapter against a fake MSAL app and a mocked Graph transport. No network."""

import json
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from lteann.adapters.microsoft import GRAPH, SCOPES, MicrosoftAdapter, TokenApp, parse_html
from lteann.domain import Notice, Scope
from lteann.ports import AccessDenied, AuthError, Unavailable

TENANT, CLIENT, OID, TEAM = (str(uuid4()) for _ in range(4))
TOKEN = "graph-token"
CH_OK, CH_DENIED, CH_FOREIGN = (
    "19:ok@thread.tacv2",
    "19:denied@thread.tacv2",
    "19:foreign@thread.tacv2",
)
MSG_URL = f"{GRAPH}/teams/{TEAM}/channels/19%3Aok%40thread.tacv2/messages"
IMG = f"{MSG_URL}/m1/hostedContents/abc/$value"
NOW = datetime(2026, 11, 8, 9, 0, tzinfo=UTC)
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"


class FakeMsal:
    """Just enough of ConfidentialClientApplication for the adapter's four calls."""

    def __init__(self):
        self.result = {
            "access_token": TOKEN,
            "expires_in": 3600,
            "scope": " ".join(SCOPES),
            "id_token_claims": {
                "tid": TENANT,
                "oid": OID,
                "iss": ISSUER,
                "aud": CLIENT,
                "exp": NOW.timestamp() + 600,
            },
        }
        self.silent = dict(self.result)
        self.accounts = [{"local_account_id": OID}]

    def __call__(self, cache) -> TokenApp:
        self.cache = cache
        return self

    def initiate_auth_code_flow(self, scopes, redirect_uri, prompt):
        return {
            "auth_uri": f"https://login.microsoftonline.com/x?redirect_uri={redirect_uri}",
            "state": "s1",
        }

    def acquire_token_by_auth_code_flow(self, flow, query):
        if query.get("state") != flow["state"]:
            raise ValueError("state mismatch")
        return self.result

    def get_accounts(self):
        return self.accounts

    def acquire_token_silent_with_error(self, scopes, account):
        return self.silent


def graph(request: httpx.Request) -> httpx.Response:
    path, q = request.url.path, request.url.params
    if request.headers.get("authorization") != "Bearer " + TOKEN:
        return httpx.Response(401)
    if path == "/v1.0/me":
        return httpx.Response(
            200,
            json={
                "id": OID.upper(),
                "userType": "Member",
                "displayName": "학생",
                "mail": "s@school.kr",
            },
        )
    if path == "/v1.0/me/joinedTeams":
        return httpx.Response(200, json={"value": [{"id": TEAM, "displayName": "1학년 3반"}]})
    if path == f"/v1.0/teams/{TEAM}/allChannels":
        return httpx.Response(
            200,
            json={
                "value": [
                    {"id": CH_OK, "displayName": "공지"},
                    {"id": CH_DENIED, "displayName": "교사 전용"},
                    {
                        "id": CH_FOREIGN,
                        "displayName": "타교 공유",
                        "tenantId": str(uuid4()),
                        "membershipType": "shared",
                    },
                ]
            },
        )
    if path.endswith("/messages") and q.get("$top") == "1":
        return httpx.Response(
            403 if CH_DENIED in request.url.path.replace("%3A", ":").replace("%40", "@") else 200,
            json={"value": []},
        )
    if path.endswith("/messages"):
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "id": "m1",
                        "messageType": "message",
                        "subject": "보고서",
                        "createdDateTime": "2026-11-01T00:00:00Z",
                        "webUrl": "https://teams.microsoft.com/l/message/1",
                        "body": {
                            "contentType": "html",
                            "content": f'<p>물리  보고서</p><p>18시까지</p><img src="{IMG}"><img src="https://evil.example/x.png">',
                        },
                        "replies": [{"body": {"content": "<div>연장 없음</div>"}}],
                    },
                    {"id": "m2", "messageType": "systemEventMessage"},
                    {
                        "id": "m3",
                        "messageType": "message",
                        "deletedDateTime": "2026-11-02T00:00:00Z",
                        "body": {"content": "x"},
                    },
                ]
            },
        )
    if path.endswith("/hostedContents/abc/$value"):
        return httpx.Response(200, content=b"\x89PNG...", headers={"content-type": "image/png"})
    if path.endswith("/hostedContents/bad/$value"):
        return httpx.Response(200, content=b"<html>", headers={"content-type": "text/html"})
    if path.endswith("/boom"):
        return httpx.Response(503)
    return httpx.Response(404)


@pytest.fixture
def ms():
    msal = FakeMsal()
    adapter = MicrosoftAdapter(
        TENANT,
        CLIENT,
        "secret",
        transport=httpx.MockTransport(graph),
        msal_app=msal,
        now=lambda: NOW,
    )
    adapter.msal = msal  # type: ignore[attr-defined]
    return adapter


def test_parse_html_collapses_whitespace_and_collects_images():
    text, images = parse_html("<p>a   b</p><div>c</div><img src='u'>")
    assert text == "a b\nc" and images == ["u"]


def test_begin_and_finish(ms):
    url, flow = ms.begin("https://app/auth/callback")
    assert "auth_uri" not in url and flow["state"] == "s1"
    principal, grant = ms.finish(flow, {"state": "s1", "code": "c"})
    assert (principal.issuer, principal.subject, principal.name, principal.email) == (
        ISSUER,
        OID,
        "학생",
        "s@school.kr",
    )
    assert grant.access_token == TOKEN and grant.blob["oid"] == OID and "cache" in grant.blob
    with pytest.raises(AuthError):
        ms.finish(flow, {"state": "forged", "code": "c"})


@pytest.mark.parametrize(
    "patch",
    [
        {"tid": str(uuid4())},
        {"iss": "https://login.microsoftonline.com/common/v2.0"},
        {"aud": "other"},
        {"acct": 1},
        {"exp": 1},
    ],
)
def test_finish_rejects_bad_claims(ms, patch):
    ms.msal.result["id_token_claims"].update(patch)
    with pytest.raises(AuthError):
        ms.finish({"state": "s1"}, {"state": "s1", "code": "c"})


def test_finish_requires_scopes_and_member_account(ms):
    ms.msal.result["scope"] = "User.Read"
    with pytest.raises(AccessDenied):
        ms.finish({"state": "s1"}, {"state": "s1", "code": "c"})
    ms.msal.result["scope"] = " ".join(SCOPES)
    ms.msal.result["access_token"] = "other"  # /me will 401 -> not our principal
    with pytest.raises(AccessDenied):
        ms.finish({"state": "s1"}, {"state": "s1", "code": "c"})


def test_refresh_paths(ms):
    blob = {"oid": OID, "cache": None}
    assert ms.refresh(blob).access_token == TOKEN
    ms.msal.silent = {"error": "server_error"}
    with pytest.raises(Unavailable):
        ms.refresh(blob)
    ms.msal.silent = {"error": "invalid_grant"}
    with pytest.raises(AccessDenied):
        ms.refresh(blob)
    ms.msal.accounts = []
    with pytest.raises(AccessDenied):
        ms.refresh(blob)


def test_scopes_keep_only_readable_same_tenant_channels(ms):
    scopes = ms.scopes(TOKEN)
    assert scopes == [Scope(f"{TEAM}/{CH_OK}", "microsoft", "1학년 3반 · 공지")]
    with pytest.raises(AccessDenied):
        ms.scopes("wrong-token")


def test_notices_text_images_and_filters(ms):
    [n] = ms.notices(TOKEN, Scope(f"{TEAM}/{CH_OK}", "microsoft", "x"))
    assert n.id == "m1" and n.url == "https://teams.microsoft.com/l/message/1"
    assert n.text == "제목: 보고서\n물리 보고서\n18시까지\n답글: 연장 없음"
    assert n.image_ids == (IMG,)  # the foreign image url is dropped
    assert n.posted_at == datetime(2026, 11, 1, tzinfo=UTC)


def test_image_fetch_validates_origin_and_type(ms):
    notice = Notice("m1", f"{TEAM}/{CH_OK}", "", (IMG,), NOW)
    assert ms.image(TOKEN, notice, IMG).startswith(b"\x89PNG")
    with pytest.raises(Unavailable):
        ms.image(TOKEN, notice, "https://evil.example/x.png")
    with pytest.raises(Unavailable):
        ms.image(TOKEN, notice, IMG.replace("/abc/", "/bad/"))


def test_graph_errors_map_to_port_exceptions(ms):
    with pytest.raises(Unavailable):
        ms._get(TOKEN, GRAPH + "/boom")
    with pytest.raises(AccessDenied):
        ms._get("bad", GRAPH + "/me")
    offline = MicrosoftAdapter(
        TENANT,
        CLIENT,
        "s",
        transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("down"))),
    )
    with pytest.raises(Unavailable):
        offline._get(TOKEN, GRAPH + "/me")


def test_json_roundtrip_of_flow_and_blob(ms):
    _, flow = ms.begin("https://app/cb")
    _, grant = ms.finish(flow, {"state": "s1", "code": "c"})
    json.dumps(flow)
    json.dumps(grant.blob)
