"""Contract tests for the ports, run against the fakes. Real adapters reuse these."""

from datetime import UTC, date, datetime

import pytest

from lteann.adapters.fakes import FakeCredentials, FakeExtractor, FakeIdentity, FakeSource
from lteann.domain import EventDraft, Notice, Period, Scope
from lteann.ports import AccessDenied, AuthError, Principal

ME = Principal("https://issuer.example", "sub-1", "학생", "s1@example.invalid")
NOW = datetime(2026, 11, 8, tzinfo=UTC)


def test_identity_round_trip_checks_state():
    ident = FakeIdentity(ME)
    url, flow = ident.begin("https://app/auth/callback")
    assert url.startswith("https://app/auth/callback?state=")
    state = url.split("state=")[1].split("&")[0]
    principal, grant = ident.finish(flow, {"state": state, "code": "ok"})
    assert principal == ME
    assert grant.access_token and grant.blob
    with pytest.raises(AuthError):
        ident.finish(flow, {"state": "forged", "code": "ok"})


def test_credentials_refresh_and_revocation():
    creds = FakeCredentials()
    grant = creds.refresh({"subject": "sub-1"})
    assert grant.access_token == "token:sub-1"
    creds.revoked.add("sub-1")
    with pytest.raises(AccessDenied):
        creds.refresh({"subject": "sub-1"})


def test_source_enforces_membership():
    src = FakeSource()
    cls = Scope("c1", "fake", "학급 공지")
    src.grant("token:sub-1", cls)
    src.posts["c1"] = [Notice("n1", "c1", "hello", (), NOW)]
    assert src.scopes("token:sub-1") == [cls]
    assert [n.id for n in src.notices("token:sub-1", cls)] == ["n1"]
    with pytest.raises(AccessDenied):
        src.scopes("token:stranger")
    with pytest.raises(AccessDenied):
        src.notices("token:stranger", cls)


def test_extractor_is_scripted():
    d = EventDraft("제출", "", Period(date(2026, 11, 8), date(2026, 11, 8)), "assignment")
    ext = FakeExtractor({"n1": [d]})
    n1 = Notice("n1", "c1", "x", (), NOW)
    assert ext.extract(n1, [], []) == [d]
    assert ext.extract(Notice("n2", "c1", "y", (), NOW), [], []) == []
    assert ext.calls == ["n1", "n2"]
