"""HTTP contract over the fakes. Cookies, status codes, error table, input validation."""

from datetime import timedelta

import pytest
from conftest import CLS, D, World
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from lteann.config import Settings
from lteann.domain import EventDraft, Period
from lteann.web import create_app


@pytest.fixture
def client(w: World):
    settings = Settings(data_key=Fernet.generate_key().decode(), demo=True)
    with TestClient(create_app(w.svc, settings), base_url="http://127.0.0.1:8080") as c:
        yield c


def sign_in(client: TestClient) -> None:
    r = client.get("/auth/login", follow_redirects=False)
    assert r.status_code == 303 and "lteann_flow" in r.cookies
    state = r.headers["location"].split("state=")[1].split("&")[0]
    r = client.get("/auth/callback", params={"state": state, "code": "ok"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert "lteann_session" in client.cookies and "lteann_flow" not in client.cookies


def test_health_and_security_headers(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.headers["X-Frame-Options"] == "DENY"
    assert client.get("/health", headers={"host": "evil.example"}).status_code == 421


def test_unauthenticated_is_401(client):
    assert client.get("/api/me").status_code == 401


def test_sign_in_me_logout(client):
    sign_in(client)
    me = client.get("/api/me").json()
    assert me["name"] == "학생"
    assert [s["id"] for s in client.get("/api/scopes").json()] == ["c2", "c1"]  # sorted by name
    assert client.post("/auth/logout").status_code == 204
    assert client.get("/api/me").status_code == 401


def test_failed_callback_redirects_without_session(client):
    r = client.get(
        "/auth/callback", params={"state": "forged", "code": "ok"}, follow_redirects=False
    )
    assert r.status_code == 303 and r.headers["location"] == "/?login=failed"
    assert "lteann_session" not in client.cookies


def test_agenda_and_review_round_trip(client, w: World):
    sign_in(client)
    w.post("n1", "보고서", [EventDraft("보고서", "", Period(D, D), "assignment")])
    w.svc.collect_scope(CLS)
    [item] = client.get("/api/agenda", params={"day": D.isoformat()}).json()
    assert item["title"] == "보고서" and item["scope"]["name"] == "학급 공지"
    r = client.patch(f"/api/events/{item['id']}/state", json={"completed": True})
    assert r.status_code == 200 and r.json()["completed"] is True
    assert client.patch("/api/events/nope/state", json={"hidden": True}).status_code == 404
    assert (
        client.get(
            "/api/calendar",
            params={"start": D.isoformat(), "end": (D - timedelta(days=1)).isoformat()},
        ).status_code
        == 422
    )


def test_task_crud_with_versions(client):
    sign_in(client)
    r = client.post(
        "/api/tasks", json={"title": "숙제", "start_date": D.isoformat(), "time": "18:00"}
    )
    assert r.status_code == 201
    task = r.json()
    assert task["period"]["at"] == "18:00:00" and task["version"] == 1
    body = {"title": "숙제!", "start_date": D.isoformat(), "version": 1}
    assert client.put(f"/api/tasks/{task['id']}", json=body).json()["version"] == 2
    assert client.put(f"/api/tasks/{task['id']}", json=body).status_code == 409
    assert (
        client.patch(
            f"/api/tasks/{task['id']}/state", json={"version": 2, "completed": True}
        ).status_code
        == 200
    )
    assert client.delete(f"/api/tasks/{task['id']}", params={"version": 3}).status_code == 204
    assert client.delete(f"/api/tasks/{task['id']}", params={"version": 3}).status_code == 409


def test_input_validation(client):
    sign_in(client)
    bad = [
        {"title": "", "start_date": D.isoformat()},
        {
            "title": "x",
            "start_date": D.isoformat(),
            "end_date": (D - timedelta(days=1)).isoformat(),
        },
        {
            "title": "x",
            "start_date": D.isoformat(),
            "display_mode": "selected",
            "selected_dates": ["2000-01-01"],
        },
        {"title": "x", "start_date": D.isoformat(), "extra": 1},
        {"title": "x", "start_date": D.isoformat(), "time": "25:00"},
    ]
    for body in bad:
        assert client.post("/api/tasks", json=body).status_code == 422, body
    assert client.put("/api/preferences", json={"disabled_kinds": ["bogus"]}).status_code == 422
    r = client.put("/api/preferences", json={"disabled_kinds": ["event"]})
    assert r.status_code == 200 and r.json()["disabled_kinds"] == ["event"]


def test_stale_membership_is_reverified_on_request(client, w: World):
    sign_in(client)
    w.clock += timedelta(hours=2)
    w.source.access["token:sub-1"].discard("c2")
    assert [s["id"] for s in client.get("/api/scopes").json()] == ["c1"]
    del w.source.access["token:sub-1"]
    w.clock += timedelta(hours=2)
    assert client.get("/api/scopes").status_code == 401
