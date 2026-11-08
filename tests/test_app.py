"""Composition root: demo wiring boots, collects, and core stays free of web frameworks."""

import sys

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from lteann.app import create_application
from lteann.config import Settings


def test_core_does_not_import_web_frameworks():
    for name in [m for m in sys.modules if m.startswith(("fastapi", "starlette", "lteann"))]:
        del sys.modules[name]
    import lteann.adapters.repo
    import lteann.service  # noqa: F401

    assert not {m for m in sys.modules if m.startswith(("fastapi", "starlette"))}


def test_demo_application_boots_and_collects(tmp_path):
    settings = Settings(
        data_key=Fernet.generate_key().decode(), database_path=tmp_path / "demo.sqlite3", demo=True
    )
    app = create_application(settings)
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        assert client.get("/health").json() == {"status": "ok"}
        r = client.get("/auth/login", follow_redirects=False)
        state = r.headers["location"].split("state=")[1].split("&")[0]
        client.get("/auth/callback", params={"state": state, "code": "ok"}, follow_redirects=False)
        reports = app.state.service.collect_all()
        assert sum(r.changed for r in reports) == 2
        assert (
            len(
                client.get(
                    "/api/calendar", params={"start": "2000-01-01", "end": "2000-12-31"}
                ).json()
            )
            == 0
        )
        assert len(client.get("/api/scopes").json()) == 2


def test_settings_validation():
    key = Fernet.generate_key().decode()
    for bad in [
        {"origin": "http://school.example"},  # plain http off loopback
        {"origin": "https://x.example/path"},
        {"tenant_id": "not-a-uuid"},
        {"demo": False},  # entra required
    ]:
        try:
            Settings(data_key=key, **{"demo": True, **bad})
        except ValueError:
            continue
        raise AssertionError(bad)
