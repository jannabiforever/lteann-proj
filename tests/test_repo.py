from datetime import UTC, date, datetime, time, timedelta

import pytest
from cryptography.fernet import Fernet

from lteann.adapters.repo import Conflict, Repository
from lteann.adapters.schema import SessionRow, UserRow
from lteann.domain import Event, Notice, Period, PersonalTask, Preferences, Scope, UserEventState
from lteann.ports import Grant, Principal

ME = Principal("https://issuer.example", "sub-1", "학생", "s1@example.invalid")
D = date(2026, 11, 8)


@pytest.fixture
def repo(tmp_path, clock):
    r = Repository(tmp_path / "t.sqlite3", Fernet.generate_key().decode(), now=clock)
    r.initialize()
    r.initialize()  # idempotent
    return r


def test_user_upsert_is_stable_and_encrypted(repo):
    u1 = repo.upsert_user(ME)
    u2 = repo.upsert_user(Principal(ME.issuer, ME.subject, "새 이름", ME.email))
    assert u1.id == u2.id and u2.name == "새 이름"
    with repo.session() as s:
        assert "새 이름" not in s.get(UserRow, u1.id).name_enc


def test_flow_is_one_shot_and_expires(repo, clock):
    ref = repo.store_flow({"state": "x"}, timedelta(minutes=10))
    assert repo.consume_flow(ref) == {"state": "x"}
    assert repo.consume_flow(ref) is None
    ref2 = repo.store_flow({"state": "y"}, timedelta(minutes=10))
    clock.now += timedelta(minutes=11)
    assert repo.consume_flow(ref2) is None


def test_sessions(repo, clock):
    u = repo.upsert_user(ME)
    tok = repo.issue_session(u.id, timedelta(hours=1))
    assert repo.session_user(tok).id == u.id
    assert repo.session_user("nope") is None
    clock.now += timedelta(hours=2)
    assert repo.session_user(tok) is None
    tok2 = repo.issue_session(u.id, timedelta(hours=1))
    repo.revoke_all_sessions(u.id)
    assert repo.session_user(tok2) is None


def test_grants(repo):
    u = repo.upsert_user(ME)
    g = Grant("tok", datetime(2026, 11, 8, 10, 0, tzinfo=UTC), {"subject": "sub-1"})
    repo.save_grant(u.id, "microsoft", g)
    assert repo.grant(u.id, "microsoft") == g
    assert repo.users_with_grant("microsoft") == [u.id]
    repo.deny_grant(u.id, "microsoft")
    assert repo.grant(u.id, "microsoft") is None
    assert repo.users_with_grant("microsoft") == []


def test_memberships_replace_per_provider(repo):
    u = repo.upsert_user(ME)
    a, b = Scope("a", "microsoft", "A"), Scope("b", "microsoft", "B")
    g = Scope("g", "google", "G")
    repo.set_memberships(u.id, "microsoft", [a, b])
    repo.set_memberships(u.id, "google", [g])
    repo.set_memberships(u.id, "microsoft", [b])
    assert sorted(m.scope_id for m in repo.memberships(u.id)) == ["b", "g"]
    assert [m.user_id for m in repo.members("b")] == [u.id]
    assert repo.scopes(["b"]) == [b]


def test_notices_and_events(repo):
    u = repo.upsert_user(ME)
    s = Scope("c1", "microsoft", "학급")
    repo.set_memberships(u.id, "microsoft", [s])
    n = Notice(
        "n1", "c1", "물리 보고서 제출", ("img",), datetime(2026, 11, 1, tzinfo=UTC), "https://x"
    )
    assert repo.notice_fingerprint("n1") is None
    repo.save_notice(n)
    assert repo.notice_fingerprint("n1") == n.fingerprint()
    e = Event("e1", "c1", "n1", "물리 보고서", "18시까지", Period(D, D, time(18, 0)), "assignment")
    repo.save_event(e)
    assert repo.events_for_notice("n1") == [e]
    assert repo.events(["c1"], D - timedelta(days=1), D) == [e]
    assert repo.events(["c1"], D + timedelta(days=1), D + timedelta(days=2)) == []
    assert repo.events([], D, D) == []
    repo.save_event(
        Event("e1", "c1", "n1", "물리 보고서", "", Period(D, D), "assignment", version=2)
    )
    assert repo.events_for_notice("n1")[0].version == 2


def test_event_states(repo):
    u = repo.upsert_user(ME)
    s = Scope("c1", "microsoft", "학급")
    repo.set_memberships(u.id, "microsoft", [s])
    repo.save_event(Event("e1", "c1", "n1", "t", "", Period(D, D), "event"))
    assert repo.event_states(u.id, ["e1"]) == {}
    st = UserEventState(u.id, "e1", 1, completed=True, override=Period(D, D, time(9, 30)))
    repo.save_event_state(st)
    assert repo.event_states(u.id, ["e1"]) == {"e1": st}


def test_tasks_with_optimistic_versions(repo):
    u = repo.upsert_user(ME)
    t = PersonalTask(
        "t1", u.id, "숙제", "", Period(D, D + timedelta(days=2)), "selected", frozenset({D})
    )
    repo.save_task(t, None)
    assert repo.task(u.id, "t1") == t
    assert repo.tasks(u.id, D + timedelta(days=1), D + timedelta(days=1)) == [t]
    t2 = PersonalTask("t1", u.id, "숙제!", "", t.period, version=2)
    repo.save_task(t2, expected_version=1)
    with pytest.raises(Conflict):
        repo.save_task(t2, expected_version=1)
    with pytest.raises(Conflict):
        repo.delete_task(u.id, "t1", 1)
    repo.delete_task(u.id, "t1", 2)
    assert repo.task(u.id, "t1") is None


def test_preferences_default_and_roundtrip(repo):
    u = repo.upsert_user(ME)
    assert repo.preferences(u.id) == Preferences()
    p = Preferences(frozenset({"event"}), frozenset({"c1"}))
    repo.save_preferences(u.id, p)
    assert repo.preferences(u.id) == p


def test_rollback_on_error(repo):
    u = repo.upsert_user(ME)
    with pytest.raises(RuntimeError), repo.session() as s:
        s.add(SessionRow(token_hash="h", user_id=u.id, expires_at=datetime(2100, 1, 1, tzinfo=UTC)))
        s.flush()
        raise RuntimeError
    with repo.session() as s:
        assert s.get(SessionRow, "h") is None


def test_migrations_match_models(repo):
    """Fails when schema.py changed without `alembic revision --autogenerate`."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from lteann.adapters.schema import Base

    with repo.engine.connect() as conn:
        ctx = MigrationContext.configure(conn, opts={"compare_type": True, "render_as_batch": True})
        assert compare_metadata(ctx, Base.metadata) == []
