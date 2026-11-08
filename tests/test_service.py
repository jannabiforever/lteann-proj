"""Use-case tests: fakes for providers, a real SQLite repository underneath."""

from datetime import UTC, date, datetime, time, timedelta

import pytest
from cryptography.fernet import Fernet

from lteann.adapters.fakes import FakeCredentials, FakeExtractor, FakeIdentity, FakeSource
from lteann.adapters.repo import Conflict, Repository
from lteann.domain import EventDraft, Kind, Notice, Period, Preferences, Scope, TaskDraft
from lteann.ports import AccessDenied, Principal
from lteann.service import NotFound, Policy, Service

ME = Principal("https://issuer.example", "sub-1", "학생", "s1@example.invalid")
TOKEN = "token:sub-1"
CLS = Scope("c1", "fake", "학급 공지")
ALL = Scope("c2", "fake", "전교 공지")
D = date(2026, 11, 8)
POSTED = datetime(2026, 11, 1, tzinfo=UTC)


class World:
    def __init__(self, tmp_path):
        self.clock = datetime(2026, 11, 8, 9, 0, tzinfo=UTC)
        self.repo = Repository(
            tmp_path / "s.sqlite3", Fernet.generate_key().decode(), now=lambda: self.clock
        )
        self.repo.initialize()
        self.source, self.extractor = FakeSource(), FakeExtractor()
        self.source.grant(TOKEN, CLS)
        self.source.grant(TOKEN, ALL)
        self.ids = iter(f"id{i}" for i in range(1000))
        self.svc = Service(
            self.repo,
            FakeIdentity(ME),
            FakeCredentials(now=lambda: self.clock),
            self.source,
            self.extractor,
            Policy(),
            now=lambda: self.clock,
            new_id=lambda: next(self.ids),
        )

    def sign_in(self) -> tuple[str, str]:
        url, ref = self.svc.start_sign_in("https://app/cb")
        state = url.split("state=")[1].split("&")[0]
        session = self.svc.finish_sign_in(ref, {"state": state, "code": "ok"})
        user = self.svc.current_user(session)
        assert user is not None
        return session, user.id

    def post(self, notice_id, text, drafts, scope=CLS, images=()):
        self.source.posts.setdefault(scope.id, []).append(
            Notice(notice_id, scope.id, text, tuple(images), POSTED)
        )
        self.extractor.drafts[notice_id] = drafts


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def draft(title="물리 보고서", day=D, at=time(18, 0), kind: Kind = "assignment", matches=None):
    return EventDraft(title, "", Period(day, day, at), kind, matches=matches)


def test_sign_in_creates_session_grant_and_memberships(w):
    session, uid = w.sign_in()
    assert w.svc.current_user(session).name == "학생"
    assert sorted(s.id for s in w.svc.readable_scopes(uid)) == ["c1", "c2"]
    assert w.svc.access_token(uid) == TOKEN
    w.svc.sign_out(session)
    assert w.svc.current_user(session) is None


def test_sign_in_with_bad_flow_persists_nothing(w):
    with pytest.raises(AccessDenied):
        w.svc.finish_sign_in("no-such-ref", {"state": "x", "code": "ok"})


def test_memberships_expire_and_reverify(w):
    _, uid = w.sign_in()
    w.clock += timedelta(hours=7)
    assert w.svc.readable_scopes(uid) == []
    w.source.access[TOKEN].discard("c2")
    assert [s.id for s in w.svc.verify_memberships(uid)] == ["c1"]
    assert [s.id for s in w.svc.readable_scopes(uid)] == ["c1"]


def test_lost_access_denies_grant_and_clears_memberships(w):
    _, uid = w.sign_in()
    del w.source.access[TOKEN]
    with pytest.raises(AccessDenied):
        w.svc.verify_memberships(uid)
    assert w.svc.readable_scopes(uid) == []


def test_token_refresh_near_expiry(w):
    _, uid = w.sign_in()
    w.clock = datetime(2099, 12, 31, 23, 59, tzinfo=UTC)  # inside refresh margin of FAR_FUTURE
    assert w.svc.access_token(uid) == TOKEN
    assert w.repo.grant(uid, "fake").expires_at > w.clock


def test_collect_extracts_only_changed_notices(w):
    _, uid = w.sign_in()
    w.post("n1", "보고서 제출", [draft()])
    r1 = w.svc.collect_scope(CLS)
    assert (r1.notices, r1.changed) == (1, 1)
    r2 = w.svc.collect_scope(CLS)
    assert (r2.notices, r2.changed) == (1, 0)
    assert w.extractor.calls == ["n1"]
    items = w.svc.agenda(uid, D)
    assert [(i.title, i.scope.name) for i in items] == [("물리 보고서", "학급 공지")]


def test_collect_skips_scope_without_fresh_member(w):
    w.post("n1", "x", [draft()])
    assert w.svc.collect_scope(CLS).skipped == "no fresh member token"


def test_reextraction_keeps_identity_and_flags_review_only_if_engaged(w):
    _, uid = w.sign_in()
    w.post("n1", "보고서 제출 18시", [draft()])
    w.svc.collect_scope(CLS)
    eid = w.svc.agenda(uid, D)[0].id
    # user engages with the event
    w.svc.set_event_state(uid, eid, completed=True)
    # notice edited: time moved; extractor links it to the old event
    w.source.posts["c1"] = [Notice("n1", "c1", "보고서 제출 20시", (), POSTED)]
    w.extractor.drafts["n1"] = [draft(at=time(20, 0), matches=eid)]
    w.svc.collect_scope(CLS)
    [item] = w.svc.agenda(uid, D)
    assert item.id == eid and item.period.at == time(20, 0) and item.version == 2
    assert item.completed and item.needs_review
    w.svc.set_event_state(uid, eid)  # acknowledge
    assert not w.svc.agenda(uid, D)[0].needs_review


def test_notice_removal_cancels_events(w):
    _, uid = w.sign_in()
    w.post("n1", "a", [draft(), draft(title="두번째", day=D + timedelta(days=1))])
    w.svc.collect_scope(CLS)
    first, second = w.svc.calendar(uid, D, D + timedelta(days=1))
    w.source.posts["c1"] = [Notice("n1", "c1", "a (edited)", (), POSTED)]
    w.extractor.drafts["n1"] = [draft(matches=first.id)]
    w.svc.collect_scope(CLS)
    by_id = {i.id: i for i in w.svc.calendar(uid, D, D + timedelta(days=1))}
    assert not by_id[first.id].cancelled and by_id[second.id].cancelled


def test_hidden_and_preferences_filter_shared_events(w):
    _, uid = w.sign_in()
    w.post("n1", "a", [draft()])
    w.post("n2", "b", [draft(title="행사", kind="event")], scope=ALL)
    w.svc.collect_scope(CLS)
    w.svc.collect_scope(ALL)
    assert len(w.svc.agenda(uid, D)) == 2
    w.svc.save_preferences(uid, Preferences(disabled_kinds=frozenset({"event"})))
    assert [i.title for i in w.svc.agenda(uid, D)] == ["물리 보고서"]
    eid = w.svc.agenda(uid, D)[0].id
    w.svc.set_event_state(uid, eid, hidden=True)
    assert w.svc.agenda(uid, D) == []
    assert [i.id for i in w.svc.calendar(uid, D, D, hidden_only=True)] == [eid]


def test_event_state_requires_readable_scope(w):
    _, uid = w.sign_in()
    w.post("n1", "a", [draft()])
    w.svc.collect_scope(CLS)
    eid = w.svc.agenda(uid, D)[0].id
    w.clock += timedelta(hours=7)  # membership stale
    with pytest.raises(NotFound):
        w.svc.set_event_state(uid, eid, completed=True)


def test_personal_task_lifecycle_and_display_rules(w):
    _, uid = w.sign_in()
    last = D + timedelta(days=3)
    t = w.svc.add_task(
        uid, TaskDraft("숙제", "", Period(D, last), "selected", frozenset({D + timedelta(days=1)}))
    )
    assert t.selected_dates == frozenset({D + timedelta(days=1), last})  # final day auto-included
    assert [i.id for i in w.svc.agenda(uid, D)] == []
    assert [i.id for i in w.svc.agenda(uid, D + timedelta(days=1))] == [t.id]
    assert [i.id for i in w.svc.agenda(uid, last)] == [t.id]
    t2 = w.svc.update_task(uid, t.id, TaskDraft("숙제!", "", Period(D, last)), version=1)
    assert t2.version == 2 and [i.id for i in w.svc.agenda(uid, D)] == [t.id]
    with pytest.raises(Conflict):
        w.svc.update_task(uid, t.id, TaskDraft("x", "", Period(D, last)), version=1)
    t3 = w.svc.set_task_state(uid, t.id, 2, completed=True)
    assert t3.completed and w.svc.agenda(uid, D)[0].completed
    w.svc.delete_task(uid, t.id, 3)
    with pytest.raises(NotFound):
        w.svc.set_task_state(uid, t.id, 3, hidden=True)


def test_agenda_is_sorted_by_time_then_source(w):
    _, uid = w.sign_in()
    w.post("n1", "a", [draft(at=time(18, 0)), draft(title="아침", at=time(8, 0))])
    w.svc.collect_scope(CLS)
    w.svc.add_task(uid, TaskDraft("종일", "", Period(D, D)))
    assert [i.title for i in w.svc.agenda(uid, D)] == ["아침", "물리 보고서", "종일"]
