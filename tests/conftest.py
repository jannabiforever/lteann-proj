"""Shared fixtures: an injectable clock and a World of fakes over a real SQLite repo."""

from dataclasses import dataclass
from datetime import UTC, date, datetime

import pytest
from cryptography.fernet import Fernet

from lteann.adapters.fakes import FakeCredentials, FakeExtractor, FakeIdentity, FakeSource
from lteann.adapters.repo import Repository
from lteann.domain import Notice, Scope
from lteann.ports import Principal
from lteann.service import Policy, Service

ME = Principal("https://issuer.example", "sub-1", "학생", "s1@example.invalid")
TOKEN = "token:sub-1"
CLS = Scope("c1", "fake", "학급 공지")
ALL = Scope("c2", "fake", "전교 공지")
D = date(2026, 11, 8)
POSTED = datetime(2026, 11, 1, tzinfo=UTC)


@dataclass
class Clock:
    now: datetime = datetime(2026, 11, 8, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


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
def w(tmp_path) -> World:
    return World(tmp_path)
