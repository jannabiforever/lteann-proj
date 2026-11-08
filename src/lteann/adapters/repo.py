"""SQLAlchemy repository. The only place that knows tables, encryption and hashing.

Service and domain code see plain dataclasses. Text a person wrote or that came
from a notice is encrypted at rest; dates, ids and scope names are not.
Tokens and flow references are stored hashed; the browser holds the raw value.
Schema changes go through Alembic (src/lteann/migrations); initialize() applies them.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Callable, Generator
from contextlib import contextmanager
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Any, cast

from cryptography.fernet import Fernet
from sqlalchemy import CursorResult, Engine, create_engine, delete, event, select, update
from sqlalchemy.orm import Session

from ..domain import (
    DisplayMode,
    Event,
    Kind,
    Membership,
    Notice,
    Period,
    PersonalTask,
    Preferences,
    Scope,
    User,
    UserEventState,
)
from ..ports import Blob, Flow, Grant, Principal
from .schema import (
    AuthFlowRow,
    CredentialRow,
    EventRow,
    EventStateRow,
    MembershipRow,
    NoticeRow,
    PreferenceRow,
    ScopeRow,
    SessionRow,
    TaskRow,
    UserRow,
)

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"


class Conflict(Exception):
    """The caller's version is stale. Reload and retry."""


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _period(start: date | None, end: date | None, at: time | None) -> Period | None:
    return Period(start, end, at) if start and end else None


class Repository:
    def __init__(self, path: Path | str, key: str, now: Callable[[], datetime] | None = None):
        self.url = f"sqlite:///{Path(path).as_posix()}"
        self.engine: Engine = create_engine(self.url)
        event.listen(self.engine, "connect", _sqlite_pragmas)
        self.fernet = Fernet(key)
        self.now = now or (lambda: datetime.now(UTC))

    # --- plumbing -------------------------------------------------------------

    @contextmanager
    def session(self) -> Generator[Session]:
        """One transaction: commits on success, rolls back on any exception."""
        with Session(self.engine) as s, s.begin():
            yield s

    def initialize(self) -> None:
        """Apply pending Alembic migrations. Safe to call on every start."""
        from alembic import command
        from alembic.config import Config

        cfg = Config()
        cfg.set_main_option("script_location", str(MIGRATIONS))
        cfg.set_main_option("sqlalchemy.url", self.url)
        command.upgrade(cfg, "head")

    def seal(self, text: str) -> str:
        return self.fernet.encrypt(text.encode()).decode()

    def open(self, token: str) -> str:
        return self.fernet.decrypt(token.encode()).decode()

    # --- users, flows, sessions ----------------------------------------------

    def upsert_user(self, p: Principal) -> User:
        with self.session() as s:
            row = s.scalar(
                select(UserRow).where(UserRow.issuer == p.issuer, UserRow.subject == p.subject)
            )
            if row is None:
                row = UserRow(id=secrets.token_urlsafe(16), issuer=p.issuer, subject=p.subject)
                s.add(row)
            row.name_enc, row.email_enc = self.seal(p.name), self.seal(p.email)
            user_id = row.id
        return User(user_id, p.issuer, p.subject, p.name, p.email)

    def user(self, user_id: str) -> User | None:
        with self.session() as s:
            row = s.get(UserRow, user_id)
            return self._user(row) if row else None

    def _user(self, r: UserRow) -> User:
        return User(r.id, r.issuer, r.subject, self.open(r.name_enc), self.open(r.email_enc))

    def store_flow(self, flow: Flow, ttl: timedelta) -> str:
        ref = secrets.token_urlsafe(32)
        with self.session() as s:
            s.add(
                AuthFlowRow(
                    ref_hash=_hash(ref),
                    flow_enc=self.seal(json.dumps(flow)),
                    expires_at=self.now() + ttl,
                )
            )
        return ref

    def consume_flow(self, ref: str) -> Flow | None:
        """One-shot: the flow is deleted whether or not it was still valid."""
        with self.session() as s:
            s.execute(delete(AuthFlowRow).where(AuthFlowRow.expires_at <= self.now()))
            row = s.get(AuthFlowRow, _hash(ref))
            if row is None:
                return None
            flow = json.loads(self.open(row.flow_enc))
            s.delete(row)
            return flow

    def issue_session(self, user_id: str, ttl: timedelta) -> str:
        token = secrets.token_urlsafe(32)
        with self.session() as s:
            s.add(SessionRow(token_hash=_hash(token), user_id=user_id, expires_at=self.now() + ttl))
        return token

    def session_user(self, token: str) -> User | None:
        with self.session() as s:
            row = s.scalar(
                select(UserRow)
                .join(SessionRow, SessionRow.user_id == UserRow.id)
                .where(SessionRow.token_hash == _hash(token), SessionRow.expires_at > self.now())
            )
            return self._user(row) if row else None

    def revoke_session(self, token: str) -> None:
        with self.session() as s:
            s.execute(delete(SessionRow).where(SessionRow.token_hash == _hash(token)))

    def revoke_all_sessions(self, user_id: str) -> None:
        with self.session() as s:
            s.execute(delete(SessionRow).where(SessionRow.user_id == user_id))

    # --- provider credentials -------------------------------------------------

    def save_grant(self, user_id: str, provider: str, grant: Grant) -> None:
        with self.session() as s:
            s.merge(
                CredentialRow(
                    user_id=user_id,
                    provider=provider,
                    blob_enc=self.seal(json.dumps(grant.blob)),
                    access_token_enc=self.seal(grant.access_token),
                    expires_at=grant.expires_at,
                    denied=False,
                )
            )

    def grant(self, user_id: str, provider: str) -> Grant | None:
        """None when absent or denied. Callers compare expires_at to decide on refresh."""
        with self.session() as s:
            row = s.get(CredentialRow, (user_id, provider))
            if row is None or row.denied:
                return None
            blob: Blob = json.loads(self.open(row.blob_enc))
            return Grant(self.open(row.access_token_enc), row.expires_at, blob)

    def deny_grant(self, user_id: str, provider: str) -> None:
        with self.session() as s:
            row = s.get(CredentialRow, (user_id, provider))
            if row:
                row.denied = True

    def users_with_grant(self, provider: str) -> list[str]:
        with self.session() as s:
            q = select(CredentialRow.user_id).where(
                CredentialRow.provider == provider, ~CredentialRow.denied
            )
            return list(s.scalars(q))

    # --- scopes and membership ------------------------------------------------

    def set_memberships(self, user_id: str, provider: str, scopes: list[Scope]) -> None:
        """Replace this user's verified scopes for one provider, as of now."""
        now = self.now()
        with self.session() as s:
            for sc in scopes:
                s.merge(ScopeRow(id=sc.id, provider=sc.provider, name=sc.name))
            s.flush()
            s.execute(
                delete(MembershipRow).where(
                    MembershipRow.user_id == user_id,
                    MembershipRow.scope_id.in_(
                        select(ScopeRow.id).where(ScopeRow.provider == provider)
                    ),
                )
            )
            s.add_all(
                MembershipRow(user_id=user_id, scope_id=sc.id, verified_at=now) for sc in scopes
            )

    def memberships(self, user_id: str) -> list[Membership]:
        with self.session() as s:
            rows = s.scalars(select(MembershipRow).where(MembershipRow.user_id == user_id))
            return [Membership(r.user_id, r.scope_id, r.verified_at) for r in rows]

    def scopes(self, scope_ids: list[str] | None = None) -> list[Scope]:
        q = select(ScopeRow).order_by(ScopeRow.name)
        if scope_ids is not None:
            q = q.where(ScopeRow.id.in_(scope_ids))
        with self.session() as s:
            return [Scope(r.id, r.provider, r.name) for r in s.scalars(q)]

    def members(self, scope_id: str) -> list[Membership]:
        with self.session() as s:
            rows = s.scalars(select(MembershipRow).where(MembershipRow.scope_id == scope_id))
            return [Membership(r.user_id, r.scope_id, r.verified_at) for r in rows]

    # --- notices and events ---------------------------------------------------

    def notice_fingerprint(self, notice_id: str) -> str | None:
        with self.session() as s:
            row = s.get(NoticeRow, notice_id)
            return row.fingerprint if row else None

    def save_notice(self, n: Notice) -> None:
        with self.session() as s:
            s.merge(
                NoticeRow(
                    id=n.id,
                    scope_id=n.scope_id,
                    fingerprint=n.fingerprint(),
                    text_enc=self.seal(n.text),
                    image_ids=list(n.image_ids),
                    posted_at=n.posted_at,
                    url=n.url,
                )
            )

    def save_event(self, e: Event) -> None:
        with self.session() as s:
            s.merge(
                EventRow(
                    id=e.id,
                    scope_id=e.scope_id,
                    notice_id=e.notice_id,
                    title_enc=self.seal(e.title),
                    notes_enc=self.seal(e.notes),
                    start_date=e.period.start,
                    end_date=e.period.end,
                    at=e.period.at,
                    kind=e.kind,
                    version=e.version,
                    cancelled=e.cancelled,
                )
            )

    def _event(self, r: EventRow) -> Event:
        return Event(
            r.id,
            r.scope_id,
            r.notice_id,
            self.open(r.title_enc),
            self.open(r.notes_enc),
            Period(r.start_date, r.end_date, r.at),
            cast(Kind, r.kind),
            r.version,
            r.cancelled,
        )

    def events_for_notice(self, notice_id: str) -> list[Event]:
        with self.session() as s:
            q = select(EventRow).where(EventRow.notice_id == notice_id).order_by(EventRow.id)
            return [self._event(r) for r in s.scalars(q)]

    def events(self, scope_ids: list[str], start: date, end: date) -> list[Event]:
        if not scope_ids:
            return []
        q = select(EventRow).where(
            EventRow.scope_id.in_(scope_ids), EventRow.start_date <= end, EventRow.end_date >= start
        )
        with self.session() as s:
            return [self._event(r) for r in s.scalars(q)]

    def event_states(self, user_id: str, event_ids: list[str]) -> dict[str, UserEventState]:
        if not event_ids:
            return {}
        q = select(EventStateRow).where(
            EventStateRow.user_id == user_id, EventStateRow.event_id.in_(event_ids)
        )
        with self.session() as s:
            return {
                r.event_id: UserEventState(
                    r.user_id,
                    r.event_id,
                    r.seen_version,
                    r.completed,
                    r.hidden,
                    _period(r.override_start, r.override_end, r.override_at),
                )
                for r in s.scalars(q)
            }

    def save_event_state(self, st: UserEventState) -> None:
        o = st.override
        with self.session() as s:
            s.merge(
                EventStateRow(
                    user_id=st.user_id,
                    event_id=st.event_id,
                    seen_version=st.seen_version,
                    completed=st.completed,
                    hidden=st.hidden,
                    override_start=o.start if o else None,
                    override_end=o.end if o else None,
                    override_at=o.at if o else None,
                )
            )

    # --- personal tasks and preferences --------------------------------------

    def _task(self, r: TaskRow) -> PersonalTask:
        return PersonalTask(
            r.id,
            r.user_id,
            self.open(r.title_enc),
            self.open(r.notes_enc),
            Period(r.start_date, r.end_date, r.at),
            cast(DisplayMode, r.display_mode),
            frozenset(date.fromisoformat(d) for d in r.selected_dates),
            r.version,
            r.completed,
            r.hidden,
        )

    def _task_values(self, t: PersonalTask) -> dict[str, Any]:
        return {
            "title_enc": self.seal(t.title),
            "notes_enc": self.seal(t.notes),
            "start_date": t.period.start,
            "end_date": t.period.end,
            "at": t.period.at,
            "display_mode": t.display_mode,
            "selected_dates": sorted(d.isoformat() for d in t.selected_dates),
            "version": t.version,
            "completed": t.completed,
            "hidden": t.hidden,
        }

    def task(self, user_id: str, task_id: str) -> PersonalTask | None:
        with self.session() as s:
            row = s.get(TaskRow, task_id)
            return self._task(row) if row and row.user_id == user_id else None

    def tasks(self, user_id: str, start: date, end: date) -> list[PersonalTask]:
        q = select(TaskRow).where(
            TaskRow.user_id == user_id, TaskRow.start_date <= end, TaskRow.end_date >= start
        )
        with self.session() as s:
            return [self._task(r) for r in s.scalars(q)]

    def save_task(self, t: PersonalTask, expected_version: int | None) -> None:
        """expected_version None inserts; otherwise the stored row must match or Conflict."""
        with self.session() as s:
            if expected_version is None:
                s.add(TaskRow(id=t.id, user_id=t.user_id, **self._task_values(t)))
                return
            result = cast(
                CursorResult[Any],
                s.execute(
                    update(TaskRow)
                    .where(
                        TaskRow.id == t.id,
                        TaskRow.user_id == t.user_id,
                        TaskRow.version == expected_version,
                    )
                    .values(**self._task_values(t))
                ),
            )
            if result.rowcount != 1:
                raise Conflict()

    def delete_task(self, user_id: str, task_id: str, expected_version: int) -> None:
        with self.session() as s:
            result = cast(
                CursorResult[Any],
                s.execute(
                    delete(TaskRow).where(
                        TaskRow.id == task_id,
                        TaskRow.user_id == user_id,
                        TaskRow.version == expected_version,
                    )
                ),
            )
            if result.rowcount != 1:
                raise Conflict()

    def preferences(self, user_id: str) -> Preferences:
        with self.session() as s:
            row = s.get(PreferenceRow, user_id)
            if row is None:
                return Preferences()
            return Preferences(frozenset(row.disabled_kinds), frozenset(row.disabled_scopes))

    def save_preferences(self, user_id: str, p: Preferences) -> None:
        with self.session() as s:
            s.merge(
                PreferenceRow(
                    user_id=user_id,
                    disabled_kinds=sorted(p.disabled_kinds),
                    disabled_scopes=sorted(p.disabled_scopes),
                )
            )


def _sqlite_pragmas(dbapi_connection, _record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()
