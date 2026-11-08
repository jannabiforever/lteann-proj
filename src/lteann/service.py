"""Use cases. Joins ports, repository and domain rules; knows nothing about HTTP.

Every method takes ids and plain dataclasses and returns plain dataclasses.
Authorization lives here: a user reads a scope only through a fresh membership.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime, timedelta

from .adapters.repo import Repository
from .domain import (
    Event,
    Period,
    PersonalTask,
    Preferences,
    Scope,
    TaskDraft,
    User,
    UserEventState,
    agenda_sort_key,
    apply_drafts,
    effective_period,
    event_visible,
    membership_is_fresh,
    needs_review,
    task_appears_on,
)
from .ports import AccessDenied, Credentials, Extractor, Identity, Source, Unavailable


class NotFound(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Policy:
    session_ttl: timedelta = timedelta(hours=8)
    flow_ttl: timedelta = timedelta(minutes=10)
    membership_max_age: timedelta = timedelta(hours=6)
    refresh_margin: timedelta = timedelta(minutes=2)


@dataclass(frozen=True, slots=True)
class Item:
    """One row of a calendar or today list; the read model the web layer renders."""

    source: str  # "shared" | "personal"
    id: str
    title: str
    notes: str
    period: Period
    kind: str
    completed: bool
    hidden: bool
    cancelled: bool
    version: int
    scope: Scope | None = None
    needs_review: bool = False


@dataclass(frozen=True, slots=True)
class CollectReport:
    scope_id: str
    notices: int = 0
    changed: int = 0
    skipped: str | None = None  # why nothing was read, if so


class Service:
    def __init__(
        self,
        repo: Repository,
        identity: Identity,
        credentials: Credentials,
        source: Source,
        extractor: Extractor,
        policy: Policy | None = None,
        now: Callable[[], datetime] | None = None,
        new_id: Callable[[], str] = lambda: secrets.token_urlsafe(12),
    ):
        self.repo, self.identity, self.credentials = repo, identity, credentials
        self.source, self.extractor, self.policy = source, extractor, policy or Policy()
        self.now = now or (lambda: datetime.now(UTC))
        self.new_id = new_id

    # --- sign in / out --------------------------------------------------------

    def start_sign_in(self, redirect_url: str) -> tuple[str, str]:
        """Return (provider url for the browser, flow reference for a short cookie)."""
        url, flow = self.identity.begin(redirect_url)
        return url, self.repo.store_flow(flow, self.policy.flow_ttl)

    def finish_sign_in(self, flow_ref: str, query: dict[str, str]) -> str:
        """Return a session token. Raises AuthError/AccessDenied; nothing is persisted then."""
        flow = self.repo.consume_flow(flow_ref)
        if flow is None:
            raise AccessDenied("sign-in flow expired")
        principal, grant = self.identity.finish(flow, query)
        scopes = self.source.scopes(grant.access_token)  # proves the token works before we keep it
        user = self.repo.upsert_user(principal)
        self.repo.save_grant(user.id, self.source.provider, grant)
        self.repo.set_memberships(user.id, self.source.provider, scopes)
        return self.repo.issue_session(user.id, self.policy.session_ttl)

    def current_user(self, session_token: str | None) -> User | None:
        return self.repo.session_user(session_token) if session_token else None

    def sign_out(self, session_token: str) -> None:
        self.repo.revoke_session(session_token)

    def sign_out_everywhere(self, user_id: str) -> None:
        self.repo.revoke_all_sessions(user_id)
        self.repo.deny_grant(user_id, self.source.provider)

    # --- provider connection --------------------------------------------------

    def access_token(self, user_id: str) -> str:
        """A working token, refreshed if near expiry. AccessDenied means re-login."""
        grant = self.repo.grant(user_id, self.source.provider)
        if grant is None:
            raise AccessDenied("no credential")
        if grant.expires_at - self.now() > self.policy.refresh_margin:
            return grant.access_token
        try:
            fresh = self.credentials.refresh(grant.blob)
        except AccessDenied:
            self.repo.deny_grant(user_id, self.source.provider)
            raise
        self.repo.save_grant(user_id, self.source.provider, fresh)
        return fresh.access_token

    def verify_memberships(self, user_id: str) -> list[Scope]:
        """Re-prove, with the user's own token, which scopes they may read."""
        try:
            scopes = self.source.scopes(self.access_token(user_id))
        except AccessDenied:
            self.repo.set_memberships(user_id, self.source.provider, [])
            raise
        self.repo.set_memberships(user_id, self.source.provider, scopes)
        return scopes

    def readable_scopes(self, user_id: str) -> list[Scope]:
        now, max_age = self.now(), self.policy.membership_max_age
        ids = [
            m.scope_id
            for m in self.repo.memberships(user_id)
            if membership_is_fresh(m, now, max_age)
        ]
        return self.repo.scopes(ids) if ids else []

    # --- collection (background, per scope) -----------------------------------

    def collect_scope(self, scope: Scope) -> CollectReport:
        """Read a scope once with any fresh member's token; extract only changed notices."""
        now, max_age = self.now(), self.policy.membership_max_age
        members = [m for m in self.repo.members(scope.id) if membership_is_fresh(m, now, max_age)]
        token = None
        for m in members:
            try:
                token = self.access_token(m.user_id)
                break
            except (AccessDenied, Unavailable):
                continue
        if token is None:
            return CollectReport(scope.id, skipped="no fresh member token")
        try:
            notices = self.source.notices(token, scope)
        except (AccessDenied, Unavailable) as error:
            return CollectReport(scope.id, skipped=type(error).__name__)
        changed = 0
        for notice in notices:
            if self.repo.notice_fingerprint(notice.id) == notice.fingerprint():
                continue
            images = [self.source.image(token, notice, i) for i in notice.image_ids]
            previous = self.repo.events_for_notice(notice.id)
            drafts = self.extractor.extract(notice, images, previous)
            for event in apply_drafts(previous, drafts, notice, self.new_id):
                self.repo.save_event(event)
            self.repo.save_notice(notice)  # after events, so a crash re-extracts next tick
            changed += 1
        return CollectReport(scope.id, notices=len(notices), changed=changed)

    def collect_all(self) -> list[CollectReport]:
        # ponytail: single process; add a per-scope lease in the repo before running two instances.
        return [self.collect_scope(s) for s in self.repo.scopes()]

    # --- reading --------------------------------------------------------------

    def calendar(
        self, user_id: str, start: date, end: date, hidden_only: bool = False
    ) -> list[Item]:
        prefs = self.repo.preferences(user_id)
        scopes = {s.id: s for s in self.readable_scopes(user_id)}
        events = self.repo.events(list(scopes), start, end)
        states = self.repo.event_states(user_id, [e.id for e in events])
        items: list[Item] = []
        for e in events:
            st = states.get(e.id)
            hidden = bool(st and st.hidden)
            if hidden != hidden_only or (not hidden_only and not event_visible(e, st, prefs)):
                continue
            items.append(
                Item(
                    "shared",
                    e.id,
                    e.title,
                    e.notes,
                    effective_period(e, st),
                    e.kind,
                    bool(st and st.completed),
                    hidden,
                    e.cancelled,
                    e.version,
                    scopes[e.scope_id],
                    needs_review(e, st),
                )
            )
        for t in self.repo.tasks(user_id, start, end):
            if t.hidden == hidden_only:
                items.append(
                    Item(
                        "personal",
                        t.id,
                        t.title,
                        t.notes,
                        t.period,
                        "personal",
                        t.completed,
                        t.hidden,
                        False,
                        t.version,
                    )
                )
        return sorted(items, key=lambda i: agenda_sort_key(i.period, i.source, i.id))

    def agenda(self, user_id: str, day: date) -> list[Item]:
        """Today list: shared events on their dates, personal tasks by their display rule."""
        tasks = {t.id: t for t in self.repo.tasks(user_id, day, day)}
        return [
            i
            for i in self.calendar(user_id, day, day)
            if i.source == "shared" or task_appears_on(tasks[i.id], day)
        ]

    def pending_reviews(self, user_id: str, start: date, end: date) -> list[Item]:
        return [i for i in self.calendar(user_id, start, end) if i.needs_review]

    # --- shared event state (per user) ----------------------------------------

    def _readable_event(self, user_id: str, event_id: str) -> Event:
        scope_ids = [s.id for s in self.readable_scopes(user_id)]
        for e in self.repo.events(scope_ids, date.min, date.max):
            if e.id == event_id:
                return e
        raise NotFound(event_id)

    def set_event_state(
        self,
        user_id: str,
        event_id: str,
        *,
        completed: bool | None = None,
        hidden: bool | None = None,
        override: Period | None = None,
        clear_override: bool = False,
    ) -> UserEventState:
        """Any change also acknowledges the current version (clears the review flag)."""
        e = self._readable_event(user_id, event_id)
        st = self.repo.event_states(user_id, [event_id]).get(event_id) or UserEventState(
            user_id, event_id, 0
        )
        st = replace(
            st,
            seen_version=e.version,
            completed=st.completed if completed is None else completed,
            hidden=st.hidden if hidden is None else hidden,
            override=None if clear_override else (override or st.override),
        )
        self.repo.save_event_state(st)
        return st

    # --- personal tasks -------------------------------------------------------

    def _from_draft(self, user_id: str, task_id: str, d: TaskDraft, **kw) -> PersonalTask:
        selected = (
            frozenset(d.selected_dates | {d.period.end})
            if d.display_mode == "selected"
            else frozenset()
        )
        return PersonalTask(
            task_id, user_id, d.title, d.notes, d.period, d.display_mode, selected, **kw
        )

    def add_task(self, user_id: str, draft: TaskDraft) -> PersonalTask:
        task = self._from_draft(user_id, self.new_id(), draft)
        self.repo.save_task(task, None)
        return task

    def update_task(
        self, user_id: str, task_id: str, draft: TaskDraft, version: int
    ) -> PersonalTask:
        """Raises Conflict when `version` is stale; completed/hidden are kept."""
        old = self.repo.task(user_id, task_id)
        if old is None:
            raise NotFound(task_id)
        task = self._from_draft(
            user_id, task_id, draft, version=version + 1, completed=old.completed, hidden=old.hidden
        )
        self.repo.save_task(task, version)
        return task

    def set_task_state(
        self,
        user_id: str,
        task_id: str,
        version: int,
        *,
        completed: bool | None = None,
        hidden: bool | None = None,
    ) -> PersonalTask:
        old = self.repo.task(user_id, task_id)
        if old is None:
            raise NotFound(task_id)
        task = replace(
            old,
            version=version + 1,
            completed=old.completed if completed is None else completed,
            hidden=old.hidden if hidden is None else hidden,
        )
        self.repo.save_task(task, version)
        return task

    def delete_task(self, user_id: str, task_id: str, version: int) -> None:
        self.repo.delete_task(user_id, task_id, version)

    # --- preferences ----------------------------------------------------------

    def preferences(self, user_id: str) -> Preferences:
        return self.repo.preferences(user_id)

    def save_preferences(self, user_id: str, prefs: Preferences) -> Preferences:
        self.repo.save_preferences(user_id, prefs)
        return prefs
