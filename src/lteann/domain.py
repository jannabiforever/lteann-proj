"""Pure domain model and rules. No I/O, no framework imports.

Invariants every adapter must keep (these outlive the code):
1. Only delegated, user-granted provider permissions. Never app-wide tokens.
2. A user sees a scope's events only while their own membership is freshly verified.
3. Issuer, audience and expiry of every identity token are checked server-side.
4. Email is display data. The principal key is (issuer, subject).
5. The browser holds only random references. Secrets stay encrypted server-side.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import date, datetime, time, timedelta, timezone
from typing import Literal

KST = timezone(timedelta(hours=9))

Kind = Literal["assignment", "application", "event"]
DisplayMode = Literal["daily", "selected", "final"]


# --- identity -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class User:
    id: str
    issuer: str
    subject: str
    name: str
    email: str  # display only, never an authorization key


@dataclass(frozen=True, slots=True)
class Scope:
    """A source of shared notices: a Teams channel today, a Classroom course later."""

    id: str
    provider: str
    name: str


@dataclass(frozen=True, slots=True)
class Membership:
    """Proof, obtained with the user's own token, that they can read a scope."""

    user_id: str
    scope_id: str
    verified_at: datetime


def membership_is_fresh(membership: Membership, now: datetime, max_age: timedelta) -> bool:
    return now - membership.verified_at <= max_age


# --- shared content -----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Notice:
    """A raw post as collected from a scope. Extraction happens elsewhere."""

    id: str
    scope_id: str
    text: str
    image_ids: tuple[str, ...]
    posted_at: datetime
    url: str | None = None

    def fingerprint(self) -> str:
        """Changes iff the content the extractor would see changes."""
        h = hashlib.sha256(self.text.encode())
        for image_id in self.image_ids:
            h.update(b"\0" + image_id.encode())
        return h.hexdigest()


@dataclass(frozen=True, slots=True)
class Period:
    start: date
    end: date
    at: time | None = None  # None means all-day

    def __post_init__(self) -> None:
        if self.end < self.start:
            raise ValueError("Period end precedes start")

    def covers(self, day: date) -> bool:
        return self.start <= day <= self.end

    def anchor(self, tz: timezone = KST) -> datetime:
        """The instant reminders count back from.

        ponytail: anchored at start; split assignments to end if users ask.
        """
        return datetime.combine(self.start, self.at or time(0), tz)


@dataclass(frozen=True, slots=True)
class Event:
    """Extracted from one notice; shared by every member of its scope."""

    id: str
    scope_id: str
    notice_id: str
    title: str
    notes: str
    period: Period
    kind: Kind
    version: int = 1
    cancelled: bool = False


@dataclass(frozen=True, slots=True)
class EventDraft:
    """Extractor output. `matches` is a suggestion; a domain rule confirms it."""

    title: str
    notes: str
    period: Period
    kind: Kind
    cancelled: bool = False
    matches: str | None = None  # id of a previous Event this is an update of


# --- per-user state -----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UserEventState:
    """One user's view of a shared event. Never visible to other users."""

    user_id: str
    event_id: str
    seen_version: int
    completed: bool = False
    hidden: bool = False
    override: Period | None = None


@dataclass(frozen=True, slots=True)
class PersonalTask:
    id: str
    user_id: str
    title: str
    notes: str
    period: Period
    display_mode: DisplayMode = "daily"
    selected_dates: frozenset[date] = frozenset()
    version: int = 1
    completed: bool = False
    hidden: bool = False

    def __post_init__(self) -> None:
        if any(not self.period.covers(d) for d in self.selected_dates):
            raise ValueError("Selected dates must be inside the task period")


@dataclass(frozen=True, slots=True)
class TaskDraft:
    """What a user types to create or edit a personal task."""

    title: str
    notes: str
    period: Period
    display_mode: DisplayMode = "daily"
    selected_dates: frozenset[date] = frozenset()


@dataclass(frozen=True, slots=True)
class Preferences:
    disabled_kinds: frozenset[str] = frozenset()
    disabled_scopes: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class ReminderRule:
    offsets_minutes: tuple[int, ...] = (-1440, -60)  # <= 0, relative to anchor
    custom_times: tuple[datetime, ...] = ()  # absolute, timezone-aware


# --- rules --------------------------------------------------------------------


def effective_period(event: Event, state: UserEventState | None) -> Period:
    return state.override if state and state.override else event.period


def needs_review(event: Event, state: UserEventState | None) -> bool:
    """A change is reviewed only when the user already engaged with the event."""
    return state is not None and state.seen_version < event.version


def event_visible(event: Event, state: UserEventState | None, prefs: Preferences) -> bool:
    if state and state.hidden:
        return False
    return event.scope_id not in prefs.disabled_scopes and event.kind not in prefs.disabled_kinds


def task_appears_on(task: PersonalTask, day: date) -> bool:
    """Today-list rule. The final day always appears; past days never move forward."""
    if not task.period.covers(day):
        return False
    if day == task.period.end or task.display_mode == "daily":
        return True
    return task.display_mode == "selected" and day in task.selected_dates


def agenda_sort_key(period: Period, source: str, item_id: str) -> tuple[time, str, str]:
    return (period.at or time.max, source, item_id)


def reminder_times(period: Period, rule: ReminderRule) -> list[datetime]:
    anchor = period.anchor()
    times = {anchor + timedelta(minutes=m) for m in rule.offsets_minutes}
    times.update(rule.custom_times)
    return sorted(times)


def due_reminders(
    period: Period, rule: ReminderRule, now: datetime, already_sent: set[datetime]
) -> list[datetime]:
    """Computed each tick; no queue to rebuild when rules change."""
    return [t for t in reminder_times(period, rule) if t <= now and t not in already_sent]


def apply_drafts(
    previous: list[Event], drafts: list[EventDraft], notice: Notice, new_id: Callable[[], str]
) -> list[Event]:
    """Reconcile one notice's stored events with a fresh extraction.

    Returns every event that should exist afterwards. A matched event keeps its
    id (so user state survives) and bumps its version only if content changed.
    Previous events no drafts claim are cancelled, never deleted.

    ponytail: a match is trusted when it names one of this notice's own events;
    add a title/date plausibility check if the extractor is seen to mislink.
    """
    by_id = {e.id: e for e in previous}
    claimed: set[str] = set()
    result: list[Event] = []
    for d in drafts:
        old = by_id.get(d.matches) if d.matches and d.matches not in claimed else None
        if old is None:
            result.append(
                Event(
                    new_id(),
                    notice.scope_id,
                    notice.id,
                    d.title,
                    d.notes,
                    d.period,
                    d.kind,
                    1,
                    d.cancelled,
                )
            )
            continue
        claimed.add(old.id)
        updated = replace(
            old, title=d.title, notes=d.notes, period=d.period, kind=d.kind, cancelled=d.cancelled
        )
        result.append(old if updated == old else replace(updated, version=old.version + 1))
    for old in previous:
        if old.id not in claimed and not old.cancelled:
            result.append(replace(old, cancelled=True, version=old.version + 1))
    return result
