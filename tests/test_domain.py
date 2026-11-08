from dataclasses import replace
from datetime import date, datetime, time, timedelta
from typing import Any

import pytest

from lteann.domain import (
    KST,
    Event,
    Membership,
    Notice,
    Period,
    PersonalTask,
    Preferences,
    ReminderRule,
    UserEventState,
    due_reminders,
    effective_period,
    event_visible,
    membership_is_fresh,
    needs_review,
    reminder_times,
    task_appears_on,
)

D = date(2026, 11, 8)
NOW = datetime(2026, 11, 8, 9, 0, tzinfo=KST)


EVENT = Event("e1", "s1", "n1", "t", "", Period(D, D), "event")
TASK = PersonalTask("t1", "u1", "t", "", Period(D, D + timedelta(days=3)))


def event(**kw: Any) -> Event:
    return replace(EVENT, **kw)


def task(**kw: Any) -> PersonalTask:
    return replace(TASK, **kw)


def test_period_rejects_reversed_dates():
    with pytest.raises(ValueError):
        Period(D, D - timedelta(days=1))


def test_notice_fingerprint_tracks_text_and_images():
    a = Notice("n", "s", "hello", ("img1",), NOW)
    assert a.fingerprint() == Notice("n", "s", "hello", ("img1",), NOW).fingerprint()
    assert a.fingerprint() != Notice("n", "s", "hello", (), NOW).fingerprint()
    assert a.fingerprint() != Notice("n", "s", "hello!", ("img1",), NOW).fingerprint()


def test_membership_freshness():
    m = Membership("u", "s", NOW - timedelta(hours=2))
    assert membership_is_fresh(m, NOW, timedelta(hours=3))
    assert not membership_is_fresh(m, NOW, timedelta(hours=1))


def test_review_only_when_user_engaged():
    e = event(version=2)
    assert not needs_review(e, None)
    assert needs_review(e, UserEventState("u", "e1", seen_version=1))
    assert not needs_review(e, UserEventState("u", "e1", seen_version=2))


def test_override_wins_over_event_period():
    e = event()
    mine = Period(D + timedelta(days=1), D + timedelta(days=1))
    assert effective_period(e, None) == e.period
    assert effective_period(e, UserEventState("u", "e1", 1, override=mine)) == mine


def test_visibility_filters():
    e = event(kind="assignment")
    assert event_visible(e, None, Preferences())
    assert not event_visible(e, UserEventState("u", "e1", 1, hidden=True), Preferences())
    assert not event_visible(e, None, Preferences(disabled_kinds=frozenset({"assignment"})))
    assert not event_visible(e, None, Preferences(disabled_scopes=frozenset({"s1"})))


def test_task_appears_rules():
    last = D + timedelta(days=3)
    assert task_appears_on(task(), D)  # daily
    assert not task_appears_on(task(), D + timedelta(days=4))  # outside
    assert not task_appears_on(task(display_mode="final"), D)
    assert task_appears_on(task(display_mode="final"), last)
    sel = task(display_mode="selected", selected_dates=frozenset({D + timedelta(days=1)}))
    assert task_appears_on(sel, D + timedelta(days=1))
    assert not task_appears_on(sel, D)
    assert task_appears_on(sel, last)  # final day always shows


def test_selected_dates_must_be_inside_period():
    with pytest.raises(ValueError):
        task(display_mode="selected", selected_dates=frozenset({D - timedelta(days=1)}))


def test_reminder_times_and_due():
    p = Period(D, D, time(18, 0))
    rule = ReminderRule(
        offsets_minutes=(-60, -1440), custom_times=(datetime(2026, 11, 8, 12, 0, tzinfo=KST),)
    )
    times = reminder_times(p, rule)
    assert times == [
        datetime(2026, 11, 7, 18, 0, tzinfo=KST),
        datetime(2026, 11, 8, 12, 0, tzinfo=KST),
        datetime(2026, 11, 8, 17, 0, tzinfo=KST),
    ]
    now = datetime(2026, 11, 8, 12, 30, tzinfo=KST)
    assert due_reminders(p, rule, now, set()) == times[:2]
    assert due_reminders(p, rule, now, {times[0]}) == [times[1]]
