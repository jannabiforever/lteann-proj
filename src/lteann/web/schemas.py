"""Request bodies. Validate here, then convert to domain types with to_*()."""

from __future__ import annotations

import datetime as dt
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..domain import DisplayMode, Period, Preferences, TaskDraft


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class PeriodIn(Input):
    start_date: date
    end_date: date | None = None
    time: dt.time | None = None

    def to_period(self) -> Period:
        return Period(self.start_date, self.end_date or self.start_date, self.time)

    @model_validator(mode="after")
    def ordered(self) -> PeriodIn:
        if self.end_date and self.end_date < self.start_date:
            raise ValueError("end_date precedes start_date")
        if self.end_date and (self.end_date - self.start_date).days > 3660:
            raise ValueError("period longer than ten years")
        return self


class TaskIn(PeriodIn):
    title: str = Field(min_length=1, max_length=500)
    notes: str = Field(default="", max_length=10000)
    display_mode: DisplayMode = "daily"
    selected_dates: list[date] = Field(default_factory=list, max_length=3660)

    @model_validator(mode="after")
    def dates_inside_period(self) -> TaskIn:
        period = self.to_period()
        if any(not period.covers(d) for d in self.selected_dates):
            raise ValueError("selected_dates must fall inside the period")
        return self

    def to_draft(self) -> TaskDraft:
        return TaskDraft(
            self.title,
            self.notes,
            self.to_period(),
            self.display_mode,
            frozenset(self.selected_dates),
        )


class TaskUpdateIn(TaskIn):
    version: int = Field(ge=1)


class TaskStateIn(Input):
    version: int = Field(ge=1)
    completed: bool | None = None
    hidden: bool | None = None

    @model_validator(mode="after")
    def something_to_change(self) -> TaskStateIn:
        if self.completed is None and self.hidden is None:
            raise ValueError("supply completed or hidden")
        return self


class EventStateIn(Input):
    completed: bool | None = None
    hidden: bool | None = None
    override: PeriodIn | None = None
    clear_override: bool = False


class PreferencesIn(Input):
    disabled_kinds: list[Literal["assignment", "application", "event"]] = Field(
        default_factory=list
    )
    disabled_scopes: list[str] = Field(default_factory=list, max_length=500)

    def to_preferences(self) -> Preferences:
        return Preferences(frozenset(self.disabled_kinds), frozenset(self.disabled_scopes))
