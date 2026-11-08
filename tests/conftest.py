"""Shared fixtures. `clock` is an injectable, mutable now()."""

from dataclasses import dataclass
from datetime import UTC, datetime

import pytest


@dataclass
class Clock:
    now: datetime = datetime(2026, 11, 8, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()
