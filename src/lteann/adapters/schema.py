"""ORM table definitions. Alembic diffs these against the database.

`*Row` classes are storage shapes, not domain objects. The repository converts.
Columns ending in `_enc` hold Fernet ciphertext; see Repository.seal/open.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time

from sqlalchemy import JSON, Boolean, Date, DateTime, ForeignKey, Index, Integer, String, Text, Time
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


class UTCDateTime(TypeDecorator[datetime]):
    """Aware UTC in Python, naive UTC in the database. Works on SQLite and PostgreSQL."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect) -> datetime | None:
        return value.astimezone(UTC).replace(tzinfo=None) if value else None

    def process_result_value(self, value: datetime | None, dialect) -> datetime | None:
        return value.replace(tzinfo=UTC) if value else None


class Base(DeclarativeBase):
    pass


class UserRow(Base):
    __tablename__ = "users"
    __table_args__ = (Index("users_principal", "issuer", "subject", unique=True),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    issuer: Mapped[str] = mapped_column(String(200))
    subject: Mapped[str] = mapped_column(String(200))
    name_enc: Mapped[str] = mapped_column(Text)
    email_enc: Mapped[str] = mapped_column(Text)


class AuthFlowRow(Base):
    __tablename__ = "auth_flows"
    ref_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    flow_enc: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)


class SessionRow(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)


class CredentialRow(Base):
    __tablename__ = "credentials"
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    provider: Mapped[str] = mapped_column(String(32), primary_key=True)
    blob_enc: Mapped[str] = mapped_column(Text)
    access_token_enc: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    denied: Mapped[bool] = mapped_column(Boolean, default=False)


class ScopeRow(Base):
    __tablename__ = "scopes"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    provider: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(500))


class MembershipRow(Base):
    __tablename__ = "memberships"
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    scope_id: Mapped[str] = mapped_column(
        ForeignKey("scopes.id", ondelete="CASCADE"), primary_key=True
    )
    verified_at: Mapped[datetime] = mapped_column(UTCDateTime)


class NoticeRow(Base):
    __tablename__ = "notices"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    scope_id: Mapped[str] = mapped_column(ForeignKey("scopes.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    text_enc: Mapped[str] = mapped_column(Text)
    image_ids: Mapped[list[str]] = mapped_column(JSON)
    posted_at: Mapped[datetime] = mapped_column(UTCDateTime)
    url: Mapped[str | None] = mapped_column(String(2000))


class EventRow(Base):
    __tablename__ = "events"
    __table_args__ = (Index("events_scope_dates", "scope_id", "start_date", "end_date"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    scope_id: Mapped[str] = mapped_column(ForeignKey("scopes.id", ondelete="CASCADE"))
    notice_id: Mapped[str] = mapped_column(String(200), index=True)
    title_enc: Mapped[str] = mapped_column(Text)
    notes_enc: Mapped[str] = mapped_column(Text)
    start_date: Mapped[date] = mapped_column(Date)
    end_date: Mapped[date] = mapped_column(Date)
    at: Mapped[time | None] = mapped_column(Time)
    kind: Mapped[str] = mapped_column(String(20))
    version: Mapped[int] = mapped_column(Integer)
    cancelled: Mapped[bool] = mapped_column(Boolean, default=False)


class EventStateRow(Base):
    __tablename__ = "event_states"
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[str] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), primary_key=True
    )
    seen_version: Mapped[int] = mapped_column(Integer)
    completed: Mapped[bool] = mapped_column(Boolean, default=False)
    hidden: Mapped[bool] = mapped_column(Boolean, default=False)
    override_start: Mapped[date | None] = mapped_column(Date)
    override_end: Mapped[date | None] = mapped_column(Date)
    override_at: Mapped[time | None] = mapped_column(Time)


class TaskRow(Base):
    __tablename__ = "tasks"
    __table_args__ = (Index("tasks_user_dates", "user_id", "start_date", "end_date"),)
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    title_enc: Mapped[str] = mapped_column(Text)
    notes_enc: Mapped[str] = mapped_column(Text)
    start_date: Mapped[date] = mapped_column(Date)
    end_date: Mapped[date] = mapped_column(Date)
    at: Mapped[time | None] = mapped_column(Time)
    display_mode: Mapped[str] = mapped_column(String(10))
    selected_dates: Mapped[list[str]] = mapped_column(JSON)
    version: Mapped[int] = mapped_column(Integer)
    completed: Mapped[bool] = mapped_column(Boolean, default=False)
    hidden: Mapped[bool] = mapped_column(Boolean, default=False)


class PreferenceRow(Base):
    __tablename__ = "preferences"
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    disabled_kinds: Mapped[list[str]] = mapped_column(JSON)
    disabled_scopes: Mapped[list[str]] = mapped_column(JSON)
