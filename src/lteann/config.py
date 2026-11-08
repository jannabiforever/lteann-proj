"""Process settings from the environment. Validated once at startup, then frozen."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.fernet import Fernet

LOOPBACK = {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True, slots=True)
class Settings:
    data_key: str = field(repr=False)
    origin: str = "http://127.0.0.1:8080"
    database_path: Path = Path("var/lteann.sqlite3")
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = field(default="", repr=False)
    openai_api_key: str = field(default="", repr=False)
    openai_model: str = "gpt-4o-mini"
    poll_interval: timedelta = timedelta(minutes=5)
    demo: bool = False

    def __post_init__(self) -> None:
        Fernet(self.data_key.encode())  # raises if not a valid key
        url = urlsplit(self.origin)
        if url.scheme not in {"http", "https"} or not url.hostname:
            raise ValueError("origin must be an absolute http(s) URL")
        if url.path or url.query or url.fragment or url.username:
            raise ValueError("origin must be scheme://host[:port] only")
        if url.scheme == "http" and url.hostname not in LOOPBACK:
            raise ValueError("plain http is allowed only on loopback")
        entra = (self.tenant_id, self.client_id, self.client_secret)
        if any(entra) and not all(entra):
            raise ValueError("set all three Entra values or none")
        for value in (self.tenant_id, self.client_id):
            if value:
                UUID(value)
        if not self.demo and not all(entra):
            raise ValueError("Entra settings are required unless LTEANN_DEMO=1")
        if not self.demo and not self.openai_api_key:
            raise ValueError("LTEANN_OPENAI_API_KEY is required unless LTEANN_DEMO=1")

    @property
    def secure_cookies(self) -> bool:
        return self.origin.startswith("https://")

    @property
    def host(self) -> str:
        return urlsplit(self.origin).hostname or ""

    @property
    def callback_url(self) -> str:
        return self.origin + "/auth/callback"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        e = os.environ if env is None else env
        return cls(
            data_key=e.get("LTEANN_DATA_KEY", ""),
            origin=e.get("LTEANN_ORIGIN", "http://127.0.0.1:8080"),
            database_path=Path(e.get("LTEANN_DATABASE_PATH", "var/lteann.sqlite3")),
            tenant_id=e.get("LTEANN_ENTRA_TENANT_ID", "").lower(),
            client_id=e.get("LTEANN_ENTRA_CLIENT_ID", "").lower(),
            client_secret=e.get("LTEANN_ENTRA_CLIENT_SECRET", ""),
            openai_api_key=e.get("LTEANN_OPENAI_API_KEY", ""),
            openai_model=e.get("LTEANN_OPENAI_MODEL", "gpt-4o-mini"),
            poll_interval=timedelta(seconds=int(e.get("LTEANN_POLL_SECONDS", "300"))),
            demo=e.get("LTEANN_DEMO") == "1",
        )
