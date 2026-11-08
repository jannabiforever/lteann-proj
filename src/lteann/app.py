"""Composition root: settings -> adapters -> Service -> FastAPI, plus the poll loop."""

from __future__ import annotations

import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, time, timedelta

from fastapi import FastAPI

from .adapters.fakes import FakeCredentials, FakeExtractor, FakeIdentity, FakeSource
from .adapters.microsoft import MicrosoftAdapter
from .adapters.openai import OpenAIExtractor
from .adapters.repo import Repository
from .config import Settings
from .domain import KST, EventDraft, Notice, Period, Scope
from .ports import Extractor, Principal
from .service import Service
from .web import create_app

log = logging.getLogger(__name__)


class Collector(threading.Thread):
    """Runs collect_all() every interval until stopped. Exceptions are logged, never fatal."""

    def __init__(self, service: Service, interval: timedelta):
        super().__init__(name="collector", daemon=True)
        self.service, self.interval, self.stop = service, interval, threading.Event()

    def run(self) -> None:
        while True:
            try:
                reports = self.service.collect_all()
                log.info(
                    "collector: %d scopes, %d changed",
                    len(reports),
                    sum(r.changed for r in reports),
                )
            except Exception:
                log.exception("collect_all failed; will retry")
            if self.stop.wait(self.interval.total_seconds()):
                return


def demo_service(repo: Repository) -> Service:
    """Fake providers with a few sample notices; the same code path as production otherwise."""
    me = Principal("https://demo.invalid", "demo-student", "미리보기 학생", "demo@example.invalid")
    source, extractor = FakeSource(), FakeExtractor()
    token = "token:demo-student"
    cls, school = (
        Scope("demo-class", "fake", "학급 공지 · 예시"),
        Scope("demo-school", "fake", "전교 공지 · 예시"),
    )
    source.grant(token, cls)
    source.grant(token, school)
    today = datetime.now(KST).date()
    posted = datetime.now(UTC)
    source.posts[cls.id] = [
        Notice("demo-n1", cls.id, "물리학 탐구 보고서 18시까지 제출", (), posted)
    ]
    source.posts[school.id] = [
        Notice("demo-n2", school.id, "동아리 신청 내일 17시 마감", (), posted)
    ]
    extractor.drafts["demo-n1"] = [
        EventDraft("물리학 탐구 보고서 제출", "", Period(today, today, time(18)), "assignment")
    ]
    extractor.drafts["demo-n2"] = [
        EventDraft(
            "동아리 신청 마감",
            "",
            Period(today + timedelta(days=1), today + timedelta(days=1), time(17)),
            "application",
        )
    ]
    return Service(repo, FakeIdentity(me), FakeCredentials(), source, extractor)


def compose(settings: Settings) -> Service:
    repo = Repository(settings.database_path, settings.data_key)
    repo.initialize()
    if settings.demo:
        return demo_service(repo)
    microsoft = MicrosoftAdapter(settings.tenant_id, settings.client_id, settings.client_secret)
    return Service(repo, microsoft, microsoft, microsoft, _extractor(settings))


def _extractor(settings: Settings) -> Extractor:
    return OpenAIExtractor(settings.openai_api_key, settings.openai_model)


def create_application(settings: Settings) -> FastAPI:
    service = compose(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        collector = Collector(service, settings.poll_interval)
        collector.start()
        yield
        collector.stop.set()
        collector.join(timeout=5)

    return create_app(service, settings, lifespan=lifespan)


def main() -> None:
    import uvicorn

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    settings = Settings.from_env()
    settings.database_path.parent.mkdir(parents=True, exist_ok=True)
    host, _, port = settings.origin.removeprefix("http://").removeprefix("https://").partition(":")
    uvicorn.run(create_application(settings), host=host, port=int(port or 8080), access_log=False)
