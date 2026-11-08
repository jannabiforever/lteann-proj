"""OpenAI extractor against a mocked transport: request shape in, drafts out."""

import base64
import json
from datetime import UTC, date, datetime, time

import httpx
import pytest

from lteann.adapters.openai import SCHEMA, OpenAIExtractor
from lteann.domain import Event, EventDraft, Notice, Period
from lteann.ports import Unavailable

NOTICE = Notice(
    "n1", "s1", "물리 보고서 내일 18시까지 제출", ("img",), datetime(2026, 11, 8, 3, 0, tzinfo=UTC)
)
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
PREV = Event(
    "e1",
    "s1",
    "n1",
    "물리 보고서",
    "",
    Period(date(2026, 11, 8), date(2026, 11, 8), time(17)),
    "assignment",
)


def completion(events=None, *, refusal=None, status=200):
    content = json.dumps({"events": events or []}, ensure_ascii=False)
    message = {"role": "assistant", "content": content, "refusal": refusal}
    return httpx.Response(status, json={"choices": [{"message": message}]})


class Recorder:
    def __init__(self, response):
        self.response, self.requests = response, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.response


def extractor(response) -> tuple[OpenAIExtractor, Recorder]:
    rec = Recorder(response)
    return OpenAIExtractor("sk-test", transport=httpx.MockTransport(rec)), rec


def test_schema_is_strict_with_all_fields_required():
    schema = SCHEMA["schema"]
    assert SCHEMA["strict"] and schema["additionalProperties"] is False
    draft = schema["$defs"]["_Draft"]
    assert (
        set(draft["required"]) == set(draft["properties"])
        and draft["additionalProperties"] is False
    )


def test_request_carries_text_date_previous_and_images():
    ex, rec = extractor(completion())
    ex.extract(NOTICE, [PNG], [PREV])
    [req] = rec.requests
    assert (
        req.headers["authorization"] == "Bearer sk-test"
        and req.url == "https://api.openai.com/v1/chat/completions"
    )
    body = json.loads(req.content)
    assert body["model"] == "gpt-4o-mini" and body["temperature"] == 0
    assert body["response_format"] == {"type": "json_schema", "json_schema": SCHEMA}
    text_part, image_part = body["messages"][1]["content"]
    assert "공지 작성일: 2026-11-08" in text_part["text"]  # 03:00 UTC is still the 8th in KST
    assert (
        "물리 보고서 내일 18시까지 제출" in text_part["text"] and '"id": "e1"' in text_part["text"]
    )
    assert (
        image_part["image_url"]["url"] == "data:image/png;base64," + base64.b64encode(PNG).decode()
    )


def test_drafts_are_parsed_validated_and_matched():
    events = [
        {
            "matches": "e1",
            "title": " 물리 보고서 ",
            "notes": "",
            "start_date": "2026-11-09",
            "end_date": "2026-11-09",
            "time": "18:00",
            "kind": "assignment",
            "cancelled": False,
        },
        {
            "matches": "ghost",
            "title": "동아리 신청",
            "notes": "n",
            "start_date": "2026-11-10",
            "end_date": "2026-11-12",
            "time": None,
            "kind": "application",
            "cancelled": False,
        },
        {
            "matches": None,
            "title": "날짜 오류",
            "notes": "",
            "start_date": "2026-13-40",
            "end_date": "2026-13-40",
            "time": None,
            "kind": "event",
            "cancelled": False,
        },
        {
            "matches": None,
            "title": "거꾸로",
            "notes": "",
            "start_date": "2026-11-10",
            "end_date": "2026-11-09",
            "time": None,
            "kind": "event",
            "cancelled": False,
        },
    ]
    ex, _ = extractor(completion(events))
    drafts = ex.extract(NOTICE, [], [PREV])
    assert drafts == [
        EventDraft(
            "물리 보고서",
            "",
            Period(date(2026, 11, 9), date(2026, 11, 9), time(18)),
            "assignment",
            False,
            "e1",
        ),
        EventDraft(
            "동아리 신청",
            "n",
            Period(date(2026, 11, 10), date(2026, 11, 12)),
            "application",
            False,
            None,
        ),
    ]


def test_refusal_yields_no_drafts_without_raising():
    ex, _ = extractor(completion(refusal="cannot help"))
    assert ex.extract(NOTICE, [], []) == []


@pytest.mark.parametrize(
    "response",
    [completion(status=500), completion(status=401), httpx.Response(200, json={"nope": 1})],
)
def test_provider_failures_are_unavailable(response):
    ex, _ = extractor(response)
    with pytest.raises(Unavailable):
        ex.extract(NOTICE, [], [])


def test_schema_violation_is_unavailable():
    ex, _ = extractor(
        httpx.Response(
            200, json={"choices": [{"message": {"content": '{"events": [{"title": 1}]}'}}]}
        )
    )
    with pytest.raises(Unavailable):
        ex.extract(NOTICE, [], [])


def test_unknown_image_type_is_rejected_before_the_call():
    ex, rec = extractor(completion())
    with pytest.raises(Unavailable):
        ex.extract(NOTICE, [b"not an image"], [])
    assert rec.requests == []


def test_api_key_required():
    with pytest.raises(ValueError):
        OpenAIExtractor("")
