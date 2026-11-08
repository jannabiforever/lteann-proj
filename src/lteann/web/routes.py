"""HTTP -> service calls. Each handler validates, calls one service method, returns dataclasses."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from ..domain import KST, PersonalTask, Preferences, Scope, User, UserEventState
from ..ports import AccessDenied, AuthError
from ..service import Item, Service
from .deps import clear_cookie, current_user, service_of, session_token, set_cookie, settings_of
from .schemas import EventStateIn, PreferencesIn, TaskIn, TaskStateIn, TaskUpdateIn

router = APIRouter()
Svc = Annotated[Service, Depends(service_of)]
Me = Annotated[User, Depends(current_user)]
MAX_RANGE = timedelta(days=366)


def date_range(start: date, end: date | None) -> tuple[date, date]:
    end = end or start
    if end < start or end - start > MAX_RANGE:
        raise HTTPException(422, "invalid date range")
    return start, end


# --- auth ---------------------------------------------------------------------


@router.get("/auth/login")
def login(request: Request, service: Svc) -> Response:
    settings = settings_of(request)
    url, ref = service.start_sign_in(settings.callback_url)
    response = RedirectResponse(url, status_code=303)
    set_cookie(response, settings, "lteann_flow", ref, service.policy.flow_ttl)
    return response


@router.get("/auth/callback")
def callback(request: Request, service: Svc) -> Response:
    settings = settings_of(request)
    ref = request.cookies.get("__Host-lteann_flow" if settings.secure_cookies else "lteann_flow")
    try:
        if not ref:
            raise AccessDenied("no flow cookie")
        token = service.finish_sign_in(ref, dict(request.query_params))
    except (AccessDenied, AuthError):
        response = RedirectResponse("/?login=failed", status_code=303)
        clear_cookie(response, settings, "lteann_flow")
        return response
    if old := session_token(request):
        service.sign_out(old)  # one browser, one live session
    response = RedirectResponse("/", status_code=303)
    clear_cookie(response, settings, "lteann_flow")
    set_cookie(response, settings, "lteann_session", token, service.policy.session_ttl)
    return response


@router.post("/auth/logout", status_code=204)
def logout(request: Request, service: Svc) -> Response:
    if token := session_token(request):
        service.sign_out(token)
    response = Response(status_code=204)
    clear_cookie(response, settings_of(request), "lteann_session")
    return response


@router.post("/auth/logout-all", status_code=204)
def logout_all(request: Request, service: Svc, me: Me) -> Response:
    service.sign_out_everywhere(me.id)
    response = Response(status_code=204)
    clear_cookie(response, settings_of(request), "lteann_session")
    return response


# --- reading ------------------------------------------------------------------


@router.get("/api/me")
def me(me: Me) -> User:
    return me


@router.get("/api/scopes")
def scopes(service: Svc, me: Me) -> list[Scope]:
    return service.readable_scopes(me.id)


@router.get("/api/calendar")
def calendar(
    service: Svc, me: Me, start: date, end: date | None = None, hidden: bool = False
) -> list[Item]:
    start, end = date_range(start, end)
    return service.calendar(me.id, start, end, hidden_only=hidden)


@router.get("/api/agenda")
def agenda(service: Svc, me: Me, day: date | None = None) -> list[Item]:
    return service.agenda(me.id, day or service.now().astimezone(KST).date())


@router.get("/api/reviews")
def reviews(service: Svc, me: Me, start: date, end: date | None = None) -> list[Item]:
    start, end = date_range(start, end)
    return service.pending_reviews(me.id, start, end)


# --- shared event state -------------------------------------------------------


@router.patch("/api/events/{event_id}/state")
def event_state(service: Svc, me: Me, event_id: str, body: EventStateIn) -> UserEventState:
    return service.set_event_state(
        me.id,
        event_id,
        completed=body.completed,
        hidden=body.hidden,
        override=body.override.to_period() if body.override else None,
        clear_override=body.clear_override,
    )


# --- personal tasks -----------------------------------------------------------


@router.post("/api/tasks", status_code=201)
def add_task(service: Svc, me: Me, body: TaskIn) -> PersonalTask:
    return service.add_task(me.id, body.to_draft())


@router.put("/api/tasks/{task_id}")
def update_task(service: Svc, me: Me, task_id: str, body: TaskUpdateIn) -> PersonalTask:
    return service.update_task(me.id, task_id, body.to_draft(), body.version)


@router.patch("/api/tasks/{task_id}/state")
def task_state(service: Svc, me: Me, task_id: str, body: TaskStateIn) -> PersonalTask:
    return service.set_task_state(
        me.id, task_id, body.version, completed=body.completed, hidden=body.hidden
    )


@router.delete("/api/tasks/{task_id}", status_code=204)
def delete_task(service: Svc, me: Me, task_id: str, version: int) -> Response:
    service.delete_task(me.id, task_id, version)
    return Response(status_code=204)


# --- preferences --------------------------------------------------------------


@router.get("/api/preferences")
def preferences(service: Svc, me: Me) -> Preferences:
    return service.preferences(me.id)


@router.put("/api/preferences")
def save_preferences(service: Svc, me: Me, body: PreferencesIn) -> Preferences:
    return service.save_preferences(me.id, body.to_preferences())
