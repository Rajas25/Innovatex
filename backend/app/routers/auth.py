"""Workbench authentication. Issues a JWT for the assessment tool itself."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response, status

from ..config import settings
from ..database import audit_events, workbench_users
from ..deps import CurrentUser, client_ip
from ..models import AuditEvent, utcnow
from ..schemas import LoginRequest, LoginResponse, WorkbenchUserOut
from ..security import issue_token, new_id, verify_password

router = APIRouter()


def _serialize(user) -> WorkbenchUserOut:
    return WorkbenchUserOut(
        id=user.id, username=user.username,
        full_name=user.full_name, role=user.role,
        last_login_at=user.last_login_at,
    )


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, request: Request, response: Response) -> LoginResponse:
    matches = workbench_users.where(lambda u: u.username == payload.username)
    user = matches[0] if matches else None

    # Constant-time-ish: always run the hash comparison, even on unknown users.
    dummy = "pbkdf2_sha256$600000$00$00"
    stored = user.password_hash if user else dummy
    ok = verify_password(payload.password, stored)

    ip = client_ip(request)
    if user is None or not ok:
        audit_events.insert(new_id("evt"), AuditEvent(
            id=new_id("evt"), ts=utcnow(), actor=payload.username,
            action="workbench.login", target="", result="denied", source_ip=ip,
        ))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid credentials")

    user.last_login_at = utcnow()
    token, claims = issue_token(subject=str(user.id), role=user.role)

    # Also set an HttpOnly cookie for curl / OpenAPI convenience.
    response.set_cookie(
        "wm_session", token,
        httponly=True, samesite="strict", secure=settings.env != "development",
        max_age=settings.token_ttl_seconds, path="/",
    )

    audit_events.insert(new_id("evt"), AuditEvent(
        id=new_id("evt"), ts=utcnow(), actor=user.username,
        action="workbench.login", target="", result="allowed", source_ip=ip,
    ))

    return LoginResponse(
        token=token,
        expires_in=settings.token_ttl_seconds,
        user=_serialize(user),
    )


@router.post("/logout")
async def logout(response: Response) -> dict[str, str]:
    response.delete_cookie("wm_session", path="/")
    return {"status": "logged_out"}


@router.get("/me", response_model=WorkbenchUserOut)
async def me(user: CurrentUser) -> WorkbenchUserOut:
    return _serialize(user)