"""FastAPI dependency callables: authentication, role gates, lab gate, audit."""
from __future__ import annotations

from typing import Annotated, Callable

from fastapi import Depends, Header, HTTPException, Request, status

from .config import settings
from .database import workbench_users
from .models import WorkbenchUser
from .security import decode_token
from .services.rbac import TOOL_PERMISSIONS


# ─── Lab gate ────────────────────────────────────────────────────────────
def require_lab_mode() -> None:
    """404 every /api/vuln/* route unless WM_LAB_MODE=1."""
    if settings.lab_mode != 1:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


# ─── Token extraction ────────────────────────────────────────────────────
def _extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


# ─── Current user ────────────────────────────────────────────────────────
def current_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> WorkbenchUser:
    """
    Resolve the authenticated workbench user. Accepts either:
      * `Authorization: Bearer <jwt>`  (preferred, used by the SPA)
      * `wm_session` cookie            (convenience for curl / the OpenAPI UI)
    """
    token = _extract_bearer(authorization) or request.cookies.get("wm_session")
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        claims = decode_token(token)
    except Exception as exc:                       # noqa: BLE001 — map all JWT errors to 401
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}") from exc

    user = workbench_users.get(int(claims["sub"])) if str(claims["sub"]).isdigit() else None
    if user is None:
        # `sub` is the username string in some flows; fall back to a scan.
        matches = workbench_users.where(lambda u: u.username == claims["sub"])
        user = matches[0] if matches else None
    if user is None:
        raise HTTPException(status_code=401, detail="Account no longer exists")

    return user


CurrentUser = Annotated[WorkbenchUser, Depends(current_user)]


# ─── Role gate ───────────────────────────────────────────────────────────
def require_permission(permission: str) -> Callable[[WorkbenchUser], WorkbenchUser]:
    """Return a dependency that 403s unless the caller's role grants `permission`."""

    allowed_roles = TOOL_PERMISSIONS.get(permission, [])

    def _dep(user: CurrentUser) -> WorkbenchUser:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{user.role}' lacks permission '{permission}'",
            )
        return user

    return _dep


# ─── Client IP ───────────────────────────────────────────────────────────
def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"