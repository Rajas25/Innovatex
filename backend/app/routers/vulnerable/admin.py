"""WM-004 · Broken function-level authorisation. Admin routes are authenticated
but never authorised. Any logged-in user — including a viewer — reaches them.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import JSONResponse

from ...database import app_users
from ...deps import require_lab_mode

router = APIRouter(dependencies=[Depends(require_lab_mode)])


def _current_app_user(as_user: str | None):
    """Simulated authentication: query param stands in for a session cookie."""
    if as_user:
        matches = app_users.where(lambda u: u.username == as_user)
        if matches:
            return matches[0]
    return app_users.get(3)     # default: viewer


# ═══════════════════════════════════════════════════════════════════════
#  🚨 VULNERABLE — no `require_role("admin")` on any of these routes
# ═══════════════════════════════════════════════════════════════════════
@router.get("/admin/users")
async def list_users(as_user: str | None = None) -> JSONResponse:
    """
    🚨 VULNERABLE — the middleware checks *authentication* only. There is no
    check that the caller holds the `admin` role. Compare with the secure
    version:

        @router.get("/admin/users", dependencies=[Depends(require_role("admin"))])
    """
    caller = _current_app_user(as_user)
    return JSONResponse({
        "_caller": caller.username,
        "_caller_role": caller.role,
        "_authorisation": "NONE — authenticated users reach this route",
        "users": [
            {
                "id": u.id, "username": u.username, "full_name": u.full_name,
                "email": u.email, "role": u.role, "department": u.department,
                "last_login_ip": u.last_login_ip, "created_at": u.created_at,
            }
            for u in app_users.all()
        ],
    })


@router.post("/admin/users/{user_id}/role")
async def update_role(
    user_id: int,
    as_user: str | None = None,
    body: dict[str, Any] = Body(default_factory=dict),
) -> JSONResponse:
    """🚨 VULNERABLE — any authenticated user can change any role, including their own."""
    caller = _current_app_user(as_user)
    target = app_users.get(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    new_role = str(body.get("role", ""))
    if new_role not in ("viewer", "analyst", "operator", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role")

    # --- BEGIN INTENTIONALLY VULNERABLE CODE ---------------------------
    old_role = target.role
    target.role = new_role
    # --- END INTENTIONALLY VULNERABLE CODE -----------------------------

    return JSONResponse({
        "_caller": caller.username,
        "_caller_role": caller.role,
        "_authorisation": "NONE — privilege escalation succeeded",
        "target_user_id": user_id,
        "old_role": old_role,
        "new_role": new_role,
    })


async def run_bfla(payload: dict[str, Any]) -> dict[str, Any]:
    as_user = str(payload.get("as_user", "s.novak"))
    target_id = int(payload.get("target_id", 3))
    new_role = str(payload.get("role", "admin"))

    before = app_users.get(target_id)
    if before is None:
        raise KeyError("target user not found")
    role_before = before.role

    listing = await list_users(as_user=as_user)
    listing_data = listing.body.decode()

    escalated = await update_role(target_id, as_user=as_user, body={"role": new_role})
    escalated_data = escalated.body.decode()

    after = app_users.get(target_id)
    role_after = after.role if after else None

    exploited = role_before != "admin" and role_after == "admin"

    return {
        "lab_id": "bfla",
        "finding_id": "WM-004",
        "request": {
            "method": "POST",
            "path": f"/api/vuln/admin/users/{target_id}/role",
            "query": {"as_user": as_user},
            "body": {"role": new_role},
        },
        "response": {
            "list_status": listing.status_code,
            "list_excerpt": listing_data[:400],
            "escalation_status": escalated.status_code,
            "escalation_body": escalated_data,
            "role_before": role_before,
            "role_after": role_after,
        },
        "exploited": exploited,
        "verdict": (
            f"Viewer '{as_user}' read the user directory and escalated user {target_id} "
            f"from '{role_before}' to '{role_after}'."
            if exploited else "Escalation did not persist."
        ),
        "notes": "Fix: enforce role checks server-side on every admin route. See WM-004.",
    }