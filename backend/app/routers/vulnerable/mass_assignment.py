"""WM-006 · Mass assignment. The profile-update handler copies every submitted
key onto the model, so an attacker can set privileged fields."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse

from ...database import app_users
from ...deps import require_lab_mode

router = APIRouter(dependencies=[Depends(require_lab_mode)])

# In-memory profile overlay so the lab can be reset without wiping the seed.
_PROFILES: dict[str, dict[str, Any]] = {}


def _profile_for(username: str) -> dict[str, Any]:
    if username not in _PROFILES:
        user = app_users.where(lambda u: u.username == username)
        u = user[0] if user else app_users.get(3)
        _PROFILES[username] = {
            "username": u.username, "full_name": u.full_name,
            "email": u.email, "department": u.department,
            "role": u.role, "is_admin": u.role == "admin", "credits": 0,
        }
    return _PROFILES[username]


@router.get("/profile/update")
async def read_profile(as_user: str = "s.novak") -> JSONResponse:
    return JSONResponse(_profile_for(as_user))


@router.post("/profile/update")
async def update_profile(
    as_user: str = "s.novak",
    body: dict[str, Any] = Body(default_factory=dict),
) -> JSONResponse:
    """
    🚨 VULNERABLE — the handler iterates every key the client sent and writes
    it onto the profile. There is no allowlist.

    Secure equivalent:
        allowed = {"full_name", "email", "department"}
        for k in allowed & body.keys():
            profile[k] = body[k]
    """
    profile = _profile_for(as_user)
    before = dict(profile)

    # --- BEGIN INTENTIONALLY VULNERABLE CODE ---------------------------
    for key, value in body.items():
        profile[key] = value
    # --- END INTENTIONALLY VULNERABLE CODE -----------------------------

    return JSONResponse({
        "_before": before,
        "_after": dict(profile),
        "_note": "Every submitted key was persisted. There is no allowlist.",
    })


async def run_mass_assignment(payload: dict[str, Any]) -> dict[str, Any]:
    as_user = str(payload.get("as_user", "s.novak"))
    fields = payload.get("fields") or {"role": "admin", "is_admin": True, "credits": 999999}

    response = await update_profile(as_user=as_user, body=fields)
    import json as _json
    data = _json.loads(response.body.decode())

    exploited = (
        data["_after"].get("role") == "admin"
        or data["_after"].get("is_admin") is True
        or data["_after"].get("credits", 0) > 1000
    )

    return {
        "lab_id": "mass_assignment",
        "finding_id": "WM-006",
        "request": {"method": "POST", "path": "/api/vuln/profile/update",
                    "query": {"as_user": as_user}, "body": fields},
        "response": {"status": response.status_code, "body": data},
        "exploited": exploited,
        "verdict": (
            "Privileged fields were accepted from the client and written to the profile."
            if exploited else "No privileged field was accepted."
        ),
        "notes": "Fix: allowlist writable fields. See WM-006.",
    }