"""WM-008 · Excessive data exposure. WM-012 · Log redaction failures."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse

from ...database import app_users
from ...deps import require_lab_mode
from ...services.redaction import redact

router = APIRouter(dependencies=[Depends(require_lab_mode)])

# Fields that the API contract says it returns.
CONTRACT_FIELDS = {"id", "username", "full_name", "email", "department", "role"}


@router.get("/profile/{user_id}")
async def get_profile(user_id: int) -> JSONResponse:
    """
    🚨 VULNERABLE — the handler serialises the whole ORM object, so every
    column reaches the client: SSN, API key, internal notes, password hash.

    Secure equivalent: define a `ProfileResponse` Pydantic model and return
    only its fields (`response_model=ProfileResponse`).
    """
    user = app_users.get(user_id)
    if user is None:
        return JSONResponse(status_code=404, content={"detail": "User not found"})

    # --- BEGIN INTENTIONALLY VULNERABLE CODE ---------------------------
    payload = vars(user)         # ← the entire dataclass, unfiltered
    # --- END INTENTIONALLY VULNERABLE CODE -----------------------------

    leaked = sorted(set(payload.keys()) - CONTRACT_FIELDS)

    return JSONResponse({
        "_contract_fields": sorted(CONTRACT_FIELDS),
        "_extra_fields_leaked": leaked,
        "_note": f"{len(leaked)} fields beyond the documented contract were returned.",
        **{k: payload[k] for k in payload},
    })


@router.post("/log/echo")
async def echo_to_log(body: dict[str, Any] = Body(default_factory=dict)) -> JSONResponse:
    """
    🚨 VULNERABLE — the handler writes the request body verbatim to the
    application log. A login handler that calls this writes plaintext
    passwords, and any PII in the body, into the SIEM.

    Secure equivalent: `redact(body)` before logging; never log credentials
    at all.
    """
    # --- BEGIN INTENTIONALLY VULNERABLE CODE ---------------------------
    raw_log_entry = f"INFO auth.login.attempt body={body}"
    # --- END INTENTIONALLY VULNERABLE CODE -----------------------------

    redacted_body, hits = redact(body)
    redacted_log_entry = f"INFO auth.login.attempt body={redacted_body}"

    return JSONResponse({
        "raw_log_entry": raw_log_entry,
        "redacted_log_entry": redacted_log_entry,
        "redaction_hits": hits,
        "raw_length": len(raw_log_entry),
        "redacted_length": len(redacted_log_entry),
    })


async def run_data_exposure(payload: dict[str, Any]) -> dict[str, Any]:
    user_id = int(payload.get("user_id", 1))
    response = await get_profile(user_id)
    import json as _json
    data = _json.loads(response.body.decode())

    exploited = len(data.get("_extra_fields_leaked", [])) > 0

    return {
        "lab_id": "data_exposure",
        "finding_id": "WM-008",
        "request": {"method": "GET", "path": f"/api/vuln/profile/{user_id}"},
        "response": {"status": response.status_code, "body": data},
        "exploited": exploited,
        "verdict": (
            f"{len(data.get('_extra_fields_leaked', []))} sensitive fields "
            f"({', '.join(data.get('_extra_fields_leaked', [])[:5])}…) were returned "
            "beyond the documented contract."
            if exploited else "No extra fields were returned."
        ),
        "notes": "Fix: use explicit response models. See WM-008.",
    }


async def run_log_redaction(payload: dict[str, Any]) -> dict[str, Any]:
    body = payload.get("body") or {
        "username": "a.reyes",
        "password": "Sunshine2019!",
        "email": "a.reyes@worldmonitor.example",
        "ssn": "412-88-7391",
        "cardNumber": "4111 1111 1111 1111",
    }

    response = await echo_to_log(body)
    import json as _json
    data = _json.loads(response.body.decode())

    leaked = any(secret in data["raw_log_entry"]
                 for secret in ("Sunshine2019!", "412-88-7391", "4111"))

    return {
        "lab_id": "log_redaction",
        "finding_id": "WM-012",
        "request": {"method": "POST", "path": "/api/vuln/log/echo", "body": body},
        "response": {"status": response.status_code, "body": data},
        "exploited": leaked,
        "verdict": (
            f"Raw log entry contains secrets/PII. The redacted form removed "
            f"{len(data['redaction_hits'])} item(s)."
            if leaked else "No secret reached the raw log."
        ),
        "notes": "Fix: redact before logging; add a log-hygiene lint rule. See WM-012.",
    }