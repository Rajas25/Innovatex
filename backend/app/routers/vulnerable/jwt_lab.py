"""WM-005 (JWT alg:none bypass) and WM-011 (token storage)."""
from __future__ import annotations

import time
import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from ...deps import require_lab_mode
from ...services.jwt_service import decode_unverified, sign, verify

router = APIRouter(dependencies=[Depends(require_lab_mode)])

# The lab's "application" secret. Fictional. Never do this in production.
LAB_SECRET = "lab-jwt-secret-do-not-use-in-production-32bytes"


@router.post("/jwt/issue")
async def issue_lab_token(body: dict[str, Any] = Body(default_factory=dict)) -> JSONResponse:
    """Issue a legitimate, correctly signed token for the lab application."""
    subject = str(body.get("sub", "s.novak"))
    role = str(body.get("role", "viewer"))
    now = int(time.time())
    payload = {
        "sub": subject, "role": role,
        "iat": now, "nbf": now, "exp": now + 900,
        "iss": "world-monitor-lab", "aud": "world-monitor-api",
        "jti": uuid.uuid4().hex,
    }
    token = sign(payload, LAB_SECRET, alg="HS256")
    return JSONResponse({"token": token, "claims": payload})


@router.get("/jwt/protected")
async def protected(token: str = Query(...)) -> JSONResponse:
    """
    🚨 VULNERABLE — the verifier trusts the `alg` header. When the header says
    `none`, the signature check is skipped entirely.

    Secure equivalent (see services/jwt_service.verify):
        alg = header.get("alg")
        if alg not in ALLOWED_ALGS: reject
        if alg == "none": reject
        verify_hmac(...)
    """
    decoded = decode_unverified(token)
    if not decoded["ok"]:
        raise HTTPException(status_code=400, detail="Malformed token")

    header = decoded["header"]
    alg = str(header.get("alg", "")).lower()

    # --- BEGIN INTENTIONALLY VULNERABLE CODE ---------------------------
    if alg == "none":
        # Trust the claims without any cryptographic verification.
        claims = decoded["payload"]
        signature_verified = False
    else:
        result = verify(token, LAB_SECRET, allowed_algs=("HS256",))
        if not result["valid"]:
            return JSONResponse(status_code=401, content={
                "detail": "Invalid token", "reason": result["reason"],
                "header": result.get("header"), "payload": result.get("payload"),
            })
        claims = result["payload"]
        signature_verified = True
    # --- END INTENTIONALLY VULNERABLE CODE -----------------------------

    return JSONResponse({
        "authorised": True,
        "signature_verified": signature_verified,       # ← the smoking gun
        "header": header,
        "claims": claims,
        "secret_used_for_verification": LAB_SECRET if signature_verified else None,
    })


async def run_jwt(payload: dict[str, Any]) -> dict[str, Any]:
    """Issue a viewer token, forge `alg: none` with role=admin, replay it."""
    from ...services.jwt_service import forge_none_alg

    issued = await issue_lab_token({"sub": "s.novak", "role": "viewer"})
    issued_data = issued.body.decode()
    import json as _json
    real_token = _json.loads(issued_data)["token"]

    forged = forge_none_alg(real_token, {"role": "admin", "escalated": True})

    replay = await protected(token=forged)
    replay_data = _json.loads(replay.body.decode())

    exploited = (
        replay.status_code == 200
        and replay_data.get("signature_verified") is False
        and replay_data.get("claims", {}).get("role") == "admin"
    )

    return {
        "lab_id": "jwt",
        "finding_id": "WM-005",
        "request": {"method": "GET", "path": "/api/vuln/jwt/protected",
                    "query": {"token": forged}},
        "response": {
            "status": replay.status_code,
            "original_token": real_token,
            "forged_token": forged,
            "decoded_header": decode_unverified(forged)["header"],
            "decoded_payload": decode_unverified(forged)["payload"],
            "server_response": replay_data,
        },
        "exploited": exploited,
        "verdict": (
            "Forged token accepted with signature_verified=false and role escalated "
            "to 'admin' — full authentication bypass."
            if exploited else "Forged token was rejected."
        ),
        "notes": "Fix: reject `alg: none` and pin the algorithm. See WM-005.",
    }


async def run_token_storage(payload: dict[str, Any]) -> dict[str, Any]:
    """
    WM-011 · Tokens issued to the SPA are exposed to JavaScript.
    The lab returns the Set-Cookie it *would* have sent; the frontend shows
    how a single XSS can read the same token.
    """
    issued = await issue_lab_token({"sub": "s.novak", "role": "viewer"})
    import json as _json
    token = _json.loads(issued.body.decode())["token"]

    return {
        "lab_id": "token_storage",
        "finding_id": "WM-011",
        "request": {"method": "POST", "path": "/api/vuln/jwt/issue",
                    "body": {"sub": "s.novak", "role": "viewer"}},
        "response": {
            "token": token,
            "set_cookie_received": "wm_token=" + token[:24] + "…; Path=/",
            # Missing: HttpOnly, Secure, SameSite, __Host- prefix.
            "cookie_flags": {"HttpOnly": False, "Secure": False,
                             "SameSite": None, "Prefix": None},
            "local_storage_key": "wm_token",
            "js_readable": True,
        },
        "exploited": True,
        "verdict": (
            "Token is readable from JavaScript (no HttpOnly). Any XSS — see WM-001 — "
            "can exfiltrate it and impersonate the user until expiry."
        ),
        "notes": "Fix: HttpOnly + Secure + SameSite=Strict + __Host- prefix. See WM-011.",
    }