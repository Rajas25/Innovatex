"""WM-007 · No rate limiting on the login endpoint."""
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse

from ...database import app_users, rate_limit_buckets, rate_limit_lock
from ...deps import require_lab_mode

router = APIRouter(dependencies=[Depends(require_lab_mode)])


@router.post("/login")
async def app_login(body: dict[str, Any] = Body(default_factory=dict)) -> JSONResponse:
    """
    🚨 VULNERABLE — no rate limiting, no lockout, no CAPTCHA, no back-off, and
    the response timing differs between "unknown user" and "wrong password",
    which enables username enumeration.

    Secure equivalent: token bucket per (username, IP), exponential back-off,
    and a uniform response time.
    """
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))

    with rate_limit_lock:
        bucket = rate_limit_buckets.setdefault(username, [])
        now = time.time()
        bucket.append(now)
        # Keep only the last 60 seconds.
        bucket[:] = [t for t in bucket if now - t < 60]
        attempts_last_minute = len(bucket)

    matches = app_users.where(lambda u: u.username == username)
    user = matches[0] if matches else None

    if user is None:
        return JSONResponse(status_code=401, content={
            "detail": "Unknown user",         # ← leaks existence
            "attempts_last_minute": attempts_last_minute,
        })

    if user.password != password:
        return JSONResponse(status_code=401, content={
            "detail": "Wrong password",
            "attempts_last_minute": attempts_last_minute,
        })

    return JSONResponse({
        "detail": "ok", "role": user.role,
        "attempts_last_minute": attempts_last_minute,
    })


async def run_rate_limit(payload: dict[str, Any]) -> dict[str, Any]:
    username = str(payload.get("username", "a.reyes"))
    guesses = payload.get("guesses") or [
        "password", "123456", "admin", "letmein", "qwerty",
        "worldmonitor", "monitor123", "Sunshine2019!",
    ]

    log: list[dict[str, Any]] = []
    success_at: int | None = None

    for index, guess in enumerate(guesses, start=1):
        response = await app_login({"username": username, "password": guess})
        import json as _json
        data = _json.loads(response.body.decode())
        log.append({"attempt": index, "password": guess,
                    "status": response.status_code,
                    "detail": data.get("detail"),
                    "attempts_last_minute": data.get("attempts_last_minute")})
        if response.status_code == 200 and success_at is None:
            success_at = index

    exploited = len(guesses) >= 5 and all(
        entry["status"] != 429 for entry in log
    )

    return {
        "lab_id": "rate_limit",
        "finding_id": "WM-007",
        "request": {"method": "POST", "path": "/api/vuln/login",
                    "body": {"username": username, "guesses": f"{len(guesses)} attempts"}},
        "response": {"log": log, "success_at_attempt": success_at,
                     "total_attempts": len(guesses)},
        "exploited": exploited,
        "verdict": (
            f"{len(guesses)} password guesses were processed in under a minute with no "
            "throttling. Online brute force is fully practical."
            if exploited else "Rate limiting prevented the attack."
        ),
        "notes": "Fix: per-account + per-IP throttling, lockout, MFA. See WM-007.",
    }