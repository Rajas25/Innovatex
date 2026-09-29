"""WM-010 · The assessed application returns an insecure header set.

The workbench itself returns the *correct* header set (see middleware).
This route echoes back what the vulnerable application would have sent, so
Lab 10 can evaluate it against the baseline.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from ...deps import require_lab_mode
from ...services.headers import RECOMMENDED_HEADERS, evaluate_headers

router = APIRouter(dependencies=[Depends(require_lab_mode)])

# Exactly what the insecure application returns. Note the absences.
INSECURE_HEADERS: dict[str, str] = {
    "Server": "nginx/1.18.0 (Ubuntu)",
    "X-Powered-By": "Express/4.18.2",
    "X-AspNet-Version": "4.0.30319",
    "Cache-Control": "public, max-age=31536000",
    # Deliberately missing:
    #   Strict-Transport-Security
    #   Content-Security-Policy
    #   X-Content-Type-Options
    #   X-Frame-Options
    #   Referrer-Policy
    #   Permissions-Policy
    #   Cross-Origin-* headers
}

# The correct header set for comparison.
SECURE_HEADERS_EXAMPLE: dict[str, str] = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


@router.get("/headers/echo")
async def echo_headers() -> JSONResponse:
    return JSONResponse({
        "observed": INSECURE_HEADERS,
        "note": "This is the header set returned by the assessed application.",
    })


@router.get("/headers/recommended")
async def recommended() -> JSONResponse:
    return JSONResponse({
        "reference": [
            {"name": h.name, "required": h.required, "weight": h.weight,
             "recommended_value": h.good, "rationale": h.why}
            for h in RECOMMENDED_HEADERS
        ],
    })


async def run_headers(_payload: dict[str, Any]) -> dict[str, Any]:
    evaluation = evaluate_headers(INSECURE_HEADERS)

    return {
        "lab_id": "headers",
        "finding_id": "WM-010",
        "request": {"method": "GET", "path": "/api/vuln/headers/echo"},
        "response": {
            "observed_headers": INSECURE_HEADERS,
            "score": evaluation.score,
            "grade": evaluation.grade,
            "results": [
                {"name": r.name, "status": r.status, "value": r.value,
                 "expected": r.expected, "note": r.note, "why": r.why}
                for r in evaluation.results
            ],
        },
        "exploited": evaluation.score < 60,
        "verdict": (
            f"Header posture scored {evaluation.score}/100 (grade {evaluation.grade}). "
            f"{sum(1 for r in evaluation.results if r.status == 'fail')} required headers "
            "are absent."
        ),
        "notes": "Fix: deploy the baseline at the CDN/edge. See WM-010.",
    }