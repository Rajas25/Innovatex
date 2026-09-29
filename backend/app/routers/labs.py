"""Lab metadata + run handlers. Each handler posts to the corresponding
intentionally vulnerable endpoint and classifies the outcome."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from ..deps import CurrentUser, require_permission
from ..schemas import LabOut, LabRunRequest, LabRunResponse
from ..seed import seed_all
from .vulnerable import dispatch

router = APIRouter()


LABS: list[dict[str, Any]] = [
    {
        "id": "xss", "finding_id": "WM-001",
        "title": "Reflected XSS in monitor-name parameter",
        "summary": "Monitor name is reflected into the DOM without encoding.",
        "endpoints": ["GET /api/vuln/monitors"],
        "parameters": ["name"],
        "hints": [
            "Try a benign marker first: `?name=<b>probe</b>`.",
            "Check whether the response body contains the raw angle brackets.",
            "An `<img onerror>` payload fires without user interaction beyond the click.",
        ],
    },
    {
        "id": "sqli", "finding_id": "WM-002",
        "title": "SQL injection in monitor search",
        "summary": "Search term is concatenated into SQL.",
        "endpoints": ["POST /api/vuln/monitors/search"],
        "parameters": ["term"],
        "hints": [
            "Start with `' OR '1'='1` — a tautology returns every row.",
            "The lab returns the exact SQL string it executed so you can see the injection.",
            "Try a UNION SELECT to enumerate the users table.",
        ],
    },
    {
        "id": "idor", "finding_id": "WM-003",
        "title": "IDOR on monitor retrieval",
        "summary": "GET /monitors/{id} never checks ownership.",
        "endpoints": ["GET /api/vuln/monitors/{id}"],
        "parameters": ["id"],
        "hints": [
            "Identifiers are sequential: wm-1001 … wm-1005.",
            "Authenticate as m.okafor (analyst) and request wm-1004 — an admin-owned RESTRICTED monitor.",
        ],
    },
    {
        "id": "bfla", "finding_id": "WM-004",
        "title": "Broken function-level authorisation",
        "summary": "Admin routes are gated only by authentication, not authorisation.",
        "endpoints": ["GET /api/vuln/admin/users", "POST /api/vuln/admin/users/{id}/role"],
        "parameters": ["id", "role"],
        "hints": [
            "Log in as s.novak (viewer) and call GET /api/vuln/admin/users.",
            "Escalate yourself: POST /api/vuln/admin/users/3/role with {\"role\":\"admin\"}.",
        ],
    },
    {
        "id": "jwt", "finding_id": "WM-005",
        "title": "JWT signature bypass via alg:none",
        "summary": "The verifier trusts the alg header and accepts unsigned tokens.",
        "endpoints": ["POST /api/vuln/jwt/issue", "GET /api/vuln/jwt/protected"],
        "parameters": ["token"],
        "hints": [
            "Issue a viewer token first.",
            "Flip the header to `alg: none`, drop the signature, and re-encode.",
            "The protected endpoint decodes the header to decide which verifier to use.",
        ],
    },
    {
        "id": "mass_assignment", "finding_id": "WM-006",
        "title": "Mass assignment on profile update",
        "summary": "Profile update copies every submitted field into the record.",
        "endpoints": ["POST /api/vuln/profile/update"],
        "parameters": ["*"],
        "hints": [
            "The endpoint reads `payload.role`, `payload.isAdmin`, `payload.credits`.",
            "Submit {\"role\":\"admin\"} and re-read your profile.",
        ],
    },
    {
        "id": "rate_limit", "finding_id": "WM-007",
        "title": "Missing rate limiting on authentication",
        "summary": "Unlimited password guesses per minute.",
        "endpoints": ["POST /api/vuln/login"],
        "parameters": ["username", "password"],
        "hints": [
            "Fire 20 requests in a row — all are processed.",
            "The lab response reports the observed attempts-per-minute so you can quote a number.",
        ],
    },
    {
        "id": "data_exposure", "finding_id": "WM-008",
        "title": "Excessive data exposure on profile API",
        "summary": "Profile endpoint returns SSN, API key, internal notes.",
        "endpoints": ["GET /api/vuln/profile/{id}"],
        "parameters": ["id"],
        "hints": [
            "Compare the response shape to the documented contract.",
            "Fields to look for: ssn, api_key, internal_notes, password_hash.",
        ],
    },
    {
        "id": "prototype_pollution", "finding_id": "WM-009",
        "title": "Prototype pollution in merge endpoint",
        "summary": "Deep-merge recurses into __proto__ without filtering.",
        "endpoints": ["POST /api/vuln/preferences/merge"],
        "parameters": ["__proto__", "constructor", "prototype"],
        "hints": [
            "Submit {\"__proto__\":{\"isAdmin\":true}}.",
            "The response reports the resulting Object.prototype state.",
        ],
    },
    {
        "id": "headers", "finding_id": "WM-010",
        "title": "Missing HTTP security headers",
        "summary": "The application returns no CSP, HSTS or X-CTO headers.",
        "endpoints": ["GET /api/vuln/headers/echo"],
        "parameters": [],
        "hints": [
            "Compare the echoed header set to the recommended baseline.",
            "Server and X-Powered-By leak the exact framework versions.",
        ],
    },
    {
        "id": "token_storage", "finding_id": "WM-011",
        "title": "Session token stored in localStorage",
        "summary": "The SPA writes the bearer token to localStorage, readable by any XSS.",
        "endpoints": ["POST /api/vuln/token/issue"],
        "parameters": [],
        "hints": [
            "Combine with Lab 1: an XSS payload can read localStorage.getItem('wm_token').",
            "The cookie set by the lab is missing HttpOnly and Secure.",
        ],
    },
    {
        "id": "log_redaction", "finding_id": "WM-012",
        "title": "Secrets and PII written to application logs",
        "summary": "Auth handler logs the full request body, including the password.",
        "endpoints": ["POST /api/vuln/log/echo"],
        "parameters": ["*"],
        "hints": [
            "Send a body containing `password`, `email` and a card number.",
            "Compare the raw log entry with the redacted version returned alongside it.",
        ],
    },
]


@router.get("", response_model=list[LabOut])
async def list_labs(user: CurrentUser) -> list[LabOut]:
    return [LabOut(**lab) for lab in LABS]


@router.get("/{lab_id}", response_model=LabOut)
async def get_lab(lab_id: str, user: CurrentUser) -> LabOut:
    for lab in LABS:
        if lab["id"] == lab_id:
            return LabOut(**lab)
    raise HTTPException(status_code=404, detail="Lab not found")


@router.post("/run", response_model=LabRunResponse)
async def run_lab(
    payload: LabRunRequest,
    _user=Depends(require_permission("labs:run")),
) -> LabRunResponse:
    if payload.lab_id not in {lab["id"] for lab in LABS}:
        raise HTTPException(status_code=404, detail="Lab not found")
    try:
        result = await dispatch(payload.lab_id, payload.payload)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return LabRunResponse(**result)


@router.post("/reset")
async def reset_labs(_user=Depends(require_permission("labs:reset"))) -> dict[str, str]:
    seed_all()
    return {"status": "reset"}