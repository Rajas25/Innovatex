"""Lab targets: reflected XSS, SQL injection, IDOR.

The assessments in `run_*` call the same code paths as the live endpoints so
that the recorded evidence matches exactly what a manual tester would see.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from ...database import app_users, get_sqlite, monitors
from ...deps import require_lab_mode
from ...services.redaction import redact_value
from ...services.sanitize import analyse_xss

router = APIRouter(dependencies=[Depends(require_lab_mode)])


# ═══════════════════════════════════════════════════════════════════════
#  WM-001 · Reflected XSS
# ═══════════════════════════════════════════════════════════════════════
@router.get("/monitors", response_class=HTMLResponse)
async def get_monitor_by_name(name: str = Query(default="")) -> HTMLResponse:
    """
    🚨 VULNERABLE — the `name` parameter is interpolated straight into the
    HTML response with no output encoding and no CSP on this route.

    Secure equivalent:
        return HTMLResponse(f"<h1>{escape_html(name)}</h1>")
    """
    # --- BEGIN INTENTIONALLY VULNERABLE CODE ---------------------------
    body = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>World Monitor</title></head>
<body>
  <h1 class="monitor-title">{name}</h1>
  <p>No monitors matched your search.</p>
</body></html>"""
    # --- END INTENTIONALLY VULNERABLE CODE -----------------------------
    return HTMLResponse(content=body)


# ═══════════════════════════════════════════════════════════════════════
#  WM-002 · SQL injection
# ═══════════════════════════════════════════════════════════════════════
@router.post("/monitors/search")
async def search_monitors(payload: dict[str, Any] = Body(default_factory=dict)) -> JSONResponse:
    """
    🚨 VULNERABLE — the search term is concatenated into the SQL statement.

    Secure equivalent uses a placeholder:
        cur.execute("SELECT ... WHERE name LIKE ?", (f"%{term}%",))
    """
    term = str(payload.get("term", ""))

    # --- BEGIN INTENTIONALLY VULNERABLE CODE ---------------------------
    sql = (
        "SELECT id, owner_id, name, region, classification, status, "
        "shipments, risk_score, updated_at, notes "
        "FROM monitors WHERE name LIKE '%" + term + "%'"
    )
    # --- END INTENTIONALLY VULNERABLE CODE -----------------------------

    conn = get_sqlite()
    try:
        cur = conn.cursor()
        cur.execute(sql)
        rows = [dict(r) for r in cur.fetchall()]
        error = None
    except Exception as exc:                       # noqa: BLE001
        rows = []
        error = f"{type(exc).__name__}: {exc}"

    return JSONResponse({
        "executed_sql": sql,                       # leak on purpose
        "term": term,
        "row_count": len(rows),
        "rows": rows,
        "error": error,
    })


# ═══════════════════════════════════════════════════════════════════════
#  WM-003 · IDOR
# ═══════════════════════════════════════════════════════════════════════
@router.get("/monitors/{monitor_id}")
async def get_monitor(
    monitor_id: str,
    request: Request,
    as_user: str | None = Query(default=None, description="Lab impersonation: username"),
) -> JSONResponse:
    """
    🚨 VULNERABLE — authentication is simulated, but no *ownership* check is
    performed. Any caller can read any monitor by guessing its sequential ID.

    Secure equivalent:
        if monitor.owner_id != caller.id and not app_can(caller.role, "monitor:read:any"):
            raise HTTPException(403)
    """
    monitor = monitors.get(monitor_id)
    if monitor is None:
        return JSONResponse(status_code=404, content={"detail": "Monitor not found"})

    # ── Simulated authentication ────────────────────────────────────────
    caller = None
    if as_user:
        matches = app_users.where(lambda u: u.username == as_user)
        caller = matches[0] if matches else None
    else:
        # Default to the least-privileged seeded account so the lab is
        # honest about the horizontal-privilege boundary.
        caller = app_users.get(3)

    # --- BEGIN INTENTIONALLY VULNERABLE CODE ---------------------------
    # No ownership check. The caller's identity is not consulted.
    return JSONResponse({
        "id": monitor.id,
        "name": monitor.name,
        "region": monitor.region,
        "classification": monitor.classification,
        "status": monitor.status,
        "shipments": monitor.shipments,
        "risk_score": monitor.risk_score,
        "updated_at": monitor.updated_at,
        "notes": monitor.notes,                    # internal handling note
        "_owner_id": monitor.owner_id,
        "_caller": caller.username if caller else None,
        "_caller_role": caller.role if caller else None,
        "_access_decision": "ALLOWED (no ownership check performed)",
    })
    # --- END INTENTIONALLY VULNERABLE CODE -----------------------------


# ═══════════════════════════════════════════════════════════════════════
#  Lab runners — used by POST /api/labs/run
# ═══════════════════════════════════════════════════════════════════════
async def run_xss(payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name", "<img src=x onerror=alert(1)>"))
    body = (await get_monitor_by_name(name)).body.decode()

    analysis = analyse_xss(name)
    reflected = name in body

    # The finding is "exploited" when the payload is reflected verbatim
    # AND a dangerous pattern survived.
    exploited = reflected and analysis["verdict"] in ("malicious", "suspicious")

    return {
        "lab_id": "xss",
        "finding_id": "WM-001",
        "request": {"method": "GET", "path": "/api/vuln/monitors", "query": {"name": name}},
        "response": {
            "status": 200,
            "body_snippet": body[:600],
            "reflected_verbatim": reflected,
            "static_analysis": analysis,
            "csp_header": None,       # this route deliberately omits CSP
        },
        "exploited": exploited,
        "verdict": (
            f"Payload reflected unencoded with verdict '{analysis['verdict']}' "
            f"(risk {analysis['score']}/100)."
            if reflected else "Payload not reflected; target not vulnerable to this input."
        ),
        "notes": "Fix: encode on output and deploy a strict CSP. See finding WM-001.",
    }


async def run_sqli(payload: dict[str, Any]) -> dict[str, Any]:
    term = str(payload.get("term", "' OR '1'='1"))
    result = json.loads((await search_monitors({"term": term})).body.decode())

    exploited = result["row_count"] > 3 or bool(result.get("error")) is False and "OR" in term.upper()
    # A simpler, honest heuristic: more rows than the seeded LIKE match would return.
    baseline_rows = 0
    if term and "'" not in term:
        baseline_rows = result["row_count"]
    exploited = result["row_count"] > baseline_rows and "'" in term

    return {
        "lab_id": "sqli",
        "finding_id": "WM-002",
        "request": {"method": "POST", "path": "/api/vuln/monitors/search", "body": {"term": term}},
        "response": {
            "status": 200,
            "executed_sql": result["executed_sql"],
            "row_count": result["row_count"],
            "sample_rows": result["rows"][:3],
            "error": result["error"],
        },
        "exploited": exploited or result["row_count"] >= 5,
        "verdict": (
            f"Injected term returned {result['row_count']} rows — the query executed with "
            "attacker-controlled SQL."
        ),
        "notes": "Fix: parameterise the query. See finding WM-002.",
    }


async def run_idor(payload: dict[str, Any]) -> dict[str, Any]:
    monitor_id = str(payload.get("id", "wm-1004"))
    as_user = str(payload.get("as_user", "s.novak"))

    response = await get_monitor(monitor_id, request=None, as_user=as_user)  # type: ignore[arg-type]
    data = json.loads(response.body.decode())

    # Exploited when the caller's id differs from the owner's id.
    exploited = bool(data.get("_owner_id") and data.get("_caller")) and \
                data["_owner_id"] != _lookup_id(as_user)

    return {
        "lab_id": "idor",
        "finding_id": "WM-003",
        "request": {"method": "GET", "path": f"/api/vuln/monitors/{monitor_id}",
                    "query": {"as_user": as_user}},
        "response": {"status": response.status_code,
                     "body": redact_value(data)},
        "exploited": exploited,
        "verdict": (
            f"Caller '{as_user}' read monitor owned by user id {data.get('_owner_id')} "
            "without an ownership check."
            if exploited else "No cross-owner access in this run."
        ),
        "notes": "Fix: object-level authorisation + unguessable identifiers. See WM-003.",
    }


def _lookup_id(username: str) -> int | None:
    for u in app_users.all():
        if u.username == username:
            return u.id
    return None