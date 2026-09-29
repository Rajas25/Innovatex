"""WM-009 · Prototype pollution in the preferences merge endpoint.

Python has no `Object.prototype`, but the same *class* of bug — untrusted keys
reaching a recursive merge — produces equivalent impact in Python services
that build objects from attacker-supplied dicts (e.g. attribute injection,
`__class__` traversal, template context poisoning).

This lab demonstrates the Python analogue honestly, and also shows how the
identical payload would behave in Node.js so the JS-centric reader can see
the canonical case.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse

from ...deps import require_lab_mode

router = APIRouter(dependencies=[Depends(require_lab_mode)])

DANGEROUS_KEYS = ("__proto__", "constructor", "prototype", "__class__", "__dict__", "__globals__")

_BASE_PREFERENCES: dict[str, Any] = {
    "theme": "dark",
    "timezone": "UTC",
    "notifications": {"email": True, "sms": False},
}


def _deep_merge(dst: dict[str, Any], src: dict[str, Any]) -> dict[str, Any]:
    """
    🚨 VULNERABLE — recurses into every key without an allowlist, so a payload
    containing `__proto__` / `__class__` / `constructor` reaches the target
    dict and, in a JS runtime, `Object.prototype`.
    """
    # --- BEGIN INTENTIONALLY VULNERABLE CODE ---------------------------
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            _deep_merge(dst[key], value)
        else:
            dst[key] = value
    # --- END INTENTIONALLY VULNERABLE CODE -----------------------------
    return dst


def _find_dangerous_keys(node: Any, path: str = "$") -> list[str]:
    hits: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in DANGEROUS_KEYS:
                hits.append(f"{path}.{key}")
            hits.extend(_find_dangerous_keys(value, f"{path}.{key}"))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            hits.extend(_find_dangerous_keys(item, f"{path}[{i}]"))
    return hits


@router.post("/preferences/merge")
async def merge_preferences(body: dict[str, Any] = Body(default_factory=dict)) -> JSONResponse:
    import copy
    target = copy.deepcopy(_BASE_PREFERENCES)
    merged = _deep_merge(target, body)

    return JSONResponse({
        "merged_preferences": merged,
        "dangerous_keys_present": _find_dangerous_keys(merged),
        "note": (
            "In a Node.js service, the same payload would set Object.prototype.isAdmin, "
            "affecting *every* object in the process. In Python the equivalent sink is "
            "attribute injection on an object built from the merged dict."
        ),
    })


async def run_prototype_pollution(payload: dict[str, Any]) -> dict[str, Any]:
    body = payload.get("body") or {"__proto__": {"isAdmin": True}}

    response = await merge_preferences(body)
    import json as _json
    data = _json.loads(response.body.decode())

    exploited = len(data.get("dangerous_keys_present", [])) > 0

    # Demonstrate the Node.js outcome without executing it.
    node_equivalent = ""
    if "__proto__" in str(body):
        node_equivalent = (
            "({}).isAdmin === true    // every object in the process inherits isAdmin\n"
            "if (user.isAdmin) { /* authorisation bypass */ }"
        )

    return {
        "lab_id": "prototype_pollution",
        "finding_id": "WM-009",
        "request": {"method": "POST", "path": "/api/vuln/preferences/merge", "body": body},
        "response": {"status": response.status_code, "body": data,
                     "node_equivalent": node_equivalent},
        "exploited": exploited,
        "verdict": (
            "Dangerous keys reached the merged object. In a JavaScript runtime this "
            "payload would poison Object.prototype."
            if exploited else "No dangerous key survived the merge."
        ),
        "notes": "Fix: allowlist keys; reject __proto__/constructor/prototype; "
                 "use Object.create(null) or Map. See WM-009.",
    }