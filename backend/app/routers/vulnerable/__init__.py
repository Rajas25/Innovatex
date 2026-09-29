"""Intentionally vulnerable endpoints — LAB ONLY.

Every route in this package is a deliberate security defect. It exists so
that the assessment can demonstrate a working proof of concept against a
controlled target. The gate in `deps.require_lab_mode` (WM_LAB_MODE) is the
only thing keeping these routes off the public internet, and it is applied
at the router level in each module.

⚠️  DO NOT COPY ANY CODE FROM THIS PACKAGE INTO PRODUCTION.
"""
from __future__ import annotations

from typing import Any

from ...deps import require_lab_mode


async def dispatch(lab_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Route a `POST /api/labs/run` request to the matching lab handler."""
    from . import (
        data_exposure,
        headers_lab,
        jwt_lab,
        mass_assignment,
        monitors,
        prototype_pollution,
        rate_limit,
    )

    handlers = {
        "xss":                 monitors.run_xss,
        "sqli":                monitors.run_sqli,
        "idor":                monitors.run_idor,
        "bfla":                __import__("app.routers.vulnerable.admin", fromlist=["run_bfla"]).run_bfla,
        "jwt":                 jwt_lab.run_jwt,
        "mass_assignment":     mass_assignment.run_mass_assignment,
        "rate_limit":          rate_limit.run_rate_limit,
        "data_exposure":       data_exposure.run_data_exposure,
        "prototype_pollution": prototype_pollution.run_prototype_pollution,
        "headers":             headers_lab.run_headers,
        "token_storage":       jwt_lab.run_token_storage,
        "log_redaction":       data_exposure.run_log_redaction,
    }
    if lab_id not in handlers:
        raise KeyError(f"Unknown lab: {lab_id}")
    return await handlers[lab_id](payload)


__all__ = ["dispatch", "require_lab_mode"]