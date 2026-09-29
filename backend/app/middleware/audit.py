"""Record every mutating request into the tamper-evident audit store."""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from ..database import audit_events
from ..models import AuditEvent
from ..security import new_id
from ..services.redaction import redact_value
from ..models import utcnow

AUDITED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SKIP_PREFIXES = ("/docs", "/redoc", "/openapi.json", "/favicon.ico", "/health")


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        path = request.url.path
        if request.method not in AUDITED_METHODS or path.startswith(SKIP_PREFIXES):
            return response

        # We never read the request body here — that would consume the stream
        # for the downstream handler. Handlers that want body-level audit
        # logging call `services.audit.record()` directly.
        actor = getattr(request.state, "actor", "anonymous")
        event = AuditEvent(
            id=new_id("evt"),
            ts=utcnow(),
            actor=actor,
            action=f"{request.method} {path}",
            target=request.url.query or "",
            result="allowed" if response.status_code < 400 else "denied",
            source_ip=request.client.host if request.client else "unknown",
            detail=redact_value({"status_code": response.status_code}),
        )
        audit_events.insert(event.id, event)
        response.headers["X-Audit-Event"] = event.id
        return response