"""FastAPI application factory."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import __version__
from .config import settings
from .middleware.audit import AuditMiddleware
from .middleware.security_headers import SecurityHeadersMiddleware
from .routers import auth, evidence, findings, labs, reports
from .routers.vulnerable import (
    admin,
    data_exposure,
    headers_lab,
    jwt_lab,
    mass_assignment,
    monitors,
    prototype_pollution,
    rate_limit,
)
from .seed import seed_all


@asynccontextmanager
async def lifespan(_app: FastAPI):
    seed_all()
    yield


app = FastAPI(
    title="World Monitor — Security Assessment Workbench",
    description=(
        "Backend for the authorised security assessment of the **World Monitor** "
        "application (Problem Statement ID 26163).\n\n"
        "Routes under `/api/vuln/*` are **intentionally vulnerable** and exist only "
        "to demonstrate findings in a controlled lab environment. They are gated "
        "behind `WM_LAB_MODE=1` and must never be deployed on a public network."
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ─── Middleware (outermost first) ────────────────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AuditMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Audit-Event", "X-Request-ID"],
)


# ─── Routers ─────────────────────────────────────────────────────────────
app.include_router(auth.router,      prefix="/api/auth",     tags=["auth"])
app.include_router(findings.router,  prefix="/api/findings", tags=["findings"])
app.include_router(labs.router,      prefix="/api/labs",     tags=["labs"])
app.include_router(evidence.router,  prefix="/api/evidence", tags=["evidence"])
app.include_router(reports.router,   prefix="/api/reports",  tags=["reports"])

# ─── Intentionally vulnerable (lab-only) ─────────────────────────────────
VULN_TAG = "🚨 VULNERABLE — lab only"
app.include_router(monitors.router,              prefix="/api/vuln", tags=[VULN_TAG])
app.include_router(admin.router,                 prefix="/api/vuln", tags=[VULN_TAG])
app.include_router(jwt_lab.router,               prefix="/api/vuln", tags=[VULN_TAG])
app.include_router(mass_assignment.router,       prefix="/api/vuln", tags=[VULN_TAG])
app.include_router(rate_limit.router,            prefix="/api/vuln", tags=[VULN_TAG])
app.include_router(data_exposure.router,         prefix="/api/vuln", tags=[VULN_TAG])
app.include_router(prototype_pollution.router,   prefix="/api/vuln", tags=[VULN_TAG])
app.include_router(headers_lab.router,           prefix="/api/vuln", tags=[VULN_TAG])


# ─── Meta endpoints ──────────────────────────────────────────────────────
@app.get("/health", tags=["meta"])
async def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__, "env": settings.env}


@app.get("/api/meta", tags=["meta"])
async def meta() -> dict[str, object]:
    return {
        "name": "World Monitor — Security Assessment Workbench",
        "version": __version__,
        "lab_mode": bool(settings.lab_mode),
        "problem_statement_id": "26163",
        "disclaimer": (
            "This tool performs security testing exclusively against a lab instance. "
            "Use only on systems for which you have explicit written authorisation."
        ),
    }


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Deliberately generic in the *workbench*; contrast with
    # routers/vulnerable/data_exposure.py which leaks stack traces on purpose.
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal workbench error", "path": request.url.path},
    )