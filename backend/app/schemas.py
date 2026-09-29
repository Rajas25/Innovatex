"""Pydantic v2 request/response schemas. These define the public API contract."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


# ─── Auth ────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class LoginResponse(BaseModel):
    token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    user: "WorkbenchUserOut"


class WorkbenchUserOut(BaseModel):
    id: int
    username: str
    full_name: str
    role: str
    last_login_at: str | None = None


# ─── Findings ────────────────────────────────────────────────────────────
class CvssOut(BaseModel):
    vector: str
    score: float | None = None
    severity: str


class FindingOut(BaseModel):
    id: str
    title: str
    category: str
    cwe: str
    owasp: str
    affected_component: str
    severity: str
    cvss: CvssOut
    lab_id: str
    summary: str
    description: str
    evidence: list[str]
    reproduction: list[str]
    business_impact: str
    remediation: list[str]
    references: list[str]
    status: Literal["open", "confirmed", "remediated", "accepted"] = "open"


class FindingStatusUpdate(BaseModel):
    status: Literal["open", "confirmed", "remediated", "accepted"]
    comment: str = Field(default="", max_length=2000)


# ─── Labs ────────────────────────────────────────────────────────────────
class LabOut(BaseModel):
    id: str
    title: str
    finding_id: str
    summary: str
    endpoints: list[str]
    parameters: list[str]
    hints: list[str]


class LabRunRequest(BaseModel):
    lab_id: str
    payload: dict[str, Any] = Field(default_factory=dict)


class LabRunResponse(BaseModel):
    lab_id: str
    finding_id: str
    request: dict[str, Any]
    response: dict[str, Any]
    exploited: bool
    verdict: str
    notes: str = ""


# ─── Evidence ────────────────────────────────────────────────────────────
class EvidenceCreate(BaseModel):
    finding_id: str
    lab_id: str
    request: dict[str, Any]
    response: dict[str, Any]
    notes: str = Field(default="", max_length=4000)


class EvidenceOut(EvidenceCreate):
    id: str
    created_at: str
    actor: str


# ─── Reports ─────────────────────────────────────────────────────────────
class ReportBuildRequest(BaseModel):
    title: str = "World Monitor — Security Assessment Report"
    assessor: str = Field(default="", max_length=200)
    engagement_id: str = Field(default="WM-2025-001", max_length=64)
    include_findings: list[str] | None = None
    format: Literal["markdown", "json", "html"] = "markdown"


class ReportBuildResponse(BaseModel):
    format: Literal["markdown", "json", "html"]
    filename: str
    content: str
    generated_at: str
    finding_count: int
    severity_summary: dict[str, int]


# ─── CVSS playground ─────────────────────────────────────────────────────
class CvssRequest(BaseModel):
    vector: str


class CvssResponse(BaseModel):
    vector: str
    score: float | None
    severity: str
    impact: float | None
    exploitability: float | None
    errors: list[str] = []


LoginResponse.model_rebuild()