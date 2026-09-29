"""Report generation. `report:generate` for preview, `report:export` for download."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from ..data.findings import FINDINGS
from ..deps import CurrentUser, require_permission
from ..schemas import ReportBuildRequest, ReportBuildResponse
from ..services.cvss import score_from_vector
from ..services.report_builder import (
    build_html,
    build_json,
    build_markdown,
    severity_summary,
    utcnow_str,
)

router = APIRouter()


def _select(findings_filter: list[str] | None) -> list[dict]:
    selected = []
    for raw in FINDINGS:
        if findings_filter and raw["id"] not in findings_filter:
            continue
        score = score_from_vector(raw["cvss"]["vector"])
        selected.append({
            **raw,
            "cvss": {"vector": raw["cvss"]["vector"],
                     "score": score["score"],
                     "severity": score["severity"] or raw["severity"]},
        })
    return selected


@router.post("/build", response_model=ReportBuildResponse)
async def build(
    payload: ReportBuildRequest,
    _user=Depends(require_permission("report:generate")),
) -> ReportBuildResponse:
    findings = _select(payload.include_findings)
    generated_at = utcnow_str()

    builder = {"markdown": build_markdown, "json": build_json, "html": build_html}[payload.format]
    content = builder(
        title=payload.title,
        assessor=payload.assessor,
        engagement_id=payload.engagement_id,
        findings=findings,
        generated_at=generated_at,
    )

    ext = {"markdown": "md", "json": "json", "html": "html"}[payload.format]
    filename = f"world-monitor-assessment-{payload.engagement_id}.{ext}"

    return ReportBuildResponse(
        format=payload.format,
        filename=filename,
        content=content,
        generated_at=generated_at,
        finding_count=len(findings),
        severity_summary=severity_summary(findings),
    )


@router.get("/download", response_class=PlainTextResponse)
async def download(
    format: str = "markdown",
    engagement_id: str = "WM-2025-001",
    _user=Depends(require_permission("report:export")),
) -> PlainTextResponse:
    findings = _select(None)
    generated_at = utcnow_str()
    builder = {"markdown": build_markdown, "json": build_json, "html": build_html}.get(format, build_markdown)
    content = builder(
        title="World Monitor — Security Assessment Report",
        assessor="",
        engagement_id=engagement_id,
        findings=findings,
        generated_at=generated_at,
    )
    media = {"markdown": "text/markdown", "json": "application/json", "html": "text/html"}.get(format, "text/plain")
    return PlainTextResponse(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="wm-report-{engagement_id}.{format[:2]}"'},
    )