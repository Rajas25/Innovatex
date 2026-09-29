"""Findings catalogue. Read is open to any authenticated role; status changes
require `findings:approve` (lead only)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..data.findings import FINDINGS
from ..deps import CurrentUser, require_permission
from ..schemas import FindingOut, FindingStatusUpdate
from ..services.cvss import score_from_vector

router = APIRouter()

# Runtime status overrides. In a real system this is a DB column.
_STATUS: dict[str, str] = {f["id"]: "open" for f in FINDINGS}


def _enrich(raw: dict) -> FindingOut:
    vector = raw["cvss"]["vector"]
    score = score_from_vector(vector)
    return FindingOut(
        **{k: v for k, v in raw.items() if k != "cvss"},
        cvss={"vector": vector,
              "score": score["score"],
              "severity": score["severity"] or raw["severity"]},
        status=_STATUS.get(raw["id"], "open"),
    )


@router.get("", response_model=list[FindingOut])
async def list_findings(
    user: CurrentUser,
    severity: str | None = Query(default=None),
    category: str | None = Query(default=None),
) -> list[FindingOut]:
    items = [_enrich(f) for f in FINDINGS]
    if severity:
        items = [f for f in items if f.severity == severity]
    if category:
        items = [f for f in items if f.category == category]
    return items


@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: str, user: CurrentUser) -> FindingOut:
    for f in FINDINGS:
        if f["id"] == finding_id:
            return _enrich(f)
    raise HTTPException(status_code=404, detail="Finding not found")


@router.patch("/{finding_id}/status", response_model=FindingOut)
async def update_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    _user=Depends(require_permission("findings:approve")),
) -> FindingOut:
    for f in FINDINGS:
        if f["id"] == finding_id:
            _STATUS[finding_id] = payload.status
            return _enrich(f)
    raise HTTPException(status_code=404, detail="Finding not found")