"""Append-only evidence store. Evidence is never mutated, only added."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..database import evidence
from ..deps import CurrentUser, require_permission
from ..models import EvidenceItem, utcnow
from ..schemas import EvidenceCreate, EvidenceOut
from ..security import new_id
from ..services.redaction import redact_value

router = APIRouter()


def _to_out(item: EvidenceItem) -> EvidenceOut:
    return EvidenceOut(
        id=item.id, finding_id=item.finding_id, lab_id=item.lab_id,
        request=item.request, response=item.response, notes=item.notes,
        created_at=item.created_at, actor=item.actor,
    )


@router.get("", response_model=list[EvidenceOut])
async def list_evidence(
    user: CurrentUser,
    finding_id: str | None = Query(default=None),
) -> list[EvidenceOut]:
    items = evidence.all()
    if finding_id:
        items = [e for e in items if e.finding_id == finding_id]
    items.sort(key=lambda e: e.created_at, reverse=True)
    return [_to_out(e) for e in items]


@router.post("", response_model=EvidenceOut, status_code=201)
async def create_evidence(
    payload: EvidenceCreate,
    user=Depends(require_permission("evidence:write")),
) -> EvidenceOut:
    item = EvidenceItem(
        id=new_id("evd"),
        finding_id=payload.finding_id,
        lab_id=payload.lab_id,
        created_at=utcnow(),
        actor=user.username,
        # Redact secrets before persisting, so the evidence store itself
        # cannot become a secondary data-leak channel.
        request=redact_value(payload.request),
        response=redact_value(payload.response),
        notes=payload.notes,
    )
    evidence.insert(item.id, item)
    return _to_out(item)


@router.get("/{evidence_id}", response_model=EvidenceOut)
async def get_evidence(evidence_id: str, user: CurrentUser) -> EvidenceOut:
    item = evidence.get(evidence_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return _to_out(item)