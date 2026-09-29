"""Plain dataclasses used as the in-memory row type. Pydantic schemas live in schemas.py."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class WorkbenchUser:
    """A user of the *assessment tool*, not of World Monitor."""
    id: int
    username: str
    password_hash: str
    full_name: str
    role: str                       # viewer | tester | lead
    created_at: str = field(default_factory=utcnow)
    last_login_at: str | None = None


@dataclass
class AppUser:
    """A user of the *assessed application* (World Monitor). Fictional."""
    id: int
    username: str
    password: str                   # plaintext on purpose: simulated app is insecure
    full_name: str
    email: str
    role: str                       # viewer | analyst | operator | admin
    department: str
    mfa_enabled: bool = False
    # Fields that must NEVER be returned by a profile API (finding WM-008):
    ssn: str = ""
    internal_notes: str = ""
    api_key: str = ""
    password_hash: str = ""
    last_login_ip: str = ""
    created_at: str = field(default_factory=utcnow)


@dataclass
class Monitor:
    id: str
    owner_id: int
    name: str
    region: str
    classification: str             # INTERNAL | CONFIDENTIAL | RESTRICTED
    status: str                     # green | amber | red
    shipments: int
    risk_score: int
    updated_at: str = field(default_factory=utcnow)
    notes: str = ""


@dataclass
class AuditEvent:
    id: str
    ts: str
    actor: str
    action: str
    target: str
    result: str                     # allowed | denied | error
    source_ip: str
    detail: dict = field(default_factory=dict)


@dataclass
class EvidenceItem:
    id: str
    finding_id: str
    lab_id: str
    created_at: str
    actor: str
    request: dict
    response: dict
    notes: str = ""