"""Populate every store from a single, deterministic fixture set."""
from __future__ import annotations

from .database import (
    app_users,
    get_sqlite,
    monitors,
    reset_all,
    reset_sqlite,
    workbench_users,
)
from .models import AppUser, Monitor, WorkbenchUser
from .security import hash_password


WORKBENCH_FIXTURES: list[tuple[str, str, str, str]] = [
    # (username, password, full_name, role)
    ("viewer",   "Viewer!Pass2024",   "Priya Raman",     "viewer"),
    ("tester",   "Tester!Pass2024",   "Diego Marchetti", "tester"),
    ("lead",     "Lead!Pass2024",     "Amara Boateng",   "lead"),
]


APP_USER_FIXTURES: list[AppUser] = [
    AppUser(
        id=1, username="a.reyes", password="Sunshine2019!",
        full_name="Ana Reyes", email="a.reyes@worldmonitor.example",
        role="admin", department="Platform Engineering",
        ssn="412-88-7391",
        internal_notes="Break-glass account. Escalate to CISO before disabling.",
        api_key="wmk_live_9f3a2c7d41be0a5588cd",
        password_hash="$2b$12$Qm9ndXNIYXNoRm9yRGVtb25zdHJhdGlvbg",
        last_login_ip="203.0.113.44",
    ),
    AppUser(
        id=2, username="m.okafor", password="Logistics#2024",
        full_name="Michael Okafor", email="m.okafor@worldmonitor.example",
        role="analyst", department="Supply Chain Analytics",
        ssn="527-61-2044",
        internal_notes="Contractor — access expires 2025-06-30.",
        api_key="wmk_live_1a77fe0b93d24c6e8f10",
        password_hash="$2b$12$QW5vdGhlckRlbW9IYXNoVmFsdWU",
        last_login_ip="198.51.100.17",
    ),
    AppUser(
        id=3, username="s.novak", password="viewer-pass-1",
        full_name="Sofia Novak", email="s.novak@worldmonitor.example",
        role="viewer", department="Executive Reporting",
        ssn="633-45-8812",
        internal_notes="Read-only dashboard access.",
        api_key="wmk_live_44bc9d1e7a3f0258b6de",
        password_hash="$2b$12$VGhpcmREZW1vSGFzaFZhbHVl",
        last_login_ip="192.0.2.88",
    ),
]


MONITOR_FIXTURES: list[Monitor] = [
    Monitor("wm-1001", 1, "APAC Logistics — Port Congestion", "APAC", "CONFIDENTIAL", "green", 18240, 22,
            "2025-03-11T06:20:00Z", "Primary executive dashboard. Do not share externally."),
    Monitor("wm-1002", 2, "EMEA Supplier Financial Health", "EMEA", "INTERNAL", "amber", 9310, 58,
            "2025-03-11T05:02:00Z", "Includes unpublished credit ratings for 14 suppliers."),
    Monitor("wm-1003", 2, "LATAM Raw Materials Watch", "LATAM", "INTERNAL", "green", 4120, 31,
            "2025-03-10T22:41:00Z", ""),
    Monitor("wm-1004", 1, "Global Sanctions Screening", "GLOBAL", "RESTRICTED", "red", 0, 89,
            "2025-03-11T07:55:00Z", "Regulated data. Retention policy R-114 applies."),
    Monitor("wm-1005", 3, "Executive KPI Rollup", "GLOBAL", "INTERNAL", "green", 31470, 12,
            "2025-03-11T07:00:00Z", ""),
]


def seed_all() -> None:
    """Drop everything and rebuild from fixtures. Idempotent."""
    reset_all()

    for username, password, full_name, role in WORKBENCH_FIXTURES:
        uid = workbench_users.next_id()
        workbench_users.insert(
            uid,
            WorkbenchUser(
                id=uid,
                username=username,
                password_hash=hash_password(password),
                full_name=full_name,
                role=role,
            ),
        )

    for user in APP_USER_FIXTURES:
        app_users.insert(user.id, user)

    for monitor in MONITOR_FIXTURES:
        monitors.insert(monitor.id, monitor)

    _seed_sqlite()


def _seed_sqlite() -> None:
    reset_sqlite()
    conn = get_sqlite()
    cur = conn.cursor()

    for user in APP_USER_FIXTURES:
        cur.execute(
            "INSERT INTO users (id, username, full_name, email, role, password_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user.id, user.username, user.full_name, user.email, user.role, user.password_hash),
        )

    for m in MONITOR_FIXTURES:
        cur.execute(
            "INSERT INTO monitors (id, owner_id, name, region, classification, status, "
            "shipments, risk_score, updated_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (m.id, m.owner_id, m.name, m.region, m.classification,
             m.status, m.shipments, m.risk_score, m.updated_at, m.notes),
        )