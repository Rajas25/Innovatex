"""Thread-safe in-memory stores + a dedicated sqlite3 instance for the SQLi lab.

The stores are plain dicts guarded by an RLock. This is a training tool: the
data is intentionally volatile and is rebuilt from seed.py on every restart.
"""
from __future__ import annotations

import sqlite3
import threading
from typing import Any

from .models import AppUser, AuditEvent, EvidenceItem, Monitor, WorkbenchUser


class Store:
    """A tiny generic dict-backed table with an auto-increment counter."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._rows: dict[Any, Any] = {}
        self._lock = threading.RLock()
        self._counter = 0

    def next_id(self) -> int:
        with self._lock:
            self._counter += 1
            return self._counter

    def insert(self, key: Any, value: Any) -> Any:
        with self._lock:
            self._rows[key] = value
            return value

    def get(self, key: Any) -> Any | None:
        with self._lock:
            return self._rows.get(key)

    def all(self) -> list[Any]:
        with self._lock:
            return list(self._rows.values())

    def where(self, predicate) -> list[Any]:
        with self._lock:
            return [row for row in self._rows.values() if predicate(row)]

    def update(self, key: Any, **fields) -> Any | None:
        with self._lock:
            row = self._rows.get(key)
            if row is None:
                return None
            for k, v in fields.items():
                setattr(row, k, v)
            return row

    def delete(self, key: Any) -> bool:
        with self._lock:
            return self._rows.pop(key, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._rows.clear()
            self._counter = 0

    def __len__(self) -> int:
        return len(self._rows)


# ─── Workbench tables ────────────────────────────────────────────────────
workbench_users: Store = Store("workbench_users")

# ─── Assessed-application tables (the "World Monitor" backend) ───────────
app_users: Store = Store("app_users")
monitors: Store = Store("monitors")

# ─── Workbench operational tables ────────────────────────────────────────
audit_events: Store = Store("audit_events")
evidence: Store = Store("evidence")

# ─── Rate-limiter state (Lab 7) ──────────────────────────────────────────
# { username: [unix_ts, ...] }
rate_limit_buckets: dict[str, list[float]] = {}
rate_limit_lock = threading.RLock()

# ─── Lab token store (Lab 5) ─────────────────────────────────────────────
# Issued JWTs keyed by jti, so the lab can demonstrate replay.
issued_tokens: dict[str, dict] = {}
issued_tokens_lock = threading.RLock()


def reset_all() -> None:
    """Wipe every store. Used by tests and by POST /api/labs/reset."""
    for store in (workbench_users, app_users, monitors, audit_events, evidence):
        store.clear()
    with rate_limit_lock:
        rate_limit_buckets.clear()
    with issued_tokens_lock:
        issued_tokens.clear()


# ─── SQLite for the SQL-injection lab ────────────────────────────────────
_sqlite_lock = threading.RLock()
_sqlite_conn: sqlite3.Connection | None = None


def get_sqlite() -> sqlite3.Connection:
    """
    Return a process-wide in-memory SQLite connection used ONLY by the
    SQL-injection lab. `check_same_thread=False` is required because Uvicorn
    runs sync endpoints in a threadpool.
    """
    global _sqlite_conn
    with _sqlite_lock:
        if _sqlite_conn is None:
            _sqlite_conn = sqlite3.connect(
                ":memory:",
                check_same_thread=False,
                isolation_level=None,
            )
            _sqlite_conn.row_factory = sqlite3.Row
        return _sqlite_conn


def reset_sqlite() -> None:
    """Drop and recreate every table in the lab database."""
    conn = get_sqlite()
    with _sqlite_lock:
        cur = conn.cursor()
        cur.executescript(
            """
            DROP TABLE IF EXISTS monitors;
            DROP TABLE IF EXISTS users;
            CREATE TABLE monitors (
                id              TEXT PRIMARY KEY,
                owner_id        INTEGER NOT NULL,
                name            TEXT NOT NULL,
                region          TEXT NOT NULL,
                classification  TEXT NOT NULL,
                status          TEXT NOT NULL,
                shipments       INTEGER NOT NULL DEFAULT 0,
                risk_score      INTEGER NOT NULL DEFAULT 0,
                updated_at      TEXT NOT NULL,
                notes           TEXT DEFAULT ''
            );
            CREATE TABLE users (
                id            INTEGER PRIMARY KEY,
                username      TEXT UNIQUE NOT NULL,
                full_name     TEXT NOT NULL,
                email         TEXT NOT NULL,
                role          TEXT NOT NULL,
                password_hash TEXT NOT NULL
            );
            """
        )