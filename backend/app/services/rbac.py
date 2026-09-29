"""Two separate RBAC domains.

  1. TOOL_*  — roles of the *assessment workbench itself* (enforced).
  2. APP_*   — roles of the *assessed application* (World Monitor). These
               are enforced nowhere on the server; that is the entire point
               of Lab 4 (BFLA). See routers/vulnerable/admin.py.
"""
from __future__ import annotations

# ─── Workbench RBAC (enforced) ───────────────────────────────────────────
TOOL_ROLES = ("viewer", "tester", "lead")

TOOL_PERMISSIONS: dict[str, list[str]] = {
    "findings:read":       ["viewer", "tester", "lead"],
    "labs:run":            ["tester", "lead"],
    "labs:reset":          ["lead"],
    "evidence:read":       ["viewer", "tester", "lead"],
    "evidence:write":      ["tester", "lead"],
    "findings:approve":    ["lead"],
    "report:generate":     ["tester", "lead"],
    "report:export":       ["lead"],
    "engagement:configure":["lead"],
}


def tool_can(role: str, permission: str) -> bool:
    return role in TOOL_PERMISSIONS.get(permission, [])


# ─── Assessed-application RBAC (NOT enforced; intentionally broken) ──────
APP_ROLES = ("viewer", "analyst", "operator", "admin")

APP_PERMISSIONS: dict[str, list[str]] = {
    "monitor:read":   ["viewer", "analyst", "operator", "admin"],
    "monitor:create": ["analyst", "operator", "admin"],
    "monitor:update": ["analyst", "operator", "admin"],
    "monitor:delete": ["operator", "admin"],
    "report:read":    ["viewer", "analyst", "operator", "admin"],
    "report:export":  ["analyst", "operator", "admin"],
    "user:read":      ["admin"],
    "user:manage":    ["admin"],
    "audit:read":     ["operator", "admin"],
    "config:write":   ["admin"],
}


def app_can(role: str, permission: str) -> bool:
    return role in APP_PERMISSIONS.get(permission, [])