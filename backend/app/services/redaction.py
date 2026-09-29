"""Log-hygiene helpers for Lab 12. Deny-by-default, recursive, depth-limited."""
from __future__ import annotations

import json
import re
from typing import Any

SECRET_KEYS = (
    "password", "passwd", "pwd", "secret", "token", "access_token", "refresh_token",
    "id_token", "authorization", "auth", "apikey", "api_key", "apisecret",
    "client_secret", "private_key", "session", "sessionid", "cookie", "set-cookie",
    "otp", "pin", "cvv", "card_number", "credit_card",
)
PII_KEYS = ("ssn", "social_security_number", "national_id", "tax_id", "dob", "date_of_birth")

PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    ("email",    "Email address",  re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "[EMAIL]"),
    ("ssn",      "US SSN",         re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                          "[SSN]"),
    ("card",     "Payment card",   re.compile(r"\b(?:\d[ -]*?){13,19}\b"),                        "[CARD]"),
    ("jwt",      "JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), "[JWT]"),
    ("bearer",   "Bearer token",   re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]+=*", re.I),          "Bearer [TOKEN]"),
    ("api_key",  "API key",        re.compile(r"\b(?:wmk|sk|pk|ghp|xox[baprs])_[A-Za-z0-9_-]{8,}\b"), "[API_KEY]"),
    ("ipv4",     "IPv4 address",   re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),                    "[IP]"),
    ("aws_key",  "AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),                  "[AWS_KEY]"),
]

MASK = "[REDACTED]"


def redact(value: Any, *, max_depth: int = 12, use_patterns: bool = True
           ) -> tuple[Any, list[dict[str, str]]]:
    """Return (scrubbed_copy, hits). Never mutates the input."""
    hits: list[dict[str, str]] = []

    def walk(node: Any, path: str, depth: int) -> Any:
        if depth > max_depth:
            return "[MAX_DEPTH]"
        if node is None:
            return None
        if isinstance(node, list):
            return [walk(item, f"{path}[{i}]", depth + 1) for i, item in enumerate(node)]
        if isinstance(node, dict):
            out: dict[str, Any] = {}
            for key, sub in node.items():
                lower = str(key).lower()
                if any(s in lower for s in SECRET_KEYS):
                    hits.append({"path": f"{path}.{key}", "rule": "secret-key"})
                    out[key] = MASK
                    continue
                if any(s in lower for s in PII_KEYS):
                    hits.append({"path": f"{path}.{key}", "rule": "pii-key"})
                    out[key] = MASK
                    continue
                out[key] = walk(sub, f"{path}.{key}", depth + 1)
            return out
        if isinstance(node, str) and use_patterns:
            text = node
            for pid, _label, pattern, mask in PATTERNS:
                if pattern.search(text):
                    hits.append({"path": path, "rule": pid})
                    text = pattern.sub(mask, text)
            return text
        return node

    return walk(value, "$", 0), hits


def redact_value(value: Any) -> Any:
    return redact(value)[0]


def safe_json(value: Any, *, max_bytes: int = 8192) -> str:
    try:
        text = json.dumps(value, indent=2, default=str)
    except (TypeError, ValueError):
        return "[UNSERIALISABLE]"
    if len(text) > max_bytes:
        return text[:max_bytes] + f"\n... [TRUNCATED at {max_bytes} bytes]"
    return text