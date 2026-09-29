"""JWT helpers for Lab 5. The *vulnerable* verification path lives in the lab
router; this module holds the correct implementation, used by the workbench.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded)


def decode_unverified(token: str) -> dict[str, Any]:
    """Decode header + payload without checking anything. For display only."""
    try:
        header_b64, payload_b64, sig = token.split(".")
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        return {"ok": True, "header": header, "payload": payload, "signature": sig,
                "raw": {"header": header_b64, "payload": payload_b64, "signature": sig}}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def sign(payload: dict[str, Any], secret: str, *, alg: str = "HS256",
         header_overrides: dict[str, Any] | None = None) -> str:
    header = {"alg": alg, "typ": "JWT"}
    if header_overrides:
        header.update(header_overrides)

    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}"

    if alg.lower() == "none":
        return f"{signing_input}."

    if alg.upper() not in ("HS256", "HS384", "HS512"):
        raise ValueError(f"Unsupported lab algorithm: {alg}")

    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}[alg.upper()]
    sig = hmac.new(secret.encode(), signing_input.encode(), digest).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


def verify(token: str, secret: str, *, allowed_algs: tuple[str, ...] = ("HS256",),
           leeway: int = 0) -> dict[str, Any]:
    """Correct verification. Rejects `none`, enforces exp/nbf, checks signature."""
    decoded = decode_unverified(token)
    if not decoded["ok"]:
        return {"valid": False, "reason": "malformed_token"}

    header = decoded["header"]
    payload = decoded["payload"]

    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        return {"valid": False, "reason": "alg_none_rejected", "header": header, "payload": payload}
    if header.get("alg") not in allowed_algs:
        return {"valid": False, "reason": "alg_not_allowed", "header": header, "payload": payload}

    signing_input = f"{decoded['raw']['header']}.{decoded['raw']['payload']}"
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}[header["alg"]]
    expected = _b64url_encode(hmac.new(secret.encode(), signing_input.encode(), digest).digest())

    if not hmac.compare_digest(expected, decoded["signature"]):
        return {"valid": False, "reason": "bad_signature", "header": header, "payload": payload}

    now = int(time.time())
    if "exp" not in payload:
        return {"valid": False, "reason": "missing_exp", "header": header, "payload": payload}
    if payload["exp"] < now - leeway:
        return {"valid": False, "reason": "expired", "header": header, "payload": payload}
    if "nbf" in payload and payload["nbf"] > now + leeway:
        return {"valid": False, "reason": "not_yet_valid", "header": header, "payload": payload}

    return {"valid": True, "reason": "ok", "header": header, "payload": payload}


def forge_none_alg(token: str, overrides: dict[str, Any] | None = None) -> str:
    """Take a real token and re-issue it with `alg: none` and altered claims."""
    decoded = decode_unverified(token)
    if not decoded["ok"]:
        raise ValueError("Cannot decode source token")
    header = {**decoded["header"], "alg": "none"}
    payload = {**decoded["payload"], **(overrides or {})}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."