"""Header reference data and evaluator used by Lab 10 and finding WM-010."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HeaderSpec:
    name: str
    required: bool
    weight: int
    good: str
    why: str


RECOMMENDED_HEADERS: tuple[HeaderSpec, ...] = (
    HeaderSpec("Strict-Transport-Security", True, 15,
               "max-age=63072000; includeSubDomains; preload",
               "Forces every subsequent request over HTTPS, defeating SSL-strip and downgrade attacks."),
    HeaderSpec("Content-Security-Policy", True, 25,
               "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
               "The primary defence-in-depth control against XSS and data injection."),
    HeaderSpec("X-Content-Type-Options", True, 8, "nosniff",
               "Stops MIME sniffing, which turns benign uploads into script execution."),
    HeaderSpec("X-Frame-Options", True, 8, "DENY",
               "Legacy clickjacking defence; superseded by CSP frame-ancestors but still needed for old browsers."),
    HeaderSpec("Referrer-Policy", True, 7, "strict-origin-when-cross-origin",
               "Prevents leaking full URLs (which often contain tokens or IDs) to third parties."),
    HeaderSpec("Permissions-Policy", False, 7,
               "geolocation=(), microphone=(), camera=(), payment=()",
               "Shrinks the attack surface available to any injected script."),
    HeaderSpec("Cross-Origin-Opener-Policy", False, 6, "same-origin",
               "Isolates the browsing context, mitigating Spectre-class and window-reference attacks."),
    HeaderSpec("Cross-Origin-Resource-Policy", False, 6, "same-origin",
               "Blocks cross-origin reads of your resources."),
    HeaderSpec("Cross-Origin-Embedder-Policy", False, 5, "require-corp",
               "Required for cross-origin isolation (SharedArrayBuffer, high-resolution timers)."),
    HeaderSpec("Cache-Control", True, 8, "no-store, no-cache, must-revalidate, private",
               "Prevents authenticated responses from being written to shared or disk caches."),
    HeaderSpec("Server", False, 3, "(suppressed)",
               "Version banners hand attackers a free CVE shortlist."),
    HeaderSpec("X-Powered-By", False, 2, "(suppressed)", "Framework fingerprinting."),
)

_WEAK_PATTERNS = {
    "Strict-Transport-Security": ("max-age=0", "max-age=300"),
    "X-Content-Type-Options": (),
    "X-Frame-Options": ("ALLOW-FROM",),
    "Referrer-Policy": ("unsafe-url", "no-referrer-when-downgrade"),
    "Cache-Control": ("public",),
}


@dataclass
class HeaderResult:
    name: str
    status: str          # pass | warn | fail
    value: str | None
    expected: str
    why: str
    note: str


@dataclass
class HeaderEvaluation:
    score: int
    grade: str
    results: list[HeaderResult]


def evaluate_headers(header_map: dict[str, str]) -> HeaderEvaluation:
    lower = {k.lower(): v for k, v in header_map.items()}
    earned = 0
    possible = 0
    results: list[HeaderResult] = []

    for spec in RECOMMENDED_HEADERS:
        possible += spec.weight
        value = lower.get(spec.name.lower())
        present = bool(value)

        if not present:
            results.append(HeaderResult(
                name=spec.name,
                status="fail" if spec.required else "warn",
                value=None, expected=spec.good, why=spec.why,
                note="Header is absent.",
            ))
            continue

        assert value is not None
        weak = [p for p in _WEAK_PATTERNS.get(spec.name, ())
                if p.lower() in value.lower()]
        if weak:
            earned += spec.weight * 0.3
            results.append(HeaderResult(
                name=spec.name, status="warn", value=value,
                expected=spec.good, why=spec.why,
                note=f"Present but weakened by: {', '.join(weak)}",
            ))
        else:
            earned += spec.weight
            results.append(HeaderResult(
                name=spec.name, status="pass", value=value,
                expected=spec.good, why=spec.why,
                note="Correctly configured.",
            ))

    score = round(earned / possible * 100) if possible else 0
    return HeaderEvaluation(score=score, grade=_grade(score), results=results)


def _grade(score: int) -> str:
    if score >= 95: return "A+"
    if score >= 85: return "A"
    if score >= 75: return "B"
    if score >= 65: return "C"
    if score >= 50: return "D"
    if score >= 35: return "E"
    return "F"