"""CVSS v3.1 base-score calculator.

Faithful to the FIRST.org specification:
https://www.first.org/cvss/v3.1/specification-document

Only the *base* metric group is implemented, which is what a static
vulnerability assessment reports.
"""
from __future__ import annotations

from typing import Any

METRIC_WEIGHTS: dict[str, Any] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.5},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}

METRIC_LABELS: dict[str, dict[str, str]] = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},
}

REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def round_up(value: float) -> float:
    """CVSS v3.1 integer roundup. Naive ceil(x*10)/10 is wrong; this is not."""
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (int_input // 10_000 + 1) / 10


def parse_vector(vector: str) -> dict[str, str] | None:
    if not isinstance(vector, str):
        return None
    trimmed = vector.strip()
    if not trimmed.upper().startswith("CVSS:3.1/"):
        return None
    out: dict[str, str] = {}
    for part in trimmed.split("/")[1:]:
        if ":" not in part:
            return None
        key, _, value = part.partition(":")
        out[key.upper()] = value.upper()
    return out


def validate_metrics(metrics: dict[str, str] | None) -> list[str]:
    errors: list[str] = []
    if not metrics:
        return ["No metrics supplied"]

    for key in REQUIRED_METRICS:
        value = metrics.get(key)
        if not value:
            errors.append(f"Missing metric: {key}")
            continue
        allowed = METRIC_LABELS.get(key, {})
        if value not in allowed:
            errors.append(f'Invalid value "{value}" for metric {key} '
                          f"(allowed: {', '.join(allowed)})")
    return errors


def base_score(metrics: dict[str, str] | None) -> dict[str, Any]:
    errors = validate_metrics(metrics)
    if errors:
        return {"score": None, "severity": "unknown",
                "impact": None, "exploitability": None, "errors": errors}

    assert metrics is not None
    AV, AC, PR, UI, S, C, I, A = (metrics[k] for k in REQUIRED_METRICS)

    iss = 1 - (
        (1 - METRIC_WEIGHTS["CIA"][C])
        * (1 - METRIC_WEIGHTS["CIA"][I])
        * (1 - METRIC_WEIGHTS["CIA"][A])
    )

    if S == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = (
        8.22
        * METRIC_WEIGHTS["AV"][AV]
        * METRIC_WEIGHTS["AC"][AC]
        * METRIC_WEIGHTS["PR"][S][PR]
        * METRIC_WEIGHTS["UI"][UI]
    )

    if impact <= 0:
        score = 0.0
    elif S == "U":
        score = round_up(min(impact + exploitability, 10))
    else:
        score = round_up(min(1.08 * (impact + exploitability), 10))

    return {
        "score": score,
        "severity": severity_from_score(score),
        "impact": round(impact, 4),
        "exploitability": round(exploitability, 4),
        "errors": [],
    }


def score_from_vector(vector: str) -> dict[str, Any]:
    metrics = parse_vector(vector)
    if not metrics:
        return {"score": None, "severity": "unknown",
                "impact": None, "exploitability": None,
                "errors": ["Malformed vector"]}
    return base_score(metrics)


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def build_vector(metrics: dict[str, str]) -> str:
    order = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    return "CVSS:3.1/" + "/".join(f"{k}:{metrics[k]}" for k in order)


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2,
                  "info": 1, "none": 0, "unknown": -1}