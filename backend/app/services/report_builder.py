"""Assemble the deliverable report in Markdown, JSON or HTML."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any

from ..services.cvss import SEVERITY_ORDER

SEVERITY_ORDER_LIST = ["critical", "high", "medium", "low", "info", "none", "unknown"]


def severity_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITY_ORDER_LIST, 0)
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return {k: v for k, v in counts.items() if v > 0}


def _sorted(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.get("severity", "unknown"), -1),
                       -(f.get("cvss", {}).get("score") or 0)),
    )


def build_markdown(*, title: str, assessor: str, engagement_id: str,
                   findings: list[dict[str, Any]], generated_at: str) -> str:
    findings = _sorted(findings)
    summary = severity_summary(findings)

    lines: list[str] = []
    lines.append(f"# {title}\n")
    lines.append(f"**Engagement:** `{engagement_id}`  ")
    lines.append(f"**Assessor:** {assessor or '—'}  ")
    lines.append(f"**Generated:** {generated_at}  ")
    lines.append(f"**Findings:** {len(findings)}\n")

    lines.append("## Executive summary\n")
    if summary:
        lines.append("| Severity | Count |")
        lines.append("| --- | ---: |")
        for sev in SEVERITY_ORDER_LIST:
            if sev in summary:
                lines.append(f"| {sev.title()} | {summary[sev]} |")
        lines.append("")
    else:
        lines.append("_No findings recorded._\n")

    lines.append("\n## Scope\n")
    lines.append("- Authentication and session management")
    lines.append("- Authorization and access control")
    lines.append("- Input validation and data handling")
    lines.append("- API security")
    lines.append("- Client-side security controls")
    lines.append("- Secure communication mechanisms")
    lines.append("- Data storage and privacy protections\n")

    lines.append("\n## Findings\n")
    for idx, f in enumerate(findings, start=1):
        cvss = f.get("cvss", {})
        lines.append(f"### {idx}. {f.get('id', 'WM-???')} — {f.get('title', 'Untitled')}\n")
        lines.append(f"**Severity:** {f.get('severity', 'unknown').upper()} "
                     f"(CVSS {cvss.get('score', '—')})  ")
        lines.append(f"**Vector:** `{cvss.get('vector', '—')}`  ")
        lines.append(f"**Category:** {f.get('category', '—')}  ")
        lines.append(f"**CWE:** {f.get('cwe', '—')}  ")
        lines.append(f"**OWASP:** {f.get('owasp', '—')}  ")
        lines.append(f"**Affected component:** `{f.get('affected_component', '—')}`\n")

        lines.append("**Description**\n")
        lines.append(f"{f.get('description', '').strip()}\n")

        if f.get("evidence"):
            lines.append("**Evidence**\n")
            for e in f["evidence"]:
                lines.append(f"- {e}")
            lines.append("")

        if f.get("reproduction"):
            lines.append("**Steps to reproduce**\n")
            for i, step in enumerate(f["reproduction"], start=1):
                lines.append(f"{i}. {step}")
            lines.append("")

        lines.append("**Business impact**\n")
        lines.append(f"{f.get('business_impact', '').strip()}\n")

        if f.get("remediation"):
            lines.append("**Remediation**\n")
            for r in f["remediation"]:
                lines.append(f"- {r}")
            lines.append("")

        if f.get("references"):
            lines.append("**References**\n")
            for r in f["references"]:
                lines.append(f"- {r}")
            lines.append("")

        lines.append("\n---\n")

    lines.append("\n## Appendix A — Assessment constraints\n")
    lines.append("Testing was performed exclusively against an isolated instance of the "
                 "World Monitor application hosted in a lab environment. No production "
                 "users, data or infrastructure were accessed or affected. All exploitation "
                 "was limited to proof-of-concept validation. The engagement complied with "
                 "the authorising party's rules of engagement, applicable computer-misuse "
                 "legislation, and the assessor's professional code of ethics.\n")

    return "\n".join(lines)


def build_json(*, title: str, assessor: str, engagement_id: str,
               findings: list[dict[str, Any]], generated_at: str) -> str:
    payload = {
        "report": {
            "title": title,
            "engagement_id": engagement_id,
            "assessor": assessor,
            "generated_at": generated_at,
        },
        "summary": severity_summary(findings),
        "findings": _sorted(findings),
    }
    return json.dumps(payload, indent=2, default=str)


def build_html(*, title: str, assessor: str, engagement_id: str,
               findings: list[dict[str, Any]], generated_at: str) -> str:
    findings = _sorted(findings)
    summary = severity_summary(findings)
    esc = html.escape

    parts: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>{esc(title)}</title>",
        "<style>",
        "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;",
        "max-width:960px;margin:40px auto;padding:0 20px;color:#111;line-height:1.55}",
        "h1{border-bottom:2px solid #111;padding-bottom:8px}",
        "h2{margin-top:36px} h3{margin-top:28px}",
        ".sev{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;",
        "font-weight:600;text-transform:uppercase;letter-spacing:.05em}",
        ".critical{background:#ffe0e6;color:#a4001d} .high{background:#ffe9d6;color:#8a3d00}",
        ".medium{background:#fff5cf;color:#7a5c00} .low{background:#d6f6f1;color:#00534b}",
        ".info{background:#e0ecff;color:#0b3d91} .none,.unknown{background:#eee;color:#555}",
        "table{border-collapse:collapse;width:100%;margin:12px 0}",
        "th,td{border:1px solid #ccc;padding:6px 10px;text-align:left}",
        "th{background:#f5f5f5}",
        "code{background:#f0f2f5;padding:1px 5px;border-radius:3px;font-size:.9em}",
        "pre{background:#f5f7fa;padding:12px;border-radius:6px;overflow:auto}",
        "hr{border:none;border-top:1px solid #ddd;margin:32px 0}",
        "</style></head><body>",
        f"<h1>{esc(title)}</h1>",
        f"<p><strong>Engagement:</strong> <code>{esc(engagement_id)}</code><br>",
        f"<strong>Assessor:</strong> {esc(assessor or '—')}<br>",
        f"<strong>Generated:</strong> {esc(generated_at)}<br>",
        f"<strong>Findings:</strong> {len(findings)}</p>",
    ]

    if summary:
        parts.append("<h2>Executive summary</h2><table><thead><tr>"
                     "<th>Severity</th><th>Count</th></tr></thead><tbody>")
        for sev in SEVERITY_ORDER_LIST:
            if sev in summary:
                parts.append(f"<tr><td>{esc(sev.title())}</td><td>{summary[sev]}</td></tr>")
        parts.append("</tbody></table>")

    parts.append("<h2>Findings</h2>")
    for idx, f in enumerate(findings, start=1):
        cvss = f.get("cvss", {})
        sev = esc(f.get("severity", "unknown"))
        parts.append(f"<h3>{idx}. {esc(f.get('id', 'WM-???'))} — {esc(f.get('title', ''))}</h3>")
        parts.append(
            f"<p><span class='sev {sev}'>{esc(f.get('severity', 'unknown').title())}</span> "
            f"CVSS {esc(str(cvss.get('score', '—')))} · "
            f"<code>{esc(cvss.get('vector', '—'))}</code><br>"
            f"<strong>CWE:</strong> {esc(f.get('cwe', '—'))} · "
            f"<strong>OWASP:</strong> {esc(f.get('owasp', '—'))} · "
            f"<strong>Component:</strong> <code>{esc(f.get('affected_component', '—'))}</code></p>"
        )
        parts.append(f"<p>{esc(f.get('description', '')).replace(chr(10), '</p><p>')}</p>")

        if f.get("evidence"):
            parts.append("<p><strong>Evidence</strong></p><ul>")
            parts.extend(f"<li>{esc(e)}</li>" for e in f["evidence"])
            parts.append("</ul>")

        if f.get("reproduction"):
            parts.append("<p><strong>Steps to reproduce</strong></p><ol>")
            parts.extend(f"<li>{esc(s)}</li>" for s in f["reproduction"])
            parts.append("</ol>")

        if f.get("business_impact"):
            parts.append(f"<p><strong>Business impact.</strong> {esc(f['business_impact'])}</p>")

        if f.get("remediation"):
            parts.append("<p><strong>Remediation</strong></p><ul>")
            parts.extend(f"<li>{esc(r)}</li>" for r in f["remediation"])
            parts.append("</ul>")

        parts.append("<hr>")

    parts.append("</body></html>")
    return "".join(parts)


def utcnow_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")