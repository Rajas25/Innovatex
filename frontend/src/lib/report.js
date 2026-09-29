import { scoreFromVector, SEVERITY_ORDER } from './cvss';

const SEVERITY_ORDER_LIST = ['critical', 'high', 'medium', 'low', 'info', 'none', 'unknown'];

export function severitySummary(findings) {
  const counts = Object.fromEntries(SEVERITY_ORDER_LIST.map((s) => [s, 0]));
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  return Object.fromEntries(Object.entries(counts).filter(([, v]) => v > 0));
}

function sorted(findings) {
  return [...findings].sort((a, b) =>
    (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0) ||
    (b.cvss.score ?? 0) - (a.cvss.score ?? 0));
}

export function buildReport({ title, assessor, engagementId, findings, format }) {
  const enriched = findings.map((f) => {
    const score = scoreFromVector(f.cvss.vector);
    return { ...f, cvss: { ...f.cvss, score: score.score, severity: score.severity || f.severity } };
  });
  const generatedAt = new Date().toISOString().replace('T', ' ').slice(0, 19) + 'Z';

  if (format === 'json') {
    return {
      filename: `world-monitor-assessment-${engagementId}.json`,
      content: JSON.stringify({
        report: { title, engagement_id: engagementId, assessor, generated_at: generatedAt },
        summary: severitySummary(enriched),
        findings: sorted(enriched),
      }, null, 2),
      summary: severitySummary(enriched), generatedAt, findingCount: enriched.length,
    };
  }

  if (format === 'html') {
    const esc = (s) => String(s).replace(/[&<>"']/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;' }[c]));
    const rows = sorted(enriched).map((f, i) => `
      <h3>${i + 1}. ${esc(f.id)} — ${esc(f.title)}</h3>
      <p><span class="sev ${f.severity}">${f.severity.toUpperCase()}</span>
         CVSS ${f.cvss.score} · <code>${esc(f.cvss.vector)}</code><br>
         <strong>CWE:</strong> ${esc(f.cwe)} · <strong>OWASP:</strong> ${esc(f.owasp)}<br>
         <strong>Component:</strong> <code>${esc(f.affectedComponent)}</code></p>
      <p>${esc(f.description)}</p>
      <p><strong>Evidence</strong></p><ul>${f.evidence.map((e) => `<li>${esc(e)}</li>`).join('')}</ul>
      <p><strong>Steps to reproduce</strong></p><ol>${f.reproduction.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>
      <p><strong>Business impact.</strong> ${esc(f.businessImpact)}</p>
      <p><strong>Remediation</strong></p><ul>${f.remediation.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>
      <hr>`).join('');
    const summaryRows = Object.entries(severitySummary(enriched))
      .map(([s, c]) => `<tr><td>${s}</td><td>${c}</td></tr>`).join('');
    const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>${esc(title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;line-height:1.55;color:#111}
h1{border-bottom:2px solid #111;padding-bottom:8px}h3{margin-top:28px}
.sev{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;text-transform:uppercase}
.critical{background:#ffe0e6;color:#a4001d}.high{background:#ffe9d6;color:#8a3d00}
.medium{background:#fff5cf;color:#7a5c00}.low{background:#d6f6f1;color:#00534b}
table{border-collapse:collapse;margin:12px 0}th,td{border:1px solid #ccc;padding:6px 10px}
code{background:#f0f2f5;padding:1px 5px;border-radius:3px}</style></head><body>
<h1>${esc(title)}</h1>
<p><strong>Engagement:</strong> ${esc(engagementId)}<br>
<strong>Assessor:</strong> ${esc(assessor || '—')}<br>
<strong>Generated:</strong> ${esc(generatedAt)}<br>
<strong>Findings:</strong> ${enriched.length}</p>
<h2>Executive summary</h2><table><thead><tr><th>Severity</th><th>Count</th></tr></thead>
<tbody>${summaryRows}</tbody></table>
<h2>Findings</h2>${rows}</body></html>`;
    return {
      filename: `world-monitor-assessment-${engagementId}.html`,
      content: html, summary: severitySummary(enriched), generatedAt, findingCount: enriched.length,
    };
  }

  /* Markdown default */
  const lines = [];
  lines.push(`# ${title}\n`);
  lines.push(`**Engagement:** \`${engagementId}\`  `);
  lines.push(`**Assessor:** ${assessor || '—'}  `);
  lines.push(`**Generated:** ${generatedAt}  `);
  lines.push(`**Findings:** ${enriched.length}\n`);

  lines.push('## Executive summary\n');
  const sum = severitySummary(enriched);
  if (Object.keys(sum).length) {
    lines.push('| Severity | Count |');
    lines.push('| --- | ---: |');
    for (const sev of SEVERITY_ORDER_LIST) if (sum[sev]) lines.push(`| ${sev} | ${sum[sev]} |`);
    lines.push('');
  } else lines.push('_No findings recorded._\n');

  lines.push('\n## Scope\n');
  lines.push('- Authentication and session management');
  lines.push('- Authorization and access control');
  lines.push('- Input validation and data handling');
  lines.push('- API security');
  lines.push('- Client-side security controls');
  lines.push('- Secure communication mechanisms');
  lines.push('- Data storage and privacy protections\n');

  lines.push('\n## Findings\n');
  sorted(enriched).forEach((f, idx) => {
    lines.push(`### ${idx + 1}. ${f.id} — ${f.title}\n`);
    lines.push(`**Severity:** ${f.severity.toUpperCase()} (CVSS ${f.cvss.score})  `);
    lines.push(`**Vector:** \`${f.cvss.vector}\`  `);
    lines.push(`**Category:** ${f.category}  `);
    lines.push(`**CWE:** ${f.cwe}  `);
    lines.push(`**OWASP:** ${f.owasp}  `);
    lines.push(`**Affected component:** \`${f.affectedComponent}\`\n`);
    lines.push('**Description**\n');
    lines.push(`${f.description}\n`);
    if (f.evidence?.length) {
      lines.push('**Evidence**\n');
      f.evidence.forEach((e) => lines.push(`- ${e}`));
      lines.push('');
    }
    if (f.reproduction?.length) {
      lines.push('**Steps to reproduce**\n');
      f.reproduction.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
      lines.push('');
    }
    lines.push('**Business impact**\n');
    lines.push(`${f.businessImpact}\n`);
    if (f.remediation?.length) {
      lines.push('**Remediation**\n');
      f.remediation.forEach((r) => lines.push(`- ${r}`));
      lines.push('');
    }
    if (f.references?.length) {
      lines.push('**References**\n');
      f.references.forEach((r) => lines.push(`- ${r}`));
      lines.push('');
    }
    lines.push('\n---\n');
  });

  lines.push('\n## Appendix A — Assessment constraints\n');
  lines.push('Testing was performed exclusively against an isolated instance of the '
    + 'World Monitor application hosted in a lab environment. No production users, data '
    + 'or infrastructure were accessed or affected. All exploitation was limited to '
    + 'proof-of-concept validation. The engagement complied with the authorising party\'s '
    + 'rules of engagement, applicable computer-misuse legislation, and the assessor\'s '
    + 'professional code of ethics.\n');

  return {
    filename: `world-monitor-assessment-${engagementId}.md`,
    content: lines.join('\n'),
    summary: sum, generatedAt, findingCount: enriched.length,
  };
}