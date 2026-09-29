export const RECOMMENDED_HEADERS = [
  { name: 'Strict-Transport-Security', required: true, weight: 15,
    good: 'max-age=63072000; includeSubDomains; preload',
    why: 'Forces every subsequent request over HTTPS, defeating SSL-strip and downgrade attacks.',
    bad: ['missing', 'max-age=0', 'max-age=300'] },
  { name: 'Content-Security-Policy', required: true, weight: 25,
    good: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    why: 'The primary defence-in-depth control against XSS and data injection.',
    bad: ['unsafe-inline', 'unsafe-eval', '*', 'data:'] },
  { name: 'X-Content-Type-Options', required: true, weight: 8, good: 'nosniff',
    why: 'Stops MIME sniffing, which turns benign uploads into script execution.', bad: ['missing'] },
  { name: 'X-Frame-Options', required: true, weight: 8, good: 'DENY',
    why: 'Legacy clickjacking defence; superseded by CSP frame-ancestors but still needed for old browsers.',
    bad: ['missing', 'ALLOW-FROM'] },
  { name: 'Referrer-Policy', required: true, weight: 7, good: 'strict-origin-when-cross-origin',
    why: 'Prevents leaking full URLs (which often contain tokens or IDs) to third parties.',
    bad: ['missing', 'unsafe-url', 'no-referrer-when-downgrade'] },
  { name: 'Permissions-Policy', required: false, weight: 7,
    good: 'geolocation=(), microphone=(), camera=(), payment=()',
    why: 'Shrinks the attack surface available to any injected script.', bad: ['missing'] },
  { name: 'Cross-Origin-Opener-Policy', required: false, weight: 6, good: 'same-origin',
    why: 'Isolates the browsing context, mitigating Spectre-class and window-reference attacks.',
    bad: ['missing', 'unsafe-none'] },
  { name: 'Cross-Origin-Resource-Policy', required: false, weight: 6, good: 'same-origin',
    why: 'Blocks cross-origin reads of your resources.', bad: ['missing', 'cross-origin'] },
  { name: 'Cache-Control', required: true, weight: 8,
    good: 'no-store, no-cache, must-revalidate, private',
    why: 'Prevents authenticated responses from being written to shared or disk caches.',
    bad: ['missing', 'public', 'max-age=31536000'] },
  { name: 'Server', required: false, weight: 3, good: '(suppressed)',
    why: 'Version banners hand attackers a free CVE shortlist.', bad: ['missing'] },
  { name: 'X-Powered-By', required: false, weight: 2, good: '(suppressed)',
    why: 'Framework fingerprinting.', bad: ['missing'] },
];

export function evaluateHeaders(headerMap = {}) {
  const lower = {};
  for (const [k, v] of Object.entries(headerMap)) lower[k.toLowerCase()] = v;
  let earned = 0; let possible = 0;
  const results = [];

  for (const spec of RECOMMENDED_HEADERS) {
    possible += spec.weight;
    const value = lower[spec.name.toLowerCase()];
    const present = value !== undefined && value !== '';

    if (!present) {
      results.push({ name: spec.name, status: spec.required ? 'fail' : 'warn', value: null,
        expected: spec.good, why: spec.why, note: 'Header is absent.' });
      continue;
    }

    const weak = (spec.bad || []).filter((b) => b !== 'missing' && value.toLowerCase().includes(b.toLowerCase()));
    if (weak.length) {
      earned += spec.weight * 0.3;
      results.push({ name: spec.name, status: 'warn', value, expected: spec.good,
        why: spec.why, note: `Header present but weakened by: ${weak.join(', ')}` });
    } else {
      earned += spec.weight;
      results.push({ name: spec.name, status: 'pass', value, expected: spec.good,
        why: spec.why, note: 'Correctly configured.' });
    }
  }

  const score = possible === 0 ? 0 : Math.round((earned / possible) * 100);
  return { score, grade: gradeFromScore(score), results };
}

export function gradeFromScore(score) {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 75) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  if (score >= 35) return 'E';
  return 'F';
}

export function analyseCsp(csp) {
  const directives = {};
  const findings = [];
  for (const chunk of String(csp || '').split(';')) {
    const parts = chunk.trim().split(/\s+/).filter(Boolean);
    if (!parts.length) continue;
    const [name, ...sources] = parts;
    directives[name.toLowerCase()] = sources;
  }
  const scriptSrc = directives['script-src'] || directives['default-src'] || [];
  if (scriptSrc.includes("'unsafe-inline'")) findings.push({ severity: 'high', message: "script-src contains 'unsafe-inline'." });
  if (scriptSrc.includes("'unsafe-eval'")) findings.push({ severity: 'high', message: "script-src contains 'unsafe-eval'." });
  if (scriptSrc.includes('*')) findings.push({ severity: 'critical', message: 'script-src allows *.' });
  if (!directives['object-src']) findings.push({ severity: 'medium', message: 'object-src is not set.' });
  if (!directives['base-uri']) findings.push({ severity: 'medium', message: 'base-uri is not set.' });
  if (!directives['frame-ancestors']) findings.push({ severity: 'medium', message: 'frame-ancestors is not set.' });
  return { directives, findings };
}

export function renderHeaderBlock(headerMap) {
  return Object.entries(headerMap).map(([k, v]) => `${k}: ${v}`).join('\n');
}