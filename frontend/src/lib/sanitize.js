/**
 * Input validation and output-encoding helpers.
 * The golden rule: ENCODE ON OUTPUT, VALIDATE ON INPUT, NEVER TRUST EITHER.
 */
const ENTITIES = {
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
  "'": '&#x27;', '/': '&#x2F;', '`': '&#x60;', '=': '&#x3D;',
};

export function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"'`=/]/g, (c) => ENTITIES[c]);
}

export function escapeJs(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"')
    .replace(/\n/g, '\\n').replace(/\r/g, '\\r')
    .replace(/</g, '\\u003C').replace(/>/g, '\\u003E')
    .replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

const XSS_PATTERNS = [
  { id: 'script-tag', label: 'Inline <script> tag', re: /<\s*script[\s>]/i, weight: 40 },
  { id: 'event-handler', label: 'Inline event handler (on*=)', re: /\son[a-z]+\s*=/i, weight: 30 },
  { id: 'javascript-uri', label: 'javascript: URI', re: /javascript\s*:/i, weight: 30 },
  { id: 'data-uri-html', label: 'data:text/html URI', re: /data\s*:\s*text\/html/i, weight: 25 },
  { id: 'svg-onload', label: '<svg> with onload', re: /<\s*svg[^>]*onload/i, weight: 30 },
  { id: 'iframe', label: '<iframe> element', re: /<\s*iframe/i, weight: 25 },
  { id: 'object-embed', label: '<object>/<embed> element', re: /<\s*(object|embed)/i, weight: 20 },
  { id: 'srcdoc', label: 'srcdoc attribute', re: /srcdoc\s*=/i, weight: 20 },
  { id: 'expression', label: 'CSS expression()', re: /expression\s*\(/i, weight: 25 },
  { id: 'template-literal', label: 'Template-literal break-out (${...})', re: /\$\{[^}]*\}/, weight: 15 },
  { id: 'img-onerror', label: '<img> with onerror', re: /<\s*img[^>]*onerror/i, weight: 30 },
  { id: 'entity-encoded', label: 'Entity-encoded angle bracket', re: /&lt;\s*script|&#x?0*3c;/i, weight: 10 },
];

export function analyseXss(input) {
  const value = String(input ?? '');
  const matches = [];
  let score = 0;
  for (const p of XSS_PATTERNS) {
    if (p.re.test(value)) { matches.push({ id: p.id, label: p.label, weight: p.weight }); score += p.weight; }
  }
  if (value.length > 200) score += 5;
  score = Math.min(score, 100);
  return { score, matches, verdict: score >= 30 ? 'malicious' : score > 0 ? 'suspicious' : 'clean' };
}

export const validators = {
  required: (v) => (v !== null && v !== undefined && String(v).trim().length > 0) || 'This field is required',
  maxLength: (n) => (v) => String(v ?? '').length <= n || `Must be ${n} characters or fewer`,
  email: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(v ?? '').trim()) || 'Enter a valid email address',
  strongPassword: (v) => {
    const value = String(v ?? '');
    if (value.length < 12) return 'Password must be at least 12 characters';
    if (!/[a-z]/.test(value)) return 'Password must include a lowercase letter';
    if (!/[A-Z]/.test(value)) return 'Password must include an uppercase letter';
    if (!/[0-9]/.test(value)) return 'Password must include a digit';
    if (!/[^A-Za-z0-9]/.test(value)) return 'Password must include a symbol';
    const breached = ['password', 'qwerty', 'letmein', 'welcome', 'admin123'];
    if (breached.some((b) => value.toLowerCase().includes(b))) return 'Password appears in known-breach corpora';
    return true;
  },
};