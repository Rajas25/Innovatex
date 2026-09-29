const SECRET_KEYS = [
  'password', 'passwd', 'pwd', 'secret', 'token', 'access_token', 'refresh_token',
  'id_token', 'authorization', 'auth', 'apikey', 'api_key', 'apisecret',
  'client_secret', 'private_key', 'session', 'sessionid', 'cookie',
  'otp', 'pin', 'cvv', 'card_number', 'credit_card',
];

const PII_KEYS = ['ssn', 'social_security_number', 'national_id', 'tax_id', 'dob'];

const PATTERNS = [
  { id: 'email', label: 'Email address', re: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, mask: '[EMAIL]' },
  { id: 'ssn', label: 'US SSN', re: /\b\d{3}-\d{2}-\d{4}\b/g, mask: '[SSN]' },
  { id: 'card', label: 'Payment card', re: /\b(?:\d[ -]*?){13,19}\b/g, mask: '[CARD]' },
  { id: 'jwt', label: 'JSON Web Token', re: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, mask: '[JWT]' },
  { id: 'bearer', label: 'Bearer token', re: /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, mask: 'Bearer [TOKEN]' },
  { id: 'apiKey', label: 'API key', re: /\b(?:wmk|sk|pk|ghp|xox[baprs])_[A-Za-z0-9_-]{8,}\b/g, mask: '[API_KEY]' },
  { id: 'ipv4', label: 'IPv4 address', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, mask: '[IP]' },
  { id: 'awsKey', label: 'AWS access key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, mask: '[AWS_KEY]' },
];

export const REDACTION_RULES = [
  ...SECRET_KEYS.map((k) => ({ id: `key:${k}`, label: `Key "${k}"`, kind: 'key', value: k })),
  ...PII_KEYS.map((k) => ({ id: `pii:${k}`, label: `PII key "${k}"`, kind: 'key', value: k })),
  ...PATTERNS.map((p) => ({ id: p.id, label: p.label, kind: 'pattern', value: p.re, mask: p.mask })),
];

const MASK = '[REDACTED]';

export function redact(input, options = {}) {
  const { maxDepth = 12, patterns = true } = options;
  const hits = [];

  const walk = (node, path, depth) => {
    if (depth > maxDepth) return '[MAX_DEPTH]';
    if (node === null || node === undefined) return node;
    if (Array.isArray(node)) return node.map((item, i) => walk(item, `${path}[${i}]`, depth + 1));
    if (typeof node === 'object') {
      const out = {};
      for (const [key, value] of Object.entries(node)) {
        const lower = key.toLowerCase();
        const isSecret = SECRET_KEYS.some((s) => lower === s || lower.includes(s));
        const isPii = PII_KEYS.some((s) => lower === s || lower.includes(s));
        if (isSecret || isPii) {
          hits.push({ path: `${path}.${key}`, rule: isSecret ? 'secret-key' : 'pii-key' });
          out[key] = MASK;
          continue;
        }
        out[key] = walk(value, `${path}.${key}`, depth + 1);
      }
      return out;
    }
    if (typeof node === 'string' && patterns) {
      let value = node;
      for (const p of PATTERNS) {
        const re = new RegExp(p.re.source, p.re.flags);
        if (re.test(value)) {
          hits.push({ path, rule: p.id });
          value = value.replace(new RegExp(p.re.source, p.re.flags), p.mask);
        }
      }
      return value;
    }
    return node;
  };

  return { value: walk(input, '$', 0), hits };
}

export function redactValue(input, options) { return redact(input, options).value; }

export function safeStringify(value, maxBytes = 8192) {
  let json;
  try { json = JSON.stringify(value, null, 2); }
  catch { return '[UNSERIALISABLE]'; }
  if (json.length > maxBytes) return `${json.slice(0, maxBytes)}\n... [TRUNCATED at ${maxBytes} bytes]`;
  return json;
}