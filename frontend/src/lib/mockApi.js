/**
 * In-browser simulation of the World Monitor backend.
 *
 * Every function returns a Promise so that swapping this module for a real
 * fetch-based client later requires no changes elsewhere. Each vulnerable
 * handler mirrors the exact defect documented in the corresponding finding,
 * and each lab runner returns the same shape as the FastAPI `LabRunResponse`.
 */
import { APP_USERS, MONITORS, LAB_WORDLIST } from '../data/mockDb';
import { FINDINGS } from '../data/findings';
import { analyseXss, escapeHtml } from './sanitize';
import { base64UrlEncode, decodeUnsafe, forgeNoneAlg, sign, verify } from './jwt';
import { evaluateHeaders } from './headers';
import { redact } from './redact';
import { scoreFromVector } from './cvss';

/* ─── Working copies (reset on demand) ────────────────────────────────── */
let users = JSON.parse(JSON.stringify(APP_USERS));
let monitors = JSON.parse(JSON.stringify(MONITORS));
let rateBuckets = {};
const LAB_JWT_SECRET = 'lab-jwt-secret-do-not-use-in-production-32bytes';

const delay = (ms = 60) => new Promise((r) => setTimeout(r, ms));
const clone = (v) => JSON.parse(JSON.stringify(v));

export function resetAll() {
  users = JSON.parse(JSON.stringify(APP_USERS));
  monitors = JSON.parse(JSON.stringify(MONITORS));
  rateBuckets = {};
  // Clear the profile overlay used by the mass-assignment lab.
  for (const k of Object.keys(profiles)) delete profiles[k];
}

const findUser = (username) => users.find((u) => u.username === username);

/* ═══════════════════════════════════════════════════════════════════════
   Vulnerable endpoint implementations
   ═══════════════════════════════════════════════════════════════════════ */

/** 🚨 VULNERABLE — reflects `name` verbatim into HTML. WM-001. */
export async function getMonitorByNameHtml(name = '') {
  const body = `<!doctype html>
<html><head><meta charset="utf-8"><title>World Monitor</title></head>
<body><h1 class="monitor-title">${name}</h1>
<p>No monitors matched your search.</p></body></html>`;
  return { status: 200, body, headers: {} };
}

/** 🚨 VULNERABLE — SQL concatenation. WM-002. Simulated with a naive matcher. */
export async function searchMonitors(term = '') {
  const sql =
    `SELECT id, owner_id, name, region, classification, status, shipments, ` +
    `risk_score, updated_at, notes FROM monitors WHERE name LIKE '%${term}%'`;

  let rows = [];
  let error = null;

  try {
    if (/'\s*or\s*'?1'?\s*=\s*'?1/i.test(term) || /or\s+1\s*=\s*1/i.test(term)) {
      // Tautology — return every row.
      rows = monitors;
    } else if (/union\s+select/i.test(term)) {
      // UNION injection — project the users table instead.
      rows = users.map((u) => ({
        id: u.id,
        owner_id: u.id,
        name: u.username,
        region: u.fullName,
        classification: u.email,
        status: u.role,
        shipments: 0,
        risk_score: 0,
        updated_at: u.createdAt ?? '',
        notes: u.passwordHash,
      }));
    } else if (/drop\s+table/i.test(term)) {
      // Destructive payload — the vulnerable service would have executed it.
      error = 'Simulated: DROP TABLE monitors executed';
    } else if (/--/.test(term) || term.includes("'")) {
      // Comment-based bypass — treat as a tautology for demonstration.
      rows = monitors;
    } else {
      const lower = term.toLowerCase();
      rows = monitors.filter((m) => m.name.toLowerCase().includes(lower));
    }
  } catch (e) {
    error = e.message;
  }

  return { status: 200, executedSql: sql, term, rowCount: rows.length, rows, error };
}

/** 🚨 VULNERABLE — no ownership check. WM-003. */
export async function getMonitor(monitorId, asUser = 's.novak') {
  const monitor = monitors.find((m) => m.id === monitorId);
  if (!monitor) return { status: 404, detail: 'Monitor not found' };

  const caller = findUser(asUser);

  return {
    status: 200,
    body: {
      ...monitor,
      _ownerId: monitor.ownerId,
      _caller: caller?.username ?? null,
      _callerRole: caller?.role ?? null,
      _accessDecision: 'ALLOWED (no ownership check performed)',
    },
  };
}

/** 🚨 VULNERABLE — no role check. WM-004. */
export async function adminListUsers(asUser = 's.novak') {
  const caller = findUser(asUser);
  return {
    status: 200,
    body: {
      _caller: caller?.username,
      _callerRole: caller?.role,
      _authorisation: 'NONE — authenticated users reach this route',
      users: users.map((u) => ({
        id: u.id,
        username: u.username,
        full_name: u.fullName,
        email: u.email,
        role: u.role,
        department: u.department,
        last_login_ip: u.lastLoginIp,
      })),
    },
  };
}

export async function adminSetRole(userId, role, asUser = 's.novak') {
  const caller = findUser(asUser);
  const target = users.find((u) => u.id === userId);
  if (!target) return { status: 404, detail: 'User not found' };

  const oldRole = target.role;
  target.role = role;

  return {
    status: 200,
    body: {
      _caller: caller?.username,
      _callerRole: caller?.role,
      _authorisation: 'NONE — privilege escalation succeeded',
      target_user_id: userId,
      old_role: oldRole,
      new_role: role,
    },
  };
}

/** 🚨 VULNERABLE — returns every column. WM-008. */
export async function getProfile(userId) {
  const user = users.find((u) => u.id === userId);
  if (!user) return { status: 404, detail: 'User not found' };

  const contractFields = ['id', 'username', 'fullName', 'email', 'department', 'role'];

  const payload = {
    id: user.id,
    username: user.username,
    full_name: user.fullName,
    email: user.email,
    department: user.department,
    role: user.role,
    ssn: user.ssn,
    api_key: user.apiKey,
    internal_notes: user.internalNotes,
    password_hash: user.passwordHash,
    last_login_ip: user.lastLoginIp,
  };

  const leaked = ['ssn', 'api_key', 'internal_notes', 'password_hash', 'last_login_ip', 'full_name'];

  return {
    status: 200,
    body: {
      _contract_fields: contractFields,
      _extra_fields_leaked: leaked,
      _note: `${leaked.length} fields beyond the documented contract were returned.`,
      ...payload,
    },
  };
}

/* ─── Mass-assignment profile overlay ─────────────────────────────────── */
const profiles = {};

function profileFor(username) {
  if (!profiles[username]) {
    const u = findUser(username);
    profiles[username] = {
      username: u?.username,
      full_name: u?.fullName,
      email: u?.email,
      department: u?.department,
      role: u?.role,
      is_admin: u?.role === 'admin',
      credits: 0,
    };
  }
  return profiles[username];
}

export async function readProfile(asUser = 's.novak') {
  return { status: 200, body: clone(profileFor(asUser)) };
}

/** 🚨 VULNERABLE — copies every submitted key. WM-006. */
export async function updateProfile(body, asUser = 's.novak') {
  const p = profileFor(asUser);
  const before = clone(p);

  for (const [k, v] of Object.entries(body)) p[k] = v;

  return {
    status: 200,
    body: {
      _before: before,
      _after: clone(p),
      _note: 'Every submitted key was persisted. There is no allowlist.',
    },
  };
}

/** 🚨 VULNERABLE — no rate limiting, distinct error messages. WM-007. */
export async function appLogin(username, password) {
  const now = Date.now() / 1000;
  rateBuckets[username] = (rateBuckets[username] ?? []).filter((t) => now - t < 60);
  rateBuckets[username].push(now);
  const attempts = rateBuckets[username].length;

  const user = findUser(username);
  if (!user) return { status: 401, detail: 'Unknown user', attemptsLastMinute: attempts };
  if (user.password !== password) {
    return { status: 401, detail: 'Wrong password', attemptsLastMinute: attempts };
  }
  return { status: 200, detail: 'ok', role: user.role, attemptsLastMinute: attempts };
}

/** 🚨 VULNERABLE — JWT verifier trusts the alg header. WM-005. */
export async function issueJwt(sub, role) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub,
    role,
    iat: now,
    nbf: now,
    exp: now + 900,
    iss: 'world-monitor-lab',
    aud: 'world-monitor-api',
  };
  const token = await sign(payload, LAB_JWT_SECRET, { alg: 'HS256' });
  return { token, claims: payload };
}

export async function verifyJwt(token) {
  const decoded = decodeUnsafe(token);
  if (!decoded.ok) return { status: 400, detail: 'Malformed token' };

  const alg = String(decoded.header.alg).toLowerCase();
  let claims;
  let signatureVerified;

  if (alg === 'none') {
    // The bug: trust the payload when the header says "none".
    claims = decoded.payload;
    signatureVerified = false;
  } else {
    const result = await verify(token, LAB_JWT_SECRET, { allowedAlgs: ['HS256'] });
    if (!result.valid) {
      return {
        status: 401,
        detail: 'Invalid token',
        reason: result.reason,
        header: result.header,
        payload: result.payload,
      };
    }
    claims = result.payload;
    signatureVerified = true;
  }

  return {
    status: 200,
    authorised: true,
    signatureVerified,
    header: decoded.header,
    claims,
  };
}

/* ─── Prototype pollution ─────────────────────────────────────────────── */
const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype', '__class__', '__dict__'];

function findDangerousKeys(node, path = '$') {
  const hits = [];
  if (node && typeof node === 'object' && !Array.isArray(node)) {
    for (const [k, v] of Object.entries(node)) {
      if (DANGEROUS_KEYS.includes(k)) hits.push(`${path}.${k}`);
      hits.push(...findDangerousKeys(v, `${path}.${k}`));
    }
  } else if (Array.isArray(node)) {
    node.forEach((item, i) => hits.push(...findDangerousKeys(item, `${path}[${i}]`)));
  }
  return hits;
}

/** 🚨 VULNERABLE — recurses into __proto__. WM-009. */
function deepMergeVulnerable(dst, src) {
  for (const [k, v] of Object.entries(src)) {
    if (v && typeof v === 'object' && !Array.isArray(v) &&
        dst[k] && typeof dst[k] === 'object') {
      deepMergeVulnerable(dst[k], v);
    } else {
      dst[k] = v;
      // Honestly simulate the JS prototype-pollution consequence.
      if (k === '__proto__' && v && typeof v === 'object') {
        try { Object.assign(Object.prototype, v); } catch { /* noop */ }
      }
    }
  }
  return dst;
}

export async function mergePreferences(body) {
  const target = {
    theme: 'dark',
    timezone: 'UTC',
    notifications: { email: true, sms: false },
  };
  const merged = deepMergeVulnerable(target, body ?? {});

  return {
    status: 200,
    body: {
      merged_preferences: merged,
      dangerous_keys_present: findDangerousKeys(merged),
      prototype_isAdmin: ({}).isAdmin ?? undefined,
    },
  };
}

/* ─── Insecure header set ─────────────────────────────────────────────── */
export const INSECURE_HEADERS = {
  'Server': 'nginx/1.18.0 (Ubuntu)',
  'X-Powered-By': 'Express/4.18.2',
  'X-AspNet-Version': '4.0.30319',
  'Cache-Control': 'public, max-age=31536000',
};

/* ─── Log echo without redaction ──────────────────────────────────────── */
export async function logEcho(body) {
  const rawLog = `INFO auth.login.attempt body=${JSON.stringify(body)}`;
  const { value: redacted, hits } = redact(body);
  return {
    status: 200,
    body: {
      raw_log_entry: rawLog,
      redacted_log_entry: `INFO auth.login.attempt body=${JSON.stringify(redacted)}`,
      redaction_hits: hits,
      raw_length: rawLog.length,
    },
  };
}

/* ═══════════════════════════════════════════════════════════════════════
   Lab dispatcher
   ═══════════════════════════════════════════════════════════════════════ */
export async function runLab(labId, payload = {}) {
  await delay(80);

  switch (labId) {
    case 'xss': {
      const name = payload.name ?? '<img src=x onerror=alert(1)>';
      const { status, body } = await getMonitorByNameHtml(name);
      const analysis = analyseXss(name);
      const reflected = body.includes(name);
      const exploited = reflected && analysis.verdict !== 'clean';
      return {
        labId, findingId: 'WM-001', exploited,
        request: { method: 'GET', path: '/api/vuln/monitors', query: { name } },
        response: {
          status,
          bodySnippet: body.slice(0, 600),
          reflectedVerbatim: reflected,
          staticAnalysis: analysis,
          cspHeader: null,
        },
        verdict: reflected
          ? `Payload reflected unencoded (${analysis.verdict}, risk ${analysis.score}/100).`
          : 'Payload not reflected; target not vulnerable to this input.',
        notes: 'Fix: encode on output and deploy a strict CSP. See finding WM-001.',
        encodedSafe: body.replace(name, escapeHtml(name)).slice(0, 600),
      };
    }

    case 'sqli': {
      const term = payload.term ?? "' OR '1'='1";
      const result = await searchMonitors(term);
      const exploited = result.rowCount > 3 || /--|or\s+1/i.test(term);
      return {
        labId, findingId: 'WM-002', exploited,
        request: { method: 'POST', path: '/api/vuln/monitors/search', body: { term } },
        response: {
          status: 200,
          executedSql: result.executedSql,
          rowCount: result.rowCount,
          sampleRows: result.rows.slice(0, 3),
          error: result.error,
        },
        verdict: `Injected term returned ${result.rowCount} rows — the query executed with attacker-controlled SQL.`,
        notes: 'Fix: parameterise the query. See finding WM-002.',
      };
    }

    case 'idor': {
      const id = payload.id ?? 'wm-1004';
      const asUser = payload.asUser ?? 's.novak';
      const res = await getMonitor(id, asUser);
      const caller = findUser(asUser);
      const exploited = res.status === 200 && res.body._ownerId !== caller?.id;
      return {
        labId, findingId: 'WM-003', exploited,
        request: { method: 'GET', path: `/api/vuln/monitors/${id}`, query: { asUser } },
        response: { status: res.status, body: res.body },
        verdict: exploited
          ? `Caller '${asUser}' read monitor owned by user id ${res.body._ownerId} without an ownership check.`
          : 'No cross-owner access in this run.',
        notes: 'Fix: object-level authorisation + unguessable identifiers. See WM-003.',
      };
    }

    case 'bfla': {
      const asUser = payload.asUser ?? 's.novak';
      const targetId = Number(payload.targetId ?? 3);
      const role = payload.role ?? 'admin';
      const before = users.find((u) => u.id === targetId)?.role;
      const listing = await adminListUsers(asUser);
      const escalate = await adminSetRole(targetId, role, asUser);
      const after = users.find((u) => u.id === targetId)?.role;
      const exploited = before !== 'admin' && after === 'admin';
      return {
        labId, findingId: 'WM-004', exploited,
        request: {
          method: 'POST',
          path: `/api/vuln/admin/users/${targetId}/role`,
          query: { asUser },
          body: { role },
        },
        response: {
          listStatus: listing.status,
          listExcerpt: JSON.stringify(listing.body).slice(0, 400),
          escalationStatus: escalate.status,
          escalationBody: escalate.body,
          roleBefore: before,
          roleAfter: after,
        },
        verdict: exploited
          ? `Viewer '${asUser}' read the user directory and escalated user ${targetId} from '${before}' to '${after}'.`
          : 'Escalation did not persist.',
        notes: 'Fix: enforce role checks server-side on every admin route. See WM-004.',
      };
    }

    case 'jwt': {
      const issued = await issueJwt('s.novak', 'viewer');
      const forged = forgeNoneAlg(issued.token, { role: 'admin', escalated: true });
      const replay = await verifyJwt(forged);
      const exploited = replay.status === 200 &&
        replay.signatureVerified === false &&
        replay.claims?.role === 'admin';
      return {
        labId, findingId: 'WM-005', exploited,
        request: {
          method: 'GET',
          path: '/api/vuln/jwt/protected',
          query: { token: forged },
        },
        response: {
          status: replay.status,
          originalToken: issued.token,
          forgedToken: forged,
          decodedHeader: decodeUnsafe(forged)?.header,
          decodedPayload: decodeUnsafe(forged)?.payload,
          serverResponse: replay,
        },
        verdict: exploited
          ? "Forged token accepted with signatureVerified=false and role escalated to 'admin' — full authentication bypass."
          : 'Forged token was rejected.',
        notes: 'Fix: reject `alg: none` and pin the algorithm. See WM-005.',
      };
    }

    case 'mass_assignment': {
      const asUser = payload.asUser ?? 's.novak';
      const fields = payload.fields ?? { role: 'admin', is_admin: true, credits: 999999 };
      const res = await updateProfile(fields, asUser);
      const exploited =
        res.body._after.role === 'admin' ||
        res.body._after.is_admin === true ||
        (res.body._after.credits ?? 0) > 1000;
      return {
        labId, findingId: 'WM-006', exploited,
        request: {
          method: 'POST',
          path: '/api/vuln/profile/update',
          query: { asUser },
          body: fields,
        },
        response: { status: res.status, body: res.body },
        verdict: exploited
          ? 'Privileged fields were accepted from the client and written to the profile.'
          : 'No privileged field was accepted.',
        notes: 'Fix: allowlist writable fields. See WM-006.',
      };
    }

    case 'rate_limit': {
      const username = payload.username ?? 'a.reyes';
      const guesses = payload.guesses ?? LAB_WORDLIST;
      const log = [];
      let successAt = null;

      for (let i = 0; i < guesses.length; i += 1) {
        const r = await appLogin(username, guesses[i]);
        log.push({
          attempt: i + 1,
          password: guesses[i],
          status: r.status,
          detail: r.detail,
          attemptsLastMinute: r.attemptsLastMinute,
        });
        if (r.status === 200 && successAt === null) successAt = i + 1;
      }

      const exploited = log.every((e) => e.status !== 429);
      return {
        labId, findingId: 'WM-007', exploited,
        request: {
          method: 'POST',
          path: '/api/vuln/login',
          body: { username, guesses: `${guesses.length} attempts` },
        },
        response: { log, successAtAttempt: successAt, totalAttempts: guesses.length },
        verdict: `${guesses.length} password guesses were processed in under a minute with no throttling. Online brute force is fully practical.`,
        notes: 'Fix: per-account + per-IP throttling, lockout, MFA. See WM-007.',
      };
    }

    case 'data_exposure': {
      const userId = Number(payload.userId ?? 1);
      const res = await getProfile(userId);
      const exploited = (res.body?._extra_fields_leaked?.length ?? 0) > 0;
      return {
        labId, findingId: 'WM-008', exploited,
        request: { method: 'GET', path: `/api/vuln/profile/${userId}` },
        response: { status: res.status, body: res.body },
        verdict: exploited
          ? `${res.body._extra_fields_leaked.length} sensitive fields (${res.body._extra_fields_leaked.slice(0, 5).join(', ')}…) were returned beyond the documented contract.`
          : 'No extra fields were returned.',
        notes: 'Fix: use explicit response models. See WM-008.',
      };
    }

    case 'prototype_pollution': {
      const body = payload.body ?? { __proto__: { isAdmin: true } };
      const res = await mergePreferences(body);
      const exploited = res.body.dangerous_keys_present.length > 0;
      return {
        labId, findingId: 'WM-009', exploited,
        request: { method: 'POST', path: '/api/vuln/preferences/merge', body },
        response: {
          status: res.status,
          body: res.body,
          nodeEquivalent: exploited ? '({}).isAdmin === true' : '',
        },
        verdict: exploited
          ? 'Dangerous keys reached the merged object. Object.prototype was poisoned.'
          : 'No dangerous key survived the merge.',
        notes: 'Fix: allowlist keys; reject __proto__/constructor/prototype. See WM-009.',
      };
    }

    case 'headers': {
      const evaluation = evaluateHeaders(INSECURE_HEADERS);
      return {
        labId, findingId: 'WM-010',
        exploited: evaluation.score < 60,
        request: { method: 'GET', path: '/api/vuln/headers/echo' },
        response: {
          observedHeaders: INSECURE_HEADERS,
          score: evaluation.score,
          grade: evaluation.grade,
          results: evaluation.results,
        },
        verdict: `Header posture scored ${evaluation.score}/100 (grade ${evaluation.grade}). ${evaluation.results.filter((r) => r.status === 'fail').length} required headers are absent.`,
        notes: 'Fix: deploy the baseline at the CDN/edge. See WM-010.',
      };
    }

    case 'token_storage': {
      const issued = await issueJwt('s.novak', 'viewer');
      return {
        labId, findingId: 'WM-011', exploited: true,
        request: {
          method: 'POST',
          path: '/api/vuln/jwt/issue',
          body: { sub: 's.novak', role: 'viewer' },
        },
        response: {
          token: issued.token,
          setCookieReceived: `wm_token=${issued.token.slice(0, 24)}…; Path=/`,
          cookieFlags: { HttpOnly: false, Secure: false, SameSite: null, Prefix: null },
          localStorageKey: 'wm_token',
          jsReadable: true,
        },
        verdict: 'Token is readable from JavaScript (no HttpOnly). Any XSS — see WM-001 — can exfiltrate it and impersonate the user until expiry.',
        notes: 'Fix: HttpOnly + Secure + SameSite=Strict + __Host- prefix. See WM-011.',
      };
    }

    case 'log_redaction': {
      const body = payload.body ?? {
        username: 'a.reyes',
        password: 'Sunshine2019!',
        email: 'a.reyes@worldmonitor.example',
        ssn: '412-88-7391',
        cardNumber: '4111 1111 1111 1111',
      };
      const res = await logEcho(body);
      const leaked = ['Sunshine2019!', '412-88-7391', '4111'].some((s) =>
        res.body.raw_log_entry.includes(s));
      return {
        labId, findingId: 'WM-012', exploited: leaked,
        request: { method: 'POST', path: '/api/vuln/log/echo', body },
        response: { status: res.status, body: res.body },
        verdict: leaked
          ? `Raw log entry contains secrets/PII. The redacted form removed ${res.body.redaction_hits.length} item(s).`
          : 'No secret reached the raw log.',
        notes: 'Fix: redact before logging. See WM-012.',
      };
    }

    default:
      throw new Error(`Unknown lab: ${labId}`);
  }
}

/* ═══════════════════════════════════════════════════════════════════════
   Assessment API (findings catalogue — read-only)
   ═══════════════════════════════════════════════════════════════════════ */
export const assessmentApi = {
  async listFindings() {
    await delay(40);
    return FINDINGS.map((f) => {
      const s = scoreFromVector(f.cvss.vector);
      return {
        ...f,
        cvss: {
          ...f.cvss,
          score: s.score,
          severity: s.severity || f.severity,
        },
        status: 'open',
      };
    });
  },

  async getFinding(id) {
    const all = await assessmentApi.listFindings();
    return all.find((f) => f.id === id) ?? null;
  },
};