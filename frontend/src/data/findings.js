/**
 * The finding catalogue.
 * Every field maps onto a required deliverable section:
 *   title, description, affectedComponent, cvss.vector (score computed at
 *   runtime), reproduction, evidence, businessImpact, remediation.
 */

export const CATEGORIES = [
  'Authentication & Session Management',
  'Authorization & Access Control',
  'Input Validation & Data Handling',
  'API Security',
  'Client-Side Security Controls',
  'Secure Communication',
  'Data Storage & Privacy',
  'Error Handling & Observability',
];

export const FINDINGS = [
  {
    id: 'WM-001',
    title: 'Reflected Cross-Site Scripting via the monitor-name parameter',
    category: 'Input Validation & Data Handling',
    cwe: 'CWE-79',
    owasp: 'A03:2021 — Injection',
    affectedComponent: 'Web UI › Monitor Detail view; GET /api/vuln/monitors?name=',
    severity: 'high',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
    labId: 'xss',
    summary: "The monitor-name query parameter is reflected into the DOM without output encoding, allowing an attacker to execute arbitrary JavaScript in the victim's authenticated session.",
    description:
      'The Monitor Detail view renders the `name` query parameter directly into the page ' +
      'using an unsafe HTML sink. No output encoding is applied and no ' +
      'Content-Security-Policy is present to constrain execution. Because the payload is ' +
      'reflected rather than stored, exploitation requires the victim to follow a crafted ' +
      'link — a realistic precondition given that monitor deep-links are routinely shared ' +
      'between operators over chat and email.',
    evidence: [
      'Request: GET /api/vuln/monitors?name=<img src=x onerror=alert(document.domain)>',
      'Response body contains the payload unencoded inside the <h1 class="monitor-title"> element.',
      'Browser renders the element, the onerror handler fires, and alert() executes.',
      'No Content-Security-Policy response header is returned on this route.',
    ],
    reproduction: [
      'Authenticate to the World Monitor web application as any role.',
      'Navigate to the Monitor Detail view.',
      'Append the payload ?name=<img src=x onerror=alert(document.domain)> to the URL.',
      'Observe that the JavaScript executes in the origin of the application.',
      'For a session-theft PoC, replace alert() with a fetch() that posts the token to an attacker-controlled collector.',
    ],
    businessImpact:
      'Successful exploitation allows an attacker to act fully as the victim: read and ' +
      'exfiltrate monitor data classified CONFIDENTIAL and RESTRICTED, perform ' +
      'state-changing operations such as deleting monitors or granting roles, and pivot ' +
      "to other users by chaining the payload. Given the application's role in global " +
      'supply-chain and sanctions monitoring, the confidentiality and integrity ' +
      'consequences are significant and may trigger regulatory notification obligations.',
    remediation: [
      'Encode all untrusted data at the point of output using a context-aware encoder. In React, avoid dangerouslySetInnerHTML entirely; render values as text nodes instead.',
      'If rich text is genuinely required, sanitise with a vetted library (DOMPurify) configured with an explicit allowlist — never with a hand-rolled regex.',
      "Deploy a strict Content-Security-Policy with per-response nonces and object-src 'none'.",
      'Validate the `name` parameter server-side against a conservative allowlist and reject angle brackets outright.',
      'Set session cookies with HttpOnly so that even a successful XSS cannot read the session token.',
    ],
    references: [
      'OWASP XSS Prevention Cheat Sheet',
      'CWE-79: Improper Neutralization of Input During Web Page Generation',
      'CSP Level 3 specification, §strict-dynamic',
    ],
  },

  {
    id: 'WM-002',
    title: 'SQL injection in the monitor search endpoint',
    category: 'API Security',
    cwe: 'CWE-89',
    owasp: 'A03:2021 — Injection',
    affectedComponent: 'POST /api/vuln/monitors/search',
    severity: 'critical',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' },
    labId: 'sqli',
    summary:
      'The search term is concatenated directly into a SQL statement, allowing an ' +
      'authenticated user to read, modify or destroy arbitrary rows in the monitors database.',
    description:
      'The monitor search endpoint builds its WHERE clause by string interpolation. ' +
      'No parameterisation is used. The endpoint is reachable by any authenticated user, ' +
      'including the lowest-privileged `viewer` role, so the attack surface is effectively ' +
      'the entire user base.',
    evidence: [
      "Payload: ' OR '1'='1 — the endpoint returns every row in the monitors table, including monitors owned by other tenants and marked RESTRICTED.",
      "Payload: '; DROP TABLE monitors; -- — the generated statement shows the destructive suffix appended verbatim.",
      'The API response echoes the exact SQL that was executed, confirming the injection point.',
    ],
    reproduction: [
      'Authenticate as the s.novak viewer account.',
      "POST to /api/vuln/monitors/search with body {\"term\":\"' OR '1'='1\"}.",
      'Observe that all five monitors are returned, including wm-1004 (RESTRICTED, owner a.reyes).',
      'Repeat with a UNION-based payload to enumerate the users table.',
    ],
    businessImpact:
      'Full read and write access to the application database. An attacker could exfiltrate ' +
      'all monitor data, all user records including password hashes, and pivot to other ' +
      'systems that share the same database credentials. Destruction of the monitors table ' +
      'would halt monitoring operations entirely.',
    remediation: [
      'Use parameterised queries or a well-maintained ORM that never interpolates values into SQL text.',
      'Apply least privilege to the database account used by the application — no DDL rights in production.',
      'Add a WAF rule as a compensating control, not as the primary fix.',
      'Enable database query logging and alerting on anomalous statement shapes.',
    ],
    references: [
      'OWASP SQL Injection Prevention Cheat Sheet',
      'CWE-89',
      'OWASP Query Parameterization Cheat Sheet',
    ],
  },

  {
    id: 'WM-003',
    title: 'Insecure Direct Object Reference on monitor retrieval',
    category: 'Authorization & Access Control',
    cwe: 'CWE-639',
    owasp: 'A01:2021 — Broken Access Control',
    affectedComponent: 'GET /api/vuln/monitors/{id}',
    severity: 'high',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N' },
    labId: 'idor',
    summary:
      'The monitor retrieval endpoint checks that the caller is authenticated but not that ' +
      'the caller owns or may access the requested monitor, allowing horizontal privilege ' +
      'escalation.',
    description:
      'Monitor identifiers are sequential and predictable (wm-1001 … wm-1005). The endpoint ' +
      'performs authentication but no object-level authorisation, so any authenticated user ' +
      'can retrieve any monitor by iterating identifiers. The API also returns the `notes` ' +
      'field, which frequently contains internal handling instructions.',
    evidence: [
      'Authenticated as m.okafor (id 2, role analyst), GET /api/vuln/monitors/wm-1004 returns 200 with full monitor data.',
      'wm-1004 is owned by user id 1 (a.reyes) and classified RESTRICTED.',
      'Enumerating wm-1000 through wm-1100 retrieved 5 valid records and 96 404s, confirming sequential identifier allocation.',
    ],
    reproduction: [
      'Authenticate as m.okafor.',
      'Request GET /api/vuln/monitors/wm-1001, then wm-1004.',
      'Observe that both return 200 and include monitors not owned by the caller.',
      'Automate enumeration across the identifier space to harvest the full dataset.',
    ],
    businessImpact:
      'Horizontal privilege escalation across every tenant and role boundary in the ' +
      'platform. Confidential and restricted supply-chain intelligence becomes readable by ' +
      'the lowest-privileged accounts, undermining the classification model the business ' +
      'relies on.',
    remediation: [
      'Enforce object-level authorisation on every request: the caller must be the owner, an explicit collaborator, or hold a role that grants global read.',
      'Replace sequential integer identifiers with unguessable UUIDv4 or ULID values — defence in depth, not a substitute for the authorisation check.',
      'Centralise the ownership check in a policy layer so it cannot be forgotten on new endpoints.',
      'Add automated authorisation regression tests that assert 403 for every cross-tenant access path.',
    ],
    references: [
      'OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization',
      'CWE-639',
    ],
  },

  {
    id: 'WM-004',
    title: 'Broken function-level authorisation on administrative endpoints',
    category: 'Authorization & Access Control',
    cwe: 'CWE-285',
    owasp: 'A01:2021 — Broken Access Control',
    affectedComponent: 'GET /api/vuln/admin/users, POST /api/vuln/admin/users/{id}/role',
    severity: 'critical',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' },
    labId: 'bfla',
    summary:
      'Administrative API routes are protected only by an authentication check. Any ' +
      'authenticated user, including a viewer, can list all users and escalate their own ' +
      'role to admin.',
    description:
      'The admin router applies an authentication middleware but no role check. Authorisation ' +
      'is enforced only in the React front-end, which hides the admin navigation for ' +
      'non-admin roles. Because the API is directly reachable, the UI check provides no ' +
      'security value whatsoever.',
    evidence: [
      'Authenticated as s.novak (role viewer), GET /api/vuln/admin/users returned 200 with all three user records.',
      'POST /api/vuln/admin/users/3/role with body {"role":"admin"} returned 200 and updated the caller\'s own role.',
      "The React bundle contains the literal string \"role === 'admin'\" as the only gate on the admin console route.",
    ],
    reproduction: [
      'Authenticate as the viewer account.',
      'Call GET /api/vuln/admin/users with the session cookie.',
      'Observe the full user list including email addresses and roles.',
      'Call POST /api/vuln/admin/users/3/role with {"role":"admin"} to escalate privileges.',
      'Re-request any admin resource to confirm the escalation persisted.',
    ],
    businessImpact:
      'Complete platform compromise from the lowest-privileged account. An attacker gains ' +
      'user administration, can create persistent backdoor accounts, can read and alter any ' +
      'monitor, and can disable audit logging.',
    remediation: [
      "Enforce authorisation server-side on every route using a declarative dependency (e.g. FastAPI's Depends(require_role('admin'))) rather than an inline if-statement.",
      'Deny by default: a route is public only if it is explicitly marked so.',
      'Add automated tests that assert 403 for every privileged route under each lower-privileged role.',
      'Never rely on client-side role checks for security; they shape the UI and nothing more.',
    ],
    references: [
      'OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization',
      'CWE-285',
    ],
  },

  {
    id: 'WM-005',
    title: 'JWT signature bypass via the `alg: none` header',
    category: 'Authentication & Session Management',
    cwe: 'CWE-347',
    owasp: 'A02:2021 — Cryptographic Failures',
    affectedComponent: 'GET /api/vuln/jwt/protected',
    severity: 'critical',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    labId: 'jwt',
    summary:
      'The token verifier selects its verification algorithm from the unauthenticated `alg` ' +
      'header. By setting the header to `none` and dropping the signature, an attacker forges ' +
      'a token with any claims they choose.',
    description:
      'The endpoint decodes the JWT header and, when `alg` is `none`, trusts the payload ' +
      'without performing any cryptographic verification. Because the role claim is taken ' +
      'directly from the payload, an attacker can escalate to admin by forging a token.',
    evidence: [
      'A legitimate viewer token was issued by POST /api/vuln/jwt/issue.',
      'The header was rewritten to {"alg":"none","typ":"JWT"} and the signature segment was dropped.',
      'The resulting token was accepted by GET /api/vuln/jwt/protected with signature_verified=false and role=admin.',
    ],
    reproduction: [
      'Issue a viewer token: POST /api/vuln/jwt/issue {"sub":"s.novak","role":"viewer"}.',
      'Base64url-decode the header and payload segments.',
      "Change the header's alg value to `none`. Change the payload's role to `admin`.",
      'Re-encode both segments and append a trailing dot with no signature.',
      'Send the forged token to GET /api/vuln/jwt/protected and observe signature_verified=false with role=admin.',
    ],
    businessImpact:
      'Complete authentication and authorisation bypass. Any anonymous attacker can ' +
      'impersonate any user, including administrators, and can mint tokens for accounts that ' +
      'do not exist.',
    remediation: [
      'Hard-code the expected algorithm at the verifier and reject any token whose `alg` header differs.',
      'Explicitly reject `alg: none`.',
      'Use a maintained JWT library rather than hand-rolled parsing, and require exp, iat, iss and aud claims.',
      'Rotate the signing secret and invalidate all outstanding tokens after the fix.',
    ],
    references: [
      'CWE-347: Improper Verification of Cryptographic Signature',
      'RFC 8725 — JSON Web Token Best Current Practices, §3.1',
      'OWASP JWT Cheat Sheet',
    ],
  },

  {
    id: 'WM-006',
    title: 'Mass assignment on the profile-update endpoint',
    category: 'API Security',
    cwe: 'CWE-915',
    owasp: 'A04:2021 — Insecure Design',
    affectedComponent: 'POST /api/vuln/profile/update',
    severity: 'high',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N' },
    labId: 'mass_assignment',
    summary:
      'The profile update handler copies every key in the request body onto the model, so an ' +
      'attacker can set privileged fields such as role and is_admin.',
    description:
      'The endpoint iterates the raw request body and writes each key onto the profile dict. ' +
      'There is no allowlist of writable fields, so a viewer can promote themselves to admin ' +
      'or grant themselves arbitrary credits.',
    evidence: [
      'POST /api/vuln/profile/update {"role":"admin"} returned 200 and the profile\'s role became admin.',
      'POST /api/vuln/profile/update {"is_admin":true} returned 200 with is_admin true.',
      'POST /api/vuln/profile/update {"credits":999999} returned 200 with credits updated.',
    ],
    reproduction: [
      'Authenticate as s.novak (viewer).',
      'POST to /api/vuln/profile/update with body {"role":"admin","is_admin":true}.',
      'GET /api/vuln/profile/update and observe the elevated role.',
    ],
    businessImpact:
      'Privilege escalation from the lowest-privileged role. Any authenticated user can ' +
      'become an administrator, and any numeric field (billing credits, quotas, access ' +
      'levels) can be set to an arbitrary value.',
    remediation: [
      "Define an explicit input model (Pydantic) for every endpoint and forbid extra fields: model_config = ConfigDict(extra='forbid').",
      'Assign fields by name from the validated model, never by iterating the request body.',
      'Add integration tests that POST a privileged field for every endpoint and assert it is ignored.',
    ],
    references: [
      'OWASP Mass Assignment Cheat Sheet',
      'CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes',
    ],
  },

  {
    id: 'WM-007',
    title: 'Absence of rate limiting on authentication',
    category: 'Authentication & Session Management',
    cwe: 'CWE-307',
    owasp: 'A07:2021 — Identification and Authentication Failures',
    affectedComponent: 'POST /api/vuln/login',
    severity: 'high',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    labId: 'rate_limit',
    summary:
      'The login endpoint processes an unlimited number of attempts per minute with no ' +
      'throttling, lockout, CAPTCHA or back-off, and reveals whether a username exists via ' +
      'distinct error messages.',
    description:
      'The handler accepts every request, records the attempt timestamp, and returns a ' +
      "distinct message for 'unknown user' versus 'wrong password'. This enables both online " +
      'password brute force and username enumeration.',
    evidence: [
      '20 consecutive POST /api/vuln/login requests returned non-429 status codes.',
      'The 200 OK on attempt 8 disclosed the correct password from the lab wordlist.',
      'Responses for an unknown username vs. a wrong password carry different `detail` strings.',
    ],
    reproduction: [
      'POST /api/vuln/login with {"username":"a.reyes","password":"password"}.',
      'Repeat with each entry in the lab wordlist.',
      'Observe that no request is throttled and that the correct password is accepted on the eighth attempt.',
    ],
    businessImpact:
      'Online credential stuffing and targeted brute force are fully practical against every ' +
      'account, including administrators. Given the account compromise statistics across the ' +
      'industry, this is a near-certain path to full platform compromise.',
    remediation: [
      'Implement a token-bucket rate limiter keyed on (username, source IP) with exponential back-off.',
      'Lock the account for a cooling-off period after a threshold of failures, or require an out-of-band unlock.',
      'Return an identical generic error message and constant response time for unknown users and wrong passwords.',
      'Require MFA for all privileged accounts, and prefer phishing-resistant factors (WebAuthn).',
      'Integrate a breach-corpus check at password-set time.',
    ],
    references: [
      'OWASP Authentication Cheat Sheet',
      'CWE-307: Improper Restriction of Excessive Authentication Attempts',
      'NIST SP 800-63B §5.2.2',
    ],
  },

  {
    id: 'WM-008',
    title: 'Excessive data exposure on the profile API',
    category: 'Data Storage & Privacy',
    cwe: 'CWE-213',
    owasp: 'A01:2021 — Broken Access Control',
    affectedComponent: 'GET /api/vuln/profile/{id}',
    severity: 'high',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N' },
    labId: 'data_exposure',
    summary:
      'The profile endpoint serialises the entire user object, leaking SSN, API key, internal ' +
      'handling notes and password hash to any authenticated caller.',
    description:
      'The handler returns the entire user record instead of projecting through a response ' +
      'schema. Fields documented as internal are therefore reachable by any authenticated ' +
      'user.',
    evidence: [
      'GET /api/vuln/profile/1 returned fields ssn, api_key, internal_notes and password_hash.',
      "The endpoint's _extra_fields_leaked field lists 6 fields beyond the documented contract.",
      'The SSN value in the response matches the seeded record exactly.',
    ],
    reproduction: [
      'Authenticate as any user.',
      'GET /api/vuln/profile/1.',
      'Compare the returned keys to the documented contract.',
    ],
    businessImpact:
      'Direct exposure of regulated personal data (SSN) and live API keys to any authenticated ' +
      'user. This is a reportable data-protection incident and enables lateral movement using ' +
      'the leaked API keys.',
    remediation: [
      'Define a Pydantic response model for every endpoint and return only its fields.',
      'Adopt a deny-by-default serialisation policy: a field must be explicitly included, never implicitly included.',
      'Separate internal-only fields into a distinct model or table and never co-mingle with API-facing columns.',
      'Add contract tests that assert the exact response key set for each endpoint.',
    ],
    references: [
      'OWASP API Security Top 10 — API3:2023 Broken Object Property Level Authorization',
      'CWE-213: Exposure of Sensitive Information Due to Incompatible Policies',
    ],
  },

  {
    id: 'WM-009',
    title: 'Prototype pollution in the preferences merge endpoint',
    category: 'Input Validation & Data Handling',
    cwe: 'CWE-1321',
    owasp: 'A03:2021 — Injection',
    affectedComponent: 'POST /api/vuln/preferences/merge',
    severity: 'high',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H' },
    labId: 'prototype_pollution',
    summary:
      'The deep-merge endpoint recurses into every key of the request body without filtering ' +
      '__proto__, constructor or prototype, allowing an attacker to poison the global object ' +
      'graph in a JavaScript runtime.',
    description:
      'In Node.js, the identical handler sets Object.prototype.isAdmin, which every object in ' +
      'the process then inherits — turning any `if (user.isAdmin)` check into an authorisation ' +
      'bypass. In Python the equivalent sinks are attribute injection and template-context ' +
      'poisoning.',
    evidence: [
      'POST /api/vuln/preferences/merge {"__proto__":{"isAdmin":true}} returned 200.',
      'The dangerous_keys_present list contains $.__proto__.isAdmin.',
      'The Node.js equivalent is shown in the response: ({}).isAdmin === true.',
    ],
    reproduction: [
      'POST /api/vuln/preferences/merge with {"__proto__":{"isAdmin":true}}.',
      "Inspect the response's dangerous_keys_present field.",
      'In a JavaScript runtime, evaluate ({}).isAdmin and observe true.',
    ],
    businessImpact:
      'In a JavaScript service this is a complete authorisation bypass: an attacker sets a ' +
      'single global property and every subsequent privilege check in the process succeeds.',
    remediation: [
      'Reject the keys __proto__, constructor, prototype, __class__ and __dict__ at the validation layer.',
      'Prefer an explicit allowlist of mergeable keys over a recursive merge of arbitrary input.',
      'In JavaScript, use Object.create(null) or a Map for user-controlled key/value storage.',
      'Apply a JSON schema to preference payloads and set additionalProperties: false.',
    ],
    references: [
      'CWE-1321: Improperly Controlled Modification of Object Prototype Attributes',
      'PortSwigger — Prototype pollution',
    ],
  },

  {
    id: 'WM-010',
    title: 'Missing HTTP security headers',
    category: 'Secure Communication',
    cwe: 'CWE-693',
    owasp: 'A05:2021 — Security Misconfiguration',
    affectedComponent: 'All responses from the assessed application',
    severity: 'medium',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N' },
    labId: 'headers',
    summary:
      'The application returns none of the modern browser-hardening headers: no ' +
      'Content-Security-Policy, no Strict-Transport-Security, no X-Content-Type-Options, no ' +
      'X-Frame-Options and no Referrer-Policy.',
    description:
      "The assessed application's responses contain only Server, X-Powered-By, X-AspNet-Version " +
      'and a public Cache-Control. Every browser-side defence-in-depth control is absent, and ' +
      'the Server and X-Powered-By headers leak exact framework versions.',
    evidence: [
      'GET /api/vuln/headers/echo returned the observed header map with no CSP, HSTS or X-CTO.',
      'The evaluator scored the posture below 60/100.',
      'Server: nginx/1.18.0 and X-Powered-By: Express/4.18.2 are returned verbatim.',
    ],
    reproduction: [
      'GET /api/vuln/headers/echo and record the response headers.',
      'Compare against the reference baseline returned by GET /api/vuln/headers/recommended.',
      "Note the number of required headers marked 'fail' by the evaluator.",
    ],
    businessImpact:
      'The absence of CSP removes the principal defence-in-depth control against XSS (finding ' +
      'WM-001). Missing HSTS exposes users to SSL-strip. Missing X-CTO enables MIME-sniffing ' +
      'attacks. The version banners give an attacker a free CVE shortlist for the exact nginx ' +
      'and Express releases in use.',
    remediation: [
      'Deploy the recommended header set at the CDN or reverse-proxy layer so it applies uniformly.',
      'Set Strict-Transport-Security with a long max-age and includeSubDomains, after confirming HTTPS everywhere.',
      "Adopt a nonce-based Content-Security-Policy rather than allowing 'unsafe-inline'.",
      'Suppress Server, X-Powered-By and X-AspNet-Version.',
      'Re-score the posture with the reference evaluator after deployment.',
    ],
    references: [
      'OWASP Secure Headers Project',
      'CWE-693: Protection Mechanism Failure',
      'MDN — HTTP security headers',
    ],
  },

  {
    id: 'WM-011',
    title: 'Session token stored in a JavaScript-readable location',
    category: 'Client-Side Security Controls',
    cwe: 'CWE-522',
    owasp: 'A02:2021 — Cryptographic Failures',
    affectedComponent: 'SPA token store; cookie flags on the assessed application',
    severity: 'high',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N' },
    labId: 'token_storage',
    summary:
      'The SPA persists the session bearer token in localStorage and the server sets the ' +
      'accompanying cookie without HttpOnly, Secure or SameSite. Any XSS — such as WM-001 — ' +
      'can exfiltrate the token.',
    description:
      'The assessed application issues a bearer token to the SPA, which writes it to ' +
      'localStorage under the key wm_token. The token is therefore readable from any ' +
      'JavaScript that executes in the origin. Combined with the reflected XSS in WM-001, an ' +
      'attacker can harvest credentials without ever seeing the login form.',
    evidence: [
      'POST /api/vuln/jwt/issue returned a bearer token.',
      'The Set-Cookie the application sends lacks HttpOnly, Secure and SameSite.',
      "The SPA reads and writes localStorage.getItem('wm_token') on every authenticated request.",
    ],
    reproduction: [
      'Authenticate to the assessed application and inspect localStorage.',
      'Observe the wm_token key and its value.',
      'Combine with WM-001: navigate to the XSS URL and observe that the payload can read the same key.',
    ],
    businessImpact:
      'A single XSS becomes full account takeover. Because the token is long-lived and not ' +
      'revocable from the client, the attacker retains access until expiry, and the token can ' +
      'be replayed from any network location.',
    remediation: [
      'Store the session token in an HttpOnly, Secure, SameSite=Strict cookie with the __Host- prefix.',
      'If a bearer token must be sent from JavaScript, keep it in memory only and refresh it frequently from a rotating refresh cookie.',
      'Implement server-side token revocation and rotate the session on privilege change.',
      'Pair the fix with the CSP and output-encoding controls from WM-001 and WM-010.',
    ],
    references: [
      'OWASP HTML5 Security Cheat Sheet — Storage APIs',
      'CWE-522: Insufficiently Protected Credentials',
      'OWASP Session Management Cheat Sheet',
    ],
  },

  {
    id: 'WM-012',
    title: 'Secrets and personal data written to application logs',
    category: 'Error Handling & Observability',
    cwe: 'CWE-532',
    owasp: 'A09:2021 — Security Logging and Monitoring Failures',
    affectedComponent: 'Authentication handler; SIEM log ingestion pipeline',
    severity: 'high',
    cvss: { vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N' },
    labId: 'log_redaction',
    summary:
      'The authentication handler writes the full request body — including the plaintext ' +
      'password, email, SSN and payment card number — into the application log, which is ' +
      'shipped to a third-party SIEM.',
    description:
      'The logging call interpolates the raw request body. Every credential submitted to the ' +
      'login endpoint, and every piece of personal data in any other request body, ends up in ' +
      'the log stream. Because the SIEM is a separate system with a wider audience, this ' +
      'defeats the access controls that protect the primary database.',
    evidence: [
      'POST /api/vuln/log/echo with a body containing a password, SSN and card number produced a raw_log_entry containing all three in plaintext.',
      'The redacted_log_entry produced by the reference redactor removed the same values.',
      'The redaction_hits list enumerates which rule fired for each field.',
    ],
    reproduction: [
      'POST /api/vuln/log/echo with {"username":"a.reyes","password":"Sunshine2019!","ssn":"412-88-7391"}.',
      'Compare raw_log_entry and redacted_log_entry in the response.',
      'Note that a SIEM search for the literal password would return the log line.',
    ],
    businessImpact:
      'Regulated personal data and live credentials are exposed to every operator of the ' +
      'logging platform, and are retained for the log retention period — often years. This is ' +
      'a reportable data-protection incident, and the leaked credentials allow account ' +
      'takeover if the user has reused the password elsewhere.',
    remediation: [
      'Never log request bodies wholesale. Log only the fields required for the operational purpose.',
      'Apply the reference redactor (services/redaction.py) at the logging boundary, before the record reaches any handler.',
      'Configure the logging framework to reject records containing known secret patterns, and alert on the rejection.',
      'Add a CI lint rule that fails on logging calls that interpolate a request body.',
      'Rotate any credential that has already been written to the log store, and purge the affected records.',
    ],
    references: [
      'OWASP Logging Cheat Sheet',
      'CWE-532: Insertion of Sensitive Information into Log File',
      'GDPR Art. 33 — Notification of a personal data breach',
    ],
  },
];

export const findingById = (id) => FINDINGS.find((f) => f.id === id) ?? null;
export const findingForLab = (labId) => FINDINGS.find((f) => f.labId === labId) ?? null;

/* ═══════════════════════════════════════════════════════════════════════
   Lab metadata — 1:1 with the twelve labs in src/labs/*
   ═══════════════════════════════════════════════════════════════════════ */
export const LABS = [
  {
    id: 'xss',
    findingId: 'WM-001',
    title: 'Reflected XSS in monitor-name parameter',
    summary: 'Monitor name is reflected into the DOM without encoding.',
    endpoints: ['GET /api/vuln/monitors'],
    parameters: ['name'],
    hints: [
      'Try a benign marker first: ?name=<b>probe</b>.',
      'Check whether the response body contains the raw angle brackets.',
      'An <img onerror> payload fires without user interaction beyond the click.',
    ],
  },
  {
    id: 'sqli',
    findingId: 'WM-002',
    title: 'SQL injection in monitor search',
    summary: 'Search term is concatenated into SQL.',
    endpoints: ['POST /api/vuln/monitors/search'],
    parameters: ['term'],
    hints: [
      "Start with ' OR '1'='1 — a tautology returns every row.",
      'The lab returns the exact SQL string it executed so you can see the injection.',
      'Try a UNION SELECT to enumerate the users table.',
    ],
  },
  {
    id: 'idor',
    findingId: 'WM-003',
    title: 'IDOR on monitor retrieval',
    summary: 'GET /monitors/{id} never checks ownership.',
    endpoints: ['GET /api/vuln/monitors/{id}'],
    parameters: ['id', 'asUser'],
    hints: [
      'Identifiers are sequential: wm-1001 … wm-1005.',
      'Authenticate as m.okafor (analyst) and request wm-1004 — an admin-owned RESTRICTED monitor.',
    ],
  },
  {
    id: 'bfla',
    findingId: 'WM-004',
    title: 'Broken function-level authorisation',
    summary: 'Admin routes are gated only by authentication, not authorisation.',
    endpoints: ['GET /api/vuln/admin/users', 'POST /api/vuln/admin/users/{id}/role'],
    parameters: ['id', 'role', 'asUser'],
    hints: [
      'Log in as s.novak (viewer) and call GET /api/vuln/admin/users.',
      'Escalate yourself: POST /api/vuln/admin/users/3/role with {"role":"admin"}.',
    ],
  },
  {
    id: 'jwt',
    findingId: 'WM-005',
    title: 'JWT signature bypass via alg:none',
    summary: 'The verifier trusts the alg header and accepts unsigned tokens.',
    endpoints: ['POST /api/vuln/jwt/issue', 'GET /api/vuln/jwt/protected'],
    parameters: ['token'],
    hints: [
      'Issue a viewer token first.',
      'Flip the header to alg: none, drop the signature, and re-encode.',
      'The protected endpoint decodes the header to decide which verifier to use.',
    ],
  },
  {
    id: 'mass_assignment',
    findingId: 'WM-006',
    title: 'Mass assignment on profile update',
    summary: 'Profile update copies every submitted field into the record.',
    endpoints: ['POST /api/vuln/profile/update'],
    parameters: ['*'],
    hints: [
      'The endpoint reads payload.role, payload.is_admin, payload.credits.',
      'Submit {"role":"admin"} and re-read your profile.',
    ],
  },
  {
    id: 'rate_limit',
    findingId: 'WM-007',
    title: 'Missing rate limiting on authentication',
    summary: 'Unlimited password guesses per minute.',
    endpoints: ['POST /api/vuln/login'],
    parameters: ['username', 'password'],
    hints: [
      'Fire 20 requests in a row — all are processed.',
      'The lab response reports the observed attempts-per-minute so you can quote a number.',
    ],
  },
  {
    id: 'data_exposure',
    findingId: 'WM-008',
    title: 'Excessive data exposure on profile API',
    summary: 'Profile endpoint returns SSN, API key, internal notes.',
    endpoints: ['GET /api/vuln/profile/{id}'],
    parameters: ['id'],
    hints: [
      'Compare the response shape to the documented contract.',
      'Fields to look for: ssn, api_key, internal_notes, password_hash.',
    ],
  },
  {
    id: 'prototype_pollution',
    findingId: 'WM-009',
    title: 'Prototype pollution in merge endpoint',
    summary: 'Deep-merge recurses into __proto__ without filtering.',
    endpoints: ['POST /api/vuln/preferences/merge'],
    parameters: ['__proto__', 'constructor', 'prototype'],
    hints: [
      'Submit {"__proto__":{"isAdmin":true}}.',
      'The response reports the resulting Object.prototype state.',
    ],
  },
  {
    id: 'headers',
    findingId: 'WM-010',
    title: 'Missing HTTP security headers',
    summary: 'The application returns no CSP, HSTS or X-CTO headers.',
    endpoints: ['GET /api/vuln/headers/echo'],
    parameters: [],
    hints: [
      'Compare the echoed header set to the recommended baseline.',
      'Server and X-Powered-By leak the exact framework versions.',
    ],
  },
  {
    id: 'token_storage',
    findingId: 'WM-011',
    title: 'Session token stored in localStorage',
    summary: 'The SPA writes the bearer token to localStorage, readable by any XSS.',
    endpoints: ['POST /api/vuln/jwt/issue'],
    parameters: [],
    hints: [
      "Combine with Lab 1: an XSS payload can read localStorage.getItem('wm_token').",
      'The cookie set by the lab is missing HttpOnly and Secure.',
    ],
  },
  {
    id: 'log_redaction',
    findingId: 'WM-012',
    title: 'Secrets and PII written to application logs',
    summary: 'Auth handler logs the full request body, including the password.',
    endpoints: ['POST /api/vuln/log/echo'],
    parameters: ['*'],
    hints: [
      'Send a body containing password, email and a card number.',
      'Compare the raw log entry with the redacted version returned alongside it.',
    ],
  },
];