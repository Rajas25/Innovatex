/**
 * CVSS v3.1 base-score calculator (FIRST.org spec).
 * Only the base metric group is implemented, which is what a static
 * vulnerability assessment reports.
 */
export const METRIC_WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0.0 },
};

export const METRIC_LABELS = {
  AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  AC: { L: 'Low', H: 'High' },
  PR: { N: 'None', L: 'Low', H: 'High' },
  UI: { N: 'None', R: 'Required' },
  S: { U: 'Unchanged', C: 'Changed' },
  C: { H: 'High', L: 'Low', N: 'None' },
  I: { H: 'High', L: 'Low', N: 'None' },
  A: { H: 'High', L: 'Low', N: 'None' },
};

const REQUIRED = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

export function roundUp(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

export function parseVector(vector) {
  if (typeof vector !== 'string') return null;
  const trimmed = vector.trim();
  if (!trimmed.toUpperCase().startsWith('CVSS:3.1/')) return null;
  const out = {};
  for (const part of trimmed.split('/').slice(1)) {
    const [k, v] = part.split(':');
    if (!k || !v) return null;
    out[k.toUpperCase()] = v.toUpperCase();
  }
  return out;
}

export function validateMetrics(metrics) {
  const errors = [];
  if (!metrics) return ['No metrics supplied'];
  for (const key of REQUIRED) {
    const value = metrics[key];
    if (!value) { errors.push(`Missing metric: ${key}`); continue; }
    const allowed = Object.keys(METRIC_LABELS[key] || {});
    if (!allowed.includes(value)) {
      errors.push(`Invalid value "${value}" for metric ${key} (allowed: ${allowed.join(', ')})`);
    }
  }
  return errors;
}

export function baseScore(metrics) {
  const errors = validateMetrics(metrics);
  if (errors.length) return { score: null, severity: 'unknown', impact: null, exploitability: null, errors };

  const { AV, AC, PR, UI, S, C, I, A } = metrics;
  const iss = 1 - (1 - METRIC_WEIGHTS.CIA[C]) * (1 - METRIC_WEIGHTS.CIA[I]) * (1 - METRIC_WEIGHTS.CIA[A]);

  const impact = S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);

  const exploitability =
    8.22 * METRIC_WEIGHTS.AV[AV] * METRIC_WEIGHTS.AC[AC] *
    METRIC_WEIGHTS.PR[S][PR] * METRIC_WEIGHTS.UI[UI];

  let score;
  if (impact <= 0) score = 0;
  else if (S === 'U') score = roundUp(Math.min(impact + exploitability, 10));
  else score = roundUp(Math.min(1.08 * (impact + exploitability), 10));

  return {
    score,
    severity: severityFromScore(score),
    impact: Number(impact.toFixed(4)),
    exploitability: Number(exploitability.toFixed(4)),
    errors: [],
  };
}

export function scoreFromVector(vector) {
  const metrics = parseVector(vector);
  if (!metrics) return { score: null, severity: 'unknown', errors: ['Malformed vector'] };
  return baseScore(metrics);
}

export function severityFromScore(score) {
  if (score === null || score === undefined || Number.isNaN(score)) return 'unknown';
  if (score === 0) return 'none';
  if (score < 4.0) return 'low';
  if (score < 7.0) return 'medium';
  if (score < 9.0) return 'high';
  return 'critical';
}

export const SEVERITY_COLORS = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--low)',
  info: 'var(--info)',
  none: 'var(--fg-3)',
  unknown: 'var(--fg-3)',
};

export const SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1, none: 0, unknown: -1 };