import Card from '../components/common/Card';

const SCOPE = [
  'Authentication and session management',
  'Authorization and access control',
  'Input validation and data handling',
  'API security',
  'Client-side security controls',
  'Secure communication mechanisms',
  'Data storage and privacy protections',
];

const CONSTRAINTS = [
  'Testing must be performed only on authorised systems.',
  'No actions should affect production users or data.',
  'Exploitation should be limited to proof-of-concept validation.',
  'Compliance with applicable laws, policies, and ethical hacking guidelines is required.',
];

const DELIVERABLES = [
  'Vulnerability title',
  'Description',
  'Affected component',
  'Severity rating (CVSS v3.1 base)',
  'Steps to reproduce',
  'Proof of concept (executed in the lab bench)',
  'Business impact assessment',
  'Remediation recommendations',
];

export default function Scope() {
  return (
    <div className="col" style={{ gap: 20 }}>
      <div>
        <h1>Scope, constraints &amp; deliverables</h1>
        <p className="muted">Problem Statement ID 26163 — Security Assessment of the World Monitor application.</p>
      </div>

      <div className="grid grid--3">
        <Card title="Assessment scope">
          <ul className="ticks">{SCOPE.map((s) => <li key={s}>{s}</li>)}</ul>
        </Card>
        <Card title="Constraints">
          <ul className="ticks">{CONSTRAINTS.map((s) => <li key={s}>{s}</li>)}</ul>
        </Card>
        <Card title="Deliverables per finding">
          <ul className="ticks">{DELIVERABLES.map((s) => <li key={s}>{s}</li>)}</ul>
        </Card>
      </div>

      <Card title="Success criteria">
        <ul className="ticks">
          <li>At least one valid vulnerability is identified and documented.</li>
          <li>Evidence supports the existence of the vulnerability.</li>
          <li>Risk and impact are clearly explained.</li>
          <li>Practical mitigation strategies are provided.</li>
        </ul>
      </Card>

      <Card title="Authorisation">
        <div className="callout callout--danger">
          The lab bench contains deliberately insecure simulations of the World Monitor
          application. They exist so that each finding can be demonstrated with a working
          proof of concept against a controlled target. Running equivalent payloads against
          any system for which you do not hold explicit written authorisation is unlawful
          and unethical. By using this workbench you confirm that you are testing only the
          simulated targets provided here.
        </div>
      </Card>
    </div>
  );
}