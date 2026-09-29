import { Link } from 'react-router-dom';
import Card from '../common/Card';
import CodeBlock from '../common/CodeBlock';
import SeverityBadge from './SeverityBadge';

export default function FindingDetail({ finding }) {
  return (
    <Card>
      <div className="row row--wrap" style={{ marginBottom: 8 }}>
        <SeverityBadge severity={finding.severity} score={finding.cvss.score} />
        <span className="badge badge--neutral">{finding.id}</span>
        <span className="badge badge--neutral">{finding.cwe}</span>
        <span className="badge badge--neutral">{finding.owasp}</span>
      </div>

      <h2>{finding.title}</h2>
      <p className="muted small">
        <strong>Affected component:</strong> <code>{finding.affectedComponent}</code>
      </p>

      <CodeBlock caption="CVSS v3.1 vector" code={finding.cvss.vector} />

      <div style={{ marginTop: 16 }}>
        <h3>Description</h3>
        <p>{finding.description}</p>
      </div>

      <div style={{ marginTop: 16 }}>
        <h3>Evidence</h3>
        <ul className="ticks">
          {finding.evidence.map((e) => <li key={e}><code>{e}</code></li>)}
        </ul>
      </div>

      <div style={{ marginTop: 16 }}>
        <h3>Steps to reproduce</h3>
        <ol className="steps">
          {finding.reproduction.map((s) => <li key={s}>{s}</li>)}
        </ol>
      </div>

      <div style={{ marginTop: 16 }}>
        <h3>Business impact</h3>
        <p>{finding.businessImpact}</p>
      </div>

      <div style={{ marginTop: 16 }}>
        <h3>Remediation</h3>
        <ul className="ticks">
          {finding.remediation.map((r) => <li key={r}>{r}</li>)}
        </ul>
      </div>

      {finding.references?.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <h3>References</h3>
          <ul className="ticks">
            {finding.references.map((r) => <li key={r}>{r}</li>)}
          </ul>
        </div>
      )}

      <div className="callout callout--info mt-16">
        <strong>Proof of concept.</strong> This finding is demonstrated by the{' '}
        <Link to={`/labs/${finding.labId}`}>{finding.labId} lab</Link>. Run the lab to
        capture a reproducible request/response pair on the local workbench.
      </div>
    </Card>
  );
}