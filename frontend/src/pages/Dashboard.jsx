import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { assessmentApi } from '../lib/mockApi';
import { SEVERITY_COLORS } from '../lib/cvss';
import Card from '../components/common/Card';
import Donut from '../components/common/Donut';
import SeverityBadge from '../components/findings/SeverityBadge';
import { useAuth } from '../context/AuthContext';

export default function Dashboard() {
  const { user } = useAuth();
  const [findings, setFindings] = useState([]);

  useEffect(() => { assessmentApi.listFindings().then(setFindings); }, []);

  const bySeverity = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1; return acc;
  }, {});

  const donut = Object.entries(bySeverity).map(([sev, count]) => ({
    label: sev, value: count, color: SEVERITY_COLORS[sev],
  }));

  const maxRisk = findings.reduce((m, f) => Math.max(m, f.cvss.score ?? 0), 0);

  return (
    <div className="col" style={{ gap: 20 }}>
      <div>
        <h1>Welcome back, {user?.fullName?.split(' ')[0] ?? user?.username}</h1>
        <p className="muted">
          Problem Statement ID <code>26163</code> — Security Assessment of the World Monitor application.
        </p>
      </div>

      <div className="grid grid--4">
        <div className="stat">
          <div className="stat__label">Findings</div>
          <div className="stat__value">{findings.length}</div>
          <div className="stat__sub">{Object.keys(bySeverity).length} severity levels</div>
        </div>
        <div className="stat">
          <div className="stat__label">Critical</div>
          <div className="stat__value" style={{ color: SEVERITY_COLORS.critical }}>
            {bySeverity.critical ?? 0}
          </div>
          <div className="stat__sub">Immediate remediation</div>
        </div>
        <div className="stat">
          <div className="stat__label">Highest CVSS</div>
          <div className="stat__value">{maxRisk.toFixed(1)}</div>
          <div className="stat__sub">CVSS v3.1 base</div>
        </div>
        <div className="stat">
          <div className="stat__label">Labs available</div>
          <div className="stat__value">12</div>
          <div className="stat__sub">1 per finding</div>
        </div>
      </div>

      <div className="grid grid--2">
        <Card title="Findings by severity">
          {donut.length ? <Donut data={donut} /> : <div className="muted small">No findings.</div>}
        </Card>

        <Card title="Quick links">
          <div className="col">
            <Link className="btn" to="/findings">Browse the finding catalogue</Link>
            <Link className="btn" to="/labs">Open the lab bench</Link>
            <Link className="btn" to="/report">Generate the report</Link>
            <Link className="btn btn--ghost" to="/scope">Review scope &amp; RoE</Link>
          </div>
        </Card>
      </div>

      <Card title="Top risks">
        <table className="table">
          <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>CVSS</th></tr></thead>
          <tbody>
            {[...findings].sort((a, b) => (b.cvss.score ?? 0) - (a.cvss.score ?? 0))
              .slice(0, 6).map((f) => (
                <tr key={f.id}>
                  <td><code>{f.id}</code></td>
                  <td><Link to={`/findings?id=${f.id}`}>{f.title}</Link></td>
                  <td><SeverityBadge severity={f.severity} score={f.cvss.score} /></td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{f.cvss.score?.toFixed(1)}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}