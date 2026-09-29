import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { assessmentApi } from '../lib/mockApi';
import { SEVERITY_ORDER } from '../lib/cvss';
import Card from '../components/common/Card';
import EmptyState from '../components/common/EmptyState';
import FindingCard from '../components/findings/FindingCard';
import FindingDetail from '../components/findings/FindingDetail';

export default function Findings() {
  const [findings, setFindings] = useState([]);
  const [params, setParams] = useSearchParams();
  const activeId = params.get('id');
  const severity = params.get('severity') ?? '';
  const category = params.get('category') ?? '';

  useEffect(() => { assessmentApi.listFindings().then(setFindings); }, []);

  const filtered = useMemo(() => {
    let list = findings;
    if (severity) list = list.filter((f) => f.severity === severity);
    if (category) list = list.filter((f) => f.category === category);
    return [...list].sort((a, b) =>
      (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0) ||
      (b.cvss.score ?? 0) - (a.cvss.score ?? 0));
  }, [findings, severity, category]);

  const active = findings.find((f) => f.id === activeId) ?? null;
  const categories = useMemo(() => [...new Set(findings.map((f) => f.category))].sort(), [findings]);

  function setParam(key, value) {
    const next = { id: activeId ?? '', severity, category };
    next[key] = value;
    if (!next[key]) delete next[key];
    setParams(next);
  }

  return (
    <div className="grid" style={{ gridTemplateColumns: 'minmax(340px, 420px) minmax(0, 1fr)' }}>
      <div className="col" style={{ gap: 16 }}>
        <Card title="Filters">
          <div className="field">
            <label>Severity</label>
            <select className="select" value={severity}
              onChange={(e) => setParam('severity', e.target.value)}>
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div className="field mb-0">
            <label>Category</label>
            <select className="select" value={category}
              onChange={(e) => setParam('category', e.target.value)}>
              <option value="">All categories</option>
              {categories.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
        </Card>

        <Card title={`Findings (${filtered.length})`} flush>
          {filtered.length === 0 && <EmptyState message="No findings match the filter." />}
          {filtered.map((f) => (
            <FindingCard key={f.id} finding={f} active={f.id === activeId}
              onSelect={() => setParam('id', f.id)} />
          ))}
        </Card>
      </div>

      <div>
        {active
          ? <FindingDetail finding={active} />
          : <Card><EmptyState message="Select a finding to view details, evidence, impact and remediation." /></Card>}
      </div>
    </div>
  );
}