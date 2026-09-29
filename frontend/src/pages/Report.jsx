import { useState } from 'react';
import { assessmentApi } from '../lib/mockApi';
import { buildReport } from '../lib/report';
import Card from '../components/common/Card';
import CodeBlock from '../components/common/CodeBlock';
import { useAuth } from '../context/AuthContext';

export default function Report() {
  const { can } = useAuth();
  const [format, setFormat] = useState('markdown');
  const [assessor, setAssessor] = useState('');
  const [engagementId, setEngagementId] = useState('WM-2025-001');
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);

  async function generate() {
    setBusy(true);
    try {
      const findings = await assessmentApi.listFindings();
      const result = buildReport({
        title: 'World Monitor — Security Assessment Report',
        assessor, engagementId, findings, format,
      });
      setReport(result);
    } finally { setBusy(false); }
  }

  function download() {
    if (!report) return;
    const blob = new Blob([report.content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = report.filename;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="col" style={{ gap: 20 }}>
      <div>
        <h1>Assessment report</h1>
        <p className="muted">
          Generate the deliverable in Markdown, JSON or standalone HTML.
          {!can('report:export') && ' Your role can preview but not export — sign in as a lead to download.'}
        </p>
      </div>

      <Card title="Report options">
        <div className="grid grid--3">
          <div className="field">
            <label>Format</label>
            <select className="select" value={format} onChange={(e) => setFormat(e.target.value)}>
              <option value="markdown">Markdown</option>
              <option value="json">JSON</option>
              <option value="html">HTML (standalone)</option>
            </select>
          </div>
          <div className="field">
            <label>Assessor name</label>
            <input className="input" value={assessor}
              onChange={(e) => setAssessor(e.target.value)} placeholder="Your name" />
          </div>
          <div className="field">
            <label>Engagement ID</label>
            <input className="input" value={engagementId}
              onChange={(e) => setEngagementId(e.target.value)} />
          </div>
        </div>

        <div className="row">
          <button className="btn btn--primary" onClick={generate}
            disabled={busy || !can('report:generate')}>
            {busy ? 'Generating…' : 'Generate preview'}
          </button>
          <button className="btn" onClick={download}
            disabled={!report || !can('report:export')}>
            Download
          </button>
        </div>
      </Card>

      {report && (
        <Card title={`Preview · ${report.filename}`}>
          <div className="row row--wrap" style={{ marginBottom: 12 }}>
            <span className="badge badge--neutral">{report.findingCount} findings</span>
            {Object.entries(report.summary).map(([sev, count]) => (
              <span key={sev} className={`badge badge--${sev}`}>{sev}: {count}</span>
            ))}
            <span className="badge badge--neutral">{report.generatedAt}</span>
          </div>
          <CodeBlock wrap code={report.content.slice(0, 6000)} />
          {report.content.length > 6000 && (
            <p className="small muted mt-8">
              Preview truncated to 6 000 characters. Download the full report to see the rest.
            </p>
          )}
        </Card>
      )}
    </div>
  );
}