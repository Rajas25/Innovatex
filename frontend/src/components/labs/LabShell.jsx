import { Link } from 'react-router-dom';
import { useLabs } from '../../context/LabContext';
import Card from '../common/Card';

export default function LabShell({ lab, children, onRun, runLabel = 'Run lab' }) {
  const { runLab, running, resultFor, reset, error } = useLabs();
  const result = resultFor(lab.id);

  async function handleRun() {
    await runLab(lab.id, onRun ? onRun() : {});
  }

  return (
    <div className="lab">
      <div>
        <h2>{lab.title}</h2>
        <div className="lab__meta">
          <Link to={`/findings?id=${lab.findingId}`} className="badge badge--neutral">
            {lab.findingId}
          </Link>
          <span className="badge badge--neutral">{lab.id}</span>
          {lab.endpoints.map((e) => (
            <code key={e} className="small muted">{e}</code>
          ))}
        </div>
        <p className="mt-8">{lab.summary}</p>
      </div>

      <div className="callout callout--warn">
        <strong>Authorised use only.</strong> This lab runs against a simulated target
        inside your browser. Do not point these payloads at any system you do not own or
        have written permission to test.
      </div>

      {children}

      <div className="row">
        <button className="btn btn--primary" onClick={handleRun} disabled={running === lab.id}>
          {running === lab.id ? 'Running…' : runLabel}
        </button>
        <button className="btn btn--ghost" onClick={reset}>Reset lab environment</button>
      </div>

      {error && <div className="callout callout--danger">{error}</div>}

      {result && (
        <Card title="Classification">
          <div className={`callout ${result.exploited ? 'callout--danger' : 'callout--ok'}`}>
            <strong>{result.exploited ? 'Exploited' : 'Not exploited'}.</strong> {result.verdict}
          </div>
          <p className="small muted mt-8">{result.notes}</p>
        </Card>
      )}

      <Card title="Hints">
        <ul className="ticks">
          {lab.hints.map((h) => <li key={h}>{h}</li>)}
        </ul>
      </Card>
    </div>
  );
}