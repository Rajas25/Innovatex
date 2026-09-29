import { useState } from 'react';
import LabShell from '../components/labs/LabShell';
import Card from '../components/common/Card';
import CodeBlock from '../components/common/CodeBlock';
import Console from '../components/common/Console';
import { useLabs } from '../context/LabContext';

export default function MassAssignmentLab({ lab }) {
  const { resultFor } = useLabs();
  const [payload, setPayload] = useState(
    JSON.stringify({ role: 'admin', is_admin: true, credits: 999999 }, null, 2));
  const [parseError, setParseError] = useState(null);
  const result = resultFor('mass_assignment');

  function handleRun() {
    try {
      const fields = JSON.parse(payload);
      setParseError(null);
      return { asUser: 's.novak', fields };
    } catch (e) {
      setParseError(e.message);
      return { asUser: 's.novak', fields: {} };
    }
  }

  return (
    <LabShell lab={lab} onRun={handleRun}>
      <div className="lab__grid">
        <Card title="Request body">
          <textarea className="textarea" rows={10} value={payload}
            onChange={(e) => setPayload(e.target.value)} />
          {parseError && <div className="callout callout--danger mt-8">{parseError}</div>}
          <div className="row row--wrap mt-8">
            <button className="btn btn--sm" type="button"
              onClick={() => setPayload(JSON.stringify({ role: 'admin' }, null, 2))}>
              role: admin
            </button>
            <button className="btn btn--sm" type="button"
              onClick={() => setPayload(JSON.stringify({ is_admin: true }, null, 2))}>
              is_admin: true
            </button>
            <button className="btn btn--sm" type="button"
              onClick={() => setPayload(JSON.stringify({ credits: 999999 }, null, 2))}>
              credits: 999999
            </button>
          </div>
        </Card>

        <Card title="Response">
          {!result && <div className="muted small">Run the lab to see what was persisted.</div>}
          {result && (
            <div className="col">
              <CodeBlock caption="Before" code={JSON.stringify(result.response.body._before, null, 2)} />
              <CodeBlock caption="After (every submitted key was persisted)"
                code={JSON.stringify(result.response.body._after, null, 2)} variant="vuln" />
              <div className={`callout ${result.exploited ? 'callout--danger' : 'callout--ok'}`}>
                <strong>{result.exploited ? 'Exploited' : 'Not exploited'}.</strong> {result.verdict}
              </div>
            </div>
          )}
        </Card>
      </div>
    </LabShell>
  );
}