import { useState } from 'react';
import LabShell from '../components/labs/LabShell';
import Card from '../components/common/Card';
import CodeBlock from '../components/common/CodeBlock';
import Console from '../components/common/Console';
import { useLabs } from '../context/LabContext';

export default function PrototypePollutionLab({ lab }) {
  const { resultFor } = useLabs();
  const [payload, setPayload] = useState(
    JSON.stringify({ __proto__: { isAdmin: true } }, null, 2));
  const [parseError, setParseError] = useState(null);
  const result = resultFor('prototype_pollution');

  function handleRun() {
    try {
      const body = JSON.parse(payload);
      setParseError(null);
      return { body };
    } catch (e) {
      setParseError(e.message);
      return { body: {} };
    }
  }

  return (
    <LabShell lab={lab} onRun={handleRun}>
      <div className="lab__grid">
        <Card title="Merge payload">
          <textarea className="textarea" rows={8} value={payload}
            onChange={(e) => setPayload(e.target.value)} />
          {parseError && <div className="callout callout--danger mt-8">{parseError}</div>}
          <div className="row row--wrap mt-8">
            <button className="btn btn--sm" type="button"
              onClick={() => setPayload(JSON.stringify({ __proto__: { isAdmin: true } }, null, 2))}>
              __proto__.isAdmin
            </button>
            <button className="btn btn--sm" type="button"
              onClick={() => setPayload(JSON.stringify({ constructor: { prototype: { isAdmin: true } } }, null, 2))}>
              constructor.prototype
            </button>
          </div>
        </Card>

        <Card title="Result">
          {!result && <div className="muted small">Run the lab to see the outcome.</div>}
          {result && (
            <div className="col">
              <CodeBlock caption="Merged preferences"
                code={JSON.stringify(result.response.body.merged_preferences, null, 2)} wrap />
              <CodeBlock caption="Dangerous keys that survived"
                code={result.response.body.dangerous_keys_present.join('\n') || '(none)'} variant="vuln" />
              {result.response.body.prototype_isAdmin !== undefined && (
                <CodeBlock caption="Global consequence" variant="vuln" wrap
                  code={`({}).isAdmin === ${result.response.body.prototype_isAdmin}\n// every object in the process inherits isAdmin\nif (user.isAdmin) { /* authorisation bypass */ }`} />
              )}
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