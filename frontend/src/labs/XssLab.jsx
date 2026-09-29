import { useState } from 'react';
import LabShell from '../components/labs/LabShell';
import Card from '../components/common/Card';
import CodeBlock from '../components/common/CodeBlock';
import Console from '../components/common/Console';
import Toggle from '../components/common/Toggle';
import { XSS_PRESETS } from '../data/labData';
import { escapeHtml } from '../lib/sanitize';
import { useLabs } from '../context/LabContext';

export default function XssLab({ lab }) {
  const { resultFor } = useLabs();
  const [name, setName] = useState(XSS_PRESETS[1].value);
  const [encode, setEncode] = useState(false);
  const result = resultFor('xss');

  const effective = encode ? escapeHtml(name) : name;

  return (
    <LabShell lab={lab} onRun={() => ({ name: effective })}>
      <div className="lab__grid">
        <Card title="Payload builder">
          <div className="field">
            <label htmlFor="xss-name">name parameter</label>
            <textarea id="xss-name" className="textarea" rows={4}
              value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="row row--wrap" style={{ marginBottom: 12 }}>
            {XSS_PRESETS.map((p) => (
              <button key={p.label} className="btn btn--sm" type="button"
                onClick={() => setName(p.value)}>{p.label}</button>
            ))}
          </div>
          <Toggle checked={encode} onChange={setEncode}
            label="Apply output encoding"
            description="Simulates the fix: escape the payload before rendering." />
          <div className="mt-16">
            <CodeBlock caption="Effective payload" code={effective} wrap />
          </div>
        </Card>

        <Card title="Response preview">
          {!result && <div className="muted small">Run the lab to see the server response.</div>}
          {result && (
            <div className="col">
              <div className="sandbox">
                <div className="sandbox__chrome">
                  <span className="sandbox__dot" />
                  <span className="sandbox__dot" />
                  <span className="sandbox__dot" />
                  <span className="sandbox__url">
                    /api/vuln/monitors?name={encodeURIComponent(effective).slice(0, 60)}
                  </span>
                </div>
                {/*
                  SECURITY: sandbox="allow-scripts" only. We deliberately do NOT
                  include allow-same-origin, so payloads cannot read this SPA's
                  storage or cookies — even in a training tool, we do not want
                  a lab page to touch the workbench itself.
                */}
                <iframe title="sandbox" sandbox="allow-scripts"
                  srcDoc={result.response.bodySnippet} />
              </div>
              <Console entries={[{
                method: result.request.method,
                path: result.request.path,
                status: result.response.status,
                requestBody: result.request.query,
                responseBody: result.response.bodySnippet,
                notes: result.verdict,
              }]} />
            </div>
          )}
        </Card>
      </div>
    </LabShell>
  );
}