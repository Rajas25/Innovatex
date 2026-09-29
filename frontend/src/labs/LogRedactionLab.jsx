import { useState } from 'react';
import LabShell from '../components/labs/LabShell';
import Card from '../components/common/Card';
import CodeBlock from '../components/common/CodeBlock';
import { useLabs } from '../context/LabContext';

const DEFAULT_BODY = {
  username: 'a.reyes',
  password: 'Sunshine2019!',
  email: 'a.reyes@worldmonitor.example',
  ssn: '412-88-7391',
  cardNumber: '4111 1111 1111 1111',
};

export default function LogRedactionLab({ lab }) {
  const { resultFor } = useLabs();
  const [payload, setPayload] = useState(JSON.stringify(DEFAULT_BODY, null, 2));
  const [error, setError] = useState(null);
  const result = resultFor('log_redaction');

  function handleRun() {
    try {
      const body = JSON.parse(payload);
      setError(null);
      return { body };
    } catch (e) {
      setError(e.message);
      return { body: {} };
    }
  }

  return (
    <LabShell lab={lab} onRun={handleRun}>
      <Card title="Request body to log">
        <textarea className="textarea" rows={8} value={payload}
          onChange={(e) => setPayload(e.target.value)} />
        {error && <div className="callout callout--danger mt-8">{error}</div>}
      </Card>

      {result && (
        <div className="lab__grid">
          <Card title="Raw log line (as it reaches the SIEM)">
            <CodeBlock wrap variant="vuln" code={result.response.body.raw_log_entry} />
          </Card>
          <Card title="Redacted log line (after the fix)">
            <CodeBlock wrap variant="safe" code={result.response.body.redacted_log_entry} />
            <p className="small muted mt-8">
              {result.response.body.redaction_hits.length} item(s) were removed by the
              reference redactor.
            </p>
          </Card>
        </div>
      )}
    </LabShell>
  );
}