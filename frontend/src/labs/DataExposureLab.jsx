import { useState } from 'react';
import LabShell from '../components/labs/LabShell';
import Card from '../components/common/Card';
import Console from '../components/common/Console';
import { useLabs } from '../context/LabContext';

export default function DataExposureLab({ lab }) {
  const { resultFor } = useLabs();
  const [userId, setUserId] = useState(1);
  const result = resultFor('data_exposure');

  return (
    <LabShell lab={lab} onRun={() => ({ userId })}>
      <Card title="Target user">
        <div className="grid grid--3">
          <div className="field">
            <label>User id</label>
            <input className="input" type="number" value={userId}
              onChange={(e) => setUserId(Number(e.target.value))} />
          </div>
        </div>
      </Card>

      {result && (
        <Card title="Response">
          <div className="callout callout--danger mb-0">
            <strong>Leaked fields:</strong>{' '}
            {result.response.body._extra_fields_leaked.map((f) => (
              <code key={f} style={{ marginRight: 6 }}>{f}</code>
            ))}
          </div>
          <div className="mt-16">
            <Console entries={[{
              method: result.request.method,
              path: result.request.path,
              status: result.response.status,
              requestBody: {},
              responseBody: result.response.body,
              notes: result.verdict,
            }]} />
          </div>
        </Card>
      )}
    </LabShell>
  );
}