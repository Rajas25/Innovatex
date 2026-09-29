import { useState } from 'react';
import LabShell from '../components/labs/LabShell';
import Card from '../components/common/Card';
import Console from '../components/common/Console';
import { useLabs } from '../context/LabContext';

const MONITORS = ['wm-1001', 'wm-1002', 'wm-1003', 'wm-1004', 'wm-1005'];
const USERS = ['s.novak', 'm.okafor', 'a.reyes'];

export default function IdorLab({ lab }) {
  const { resultFor } = useLabs();
  const [id, setId] = useState('wm-1004');
  const [asUser, setAsUser] = useState('s.novak');
  const result = resultFor('idor');

  return (
    <LabShell lab={lab} onRun={() => ({ id, asUser })}>
      <Card title="Request builder">
        <div className="grid grid--2">
          <div className="field">
            <label>Monitor id</label>
            <select className="select" value={id} onChange={(e) => setId(e.target.value)}>
              {MONITORS.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
          </div>
          <div className="field">
            <label>Authenticated as</label>
            <select className="select" value={asUser} onChange={(e) => setAsUser(e.target.value)}>
              {USERS.map((u) => <option key={u} value={u}>{u}</option>)}
            </select>
          </div>
        </div>
      </Card>

      {result && (
        <Card title="Response">
          <Console entries={[{
            method: result.request.method,
            path: result.request.path,
            status: result.response.status,
            requestBody: result.request.query,
            responseBody: result.response.body,
            notes: result.verdict,
          }]} />
        </Card>
      )}
    </LabShell>
  );
}