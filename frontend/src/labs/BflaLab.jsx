import { useState } from 'react';
import LabShell from '../components/labs/LabShell';
import Card from '../components/common/Card';
import Console from '../components/common/Console';
import { useLabs } from '../context/LabContext';

export default function BflaLab({ lab }) {
  const { resultFor } = useLabs();
  const [asUser, setAsUser] = useState('s.novak');
  const [targetId, setTargetId] = useState(3);
  const [role, setRole] = useState('admin');
  const result = resultFor('bfla');

  return (
    <LabShell lab={lab} onRun={() => ({ asUser, targetId, role })}>
      <Card title="Escalation parameters">
        <div className="grid grid--3">
          <div className="field">
            <label>Authenticated as</label>
            <select className="select" value={asUser} onChange={(e) => setAsUser(e.target.value)}>
              <option value="s.novak">s.novak (viewer)</option>
              <option value="m.okafor">m.okafor (analyst)</option>
            </select>
          </div>
          <div className="field">
            <label>Target user id</label>
            <input className="input" type="number" value={targetId}
              onChange={(e) => setTargetId(Number(e.target.value))} />
          </div>
          <div className="field">
            <label>New role</label>
            <select className="select" value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="admin">admin</option>
              <option value="operator">operator</option>
              <option value="analyst">analyst</option>
              <option value="viewer">viewer</option>
            </select>
          </div>
        </div>
      </Card>

      {result && (
        <Card title="Run record">
          <Console entries={[
            { method: 'GET', path: '/api/vuln/admin/users',
              status: result.response.listStatus,
              requestBody: { asUser },
              responseBody: result.response.listExcerpt,
              notes: 'User directory retrieved as a viewer.' },
            { method: 'POST', path: `/api/vuln/admin/users/${result.request.body ? targetId : ''}/role`,
              status: result.response.escalationStatus,
              requestBody: result.request.body,
              responseBody: result.response.escalationBody,
              notes: result.verdict },
          ]} />
        </Card>
      )}
    </LabShell>
  );
}