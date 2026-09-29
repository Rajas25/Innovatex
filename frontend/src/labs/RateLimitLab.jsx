import { useState } from 'react';
import LabShell from '../components/labs/LabShell';
import Card from '../components/common/Card';
import { LAB_WORDLIST } from '../data/mockDb';
import { useLabs } from '../context/LabContext';

export default function RateLimitLab({ lab }) {
  const { resultFor } = useLabs();
  const [username, setUsername] = useState('a.reyes');
  const result = resultFor('rate_limit');

  return (
    <LabShell lab={lab} onRun={() => ({ username, guesses: LAB_WORDLIST })}
      runLabel={`Attempt all ${LAB_WORDLIST.length} passwords`}>
      <Card title="Target account">
        <div className="field">
          <label>Username</label>
          <select className="select" value={username} onChange={(e) => setUsername(e.target.value)}>
            <option value="a.reyes">a.reyes (admin)</option>
            <option value="m.okafor">m.okafor (analyst)</option>
            <option value="s.novak">s.novak (viewer)</option>
          </select>
        </div>
        <p className="small muted mb-0">
          The lab will attempt each of the {LAB_WORDLIST.length} seeded passwords in
          rapid succession. A correctly hardened endpoint would begin returning HTTP
          429 after a small number of failures.
        </p>
      </Card>

      {result && (
        <Card title="Attempt log">
          <table className="table">
            <thead>
              <tr><th>#</th><th>Password</th><th>Status</th><th>Detail</th><th>Attempts / min</th></tr>
            </thead>
            <tbody>
              {result.response.log.map((row) => (
                <tr key={row.attempt}>
                  <td>{row.attempt}</td>
                  <td><code>{row.password}</code></td>
                  <td>
                    <span className={`badge badge--${row.status === 200 ? 'critical' : 'neutral'}`}>
                      {row.status}
                    </span>
                  </td>
                  <td>{row.detail}</td>
                  <td style={{ fontVariantNumeric: 'tabular-nums' }}>{row.attemptsLastMinute}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {result.response.successAtAttempt && (
            <div className="callout callout--danger mt-16">
              <strong>Password found</strong> on attempt {result.response.successAtAttempt}. No
              request was throttled — the account is fully open to online brute force.
            </div>
          )}
        </Card>
      )}
    </LabShell>
  );
}