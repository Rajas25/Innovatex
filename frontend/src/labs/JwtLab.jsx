import { useState } from 'react';
import LabShell from '../components/labs/LabShell';
import Card from '../components/common/Card';
import CodeBlock from '../components/common/CodeBlock';
import Console from '../components/common/Console';
import { useLabs } from '../context/LabContext';
import { decodeUnsafe, forgeNoneAlg } from '../lib/jwt';

export default function JwtLab({ lab }) {
  const { resultFor } = useLabs();
  const [sub, setSub] = useState('s.novak');
  const [role, setRole] = useState('viewer');
  const [liveToken, setLiveToken] = useState('');
  const [forged, setForged] = useState('');
  const result = resultFor('jwt');

  function doForge() {
    if (!liveToken) return;
    const f = forgeNoneAlg(liveToken, { role: 'admin', escalated: true });
    setForged(f ?? '');
  }

  return (
    <LabShell lab={lab} onRun={() => ({})}>
      <div className="lab__grid">
        <Card title="1 · Issue a legitimate token">
          <div className="grid grid--2">
            <div className="field">
              <label>Subject</label>
              <input className="input" value={sub} onChange={(e) => setSub(e.target.value)} />
            </div>
            <div className="field">
              <label>Role</label>
              <select className="select" value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="viewer">viewer</option>
                <option value="analyst">analyst</option>
              </select>
            </div>
          </div>
          <button className="btn" type="button" onClick={() => {
            import('../lib/mockApi').then(async ({ issueJwt }) => {
              const { token } = await issueJwt(sub, role);
              setLiveToken(token);
              setForged('');
            });
          }}>
            Issue token
          </button>
          {liveToken && (
            <div className="mt-16">
              <CodeBlock caption="Legitimate JWT (HS256)" code={liveToken} wrap />
            </div>
          )}
        </Card>

        <Card title="2 · Forge an alg:none token">
          <button className="btn" type="button" onClick={doForge} disabled={!liveToken}>
            Forge with role=admin
          </button>
          {forged && (
            <>
              <div className="mt-16">
                <CodeBlock caption="Forged JWT (alg: none, role: admin)" code={forged} wrap variant="vuln" />
              </div>
              <div className="mt-16">
                <CodeBlock caption="Decoded header"
                  code={JSON.stringify(decodeUnsafe(forged).header, null, 2)} />
                <CodeBlock caption="Decoded payload"
                  code={JSON.stringify(decodeUnsafe(forged).payload, null, 2)} />
              </div>
            </>
          )}
        </Card>
      </div>

      {result && (
        <Card title="Server response">
          <Console entries={[{
            method: result.request.method,
            path: result.request.path,
            status: result.response.status,
            requestBody: { token: result.request.query.token?.slice(0, 60) + '…' },
            responseBody: result.response.serverResponse,
            notes: result.verdict,
          }]} />
          <div className="callout callout--info mt-16">
            The smoking gun is <code>signatureVerified: false</code> in the server's
            response while the claims still carry <code>role: "admin"</code>. That is
            the authentication bypass.
          </div>
        </Card>
      )}
    </LabShell>
  );
}