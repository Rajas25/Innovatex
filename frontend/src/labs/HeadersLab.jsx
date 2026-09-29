import LabShell from '../components/labs/LabShell';
import Card from '../components/common/Card';
import CodeBlock from '../components/common/CodeBlock';
import { useLabs } from '../context/LabContext';
import { RECOMMENDED_HEADERS } from '../lib/headers';

export default function HeadersLab({ lab }) {
  const { resultFor } = useLabs();
  const result = resultFor('headers');

  return (
    <LabShell lab={lab} onRun={() => ({})}>
      {result && (
        <>
          <Card title={`Posture score: ${result.response.score}/100 (grade ${result.response.grade})`}>
            <table className="table">
              <thead>
                <tr><th>Header</th><th>Status</th><th>Observed value</th><th>Recommended</th></tr>
              </thead>
              <tbody>
                {result.response.results.map((r) => (
                  <tr key={r.name}>
                    <td><code>{r.name}</code></td>
                    <td>
                      <span className={`badge badge--${r.status === 'pass' ? 'ok'
                        : r.status === 'warn' ? 'medium' : 'critical'}`}>
                        {r.status}
                      </span>
                    </td>
                    <td>
                      {r.value ? <code>{r.value}</code>
                        : <span className="muted small">absent</span>}
                    </td>
                    <td><code className="small">{r.expected}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>

          <Card title="Corrective header block (deploy at the edge)">
            <CodeBlock wrap variant="safe"
              code={RECOMMENDED_HEADERS.map((h) => `${h.name}: ${h.good}`).join('\n')} />
          </Card>
        </>
      )}
    </LabShell>
  );
}