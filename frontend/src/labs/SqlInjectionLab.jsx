import { useState } from 'react';
import LabShell from '../components/labs/LabShell';
import Card from '../components/common/Card';
import CodeBlock from '../components/common/CodeBlock';
import Console from '../components/common/Console';
import { SQLI_PRESETS } from '../data/labData';
import { useLabs } from '../context/LabContext';

export default function SqlInjectionLab({ lab }) {
  const { resultFor } = useLabs();
  const [term, setTerm] = useState(SQLI_PRESETS[0].value);
  const result = resultFor('sqli');

  return (
    <LabShell lab={lab} onRun={() => ({ term })}>
      <div className="lab__grid">
        <Card title="Search request">
          <div className="field">
            <label htmlFor="sqli-term">term</label>
            <textarea id="sqli-term" className="textarea" rows={3}
              value={term} onChange={(e) => setTerm(e.target.value)} />
          </div>
          <div className="row row--wrap">
            {SQLI_PRESETS.map((p) => (
              <button key={p.label} className="btn btn--sm" type="button"
                onClick={() => setTerm(p.value)}>{p.label}</button>
            ))}
          </div>
        </Card>

        <Card title="Executed statement">
          {!result && <div className="muted small">Run the lab to see the SQL that was executed.</div>}
          {result && (
            <div className="col">
              <CodeBlock caption="Server-side SQL" code={result.response.executedSql} variant="vuln" wrap />
              <CodeBlock caption="Correct (parameterised)" variant="safe" wrap
                code={`-- Node/Sequelize:\nMonitor.findAll({ where: { name: { [Op.like]: '%' + term + '%' } } });\n\n-- Python/psycopg:\ncur.execute("SELECT ... WHERE name LIKE %s", (f"%{term}%",))`} />
              <Console entries={[{
                method: result.request.method,
                path: result.request.path,
                status: result.response.status,
                requestBody: result.request.body,
                responseBody: {
                  rowCount: result.response.rowCount,
                  sampleRows: result.response.sampleRows,
                  error: result.response.error,
                },
                notes: result.verdict,
              }]} />
            </div>
          )}
        </Card>
      </div>
    </LabShell>
  );
}