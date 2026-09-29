export default function Console({ entries = [] }) {
  if (!entries.length) return null;
  return (
    <div className="console">
      {entries.map((e, i) => {
        const statusClass = e.status >= 500 ? '5xx'
          : e.status >= 400 ? '4xx'
          : e.status >= 300 ? '3xx'
          : '2xx';
        return (
          <div className="console__entry" key={i}>
            <div className="console__bar">
              <span className="console__method">{e.method}</span>
              <span className="console__path">{e.path}</span>
              <span className={`console__status console__status--${statusClass}`}>{e.status}</span>
            </div>
            <div className="console__panes">
              <div className="console__pane">
                <div className="console__pane-label">Request</div>
                <pre className="code code--wrap">
                  {typeof e.requestBody === 'string' ? e.requestBody : JSON.stringify(e.requestBody, null, 2)}
                </pre>
              </div>
              <div className="console__pane">
                <div className="console__pane-label">Response</div>
                <pre className="code code--wrap">
                  {typeof e.responseBody === 'string' ? e.responseBody : JSON.stringify(e.responseBody, null, 2)}
                </pre>
              </div>
            </div>
            {e.notes && (
              <div style={{ padding: '10px 12px', borderTop: '1px solid var(--line-soft)', fontSize: 12.5 }}>
                <strong>Verdict.</strong> {e.notes}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}