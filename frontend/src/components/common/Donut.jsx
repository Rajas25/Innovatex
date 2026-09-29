export default function Donut({ data = [], size = 160, stroke = 22 }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  if (!total) return <div className="muted small">No data.</div>;

  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="donut">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
          {data.map((d) => {
            const len = (d.value / total) * circumference;
            const seg = (
              <circle key={d.label} cx={size / 2} cy={size / 2} r={radius}
                fill="none" stroke={d.color} strokeWidth={stroke}
                strokeDasharray={`${len} ${circumference - len}`}
                strokeDashoffset={-offset} />
            );
            offset += len;
            return seg;
          })}
        </g>
        <text x="50%" y="50%" textAnchor="middle" dy="0.35em"
          fill="var(--fg-0)" fontSize="20" fontWeight="700">{total}</text>
      </svg>
      <div className="donut__legend">
        {data.map((d) => (
          <div key={d.label} className="donut__legend-row">
            <span className="donut__swatch" style={{ background: d.color }} />
            <span style={{ textTransform: 'capitalize' }}>{d.label}</span>
            <span className="donut__legend-count">{d.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}