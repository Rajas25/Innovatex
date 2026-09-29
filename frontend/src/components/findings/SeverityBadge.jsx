export default function SeverityBadge({ severity, score }) {
  return (
    <span className={`badge badge--${severity}`}>
      {severity}{score != null && ` · ${Number(score).toFixed(1)}`}
    </span>
  );
}