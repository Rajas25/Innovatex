import SeverityBadge from './SeverityBadge';

export default function FindingCard({ finding, onSelect, active }) {
  return (
    <div className={`finding-row${active ? ' is-active' : ''}`} onClick={onSelect}
      role="button" tabIndex={0}
      onKeyDown={(e) => e.key === 'Enter' && onSelect?.()}>
      <span className="finding-row__id">{finding.id}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div className="finding-row__title truncate">{finding.title}</div>
        <div className="finding-row__cat">{finding.category}</div>
      </div>
      <SeverityBadge severity={finding.severity} score={finding.cvss.score} />
    </div>
  );
}