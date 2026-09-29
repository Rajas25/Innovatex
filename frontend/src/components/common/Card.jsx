export default function Card({ title, actions, children, flush = false, style }) {
  return (
    <div className={`card${flush ? ' card--flush' : ''}`} style={style}>
      {title && (
        <div className="card__header">
          <h3>{title}</h3>
          <div className="spacer" />
          {actions}
        </div>
      )}
      <div className={flush ? '' : 'card__body'}>{children}</div>
    </div>
  );
}