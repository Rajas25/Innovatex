export default function Badge({ tone = 'neutral', children, style }) {
  return <span className={`badge badge--${tone}`} style={style}>{children}</span>;
}