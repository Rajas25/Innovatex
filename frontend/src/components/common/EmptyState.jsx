export default function EmptyState({ message = 'Nothing to display.' }) {
  return <div className="empty">{message}</div>;
}