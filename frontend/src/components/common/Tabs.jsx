export default function Tabs({ tabs = [], active, onChange }) {
  return (
    <div className="tabs">
      {tabs.map((t) => (
        <button key={t.id} type="button"
          className={`tab${t.id === active ? ' is-active' : ''}`}
          onClick={() => onChange?.(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}