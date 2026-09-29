export default function Toggle({ checked, onChange, label, description }) {
  return (
    <label className="toggle">
      <span className={`toggle__track${checked ? ' is-on' : ''}`}
        onClick={() => onChange?.(!checked)}>
        <span className="toggle__knob" />
      </span>
      <span className="toggle__label">
        <strong>{label}</strong>
        {description && <span>{description}</span>}
      </span>
    </label>
  );
}