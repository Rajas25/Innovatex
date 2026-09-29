import { NavLink } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { FINDINGS } from '../../data/findings';

const LINKS = [
  { to: '/dashboard', icon: '▦', label: 'Dashboard' },
  { to: '/findings', icon: '⚑', label: 'Findings', count: FINDINGS.length },
  { to: '/labs', icon: '⚗', label: 'Lab bench', count: 12 },
  { to: '/report', icon: '❐', label: 'Report' },
  { to: '/scope', icon: '⛨', label: 'Scope & RoE' },
];

export default function Sidebar() {
  const { user } = useAuth();
  return (
    <aside className="sidebar">
      <div className="sidebar__brand">
        <div className="sidebar__brand-mark">
          <span className="sidebar__brand-dot" />
          World Monitor
        </div>
        <div className="sidebar__brand-sub">Assessment Workbench</div>
      </div>
      <nav className="sidebar__nav">
        <div className="sidebar__group-label">Assessment</div>
        {LINKS.map((l) => (
          <NavLink key={l.to} to={l.to}
            className={({ isActive }) => `nav-item${isActive ? ' is-active' : ''}`}>
            <span className="nav-item__icon">{l.icon}</span>
            <span>{l.label}</span>
            {l.count != null && <span className="nav-item__count">{l.count}</span>}
          </NavLink>
        ))}
      </nav>
      <div className="sidebar__footer">
        <div><strong>PS ID 26163</strong></div>
        <div>{user ? `Signed in as ${user.username} (${user.role})` : 'Not signed in'}</div>
        <div style={{ marginTop: 6 }}>Authorised testing only.</div>
      </div>
    </aside>
  );
}