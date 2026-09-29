import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

const TITLES = {
  '/dashboard': 'Dashboard',
  '/findings': 'Findings catalogue',
  '/labs': 'Lab bench',
  '/report': 'Assessment report',
  '/scope': 'Scope & rules of engagement',
};

export default function Topbar() {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  const { pathname } = useLocation();
  const root = '/' + pathname.split('/').filter(Boolean)[0];
  const title = TITLES[root] ?? 'World Monitor';

  return (
    <div className="topbar">
      <div>
        <div className="topbar__title">{title}</div>
        <div className="topbar__crumb">Problem Statement ID 26163</div>
      </div>
      <div className="topbar__spacer" />
      <div className="row">
        {user && (
          <span className="small muted">
            {user.fullName} · <code>{user.role}</code>
          </span>
        )}
        <button className="btn btn--sm" onClick={() => { logout(); nav('/login'); }}>
          Sign out
        </button>
      </div>
    </div>
  );
}