import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { WORKBENCH_USERS } from '../data/mockDb';

export default function Login() {
  const nav = useNavigate();
  const { login, error } = useAuth();
  const [username, setUsername] = useState('tester');
  const [password, setPassword] = useState('Tester!Pass2024');
  const [busy, setBusy] = useState(false);

  async function onSubmit(e) {
    e.preventDefault();
    setBusy(true);
    try {
      await login(username, password);
      nav('/dashboard', { replace: true });
    } catch { /* surfaced via context */ }
    finally { setBusy(false); }
  }

  return (
    <div className="login">
      <form className="login__card" onSubmit={onSubmit} autoComplete="off">
        <div className="login__brand">
          <span className="login__brand-dot" />
          <h1 style={{ margin: 0, fontSize: 17 }}>World Monitor</h1>
        </div>
        <p className="login__sub">Security Assessment Workbench · PS ID 26163</p>

        <div className="field">
          <label htmlFor="username">Username</label>
          <input id="username" className="input" value={username}
            onChange={(e) => setUsername(e.target.value)} autoFocus required />
        </div>

        <div className="field">
          <label htmlFor="password">Password</label>
          <input id="password" className="input" type="password" value={password}
            onChange={(e) => setPassword(e.target.value)} required />
        </div>

        {error && <div className="callout callout--danger mb-0">{error}</div>}

        <button className="btn btn--primary btn--block mt-16" type="submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>

        <hr />
        <p className="small muted" style={{ marginBottom: 6 }}>Demo accounts</p>
        <div className="login__accounts">
          {WORKBENCH_USERS.map((u) => (
            <button key={u.username} type="button" className="login__account"
              onClick={() => { setUsername(u.username); setPassword(u.password); }}>
              <code style={{ minWidth: 58 }}>{u.username}</code>
              <span className="muted small">{u.fullName} · {u.role}</span>
            </button>
          ))}
        </div>
      </form>
    </div>
  );
}