import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div className="login">
      <div className="login__card" style={{ textAlign: 'center' }}>
        <h1>404</h1>
        <p className="muted">That route does not exist.</p>
        <Link className="btn btn--primary" to="/dashboard">Back to dashboard</Link>
      </div>
    </div>
  );
}