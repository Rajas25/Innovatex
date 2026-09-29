import { Navigate, Route, Routes } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AuditProvider } from './context/AuditContext';
import { LabProvider } from './context/LabContext';
import Layout from './components/layout/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Findings from './pages/Findings';
import Labs from './pages/Labs';
import Report from './pages/Report';
import Scope from './pages/Scope';
import NotFound from './pages/NotFound';

function RequireAuth({ children }) {
  const { isAuthenticated } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return children;
}

export default function App() {
  return (
    <AuthProvider>
      <AuditProvider>
        <LabProvider>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/" element={<RequireAuth><Layout /></RequireAuth>}>
              <Route index element={<Navigate to="/dashboard" replace />} />
              <Route path="dashboard" element={<Dashboard />} />
              <Route path="findings" element={<Findings />} />
              <Route path="labs" element={<Labs />} />
              <Route path="labs/:labId" element={<Labs />} />
              <Route path="report" element={<Report />} />
              <Route path="scope" element={<Scope />} />
            </Route>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </LabProvider>
      </AuditProvider>
    </AuthProvider>
  );
}