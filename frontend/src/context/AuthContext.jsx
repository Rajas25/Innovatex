import { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { WORKBENCH_USERS } from '../data/mockDb';
import { toolCan } from '../lib/rbac';

const AuthContext = createContext(null);
const KEY = 'wm_assessment_session';

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try { return JSON.parse(sessionStorage.getItem(KEY) ?? 'null'); }
    catch { return null; }
  });
  const [error, setError] = useState(null);

  const login = useCallback(async (username, password) => {
    setError(null);
    await new Promise((r) => setTimeout(r, 180));
    const found = WORKBENCH_USERS.find((u) => u.username === username && u.password === password);
    if (!found) {
      setError('Invalid credentials');
      throw new Error('Invalid credentials');
    }
    const session = { username: found.username, fullName: found.fullName, role: found.role };
    sessionStorage.setItem(KEY, JSON.stringify(session));
    setUser(session);
    return session;
  }, []);

  const logout = useCallback(() => {
    sessionStorage.removeItem(KEY);
    setUser(null);
  }, []);

  const value = useMemo(() => ({
    user,
    isAuthenticated: !!user,
    role: user?.role ?? null,
    error,
    login,
    logout,
    can: (permission) => toolCan(user?.role, permission),
  }), [user, error, login, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}