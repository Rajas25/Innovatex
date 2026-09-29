import { createContext, useCallback, useContext, useMemo, useState } from 'react';

const AuditContext = createContext(null);
const MAX = 200;

export function AuditProvider({ children }) {
  const [entries, setEntries] = useState([]);

  const record = useCallback((entry) => {
    setEntries((prev) => [{
      ...entry,
      id: entry.id ?? `local-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      at: entry.at ?? new Date().toISOString(),
    }, ...prev].slice(0, MAX));
  }, []);

  const clear = useCallback(() => setEntries([]), []);

  const value = useMemo(() => ({ entries, record, clear }), [entries, record, clear]);
  return <AuditContext.Provider value={value}>{children}</AuditContext.Provider>;
}

export function useAudit() {
  const ctx = useContext(AuditContext);
  if (!ctx) throw new Error('useAudit must be used inside <AuditProvider>');
  return ctx;
}