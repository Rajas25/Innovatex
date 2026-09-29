import { createContext, useCallback, useContext, useMemo, useState } from 'react';
import { runLab as runLabImpl, resetAll } from '../lib/mockApi';
import { LABS } from '../data/findings';        // LABS re-exported below
import { useAuth } from './AuthContext';

const LabContext = createContext(null);

export function LabProvider({ children }) {
  const { can } = useAuth();
  const [results, setResults] = useState({});
  const [running, setRunning] = useState(null);
  const [error, setError] = useState(null);

  const runLab = useCallback(async (labId, payload = {}) => {
    if (!can('labs:run')) throw new Error('Your role does not permit running labs.');
    setRunning(labId);
    setError(null);
    try {
      const result = await runLabImpl(labId, payload);
      setResults((prev) => ({ ...prev, [labId]: result }));
      return result;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setRunning(null);
    }
  }, [can]);

  const reset = useCallback(() => {
    if (!can('labs:reset')) throw new Error('Only a lead may reset the lab environment.');
    resetAll();
    setResults({});
  }, [can]);

  const value = useMemo(() => ({
    labs: LABS, results, running, error, runLab, reset,
    resultFor: (id) => results[id] ?? null,
  }), [results, running, error, runLab, reset]);

  return <LabContext.Provider value={value}>{children}</LabContext.Provider>;
}

export function useLabs() {
  const ctx = useContext(LabContext);
  if (!ctx) throw new Error('useLabs must be used inside <LabProvider>');
  return ctx;
}