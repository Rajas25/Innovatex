/* Workbench RBAC (enforced). */
export const TOOL_ROLES = { viewer: 'viewer', tester: 'tester', lead: 'lead' };

export const TOOL_PERMISSIONS = {
  'findings:read':       ['viewer', 'tester', 'lead'],
  'labs:run':            ['tester', 'lead'],
  'labs:reset':          ['lead'],
  'evidence:read':       ['viewer', 'tester', 'lead'],
  'evidence:write':      ['tester', 'lead'],
  'findings:approve':    ['lead'],
  'report:generate':     ['tester', 'lead'],
  'report:export':       ['lead'],
  'engagement:configure':['lead'],
};

export function toolCan(role, permission) {
  if (!role) return false;
  return (TOOL_PERMISSIONS[permission] ?? []).includes(role);
}

/* Assessed-application RBAC (documentation only; NOT enforced — that is the point). */
export const APP_ROLES = ['viewer', 'analyst', 'operator', 'admin'];

export const APP_PERMISSIONS = {
  'monitor:read':   ['viewer', 'analyst', 'operator', 'admin'],
  'monitor:create': ['analyst', 'operator', 'admin'],
  'monitor:update': ['analyst', 'operator', 'admin'],
  'monitor:delete': ['operator', 'admin'],
  'user:read':      ['admin'],
  'user:manage':    ['admin'],
  'audit:read':     ['operator', 'admin'],
};

export function appCan(role, permission) {
  return (APP_PERMISSIONS[permission] ?? []).includes(role);
}