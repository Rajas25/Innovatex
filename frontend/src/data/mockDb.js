/**
 * In-memory fixture data. Fictional. No production credentials represented.
 * Everything resets on page reload — this is intentional for a training tool.
 */
export const APP_USERS = [
  { id: 1, username: 'a.reyes', password: 'Sunshine2019!', fullName: 'Ana Reyes',
    email: 'a.reyes@worldmonitor.example', role: 'admin', department: 'Platform Engineering',
    mfaEnabled: false, ssn: '412-88-7391',
    internalNotes: 'Break-glass account. Escalate to CISO before disabling.',
    apiKey: 'wmk_live_9f3a2c7d41be0a5588cd',
    passwordHash: '$2b$12$Qm9ndXNIYXNoRm9yRGVtb25zdHJhdGlvbg',
    lastLoginIp: '203.0.113.44', createdAt: '2023-02-14T09:12:00Z' },
  { id: 2, username: 'm.okafor', password: 'Logistics#2024', fullName: 'Michael Okafor',
    email: 'm.okafor@worldmonitor.example', role: 'analyst', department: 'Supply Chain Analytics',
    mfaEnabled: false, ssn: '527-61-2044',
    internalNotes: 'Contractor — access expires 2025-06-30.',
    apiKey: 'wmk_live_1a77fe0b93d24c6e8f10',
    passwordHash: '$2b$12$QW5vdGhlckRlbW9IYXNoVmFsdWU',
    lastLoginIp: '198.51.100.17', createdAt: '2023-07-02T11:45:00Z' },
  { id: 3, username: 's.novak', password: 'viewer-pass-1', fullName: 'Sofia Novak',
    email: 's.novak@worldmonitor.example', role: 'viewer', department: 'Executive Reporting',
    mfaEnabled: false, ssn: '633-45-8812',
    internalNotes: 'Read-only dashboard access.',
    apiKey: 'wmk_live_44bc9d1e7a3f0258b6de',
    passwordHash: '$2b$12$VGhpcmREZW1vSGFzaFZhbHVl',
    lastLoginIp: '192.0.2.88', createdAt: '2024-01-19T08:00:00Z' },
];

export const MONITORS = [
  { id: 'wm-1001', ownerId: 1, name: 'APAC Logistics — Port Congestion', region: 'APAC',
    classification: 'CONFIDENTIAL', status: 'green', shipments: 18240, riskScore: 22,
    updatedAt: '2025-03-11T06:20:00Z', notes: 'Primary executive dashboard. Do not share externally.' },
  { id: 'wm-1002', ownerId: 2, name: 'EMEA Supplier Financial Health', region: 'EMEA',
    classification: 'INTERNAL', status: 'amber', shipments: 9310, riskScore: 58,
    updatedAt: '2025-03-11T05:02:00Z', notes: 'Includes unpublished credit ratings for 14 suppliers.' },
  { id: 'wm-1003', ownerId: 2, name: 'LATAM Raw Materials Watch', region: 'LATAM',
    classification: 'INTERNAL', status: 'green', shipments: 4120, riskScore: 31,
    updatedAt: '2025-03-10T22:41:00Z', notes: '' },
  { id: 'wm-1004', ownerId: 1, name: 'Global Sanctions Screening', region: 'GLOBAL',
    classification: 'RESTRICTED', status: 'red', shipments: 0, riskScore: 89,
    updatedAt: '2025-03-11T07:55:00Z', notes: 'Regulated data. Retention policy R-114 applies.' },
  { id: 'wm-1005', ownerId: 3, name: 'Executive KPI Rollup', region: 'GLOBAL',
    classification: 'INTERNAL', status: 'green', shipments: 31470, riskScore: 12,
    updatedAt: '2025-03-11T07:00:00Z', notes: '' },
];

export const WORKBENCH_USERS = [
  { id: 1, username: 'viewer', password: 'Viewer!Pass2024', fullName: 'Priya Raman', role: 'viewer' },
  { id: 2, username: 'tester', password: 'Tester!Pass2024', fullName: 'Diego Marchetti', role: 'tester' },
  { id: 3, username: 'lead',   password: 'Lead!Pass2024',   fullName: 'Amara Boateng',   role: 'lead' },
];

export const LAB_WORDLIST = [
  'password', '123456', 'admin', 'letmein', 'qwerty',
  'worldmonitor', 'monitor123', 'Sunshine2019!', 'Spring2024!', 'P@ssw0rd',
];