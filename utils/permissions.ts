// The server's permission names. The signed-in principal's set comes from /api/whoami: the role's
// permissions, narrowed to an API key's scopes. The UI hides controls outside that set; the server
// authorizes every request against the same set, so this gating is a usability aid, not a boundary.

export type Permission =
  | 'ProxyControl'
  | 'ProxyReload'
  | 'ServerRead'
  | 'ServerWrite'
  | 'RuleWrite'
  | 'CertRead'
  | 'CertWrite'
  | 'CertRenew'
  | 'UserWrite'
  | 'ApiKeyManage'
  | 'AuditRead'
  | 'AlertManage'
  | 'BackupManage'
  | 'RecentRequestsRead';

export type PermissionGroup = 'Servers' | 'Proxy' | 'Certificates' | 'Administration';

export const PERMISSION_INFO: Record<Permission, { label: string; group: PermissionGroup }> = {
  ServerRead: { label: 'Read servers, rules and traffic', group: 'Servers' },
  ServerWrite: { label: 'Add and delete servers', group: 'Servers' },
  RuleWrite: { label: 'Edit rules', group: 'Servers' },
  RecentRequestsRead: { label: "Read rules' recent requests", group: 'Servers' },
  ProxyReload: { label: 'Preview, validate and reload', group: 'Proxy' },
  ProxyControl: { label: 'Start, stop and roll back', group: 'Proxy' },
  CertRead: { label: 'Read certificates', group: 'Certificates' },
  CertRenew: { label: 'Renew certificates', group: 'Certificates' },
  CertWrite: { label: 'Add, change and delete certificates', group: 'Certificates' },
  AuditRead: { label: 'Read the audit log', group: 'Administration' },
  AlertManage: { label: 'List and test alert targets', group: 'Administration' },
  UserWrite: { label: 'Manage users', group: 'Administration' },
  ApiKeyManage: { label: 'Manage API keys', group: 'Administration' },
  BackupManage: { label: 'Export and import backups', group: 'Administration' },
};

export const PERMISSION_GROUPS: PermissionGroup[] = ['Servers', 'Proxy', 'Certificates', 'Administration'];

/** A permission's label, or its name when the server sends one this build does not know. */
export const permissionLabel = (name: string): string =>
  (PERMISSION_INFO as Record<string, { label: string } | undefined>)[name]?.label ?? name;

export const permissionGroup = (name: string): PermissionGroup | 'Other' =>
  (PERMISSION_INFO as Record<string, { group: PermissionGroup } | undefined>)[name]?.group ?? 'Other';
