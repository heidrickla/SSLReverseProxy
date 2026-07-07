import { UserRole } from '../types';

// Role-based access control map.
//
// IMPORTANT: This gates the UI only (hiding/disabling controls a role may not
// use). It is defense-in-depth and a usability aid, NOT a security boundary.
// Anyone can edit the client or localStorage to change their role, so the
// backend MUST authorize every privileged action server-side against the
// authenticated session's real role. Never rely on this map for enforcement.

export type Permission =
  | 'proxy:control'
  | 'server:create'
  | 'server:update'
  | 'server:delete'
  | 'rule:manage'
  | 'cert:create'
  | 'cert:delete'
  | 'user:create'
  | 'user:update';

const ROLE_PERMISSIONS: Record<UserRole, Permission[]> = {
  Viewer: [],
  Editor: [
    'proxy:control',
    'server:create',
    'server:update',
    'server:delete',
    'rule:manage',
    'cert:create',
    'cert:delete',
  ],
  Admin: [
    'proxy:control',
    'server:create',
    'server:update',
    'server:delete',
    'rule:manage',
    'cert:create',
    'cert:delete',
    'user:create',
    'user:update',
  ],
};

export const roleCan = (role: UserRole | undefined, permission: Permission): boolean => {
  if (!role) return false;
  return ROLE_PERMISSIONS[role]?.includes(permission) ?? false;
};
