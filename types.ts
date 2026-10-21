import { Area } from 'react-easy-crop';
import { Permission } from './utils/permissions';
import type { ChallengeName, Rule } from './services/apiClient';

export type View = 'dashboard' | 'proxy' | 'servers' | 'ssl' | 'users' | 'api-keys' | 'audit-log' | 'settings';

// From the control plane's background probe of each enabled rule's upstreams; 'unknown' until the first probe.
export type ServerStatus = 'active' | 'inactive' | 'error' | 'unknown';
export type CertificateStatus = 'valid' | 'expiring' | 'expired' | 'issuing' | 'failed' | 'unknown';
export type UserRole = 'Admin' | 'Editor' | 'Viewer';

export interface Server {
  id: string;
  name: string;
  host: string;
  os: 'linux' | 'windows';
  ruleCount: number;
  status: ServerStatus;
  upstreamsUp: number;
  upstreamsTotal: number;
  statusCheckedAt: string | null;
  // The API rule verbatim, not a trimmed-down view shape. Rule writes are
  // full replacements, so anything dropped here would be dropped on the next
  // PUT — see toPayload in components/ServerDetailPane.tsx.
  rules: Rule[];
}

// Rows for TLS rules' hosts come and go with the rules; manual rows name a host or wildcard on their own.
export interface Certificate {
  id: string;
  domain: string;
  issuer: string;
  status: CertificateStatus;
  daysRemaining: number | null;
  issuedAt: string | null;
  expiresAt: string | null;
  serialNumber: string | null;
  algorithm: string | null;
  source: 'rule' | 'manual';
  challenge: ChallengeName;
  lastError: string | null;
  checkedAt: string | null;
  renewPending: boolean;
}

export interface User {
  id:string;
  name: string;
  email: string;
  role: UserRole;
  avatar?: string;
  lastLogin: string;
  /** The signed-in principal's effective permissions, from /api/whoami. */
  permissions?: string[];
  /** The API key the session signed in with; null scopes mean it follows the role. */
  apiKey?: { id: string; name: string; expiresAt: string | null; scopes: string[] | null } | null;
}

export interface LogEntry {
  id: string;
  user: {
    id: string;
    name: string;
    avatar?: string;
  };
  action: string;
  targetType: string;
  targetName: string;
  timestamp: string;
  details: Record<string, any>;
}

export type ThemeColors = Record<string, string>;

export interface Theme {
  name: string;
  type: 'light' | 'dark';
  custom?: boolean;
  colors: ThemeColors;
}

export interface ThemeContextType {
  mode: 'light' | 'dark';
  toggleMode: () => void;
  lightTheme: Theme;
  darkTheme: Theme;
  setLightTheme: (theme: Theme) => void;
  setDarkTheme: (theme: Theme) => void;
  allThemes: Theme[];
  addTheme: (newThemeData: Omit<Theme, 'custom'>) => void;
  deleteTheme: (themeName: string) => void;
  scale: number;
  setScale: (scale: number) => void;
}

export interface AuthContextType {
  currentUser: User | null;
  authReady: boolean;
  /** The server offers passkey sign-in (Passkeys:RelyingPartyId is set). */
  passkeysEnabled: boolean;
  /** Shown on the sign-in view: the last sign-out could not end the passkey session. */
  authNotice: string | null;
  users: User[];
  login: (apiKey: string) => Promise<void>;
  loginWithPasskey: () => Promise<void>;
  logout: () => Promise<void>;
  switchUser: () => void;
  updateUser: (updatedUser: User) => void;
  hasPermission: (permission: Permission) => boolean;
  addUser: (newUser: { name: string; email: string; role: UserRole; avatar?: string; }) => void;
  
  // Centralized data management
  servers: Server[];
  certificates: Certificate[];
  auditLogs: LogEntry[];
  addServer: (newServerData: { name: string; ip: string; os: 'linux' | 'windows'; }) => void;
  updateServer: (updatedServer: Server) => void;
  deleteServer: (serverId: string) => void;
  addCertificate: (newCertData: { domain: string; challenge: ChallengeName }) => Promise<void>;
  deleteCertificate: (certificateId: string) => Promise<void>;
  renewCertificate: (certificateId: string) => Promise<void>;
  setCertificateChallenge: (certificateId: string, challenge: ChallengeName) => Promise<void>;
  reloadData: () => Promise<void>;
}