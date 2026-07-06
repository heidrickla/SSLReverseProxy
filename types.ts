import { Area } from 'react-easy-crop';
import { Permission } from './utils/permissions';

export type View = 'dashboard' | 'servers' | 'ssl' | 'users' | 'audit-log' | 'settings';

export type ServerStatus = 'active' | 'inactive' | 'error';
export type CertificateStatus = 'valid' | 'expiring' | 'expired' | 'issuing';
export type UserRole = 'Admin' | 'Editor' | 'Viewer';

export interface ProxyRule {
  id: string;
  domain: string;
  proxyTo: string;
  ssl: boolean;
}

export interface Server {
  id: string;
  name: string;
  ip: string;
  os: 'linux' | 'windows';
  status: ServerStatus;
  cpuUsage: number;
  ramUsage: number;
  storageUsage: number;
  rules: ProxyRule[];
}

export interface Certificate {
  id: string;
  domain: string;
  issuer: string;
  status: CertificateStatus;
  issuedAt: string;
  expiresAt: string;
  serialNumber: string;
  algorithm: string;
}

export interface User {
  id:string;
  name: string;
  email: string;
  role: UserRole;
  avatar?: string;
  lastLogin: string;
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

export interface CloudflareCredential {
  id: string; // Will use the Zone ID
  name: string; // Formatted name for dropdown
  apiToken: string;
  zoneId: string;
}

export interface AuthContextType {
  currentUser: User | null;
  users: User[];
  login: (userId: string) => void;
  logout: () => void;
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
  addCertificate: (newCertData: { 
    domain: string; 
    provider: string; 
    method: string; 
    cloudflareApiToken?: string;
    cloudflareZoneId?: string;
  }) => void;
  deleteCertificate: (certificateId: string) => void;
}