// Typed client for the C# control-plane API (server/).
//
// AUTH: the backend authenticates with an API key (or mTLS). The key is sent in
// the `X-Api-Key` header. We keep it in sessionStorage (cleared when the tab
// closes) rather than localStorage to shrink the exposure window — but note that
// ANY value the browser can read is reachable by an XSS payload. For production,
// prefer terminating mTLS / injecting the key at an authenticating gateway so the
// SPA never holds a long-lived credential. See server/README.md.

const API_BASE = (import.meta as any).env?.VITE_API_BASE_URL ?? 'https://localhost:5001';
const KEY_STORAGE = 'sslrp-api-key';

export const apiKeyStore = {
  get: (): string | null => sessionStorage.getItem(KEY_STORAGE),
  set: (key: string) => sessionStorage.setItem(KEY_STORAGE, key),
  clear: () => sessionStorage.removeItem(KEY_STORAGE),
};

export class ApiError extends Error {
  constructor(public status: number, message: string, public problem?: unknown) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const key = apiKeyStore.get();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (key) headers['X-Api-Key'] = key;

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    // Do not attach ambient cookies; auth is via the explicit API-key header.
    credentials: 'omit',
  });

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = text ? JSON.parse(text) : undefined;
  if (!res.ok) {
    throw new ApiError(res.status, (data && (data.title || data.message)) || res.statusText, data);
  }
  return data as T;
}

// --- Types (mirror server/src/SslReverseProxy.Api/Contracts) ---
export type ProxyState = 'Unknown' | 'Stopped' | 'Running' | 'Faulted' | 'Unavailable';
export interface ProxyStatus {
  state: ProxyState; engine: string; processId: number | null;
  startedAt: string | null; activeRuleCount: number; message: string | null;
}
export interface Server { id: string; name: string; host: string; os: string; ruleCount: number; }
export interface Rule {
  id: string; serverId: string; domain: string; upstreamUrl: string;
  enableTls: boolean; enabled: boolean; allowedCidrs: string | null; deniedCidrs: string | null;
}
export interface WhoAmI { userId: string | null; name: string; role: string; permissions: string[]; }
export interface ProxyValidation { valid: boolean; issues: string[]; engineValidated: boolean; }
export interface Metrics { collectedAt: string; available: boolean; totalRequests: number; requestsInFlight: number; series: Record<string, number>; message: string | null; }
export interface Snapshot { id: number; createdAt: string; actor: string; ruleCount: number; note: string | null; }
export interface UpstreamHealth { reachable: boolean; statusCode: number | null; latencyMs: number | null; error: string | null; }
export interface CertStatus { id: string; domain: string; status: string; daysRemaining: number | null; expiresAt: string | null; }
export interface ApiCertificate { id: string; domain: string; issuer: string; status: string; expiresAt: string | null; managed: boolean; }
export interface ApiUser { id: string; name: string; email: string; role: string; isActive: boolean; lastSeenAt: string | null; }
export interface ApiAuditEntry { id: number; timestamp: string; actor: string; action: string; targetType: string; targetName: string; success: boolean; sourceIp: string | null; }

export const api = {
  whoami: () => request<WhoAmI>('GET', '/api/whoami'),

  proxy: {
    status: () => request<ProxyStatus>('GET', '/api/proxy/status'),
    start: () => request<ProxyStatus>('POST', '/api/proxy/start'),
    stop: () => request<ProxyStatus>('POST', '/api/proxy/stop'),
    reload: () => request<ProxyStatus>('POST', '/api/proxy/reload'),
    validate: () => request<ProxyValidation>('POST', '/api/proxy/validate'),
    metrics: () => request<Metrics>('GET', '/api/proxy/metrics'),
    configPreview: () => request<string>('GET', '/api/proxy/config'),
    snapshots: () => request<Snapshot[]>('GET', '/api/proxy/snapshots'),
    rollback: (snapshotId: number) => request<ProxyStatus>('POST', '/api/proxy/rollback', { snapshotId }),
  },

  servers: {
    list: () => request<Server[]>('GET', '/api/servers'),
    create: (s: { name: string; host: string; os: string }) => request<Server>('POST', '/api/servers', s),
    remove: (id: string) => request<void>('DELETE', `/api/servers/${id}`),
    rules: {
      list: (serverId: string) => request<Rule[]>('GET', `/api/servers/${serverId}/rules`),
      create: (serverId: string, r: Omit<Rule, 'id' | 'serverId'>) =>
        request<Rule>('POST', `/api/servers/${serverId}/rules`, r),
      update: (serverId: string, ruleId: string, r: Omit<Rule, 'id' | 'serverId'>) =>
        request<Rule>('PUT', `/api/servers/${serverId}/rules/${ruleId}`, r),
      toggle: (serverId: string, ruleId: string, enabled: boolean) =>
        request<Rule>('PATCH', `/api/servers/${serverId}/rules/${ruleId}/enabled`, { enabled }),
      health: (serverId: string, ruleId: string) =>
        request<UpstreamHealth>('GET', `/api/servers/${serverId}/rules/${ruleId}/health`),
      remove: (serverId: string, ruleId: string) =>
        request<void>('DELETE', `/api/servers/${serverId}/rules/${ruleId}`),
    },
  },

  certificates: {
    list: () => request<ApiCertificate[]>('GET', '/api/certificates'),
    create: (c: { domain: string }) =>
      request<ApiCertificate>('POST', '/api/certificates', { id: '00000000-0000-0000-0000-000000000000', domain: c.domain, issuer: '', status: 'Unknown', expiresAt: null, managed: true }),
    remove: (id: string) => request<void>('DELETE', `/api/certificates/${id}`),
    status: (id: string) => request<CertStatus>('GET', `/api/certificates/${id}/status`),
    renew: (id: string) => request<unknown>('POST', `/api/certificates/${id}/renew`),
  },

  users: {
    list: () => request<ApiUser[]>('GET', '/api/users'),
    create: (u: { name: string; email: string; role: string }) => request<ApiUser>('POST', '/api/users', u),
    update: (id: string, u: { name: string; role: string; isActive: boolean }) => request<ApiUser>('PUT', `/api/users/${id}`, u),
  },

  audit: (params?: { actor?: string; action?: string; targetType?: string; beforeId?: number; take?: number }) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params ?? {})) if (v != null) q.set(k, String(v));
    const qs = q.toString();
    return request<ApiAuditEntry[]>('GET', `/api/audit${qs ? `?${qs}` : ''}`);
  },

  // Live event stream (SSE). Returns an EventSource-like reader via fetch.
  events: (onEvent: (evt: unknown) => void, signal?: AbortSignal) =>
    streamEvents(onEvent, signal),
};

// Minimal SSE reader over fetch (EventSource can't send the X-Api-Key header).
async function streamEvents(onEvent: (evt: unknown) => void, signal?: AbortSignal): Promise<void> {
  const key = apiKeyStore.get();
  const res = await fetch(`${API_BASE}/api/events`, {
    headers: key ? { 'X-Api-Key': key } : {},
    credentials: 'omit',
    signal,
  });
  if (!res.body) return;
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buffer.indexOf('\n\n')) >= 0) {
      const frame = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      const line = frame.split('\n').find(l => l.startsWith('data: '));
      if (line) {
        try { onEvent(JSON.parse(line.slice(6))); } catch { /* ignore malformed frame */ }
      }
    }
  }
}
