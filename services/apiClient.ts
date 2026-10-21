import type { CreationOptionsJson, RequestOptionsJson } from '../utils/webauthn';

// Typed client for the C# control-plane API (server/).
//
// AUTH: an API key in the `X-Api-Key` header, or a passkey session. The key is
// kept in sessionStorage (cleared when the tab closes); any value the browser can
// read is reachable by an XSS payload. A passkey session is an HttpOnly cookie the
// page cannot read, sent only to the page's own origin; unsafe requests on it
// carry the session's CSRF token, held in memory. See server/README.md.

// Empty means the page's own origin, with /api routed to the control plane by the edge (or Vite's proxy).
const API_BASE: string = (import.meta as any).env?.VITE_API_BASE_URL ?? '';
const KEY_STORAGE = 'sslrp-api-key';

export const apiKeyStore = {
  get: (): string | null => sessionStorage.getItem(KEY_STORAGE),
  set: (key: string) => sessionStorage.setItem(KEY_STORAGE, key),
  clear: () => sessionStorage.removeItem(KEY_STORAGE),
};

/** Passkey sessions ride on a cookie the browser sends only to the page's own origin. */
export const sessionsAvailable = (base: string = API_BASE): boolean => {
  if (!base) return true;
  try {
    return new URL(base, window.location.href).origin === window.location.origin;
  } catch {
    return false;
  }
};

// The CSRF token of the passkey session, held in memory only. A reload recovers it from /api/auth/session.
let csrfToken: string | null = null;
export const csrfStore = {
  get: (): string | null => csrfToken,
  set: (token: string) => { csrfToken = token; },
  clear: () => { csrfToken = null; },
};

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export class ApiError extends Error {
  constructor(public status: number, message: string, public problem?: unknown) {
    super(message);
  }
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  extraHeaders?: Record<string, string>,
): Promise<T> {
  const key = apiKeyStore.get();
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...extraHeaders };
  if (key) headers['X-Api-Key'] = key;
  else if (csrfToken && !SAFE_METHODS.has(method)) headers['X-CSRF-Token'] = csrfToken;

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    // With an API key the session cookie stays home: the server refuses a request carrying both.
    credentials: key ? 'omit' : 'same-origin',
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
export interface Server {
  id: string; name: string; host: string; os: string; ruleCount: number;
  status: 'Unknown' | 'Active' | 'Inactive' | 'Error'; upstreamsUp: number; upstreamsTotal: number; statusCheckedAt: string | null;
}
/** A control-plane event from GET /api/events. */
export interface ControlEvent { type: string; message: string; at: string; actor: string | null; }
// Per-route hardening emitted into the Caddy config. Mirrors RuleHardeningDto.
export interface RuleHardening {
  additionalUpstreams: string | null;
  loadBalancePolicy: string | null;
  dialTimeoutSeconds: number | null;
  upstreamReadTimeoutSeconds: number | null;
  upstreamWriteTimeoutSeconds: number | null;
  maxRequestBodyBytes: number | null;
  enableSecurityHeaders: boolean;
  upstreamTlsServerName: string | null;
  upstreamTlsTrustedCaFile: string | null;
  upstreamTlsInsecureSkipVerify: boolean;
  hstsMaxAgeDays: number | null;
  hstsIncludeSubdomains: boolean;
  frameOptions: string | null;
  healthCheckPath: string | null;
  healthCheckIntervalSeconds: number | null;
  healthCheckTimeoutSeconds: number | null;
  healthCheckExpectStatus: number | null;
  skipAccessLog: boolean;
}
/** Path routing. A null prefix serves the whole host. Mirrors RuleRoutingDto. */
export interface RuleRouting { pathPrefix: string | null; stripPathPrefix: boolean; }
export interface Rule {
  id: string; serverId: string; domain: string; upstreamUrl: string;
  enableTls: boolean; enabled: boolean; allowedCidrs: string | null; deniedCidrs: string | null;
  rateLimitPerMinute: number | null;
  basicAuthEnabled: boolean; basicAuthUsername: string | null;
  hardening: RuleHardening;
  routing: RuleRouting;
  /**
   * Optimistic-concurrency token. Pass it back on update/delete so an edit made
   * from a stale copy is rejected rather than silently overwriting whoever
   * wrote in between. The API sends the same value as an ETag.
   */
  version: number;
}
/**
 * Body for creating/updating a rule. Not Omit<Rule, ...>: the write shape and
 * the read shape genuinely differ — basicAuthPassword is write-only, and
 * basicAuthEnabled is derived server-side.
 *
 * PUT replaces, so every field left out is cleared. `hardening` is all-or-
 * nothing on the same principle: omit it entirely and those settings are left
 * alone, but send one and every field in it is written, so a field you leave
 * out is cleared rather than kept. That is why this is `RuleHardening` and not
 * `Partial<RuleHardening>` — a partial-looking type would make
 * `hardening: { skipAccessLog: true }` type-check while silently dropping the
 * rule's upstreams, timeouts and health check.
 */
export interface RuleInput {
  domain: string; upstreamUrl: string; enableTls: boolean; enabled: boolean;
  allowedCidrs?: string | null; deniedCidrs?: string | null;
  rateLimitPerMinute?: number | null;
  basicAuthUsername?: string | null; basicAuthPassword?: string | null;
  hardening?: RuleHardening | null;
  /** Omitted or null leaves the rule's routing as it is; sent, both fields are written. */
  routing?: RuleRouting | null;
}
/** `permissions` is the effective set: the role's, narrowed to the key's scopes. `key` is set when signed in with a key. */
export interface WhoAmI {
  userId: string | null; name: string; role: string; permissions: string[];
  key?: { id: string; name: string; expiresAt: string | null; scopes: string[] | null } | null;
}
/** Null `scopes`: the key follows its owner's role. */
export interface ApiKey {
  id: string; name: string; prefix: string; userId: string; userName: string; createdAt: string;
  expiresAt: string | null; revokedAt: string | null; lastUsedAt: string | null; scopes: string[] | null;
}
export interface IssuedApiKey { id: string; name: string; token: string; expiresAt: string | null; scopes: string[] | null; }
export interface ApiKeyPreset { id: string; name: string; description: string; scopes: string[] | null; }
export interface ApiKeyOptions {
  lifetimeDays: number[]; defaultLifetimeDays: number; maxLifetimeDays: number;
  presets: ApiKeyPreset[]; permissions: string[]; roles: Record<string, string[]>;
}
/** One of lifetimeDays or expiresAt. Null scopes follow the owner's role. */
export interface ApiKeyGrant { lifetimeDays?: number; expiresAt?: string; scopes: string[] | null; }
/** A WebAuthn ceremony: `options` go to the browser, `handle` comes back with its answer. */
export interface PasskeyCeremony<T> { handle: string; options: T; }
export interface PasskeySignIn { csrfToken: string; expiresAt: string; user: WhoAmI; }
export interface PasskeySession { csrfToken: string; expiresAt: string; }
export interface Passkey { id: string; name: string; createdAt: string; lastUsedAt: string | null; backedUp: boolean; }
export interface ProxyValidation { valid: boolean; issues: string[]; engineValidated: boolean; }
export interface Metrics { collectedAt: string; available: boolean; totalRequests: number; requestsInFlight: number; series: Record<string, number>; message: string | null; }
/** GET /api/proxy/traffic: the last 24 hours of stored samples. Nulls mean no data for that figure. */
export interface Traffic {
  sampleSeconds: number; proxyRunning: boolean; samples: number; from: string | null; to: string | null;
  requests: number; bytesIn: number; bytesOut: number; inFlight: number | null;
  avgTtfbMs: number | null; avgResponseMs: number | null; p50Ms: number | null; p90Ms: number | null; p95Ms: number | null;
  status: { success: number; redirect: number; clientError: number; serverError: number };
  hourly: { start: string; requests: number }[];
}
export interface Snapshot { id: number; createdAt: string; actor: string; ruleCount: number; note: string | null; }
export interface UpstreamHealth { reachable: boolean; statusCode: number | null; latencyMs: number | null; error: string | null; }
export interface CertStatus { id: string; domain: string; status: string; daysRemaining: number | null; expiresAt: string | null; }
export type ChallengeName = 'Http' | 'DnsCloudflare';
/** A certificate row. `status` is derived from the served certificate's dates when the list is read. */
export interface ApiCertificate {
  id: string; domain: string; issuer: string; status: string; daysRemaining: number | null;
  issuedAt: string | null; expiresAt: string | null; serialNumber: string | null; algorithm: string | null;
  source: 'Rule' | 'Manual'; challenge: ChallengeName; lastError: string | null; checkedAt: string | null;
  renewPending: boolean; managed: boolean;
}
/** A validation method and whether the server can use it now. */
export interface AlertTarget { name: string; kind: string; events: string[]; problem: string | null; }
export interface AlertsInfo { targets: AlertTarget[]; events: string[]; }
export interface AlertDelivery { target: string; delivered: boolean; status: number | null; error: string | null; attempts: number; }
export interface CertificateChallenge { name: ChallengeName; available: boolean; wildcard: boolean; reason: string | null; }
export interface ApiUser { id: string; name: string; email: string; role: string; isActive: boolean; lastSeenAt: string | null; }
export interface ApiAuditEntry { id: number; timestamp: string; actor: string; action: string; targetType: string; targetName: string; success: boolean; sourceIp: string | null; }

/** RFC 7232 entity-tag for a rule version. */
const ifMatch = (version: number): Record<string, string> => ({ 'If-Match': `"${version}"` });

/**
 * True when a write was rejected because someone else got there first --
 * 412 (the version we sent is stale) or 409 (we lost the race during the save).
 * Either way the fix is the same: reload and reapply.
 */
export const isConcurrencyConflict = (e: unknown): boolean =>
  e instanceof ApiError && (e.status === 412 || e.status === 409 || e.status === 428);

/** The first field error of a validation problem, else the problem's own message. */
export const apiErrorMessage = (e: unknown, fallback = 'Request failed.'): string => {
  if (!(e instanceof ApiError)) return fallback;
  const errors = (e.problem as { errors?: Record<string, string[]> } | undefined)?.errors;
  const first = errors && Object.values(errors).flat()[0];
  return first || e.message || fallback;
};

export const api = {
  whoami: () => request<WhoAmI>('GET', '/api/whoami'),

  // First-run only: claims the seeded bootstrap admin key. The backend answers
  // solely in Development, from loopback, until the key is claimed once; every
  // other case is a 404.
  bootstrapKey: () => request<{ apiKey: string }>('GET', '/api/bootstrap-key'),

  proxy: {
    status: () => request<ProxyStatus>('GET', '/api/proxy/status'),
    start: () => request<ProxyStatus>('POST', '/api/proxy/start'),
    stop: () => request<ProxyStatus>('POST', '/api/proxy/stop'),
    reload: () => request<ProxyStatus>('POST', '/api/proxy/reload'),
    validate: () => request<ProxyValidation>('POST', '/api/proxy/validate'),
    metrics: () => request<Metrics>('GET', '/api/proxy/metrics'),
    traffic: () => request<Traffic>('GET', '/api/proxy/traffic'),
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
      create: (serverId: string, r: RuleInput) =>
        request<Rule>('POST', `/api/servers/${serverId}/rules`, r),
      // `version` is required: PUT replaces the whole rule, so the API refuses
      // one that does not say which version it is replacing (428).
      update: (serverId: string, ruleId: string, r: RuleInput, version: number) =>
        request<Rule>('PUT', `/api/servers/${serverId}/rules/${ruleId}`, r, ifMatch(version)),
      toggle: (serverId: string, ruleId: string, enabled: boolean, version?: number) =>
        request<Rule>('PATCH', `/api/servers/${serverId}/rules/${ruleId}/enabled`, { enabled },
          version === undefined ? undefined : ifMatch(version)),
      health: (serverId: string, ruleId: string) =>
        request<UpstreamHealth>('GET', `/api/servers/${serverId}/rules/${ruleId}/health`),
      remove: (serverId: string, ruleId: string, version?: number) =>
        request<void>('DELETE', `/api/servers/${serverId}/rules/${ruleId}`, undefined,
          version === undefined ? undefined : ifMatch(version)),
    },
  },

  certificates: {
    list: () => request<ApiCertificate[]>('GET', '/api/certificates'),
    create: (c: { domain: string; challenge: ChallengeName }) => request<ApiCertificate>('POST', '/api/certificates', c),
    setChallenge: (id: string, challenge: ChallengeName) =>
      request<ApiCertificate>('PUT', `/api/certificates/${id}`, { challenge }),
    remove: (id: string) => request<void>('DELETE', `/api/certificates/${id}`),
    status: (id: string) => request<CertStatus>('GET', `/api/certificates/${id}/status`),
    // 202 once the renewal is under way; the row's renewPending clears when a new certificate is served.
    renew: (id: string) => request<ApiCertificate>('POST', `/api/certificates/${id}/renew`),
    challenges: () => request<CertificateChallenge[]>('GET', '/api/certificates/challenges'),
  },

  // Targets are server configuration; the API lists them without URLs or tokens.
  alerts: {
    list: () => request<AlertsInfo>('GET', '/api/alerts'),
    test: (target: string) => request<AlertDelivery[]>('POST', '/api/alerts/test', { target }),
  },

  auth: {
    methods: () => request<{ passkeys: boolean }>('GET', '/api/auth/methods'),
    passkeyOptions: () => request<PasskeyCeremony<RequestOptionsJson>>('POST', '/api/auth/passkey/options'),
    passkeySignIn: (handle: string, response: unknown) =>
      request<PasskeySignIn>('POST', '/api/auth/passkey', { handle, response }),
    session: () => request<PasskeySession>('GET', '/api/auth/session'),
    logout: () => request<void>('POST', '/api/auth/logout'),
  },

  // The signed-in user's own passkeys.
  passkeys: {
    list: () => request<Passkey[]>('GET', '/api/passkeys'),
    options: () => request<PasskeyCeremony<CreationOptionsJson>>('POST', '/api/passkeys/options'),
    register: (handle: string, name: string, response: unknown) =>
      request<Passkey>('POST', '/api/passkeys', { handle, name, response }),
    remove: (id: string) => request<void>('DELETE', `/api/passkeys/${id}`),
  },

  apiKeys: {
    list: () => request<ApiKey[]>('GET', '/api/apikeys'),
    options: () => request<ApiKeyOptions>('GET', '/api/apikeys/options'),
    create: (userId: string, name: string, grant: ApiKeyGrant) =>
      request<IssuedApiKey>('POST', '/api/apikeys', { userId, name, ...grant }),
    rotate: (id: string, grant: ApiKeyGrant) => request<IssuedApiKey>('POST', `/api/apikeys/${id}/rotate`, grant),
    revoke: (id: string) => request<void>('POST', `/api/apikeys/${id}/revoke`),
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

  // Live event stream (SSE). onOpen runs once the server has registered the
  // subscriber, so state fetched from then on cannot miss a later event.
  events: (onEvent: (evt: ControlEvent) => void, signal?: AbortSignal, onOpen?: () => void) =>
    streamEvents(onEvent, signal, onOpen),
};

// Minimal SSE reader over fetch (EventSource can't send the X-Api-Key header).
async function streamEvents(onEvent: (evt: ControlEvent) => void, signal?: AbortSignal, onOpen?: () => void): Promise<void> {
  const key = apiKeyStore.get();
  const res = await fetch(`${API_BASE}/api/events`, {
    headers: key ? { 'X-Api-Key': key } : {},
    credentials: key ? 'omit' : 'same-origin',
    signal,
  });
  if (!res.ok || !res.body) return;
  onOpen?.();
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
