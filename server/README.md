# SSLReverseProxy — Control Plane (C#)

ASP.NET Core control plane for the reverse proxy: a secure web API plus a
**control service that starts/stops and configures an external Caddy proxy**.
Built security-first — see the "Security model" section.

## Architecture

```
server/
├── src/
│   ├── SslReverseProxy.Core            Domain, roles/permissions, SSRF validator (no deps)
│   ├── SslReverseProxy.Infrastructure  EF Core (SQLite), API-key hashing, Caddy controller, audit
│   └── SslReverseProxy.Api             Minimal-API endpoints, auth, security middleware
└── tests/SslReverseProxy.Tests         Unit + WebApplicationFactory integration tests
```

The **control service** (`IProxyController` → `CaddyProxyController`) manages the
Caddy process lifecycle and pushes configuration to Caddy's **loopback-only**
admin API. Caddy owns ACME / automatic HTTPS, so certificate issuance and renewal
use a mature, audited implementation instead of hand-rolled crypto.

## Security model

| Concern | Control |
| --- | --- |
| Authentication | API key in `X-Api-Key` (or `Authorization: Bearer`). Optional **mutual TLS** pinned to allow-listed client-cert thumbprints. |
| API-key storage | Only a **PBKDF2-SHA256** hash + per-key salt + server pepper is stored. Plaintext shown once at creation. Constant-time verification. |
| Authorization | Deny-by-default. Every endpoint requires a permission; roles → permissions enforced server-side (`Core/Security/Permissions.cs`). |
| SSRF | Every proxy upstream is validated server-side (`ProxyTargetValidator`) — http(s) only, cloud-metadata/link-local blocked, private/loopback gated by policy. |
| Transport | HSTS + HTTPS redirect in production; strict security headers on every response; JSON-only CSP. |
| Abuse | Per-IP fixed-window rate limiting (100/min). |
| Audit | Append-only audit log of every control/mutation action (actor, action, target, source IP). |
| Secrets | Pepper, client-cert thumbprints, ACME email come from configuration/user-secrets/environment — never source. |

## Configuration (`appsettings.json` + user-secrets / env)

- `ConnectionStrings:AppDb` — SQLite connection string.
- `Security:ApiKeyPepper` — base64 pepper mixed into key hashing. **Set via secrets.**
- `Security:RequireMutualTls` + `Security:AllowedClientCertificateThumbprints` — enable/pin mTLS.
- `Security:CorsAllowedOrigins` — SPA origin(s); empty = no cross-origin access.
- `Proxy:CaddyPath`, `Proxy:AdminEndpoint` (loopback), `Proxy:AcmeContactEmail`, `Proxy:UseAcmeStaging`.
- `Proxy:AllowLoopbackUpstreams`, `Proxy:AllowPrivateUpstreams` — SSRF policy.

Set secrets locally without committing them:

```bash
cd src/SslReverseProxy.Api
dotnet user-secrets init
dotnet user-secrets set "Security:ApiKeyPepper" "$(openssl rand -base64 32)"
```

## Run

```bash
dotnet build
dotnet test
dotnet run --project src/SslReverseProxy.Api
```

On first run the database is created/migrated and a **bootstrap admin + one-time
API key** are seeded; the plaintext key is written to the log **once** — capture
it. Use it as `X-Api-Key` to create real users/keys, then stop using the
bootstrap key.

## Endpoints (all require auth except `/api/health` and `/api/ready`)

Meta
- `GET /api/health` — anonymous liveness. `GET /api/ready` — anonymous readiness (DB + proxy).
- `GET /api/whoami` — current principal + permissions.
- `GET /api/events` — Server-Sent Events stream of control-plane events.

Control service
- `GET /api/proxy/status`, `POST /api/proxy/{start|stop|reload}`.
- `POST /api/proxy/validate` — dry-run validate the rule set (structural always; engine when Caddy present).
- `GET /api/proxy/config` — preview the generated proxy config without applying.
- `GET /api/proxy/metrics` — scraped runtime metrics.
- `GET /api/proxy/snapshots`, `POST /api/proxy/rollback` — config history + one-call rollback.

Servers / rules
- `GET/POST/DELETE /api/servers`, `GET/POST/PUT/DELETE .../rules` — SSRF-validated; rules support
  per-route IP allow/deny (`allowedCidrs`/`deniedCidrs`, native Caddy `remote_ip`).
- `PATCH .../rules/{id}/enabled` — quick enable/disable toggle.
- `GET .../rules/{id}/health` — probe the upstream (SSRF policy re-applied).

Certificates
- `GET/POST/DELETE /api/certificates` — ACME-managed (issued by Caddy).
- `GET /api/certificates/{id}/status` — real status derived from cert dates.
- `POST /api/certificates/{id}/renew` — force renewal (marks issuing + reloads).

Users / keys / audit
- `GET/POST/PUT /api/users` — create/update; the last active admin can't be demoted/deactivated.
- `GET/POST /api/apikeys` (filter by `userId`), `POST /api/apikeys/{id}/{revoke|rotate}`.
- `GET /api/audit` — audit trail with filtering (`actor`, `action`, `targetType`) and cursor paging (`beforeId`).

> **Scope note:** per-route access control ships IP allow/deny (native Caddy). Route-level
> rate limiting (needs the caddy-ratelimit plugin) and basic-auth (needs bcrypt credential
> management) are natural next additions and were intentionally deferred.

## Frontend

The React app talks to this API via [`services/apiClient.ts`](../services/apiClient.ts)
(sends `X-Api-Key`). Set `VITE_API_BASE_URL` to the API origin. Swapping the app's
mock data hooks over to `api.*` is the remaining integration step.
