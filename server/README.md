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
- `Proxy:TrustedProxyCidrs` — CIDRs of any L7 proxy in front of **Caddy**. Empty (the default)
  means `X-Forwarded-For` is ignored outright, which is correct when Caddy faces clients
  directly and is what makes the per-route IP lists unspoofable. Not to be confused with
  `Security:TrustedProxies`, which is the same idea for the **control API**.
- `Proxy:TlsMinVersion` (`tls1.2` / `tls1.3`) and `Proxy:TlsCipherSuites` — the data-plane TLS
  floor. Caddy accepts only those two version strings and quietly ignores anything else, so an
  unrecognised value is treated as `tls1.2`. A cipher name Caddy does not know fails the entire
  config load, so run `POST /api/proxy/validate` after changing the suite list.
- `Proxy:ReadHeaderTimeoutSeconds`, `Proxy:ReadTimeoutSeconds`, `Proxy:WriteTimeoutSeconds`,
  `Proxy:IdleTimeoutSeconds` — data-plane timeouts; `0` keeps Caddy's default, which for
  read/write is no timeout at all.
- `Proxy:AccessLogPath` (+ `AccessLogRollSizeMb`, `AccessLogKeepDays`) — writes the data-plane
  access log as JSON lines. Off by default: these records carry client IPs and request URLs.

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

`CaddyBinaryValidationTests` puts the generated config permutations through a real
`caddy validate`, which catches a key that is spelled correctly but does not belong where it was
emitted — something assertions on the JSON alone cannot. It runs whenever `caddy` is on `PATH`,
or point it at a binary explicitly; without one it no-ops so the suite still runs on a box with
no Caddy installed.

```bash
SSLRP_TEST_CADDY=/path/to/caddy dotnet test
```

On first run the database is created/migrated and a **bootstrap admin + one-time
API key** are seeded; the plaintext key is written to the log **once** — capture
it. Use it as `X-Api-Key` to create real users/keys, then stop using the
bootstrap key.

In **Development only**, the seeded key can instead be claimed once via
`GET /api/bootstrap-key` (loopback clients only, and only while the process that
seeded the database is still running) — the React dev UI does this automatically
on first load, so a fresh install signs in without touching the log.

## Endpoints (all require auth except `/api/health`, `/api/ready`, and `/api/bootstrap-key`)

Meta
- `GET /api/health` — anonymous liveness. `GET /api/ready` — anonymous readiness (DB + proxy).
- `GET /api/bootstrap-key` — one-time first-run key claim (Development + loopback only; otherwise 404).
- `GET /api/whoami` — current principal + permissions.
- `GET /api/events` — Server-Sent Events stream of control-plane events.

Control service
- `GET /api/proxy/status`, `POST /api/proxy/{start|stop|reload}`.
- `POST /api/proxy/validate` — dry-run validate the rule set (structural always; engine when Caddy present).
- `GET /api/proxy/config` — preview the generated proxy config without applying.
- `GET /api/proxy/metrics` — scraped runtime metrics.
- `GET /api/proxy/snapshots`, `POST /api/proxy/rollback` — config history + one-call rollback.

Servers / rules
- `GET/POST/DELETE /api/servers`, `GET/POST/PUT/DELETE .../rules` — SSRF-validated. Per-route
  access control: IP allow/deny (`allowedCidrs`/`deniedCidrs`, native Caddy `client_ip`),
  rate limiting (`rateLimitPerMinute`, caddy-ratelimit plugin), and HTTP basic auth
  (`basicAuthUsername`/`basicAuthPassword` — hashed with bcrypt server-side; the plaintext is
  never stored or returned).
- Rules also take an optional `hardening` object. Omit it and nothing changes, which is what
  keeps older clients working; send it and every field in it is replaced, matching how the rest
  of `PUT` behaves.

  | Field | Effect |
  | --- | --- |
  | `additionalUpstreams`, `loadBalancePolicy` | Extra upstreams (same SSRF policy, and all must share the primary's scheme) plus a Caddy selection policy: `random`, `random_choose`, `first`, `round_robin`, `least_conn`, `ip_hash`, `uri_hash`, `client_ip_hash`. |
  | `dialTimeoutSeconds`, `upstreamReadTimeoutSeconds`, `upstreamWriteTimeoutSeconds` | Bounds on the upstream leg. Caddy ships no read/write timeout, so a backend that stalls mid-response otherwise holds the connection open indefinitely. |
  | `maxRequestBodyBytes` | Caps the request body; the client gets `413`. Enforced as the body is read, not from `Content-Length`, so an oversized upload is cut off partway rather than refused up front. |
  | `enableSecurityHeaders` | On by default; emits `X-Content-Type-Options: nosniff` and `Referrer-Policy: strict-origin-when-cross-origin`. |
  | `hstsMaxAgeDays`, `hstsIncludeSubdomains`, `frameOptions` | Opt-in, and off by default because both can break a working site. HSTS cannot be recalled once a browser has seen it, and is suppressed on rules with TLS disabled. `includeSubDomains` is a separate opt-in again: on an apex domain it pins every sibling host to HTTPS for the whole max-age, including hosts this rule does not serve. |
  | `healthCheckPath`, `healthCheckIntervalSeconds`, `healthCheckTimeoutSeconds`, `healthCheckExpectStatus` | Caddy-native active health checking, so an unhealthy upstream is taken out of rotation between requests rather than only being visible in the control plane's own probe. `expectStatus` accepts a full code or a single digit for the whole class (`2` = any 2xx); left unset, Caddy's own 200-399 applies, which is what you want for a health endpoint that redirects. |
  | `skipAccessLog` | Keeps this host out of the access log. |
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

> **Note:** route-level **rate limiting** emits config for the [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit)
> plugin, which must be present in the Caddy build (e.g. `xcaddy build --with github.com/mholt/caddy-ratelimit`).
> **Basic auth** uses native Caddy and works with a stock build.
>
> **Caddy version floor: 2.7.** The IP allow/deny lists emit the `client_ip` matcher, which
> does not exist before 2.7 — on an older build the config is rejected outright rather than
> silently ignored, since Caddy rejects unknown fields.
>
> **`https://` upstreams:** Caddy's JSON has no scheme inference — the `dial` address is only
> `host:port`, and it is the reverse-proxy transport that decides TLS. The generated config sets
> that transport, so an `https://` upstream is now actually spoken to over TLS. On Caddy 2.11+
> the transport also rewrites the `Host` header to the upstream's `host:port`; if your backend
> serves virtual hosts keyed on the original `Host`, account for that.

## Production / deployment

- **Secrets:** set `Security:ApiKeyPepper` (random, base64) via `Security__ApiKeyPepper` env
  or user-secrets — the app logs a warning on startup in Production if it's unset. Provide
  ACME email and any client-cert thumbprints the same way. Never commit them.
- **TLS & headers:** HSTS + HTTPS redirect are enabled in Production; also terminate real TLS
  (or mTLS) for the control API at your edge. Put the control API behind an authenticating
  gateway or enable `Security:RequireMutualTls`.
- **Behind a proxy:** list your reverse proxies in `Security:TrustedProxies` (IP or CIDR) so
  the rate limiter and audit log record the real client IP from `X-Forwarded-For` — untrusted
  sources are ignored to prevent spoofing.
- **Containers:** [`Dockerfile`](Dockerfile) bundles the API with the Caddy binary (the API
  manages Caddy as a child process); [`docker-compose.yml`](docker-compose.yml) runs it with a
  persisted `/data` volume. Provide `SSLRP_API_KEY_PEPPER` (and optionally `SSLRP_ACME_EMAIL`,
  `SSLRP_SPA_ORIGIN`) in the environment.

## Frontend

The React app talks to this API via [`services/apiClient.ts`](../services/apiClient.ts)
(sends `X-Api-Key`). Set `VITE_API_BASE_URL` to the API origin. Swapping the app's
mock data hooks over to `api.*` is the remaining integration step.
