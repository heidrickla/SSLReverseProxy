# SSLReverseProxy control plane

ASP.NET Core web API plus a control service that starts, stops and configures an external Caddy proxy.

## Architecture

```
server/
├── src/
│   ├── SslReverseProxy.Core            Domain, roles and permissions, SSRF validator (no deps)
│   ├── SslReverseProxy.Infrastructure  EF Core (SQLite), API-key hashing, Caddy controller, audit
│   └── SslReverseProxy.Api             Minimal-API endpoints, auth, security middleware
└── tests/SslReverseProxy.Tests         Unit and WebApplicationFactory integration tests
```

The control service (`IProxyController`, `CaddyProxyController`) runs Caddy as a child process and pushes configuration to Caddy's loopback-only admin API. Caddy does ACME and automatic HTTPS.

## Security model

| Concern | Control |
| --- | --- |
| Authentication | API key in `X-Api-Key` or `Authorization: Bearer`. Optional mutual TLS pinned to allow-listed client-certificate thumbprints. |
| API-key storage | PBKDF2-SHA256 hash, per-key salt and server pepper only. Plaintext shown once at creation. Constant-time verification. |
| Authorization | Deny-by-default. Every endpoint requires a permission; roles map to permissions server-side (`Core/Security/Permissions.cs`). |
| SSRF | Every upstream is validated server-side (`ProxyTargetValidator`): http(s) only, cloud-metadata and link-local blocked, private and loopback gated by policy. |
| Transport | HSTS and HTTPS redirect in Production; security headers and a JSON-only CSP on every response. |
| Abuse | Per-IP fixed-window rate limit, 100 a minute. |
| Audit | Append-only log of every control and mutation action (actor, action, target, source IP). |
| Secrets | Pepper, client-certificate thumbprints and ACME email from configuration, user-secrets or environment. Configured secret values are masked in Caddy's forwarded output, `/load` errors and validation issues, and a rollback config holding one is refused. |
| Caddy process | Started with a fixed environment: system paths, its data and config directories, outbound proxy and trust-store variables, and the Cloudflare token when set. Rule text may not contain `{` or `}`, which Caddy reads as placeholders. |

## Configuration

`appsettings.json`, user-secrets or environment (`Section__Key`).

| Key | Meaning |
| --- | --- |
| `ConnectionStrings:AppDb` | SQLite connection string. |
| `Security:ApiKeyPepper` | Base64 pepper mixed into key hashing. Set through secrets. |
| `Security:RequireMutualTls`, `Security:AllowedClientCertificateThumbprints` | Require and pin client certificates. |
| `Security:CorsAllowedOrigins` | SPA origins; empty allows no cross-origin access. |
| `Security:TrustedProxies` | Proxies in front of the control API whose `X-Forwarded-For` is honoured. |
| `Proxy:CaddyPath`, `Proxy:AdminEndpoint` | Caddy binary and its admin endpoint (loopback). |
| `Proxy:AcmeContactEmail`, `Proxy:UseAcmeStaging` | ACME account email and Let's Encrypt staging. |
| `Proxy:CertificateIssuer` | `acme` (default: Let's Encrypt with `AcmeContactEmail`, Caddy's default issuers without it) or `internal` (Caddy's own CA; its root is not installed in the host trust store). |
| `Proxy:HttpPort` (80), `Proxy:HttpsPort` (443) | Caddy's listeners. TLS rules are served on the HTTPS port only. The HTTP port serves plaintext rules, redirects TLS hosts and answers ACME challenges. Redirects name the standard port, so a non-default `HttpsPort` needs 443 forwarded to it. |
| `Proxy:ServerHealthIntervalSeconds` | Seconds between background probes of every enabled rule's upstreams (60; 0 off). A server is `Active` (every upstream answered), `Error` (one or more did not), `Inactive` (no enabled rule) or `Unknown` (not probed). A successful write under `/api/servers` probes again at once. Probes apply the SSRF policy. |
| `Proxy:TrafficSampleSeconds` | Seconds between dashboard traffic samples (60; 0 off). Each sample is the change in Caddy's metrics since the last; samples are kept 25 hours. |
| `Proxy:AllowLoopbackUpstreams`, `Proxy:AllowPrivateUpstreams` | SSRF policy. |
| `Proxy:TrustedProxyCidrs` | CIDRs of L7 proxies in front of Caddy. Empty (default) ignores `X-Forwarded-For`, which keeps the per-route IP lists unspoofable when Caddy faces clients directly. |
| `Proxy:TlsMinVersion`, `Proxy:TlsCipherSuites` | Data-plane TLS floor: `tls1.2` or `tls1.3`; any other value is treated as `tls1.2`. A cipher name Caddy does not know fails the whole config load, so run `POST /api/proxy/validate` after changing the list. |
| `Proxy:ReadHeaderTimeoutSeconds`, `Proxy:ReadTimeoutSeconds`, `Proxy:WriteTimeoutSeconds`, `Proxy:IdleTimeoutSeconds` | Data-plane timeouts; 0 keeps Caddy's default, which for read and write is none. |
| `Proxy:AccessLogPath`, `AccessLogRollSizeMb`, `AccessLogKeepDays` | Data-plane access log as JSON lines. Off by default: records carry client IPs and URLs. |
| `Seed:Demo` | Development only: fills a new database with demo servers, rules, certificates, users and audit entries. Upstreams point at `Seed:DemoUpstreamBase` (default `http://127.0.0.1:5195`, this API under the `http` launch profile) and the discard port, so the three servers come up `Active`, `Error` and `Inactive`. Ignored with a warning elsewhere. |

Secrets locally:

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

`CaddyBinaryValidationTests` runs the generated config permutations through a real `caddy validate`, which catches a key emitted where it does not belong. It uses `SSLRP_TEST_CADDY`, or `caddy` on `PATH`, and no-ops without either. Plugin cases skip on a binary without the plugin. `SSLRP_REQUIRE_CADDY=1`, set in CI, turns both into failures.

```bash
SSLRP_TEST_CADDY=/path/to/caddy SSLRP_REQUIRE_CADDY=1 dotnet test
```

The first run creates or migrates the database and seeds a bootstrap admin with a one-time API key, written to the log once. Use it as `X-Api-Key` to create users and keys, then retire it. In Development the key can instead be claimed once through `GET /api/bootstrap-key` (loopback clients, while the seeding process runs); the dev UI does this on first load.

### Caddy

The image and CI build Caddy with [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) at the versions pinned by `CADDY_VERSION` and `CADDY_RATELIMIT` in the [`Dockerfile`](Dockerfile). The same build locally, with Go:

```bash
go run github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.7 build v2.11.7 --with github.com/mholt/caddy-ratelimit@5625512f24f6f59d6f64fb3aafe5eecff0b286db --output ~/.sslrp/caddy/caddy
```

Caddy 2.7 or later: the IP lists emit the `client_ip` matcher. Rate-limited rules need caddy-ratelimit; a stock Caddy rejects the config. Basic auth is native.

## Endpoints

All require authentication except `/api/health`, `/api/ready` and `/api/bootstrap-key`.

Meta

- `GET /api/health`: anonymous liveness. `GET /api/ready`: anonymous readiness (database and proxy).
- `GET /api/bootstrap-key`: one-time first-run key claim (Development and loopback only; 404 otherwise).
- `GET /api/whoami`: current principal and permissions.
- `GET /api/events`: Server-Sent Events, each `{type, message, at, actor}`. `server.health` is published when a server's status changes. Headers go out once the subscriber is registered, so no event published after the client has them is missed.

Control service

- `GET /api/proxy/status`, `POST /api/proxy/{start|stop|reload}`.
- `POST /api/proxy/validate`: dry-run validation of the rule set (structural always; Caddy's when present).
- `GET /api/proxy/config`: the generated config, not applied.
- `GET /api/proxy/metrics`: scraped runtime metrics.
- `GET /api/proxy/traffic`: the last 24 hours from stored samples: requests, bytes in and out, status classes, average response time and time to first byte, median, P90 and P95 from Caddy's duration histogram, requests in flight at the latest sample, requests per hour. Answers from the database.
- `GET /api/proxy/snapshots`, `POST /api/proxy/rollback`: config history and rollback.

Servers and rules

- `GET /api/servers` returns each server's `status`, `upstreamsUp`, `upstreamsTotal` and `statusCheckedAt`.
- `GET/POST/DELETE /api/servers`, `GET/POST/PUT/DELETE .../rules`: SSRF-validated. Per-route IP allow and deny (`allowedCidrs`, `deniedCidrs`, Caddy `client_ip`), rate limiting (`rateLimitPerMinute`, caddy-ratelimit) and basic auth (`basicAuthUsername`, `basicAuthPassword`, bcrypt-hashed server-side, never returned).
- Each rate-limited rule has its own limiter zone.
- `PATCH .../rules/{id}/enabled`: enable or disable.
- `GET .../rules/{id}/health`: probe the upstream (SSRF policy applied).

Rules take an optional `routing` object. Omitted, routing is unchanged; sent, both fields are replaced.

| Field | Effect |
| --- | --- |
| `pathPrefix` | Serves only this path and below it, such as `/api`. Null or `/` serves the whole host. Letters, digits, `-`, `.`, `_`, `~` and `/`; a trailing slash is dropped. |
| `stripPathPrefix` | Removes the prefix before proxying, so `/api/users` reaches the upstream as `/users`. |

A host's rules match longest prefix first and the whole-host rule last, ignoring case as Caddy does. Host plus prefix is unique, all rules for a host share one TLS setting, and `skipAccessLog` applies to the host.

Rules take an optional `hardening` object. Omitted, nothing changes; sent, every field in it is replaced.

| Field | Effect |
| --- | --- |
| `additionalUpstreams`, `loadBalancePolicy` | Extra upstreams (same SSRF policy and scheme as the primary) and a selection policy: `random`, `random_choose`, `first`, `round_robin`, `least_conn`, `ip_hash`, `uri_hash`, `client_ip_hash`. |
| `upstreamTlsServerName`, `upstreamTlsTrustedCaFile`, `upstreamTlsInsecureSkipVerify` | How an `https://` upstream's certificate is judged; rejected on a plaintext upstream. `serverName` sets the expected SNI and certificate name. `trustedCaFile` is a PEM on the proxy host, emitted as `tls.ca_pool.source`. `insecureSkipVerify` turns verification off and cannot be combined with a trusted CA. |
| `dialTimeoutSeconds`, `upstreamReadTimeoutSeconds`, `upstreamWriteTimeoutSeconds` | Bounds on the upstream leg; Caddy has no read or write timeout by default. |
| `maxRequestBodyBytes` | Caps the request body as it is read; the client gets 413. |
| `enableSecurityHeaders` | On by default: `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`. |
| `hstsMaxAgeDays`, `hstsIncludeSubdomains`, `frameOptions` | Opt-in. HSTS cannot be recalled once a browser has seen it and is suppressed on rules without TLS. `includeSubDomains` on an apex pins every sibling host to HTTPS for the max-age. |
| `healthCheckPath`, `healthCheckIntervalSeconds`, `healthCheckTimeoutSeconds`, `healthCheckExpectStatus` | Caddy active health checks, taking an unhealthy upstream out of rotation. `expectStatus` takes a code or a class digit (`2` = any 2xx); unset, Caddy accepts 200-399. |
| `skipAccessLog` | Keeps the host out of the access log. |

`https://` upstreams: Caddy's `dial` is `host:port` and the transport decides TLS, so the generated config sets the TLS transport with verification on. On Caddy 2.11 and later the transport rewrites `Host` to the upstream's `host:port`.

Concurrent edits: each rule carries a `version`, returned in the body and as an `ETag`. `PUT` requires `If-Match` (428 without, 412 when stale; 409 when a write lands during the save). `PATCH .../enabled` and `DELETE` check it when sent.

```bash
curl -X PUT .../rules/$ID -H 'If-Match: "3"' -H 'Content-Type: application/json' -d @rule.json
```

Certificates

- `GET/POST/DELETE /api/certificates`: ACME-managed by Caddy.
- `GET /api/certificates/{id}/status`: status from the certificate dates.
- `POST /api/certificates/{id}/renew`: marks the certificate issuing and reloads.

Users, keys, audit

- `GET/POST/PUT /api/users`: the last active admin cannot be demoted or deactivated.
- `GET/POST /api/apikeys` (filter by `userId`), `POST /api/apikeys/{id}/{revoke|rotate}`.
- `GET /api/audit`: filter by `actor`, `action`, `targetType`; cursor paging with `beforeId`.

## Deployment

- Secrets: `Security__ApiKeyPepper` (random, base64) through the environment or user-secrets; Production logs a warning when it is unset. ACME email and client-certificate thumbprints the same way.
- TLS: HSTS and HTTPS redirect are on in Production. Terminate TLS (or mTLS) for the control API at the edge, and put it behind an authenticating gateway or set `Security:RequireMutualTls`.
- Behind a proxy: list it in `Security:TrustedProxies` (IP or CIDR) so the rate limiter and audit log see the client IP from `X-Forwarded-For`.
- Containers: the [`Dockerfile`](Dockerfile) bundles the API with Caddy and its plugins; the API runs Caddy as a child process. The database, proxy config and Caddy's certificates live in `/data`, a volume in [`docker-compose.yml`](docker-compose.yml). Environment: `SSLRP_API_KEY_PEPPER`, optional `SSLRP_ACME_EMAIL` and `SSLRP_SPA_ORIGIN`.

## Frontend

The React app calls this API through [`services/apiClient.ts`](../services/apiClient.ts), on its own origin under `/api` by default: serve the UI and route `/api` here from the same edge. For a UI on another origin, build with `VITE_API_BASE_URL` set to the API origin (added to the CSP `connect-src`) and list the UI's origin in `Security:CorsAllowedOrigins` (`SSLRP_SPA_ORIGIN` in docker-compose). Framing protection goes on the server that serves the UI as a header (`Content-Security-Policy: frame-ancestors 'none'` or `X-Frame-Options: DENY`); a `<meta>` policy cannot carry it.
