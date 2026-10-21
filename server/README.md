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

Caddy's config is built from the rules, certificate rows and renewal marks. `ProxyChanges` runs every change to what Caddy holds one at a time: start, stop, reload, rollback, Renew, certificate writes, a rule write's server check, conflict check and save, server and rule deletes, and the certificate monitor's renewal decisions and cleanup. Each reads the rows it decides on inside its turn, and nothing else starts, stops or pushes to Caddy. A Caddy admin call times out after 30 s, so a stalled Caddy holds a turn at most that long. The monitor's TLS readings are taken outside a turn; a reading taken before a renewal was requested does not end it.

## Security model

| Concern | Control |
| --- | --- |
| Authentication | API key in `X-Api-Key` or `Authorization: Bearer`, or a passkey session. Optional mutual TLS pinned to allow-listed client-certificate thumbprints. A request carrying both an API key and a session cookie is refused. |
| Passkey sessions | WebAuthn ([fido2-net-lib](https://github.com/passwordless-lib/fido2-net-lib)) with discoverable credentials and user verification required. Sign-in sets an HttpOnly, Secure, SameSite=Strict `__Host-sslrp-session` cookie; the database holds the secret's SHA-256 only. Every request rechecks the session: unexpired, not revoked, the user active and in the role the session started with. Sign-out, a role change, deactivation or removing the passkey ends it. Unsafe methods need an `Origin` listed in `Passkeys:Origins` and the session's CSRF token (an HMAC of the secret) in `X-CSRF-Token`. |
| API-key storage | PBKDF2-SHA256 hash, per-key salt and server pepper only. Plaintext shown once at creation. Constant-time verification. |
| Authorization | Deny-by-default. Every endpoint requires a permission; roles map to permissions server-side (`Core/Security/Permissions.cs`). An API key's scopes narrow its owner's current role, checked on every request. |
| SSRF | Every upstream is validated server-side (`ProxyTargetValidator`): http(s) only, cloud-metadata and link-local blocked, private and loopback gated by policy. |
| Transport | HSTS and HTTPS redirect in Production; security headers and a JSON-only CSP on every response. |
| Abuse | Per-IP fixed-window rate limit, `Security:RequestsPerMinute` (100). Anonymous passkey ceremonies have their own per-IP limits; at most 1000 are pending, each for 2 minutes. |
| Audit | Append-only log of every control and mutation action (actor, action, target, source IP). |
| Secrets | Pepper, Cloudflare token, alert target URLs and tokens, client-certificate thumbprints and ACME email from configuration, user-secrets or environment. The Cloudflare token stays on the server: the UI asks only which validation methods are available. Configured secret values are masked in Caddy's forwarded output, `/load` errors and validation issues, and a rollback config holding one is refused. Alert URLs and tokens are never returned by the API or logged. |
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
| `Security:RequestsPerMinute` | Requests one client IP may make in a minute before it gets 429 (100). |
| `Proxy:CaddyPath`, `Proxy:AdminEndpoint` | Caddy binary and its admin endpoint (loopback). |
| `Proxy:AcmeContactEmail`, `Proxy:UseAcmeStaging` | ACME account email and Let's Encrypt staging. |
| `Proxy:CertificateIssuer` | `acme` (default: Let's Encrypt with `AcmeContactEmail` or `UseAcmeStaging`, Caddy's default issuers with neither) or `internal` (Caddy's own CA; its root is not installed in the host trust store). |
| `Proxy:CloudflareApiToken` | Cloudflare API token for DNS-01, with Zone:Read and DNS:Edit on the zones. Caddy reads it from its environment; configs hold `{env.SSLRP_CLOUDFLARE_API_TOKEN}`. A value in a shape Cloudflare does not issue keeps DNS-01 names out of the config, and their rows show why. |
| `Proxy:DnsChallengeResolvers` | Resolvers Caddy asks to see a DNS-01 record, comma-separated `host:port`. Empty uses the system's. |
| `Proxy:CertificateCheckSeconds` | Seconds between reads of the certificate Caddy serves for each name (300; 0 off, which also turns Renew off). |
| `Proxy:RenewCheckSeconds` | Caddy's certificate maintenance interval (60). |
| `Proxy:RenewMinimumAgeMinutes` (60), `Proxy:RenewTimeoutMinutes` (10) | Wait between forced renewals of one name, and how long one may take before it is recorded as failed. |
| `Proxy:HttpPort` (80), `Proxy:HttpsPort` (443) | Caddy's listeners. TLS rules are served on the HTTPS port only. The HTTP port serves plaintext rules, redirects TLS hosts and answers ACME challenges. Redirects name the standard port, so a non-default `HttpsPort` needs 443 forwarded to it. |
| `Proxy:ServerHealthIntervalSeconds` | Seconds between background probes of every enabled rule's upstreams (60; 0 off). A server is `Active` (every upstream answered), `Error` (one or more did not), `Inactive` (no enabled rule) or `Unknown` (not probed). A successful write under `/api/servers` probes again at once. Probes apply the SSRF policy. |
| `Proxy:TrafficSampleSeconds` | Seconds between dashboard traffic samples (60; 0 off). Each sample is the change in Caddy's metrics since the last; samples are kept 25 hours. |
| `Proxy:AllowLoopbackUpstreams`, `Proxy:AllowPrivateUpstreams` | SSRF policy. |
| `Proxy:TrustedProxyCidrs` | CIDRs of L7 proxies in front of Caddy. Empty (default) ignores `X-Forwarded-For`, which keeps the per-route IP lists unspoofable when Caddy faces clients directly. |
| `Proxy:TlsMinVersion`, `Proxy:TlsCipherSuites` | Data-plane TLS floor: `tls1.2` or `tls1.3`; any other value is treated as `tls1.2`. A cipher name Caddy does not know fails the whole config load, so run `POST /api/proxy/validate` after changing the list. |
| `Proxy:ReadHeaderTimeoutSeconds`, `Proxy:ReadTimeoutSeconds`, `Proxy:WriteTimeoutSeconds`, `Proxy:IdleTimeoutSeconds` | Data-plane timeouts; 0 keeps Caddy's default, which for read and write is none. |
| `Proxy:AccessLogPath`, `AccessLogRollSizeMb`, `AccessLogKeepDays` | Data-plane access log as JSON lines. Off by default: records carry client IPs and URLs. |
| `Alerts:Targets` | Where alerts go: each has `Name`, `Kind` (`webhook` or `ntfy`), `Url`, optional `Token` and `Events` (empty sends every type). URL and token are secrets; set them through the environment (`Alerts__Targets__0__Url`). A target that fails validation is listed with the reason and not sent to. |
| `Alerts:ServerDownChecks` | Consecutive `Error` readings before a server alerts as down (2). |
| `Passkeys:RelyingPartyId` | The host the UI is served from, such as `proxy.example.com`. Empty turns passkey sign-in off. |
| `Passkeys:Origins` | Exact origins the UI is served from, such as `https://proxy.example.com`. Passkey answers must come from one, and unsafe requests on a session need an `Origin` in the list. Blank entries are ignored. |
| `Passkeys:RelyingPartyName` | Name the browser shows (`SSLReverseProxy`). |
| `Passkeys:SessionHours` | Session lifetime (12; 1 to 168). |
| `Passkeys:OptionsPerMinute` (10), `Passkeys:SignInsPerMinute` (5) | Anonymous sign-in ceremonies and sign-in attempts one client IP may start per minute. |
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

The image and CI build Caddy with [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) and [caddy-dns/cloudflare](https://github.com/caddy-dns/cloudflare) at the versions pinned by `CADDY_VERSION`, `CADDY_RATELIMIT` and `CADDY_CLOUDFLARE` in the [`Dockerfile`](Dockerfile). The same build locally, with Go:

```bash
go run github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.7 build v2.11.7 --with github.com/mholt/caddy-ratelimit@5625512f24f6f59d6f64fb3aafe5eecff0b286db --with github.com/caddy-dns/cloudflare@v0.2.4 --output ~/.sslrp/caddy/caddy
```

Caddy 2.7 or later: the IP lists emit the `client_ip` matcher. Rate-limited rules need caddy-ratelimit and DNS-01 names need caddy-dns/cloudflare; a stock Caddy rejects either config. Basic auth is native.

## Endpoints

All require authentication except `/api/health`, `/api/ready`, `/api/bootstrap-key` and the passkey sign-in endpoints marked anonymous.

Meta

- `GET /api/health`: anonymous liveness. `GET /api/ready`: anonymous readiness (database and proxy).
- `GET /api/bootstrap-key`: one-time first-run key claim (Development and loopback only; 404 otherwise).
- `GET /api/whoami`: current principal and its effective permissions (the role's, narrowed to a key's scopes); `key` holds the signing key's id, name, expiry and scopes.
- `GET /api/events`: Server-Sent Events, each `{type, message, at, actor}`. `server.health` is published when a server's status changes, `certificate.status` when a certificate's does, `certificate.renewed` or `certificate.renew_failed` when a forced renewal ends, and `certificate.renew_cancelled` when a rollback stops one. Headers go out once the subscriber is registered, so no event published after the client has them is missed.

Passkeys

Off until `Passkeys:RelyingPartyId` and `Passkeys:Origins` are set. A ceremony's options come with a `handle` that its answer sends back; a handle works once, within 2 minutes, for the ceremony and user it was issued to.

| Endpoint | |
| --- | --- |
| `GET /api/auth/methods` | Anonymous. `{passkeys}`: whether passkey sign-in is configured. |
| `POST /api/auth/passkey/options` | Anonymous. `{handle, options}` for `navigator.credentials.get`. |
| `POST /api/auth/passkey` | Anonymous. `{handle, response}` verifies the assertion, sets the session cookie and returns `{csrfToken, expiresAt, user}`. Any failure is 401, audited with its reason. |
| `GET /api/auth/session` | The session's `{csrfToken, expiresAt}`, so a reloaded page recovers its token. 404 for an API key. |
| `POST /api/auth/logout` | Anonymous. Revokes a live session and clears the cookie. The UI signs out at once, then reads the session's CSRF token and calls this whichever credential it held, and says so on the sign-in view when the server does not confirm. A passkey sign-in first ends a session still on the cookie the same way. The UI runs sign-ins and sign-outs one at a time. |
| `GET /api/passkeys` | The caller's passkeys: `id`, `name`, `createdAt`, `lastUsedAt`, `backedUp`. |
| `POST /api/passkeys/options` | `{handle, options}` for `navigator.credentials.create`, excluding the caller's passkeys. 409 at 10 per user. |
| `POST /api/passkeys` | `{handle, name, response}` registers the passkey to the caller. 409 at 10 per user, counted in the transaction that adds it. |
| `DELETE /api/passkeys/{id}` | Removes one of the caller's passkeys and ends the sessions it started. |

Control service

- `GET /api/proxy/status`, `POST /api/proxy/{start|stop|reload}`.
- `POST /api/proxy/validate`: dry-run validation of the rule set (structural always; Caddy's when present).
- `GET /api/proxy/config`: the generated config, not applied.
- `GET /api/proxy/metrics`: scraped runtime metrics.
- `GET /api/proxy/traffic`: the last 24 hours from stored samples: requests, bytes in and out, status classes, average response time and time to first byte, median, P90 and P95 from Caddy's duration histogram, requests in flight at the latest sample, requests per hour. Answers from the database.
- `GET /api/proxy/snapshots`, `POST /api/proxy/rollback`: config history and rollback. A rollback ends any renewal under way, and its config stands until a start, reload, Renew or certificate write pushes the rules again.

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

A host's rules match longest prefix first and the whole-host rule last, ignoring case as Caddy does. Host plus prefix is unique among enabled rules, all enabled rules for a host share one TLS setting, and `skipAccessLog` applies to the host. A create, update or enable that breaks either answers 400, and apply refuses a set that breaks either, running or stopped.

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

Each enabled TLS rule's host has a row, which the certificate monitor adds and removes with the rules. A manual row names a host or a wildcard (`*.example.com`) that Caddy obtains with no rule naming it, served by SNI on the HTTPS port. Every `CertificateCheckSeconds` the monitor reads the certificate Caddy serves for each name with a TLS handshake on loopback (a wildcard as `sslrp-check.<base>`) and takes obtain errors from Caddy's log.

| Endpoint | |
| --- | --- |
| `GET /api/certificates` | Rows with status from the served certificate's dates: `Valid`, `Expiring` (the last third of its lifetime, at most 30 days), `Expired`, `Issuing` (none served yet), `Failed` (Caddy logged an error and none is served) or `Unknown` (not read yet). `lastError` is Caddy's last error for the name, redacted. |
| `GET /api/certificates/challenges` | `Http` and `DnsCloudflare`, each with whether it can be used now, why not, and whether it validates a wildcard. |
| `POST /api/certificates` | `{domain, challenge}` adds a manual row. A wildcard needs `DnsCloudflare` unless `CertificateIssuer` is `internal`, and `DnsCloudflare` needs a usable token. 409 when the name has a row. |
| `PUT /api/certificates/{id}` | `{challenge}` changes how the name is validated, for rule rows too. |
| `DELETE /api/certificates/{id}` | Manual rows only; a rule row goes with its rule. |
| `POST /api/certificates/{id}/renew` | Forces a reissue. The config marks the name due for renewal, Caddy replaces the certificate in place while the old one keeps serving, and the monitor drops the mark once a new serial is served or after `RenewTimeoutMinutes`. 409 while the proxy is stopped, the monitor is off, a renewal is under way, no certificate is served, or within `RenewMinimumAgeMinutes` of the last request. Snapshots are taken without the mark, so a rollback does not renew again. |
| `GET /api/certificates/{id}/status` | Status and days remaining. |

Alerts

The server, certificate and API key monitors raise alerts; each goes to every usable target subscribed to its type. Up to 100 wait for delivery; when the queue is full the oldest is dropped and logged. A send gets three tries at most, 10 s each, 2 s then 10 s apart, retried on network errors, timeouts, 408, 429 and 5xx. Requests do not follow redirects.

| Type | Severity | Raised when |
| --- | --- | --- |
| `server.down` | critical | A server reads `Error` on `Alerts:ServerDownChecks` checks in a row. |
| `server.up` | info | A server that alerted down reads `Active`. An `Inactive` or `Unknown` reading in between leaves it down. |
| `certificate.expiring` | warning | A fresh reading is `Expiring`; once per expiry date. |
| `certificate.expired` | critical | A fresh reading is `Expired`; once per expiry date. |
| `certificate.failed` | warning | A fresh reading is `Failed`; once until the name reads `Valid`. |
| `api_key.expiring` | warning, critical at 1 day | An unrevoked key has 7 days or fewer left, then 1 day or fewer; once per threshold, checked hourly. Names the key and owner, never the token. |

Server down state is kept in memory, so after a restart a server still down alerts again. Certificate and API key alert state is stored on the row.

| Kind | Request |
| --- | --- |
| `webhook` | `POST` to `Url` with `{type, severity, subject, title, message, at}`. |
| `ntfy` | `POST` to the ntfy server root with `{topic, title, message, priority, tags}`; the topic is the URL's last segment (`https://ntfy.sh/<topic>`). Priority 5 critical, 4 warning, 3 info. |

`Token` goes out as `Authorization: Bearer`. A Home Assistant automation for a `webhook` target with `Url` `http://homeassistant.local:8123/api/webhook/<id>`:

```yaml
triggers:
  - trigger: webhook
    webhook_id: <id>
    allowed_methods: [POST]
    local_only: true
actions:
  - action: notify.notify
    data:
      title: "{{ trigger.json.title }}"
      message: "{{ trigger.json.message }}"
```

| Endpoint | |
| --- | --- |
| `GET /api/alerts` | Targets with name, kind, events and any validation problem, and the subscribable types. |
| `POST /api/alerts/test` | `{target}` sends a test alert to that target, or to every usable target when omitted, and returns each delivery: `delivered`, `status`, `error`, `attempts`. Audited. |

Both need `AlertManage` (Admin).

Users, keys, audit

- `GET/POST/PUT /api/users`: the last active admin cannot be demoted or deactivated.
- API keys, below.
- `GET /api/audit`: filter by `actor`, `action`, `targetType`; cursor paging with `beforeId`.

API keys

Token `srp.<prefix>.<secret>`, sent as `X-Api-Key` or `Authorization: Bearer`. A key lasts 1 to 365 days. Its scopes are permission names held within the owner's current role: demoting the owner narrows the key at once. Null scopes follow the role. Scopes and expiry are fixed at issue. All endpoints need `ApiKeyManage` (Admin).

| Endpoint | |
| --- | --- |
| `GET /api/apikeys` | Keys, newest first, with owner, scopes, expiry, last use and revocation. `userId` filters. |
| `GET /api/apikeys/options` | Lifetime presets in days, the default and maximum, scope presets, every permission, and each role's permissions. |
| `POST /api/apikeys` | `{userId, name, lifetimeDays \| expiresAt, scopes}` returns the token once. 400 for a lifetime outside 1 to 365 days, an unknown or empty scope list, or a scope the owner's role lacks; 403 for a scope the caller lacks, or null scopes from a scoped key. |
| `POST /api/apikeys/{id}/rotate` | Issues a new key for the same owner and name and revokes the old one in one transaction. A body chooses lifetime and scopes as on create; no body keeps the old ones (a non-expiring key needs a body). 409 for a revoked key. |
| `POST /api/apikeys/{id}/revoke` | Ends the key at once. |

| Preset | Scopes |
| --- | --- |
| Read only | `ServerRead`, `CertRead` |
| Home Assistant | `ServerRead`, `CertRead`, `ProxyReload`, `CertRenew` |
| Rules editor | `ServerRead`, `RuleWrite`, `ProxyReload` |
| Full access | null: the owner's role |

| Permission | Allows | Roles |
| --- | --- | --- |
| `ServerRead` | Servers, rules, status, metrics, traffic, events | Viewer, Editor, Admin |
| `CertRead` | Certificates and challenges | Viewer, Editor, Admin |
| `AuditRead` | Audit log | Viewer, Editor, Admin |
| `ServerWrite` | Add and delete servers | Editor, Admin |
| `RuleWrite` | Add, change and delete rules | Editor, Admin |
| `ProxyReload` | Config preview, validate, reload | Editor, Admin |
| `ProxyControl` | Start, stop, snapshots, rollback | Editor, Admin |
| `CertRenew` | Force a renewal | Editor, Admin |
| `CertWrite` | Add, change and delete certificate rows | Editor, Admin |
| `UserWrite` | Users | Admin |
| `ApiKeyManage` | API keys | Admin |
| `AlertManage` | Alert targets and test alerts | Admin |

A scoped key cannot manage passkeys: a passkey signs in with the whole role. The bootstrap key follows the admin role and does not expire.

## Deployment

- Secrets: `Security__ApiKeyPepper` (random, base64) through the environment or user-secrets; Production logs a warning when it is unset. ACME email and client-certificate thumbprints the same way.
- TLS: HSTS and HTTPS redirect are on in Production. Terminate TLS (or mTLS) for the control API at the edge, and put it behind an authenticating gateway or set `Security:RequireMutualTls`.
- Behind a proxy: list it in `Security:TrustedProxies` (IP or CIDR) so the rate limiter and audit log see the client IP from `X-Forwarded-For`.
- Containers: the [`Dockerfile`](Dockerfile) bundles the API with Caddy and its plugins; the API runs Caddy as a child process. The database, proxy config and Caddy's certificates live in `/data`, a volume in [`docker-compose.yml`](docker-compose.yml). Environment: `SSLRP_API_KEY_PEPPER`, optional `SSLRP_ACME_EMAIL`, `SSLRP_CLOUDFLARE_API_TOKEN`, `SSLRP_SPA_ORIGIN`, and `SSLRP_PASSKEY_RP_ID` with `SSLRP_PASSKEY_ORIGIN` for passkey sign-in. Alert targets go in the service's environment as `Alerts__Targets__<n>__<Key>`.

## Frontend

The React app calls this API through [`services/apiClient.ts`](../services/apiClient.ts), on its own origin under `/api` by default: serve the UI and route `/api` here from the same edge. For a UI on another origin, build with `VITE_API_BASE_URL` set to the API origin (added to the CSP `connect-src`) and list the UI's origin in `Security:CorsAllowedOrigins` (`SSLRP_SPA_ORIGIN` in docker-compose). Passkey sessions need the same-origin layout: the browser sends the cookie only to the page's own origin, so a UI on another origin offers API keys only. Framing protection goes on the server that serves the UI as a header (`Content-Security-Policy: frame-ancestors 'none'` or `X-Frame-Options: DENY`); a `<meta>` policy cannot carry it.
