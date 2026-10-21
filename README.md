# SSLReverseProxy

A control plane for a [Caddy](https://caddyserver.com) reverse proxy: a React admin dashboard over an ASP.NET Core (.NET 10) service that starts, stops and configures the proxy, its servers, host and path routes, and ACME certificates. It reads the certificate Caddy serves for each name, forces renewals, obtains wildcards over Cloudflare DNS-01 with a server-held token, and sends server and certificate alerts to a webhook (such as Home Assistant's) or ntfy. The API authenticates with passkeys (cookie sessions with CSRF tokens), hashed API keys scoped to chosen permissions and expiring within a year, or mutual TLS, enforces deny-by-default role-based access on every action, re-validates every upstream server-side against SSRF, supports per-route IP allow and deny lists, puts a rule behind Authelia, Authentik or oauth2-proxy forward auth or a Cloudflare Access token check, shows a redacted diff against Caddy's running config before a Reload or rollback and refuses the push if either side moved since, exports servers, rules and certificate definitions to a file and imports one after a dry run of the exact changes, lists each rule's recent requests without query strings or headers, and keeps an append-only audit trail with config snapshots and one-call rollback.

## Layout

| Path | Contents |
| --- | --- |
| `/` (React, TypeScript, Vite) | Admin UI: dashboard, servers, proxy rules, SSL certificates, users, API keys, audit log. Talks to the API through [`services/apiClient.ts`](services/apiClient.ts). |
| [`server/`](server/README.md) (ASP.NET Core, .NET 10) | Control plane: authentication, authorization, secret custody, proxy lifecycle. Endpoint and configuration reference in its README. |
| [SECURITY.md](SECURITY.md) | Security model and trust boundaries. |

## Screenshots

From the control plane's Development demo data (`Seed:Demo`): example domains and documentation IP addresses. Dashboard traffic is what Caddy served to test requests during the capture.

![Dashboard](docs/screenshots/dashboard.png)

| Proxy control | Servers |
| --- | --- |
| ![Proxy control](docs/screenshots/proxy-control.png) | ![Servers](docs/screenshots/servers.png) |

| Proxy rules | SSL certificates |
| --- | --- |
| ![Proxy rules](docs/screenshots/proxy-rules.png) | ![SSL certificates](docs/screenshots/certificates.png) |

| Users | Audit log |
| --- | --- |
| ![Users](docs/screenshots/users.png) | ![Audit log](docs/screenshots/audit-log.png) |

## Run locally

Frontend (Bun 1.4, Node.js 22.12 or later):

| Command | Does |
| --- | --- |
| `bun install` | Installs from `bun.lock`. |
| `bun run dev` | Dev server. `/api` is forwarded to `http://localhost:5195`; `SSLRP_API_TARGET` changes the target. |
| `bun run build && bun run preview` | Production build with the injected Content-Security-Policy, same `/api` forwarding. |
| `bun run test` | Vitest suite. |
| `bun run e2e` | Playwright tests (below). |
| `bun run screenshots` | Retakes `docs/screenshots` from the demo data, with proxy traffic when `SSLRP_TEST_CADDY` is set. |

`bun run e2e` starts the control plane with demo data on a new database, builds and previews the UI, and checks every view in both themes, server statuses and live status updates. With `SSLRP_TEST_CADDY` naming a Caddy built with the plugins in [server/README.md](server/README.md#caddy), it also starts the proxy, checks plaintext and TLS hosts and a stripped path route on its HTTP port, checks the dashboard shows the traffic it served, reads certificates from Caddy and renews a wildcard through the UI. A local listener checks the Settings test alert, and a virtual authenticator registers a passkey and signs in with it. It needs the .NET 10 SDK and free ports 5195, 4173 and 8790, plus 8780, 8743 and 2019 for Caddy. Install the browser once with `bunx playwright install chromium`.

Backend (.NET 10 SDK):

```bash
cd server
dotnet test
dotnet run --project src/SslReverseProxy.Api
```

The first backend run seeds a bootstrap admin and prints a one-time API key to the log. In Development the UI claims it on first load through `GET /api/bootstrap-key` (loopback only, single claim) and signs in. `Seed__Demo=true` fills a new Development database with sample servers, rules, certificates, users and audit entries. Details in [server/README.md](server/README.md).
