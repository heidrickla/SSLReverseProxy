# SSLReverseProxy

**A security-first control plane for a [Caddy](https://caddyserver.com) reverse
proxy.** It pairs a React admin dashboard with an ASP.NET Core (.NET 10) service
that starts, stops, and configures the proxy — managing servers, proxy rules, and
ACME-issued TLS certificates. Security is the design center rather than an
afterthought: the API authenticates with hashed API keys or mutual TLS, enforces
deny-by-default role-based access on every action, re-validates every proxy
upstream server-side to block SSRF, supports per-route IP allow/deny, and records
an append-only audit trail with config snapshots and one-call rollback.

## What's here

- **`/` (React + TypeScript + Vite)** — the admin UI: dashboard, servers, proxy
  rules, SSL certificates, users, and audit log.
- **[`server/`](server/README.md) (ASP.NET Core / .NET 10)** — the control plane
  that owns authentication, authorization, secret custody, and the proxy
  lifecycle. See its README for the full endpoint and security reference.
- **[SECURITY.md](SECURITY.md)** — the security model and threat boundaries.

> **Status:** the backend control plane is implemented and tested, and the React
> app talks to it via [`services/apiClient.ts`](services/apiClient.ts) —
> sign in with an API key (auto-claimed on a first dev run).

## Run Locally

**Frontend** (prerequisite: Node.js)

1. `npm install`
2. `npm run dev` — or `npm run build && npm run preview` for a production build
   (which injects the Content-Security-Policy).

**Backend** (prerequisite: .NET 10 SDK)

```bash
cd server
dotnet test          # 55 tests
dotnet run --project src/SslReverseProxy.Api
```

The first backend run seeds a bootstrap admin and prints a one-time API key to
the log. In development you don't need to copy it: the UI claims it
automatically on first load via `GET /api/bootstrap-key` (Development +
loopback only, single claim) and signs you in. Full details in
[server/README.md](server/README.md).
