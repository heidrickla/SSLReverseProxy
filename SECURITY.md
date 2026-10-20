# Security model

The React SPA reads and writes everything through the control plane in [`server/`](server/README.md), via [`services/apiClient.ts`](services/apiClient.ts). Anything in the browser is under the user's control, so the client is never a security boundary.

## Client

| Measure | Detail |
| --- | --- |
| No secrets in the bundle | Nothing is injected through Vite `define`, which substitutes text literally into the public JS. |
| No third-party scripts | React, charts and Tailwind are bundled from npm. A production Content-Security-Policy is injected at build time (`vite.config.ts`, `config/csp.ts`). |
| Input checks | Proxy targets are restricted to `http(s)` URLs and reject cloud-metadata and link-local hosts; domains and server IPs are format-checked (`utils/validation.ts`). These advise; the server decides. |
| Role gating | `utils/permissions.ts` hides actions a role cannot perform, as a usability aid. |
| Credentials in the browser | An API key is held in sessionStorage and sent without cookies. A passkey session is an HttpOnly cookie script cannot read; its CSRF token is held in memory and recovered from `/api/auth/session` after a reload. |
| Theme CSS | Only `--color-*` keys with `#hex` values from stored themes are applied (`contexts/ThemeContext.tsx`). |
| Uploads | Avatars and logos reject SVG and oversized files and are re-encoded through a canvas (`utils/imageFile.ts`). |

## Server

| Concern | Control |
| --- | --- |
| Authentication | API keys (`X-Api-Key` or Bearer) stored as PBKDF2-SHA256 hashes with a per-key salt and a server pepper, verified in constant time, revocable. Passkeys (WebAuthn, user verification required) start cookie sessions stored as SHA-256 hashes, rechecked on every request, with an Origin check and a CSRF token on unsafe methods. Optional mutual TLS pinned to client-certificate thumbprints. |
| Authorization | Deny-by-default policies map roles to permissions on every endpoint (`server/src/SslReverseProxy.Core/Security/Permissions.cs`). |
| Secret custody | Certificates are issued and renewed by Caddy (ACME). The pepper, the Cloudflare token, alert target URLs and tokens, and TLS material come from configuration, user-secrets or the environment, never source, and the API never returns them. The browser stores none of them. |
| SSRF | `ProxyTargetValidator` re-validates every upstream before config reaches the proxy: `http(s)` only, cloud-metadata and link-local blocked, private and loopback gated by policy. |
| Headers | `SecurityHeadersMiddleware` sends a JSON-only CSP and hardening headers on every response; HSTS and HTTPS redirect in Production. |
