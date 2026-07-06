# Security Model

This app is currently a **browser-only React SPA on mock data**. Anything that
runs in the browser is fully controllable by the user, so the client can never
be a security boundary. This document records what has been hardened in the
client and — more importantly — what the backend **must** enforce before the app
handles real servers, certificates, or credentials.

## Hardened in the client

- **No secrets baked into the bundle.** The old `GEMINI_API_KEY` injection via
  Vite `define` was removed; `define` performs literal text substitution and
  would have shipped any key in the public JS.
- **No third-party CDN scripts.** React, charts, and Tailwind are bundled from
  npm instead of `aistudiocdn.com` / `cdn.tailwindcss.com`. A production
  Content-Security-Policy is injected at build time (see `vite.config.ts`).
- **Input validation.** Proxy targets are restricted to `http(s)` URLs and
  reject cloud-metadata/link-local hosts; domains and server IPs are format-
  checked (`utils/validation.ts`).
- **UI role gating.** `utils/permissions.ts` hides actions a role can't perform.
  This is a usability aid and defense-in-depth only.
- **Theme CSS injection blocked.** Only `--color-*` keys with `#hex` values from
  stored themes are applied (`contexts/ThemeContext.tsx`).
- **Upload sanitization.** Avatars/logos reject SVG and oversized files and are
  re-encoded through a canvas (`utils/imageFile.ts`).

## The backend enforcement (now implemented in `server/`)

The C# control plane under [`server/`](server/README.md) implements the
server-side boundary the client checks only advise. Status of each item:

1. **Authentication — implemented.** API-key auth (`X-Api-Key`) with optional
   mutual TLS; keys stored as PBKDF2 hashes, verified in constant time, and
   revocable. (No interactive browser login this pass — authentication is by
   scoped key/cert per the chosen design.)
2. **Authorization on every action — implemented.** Deny-by-default policies map
   roles → permissions and are enforced on every endpoint server-side
   (`server/src/SslReverseProxy.Core/Security/Permissions.cs`).
3. **Secret custody off the client — implemented.** Certificates are issued and
   renewed by the proxy engine (Caddy ACME); the pepper and any TLS material come
   from configuration/user-secrets, never source. The legacy Cloudflare-token
   flow in the SPA remains client-side and should be retired in favor of the
   server path.
4. **SSRF validation on proxy targets — implemented.** `ProxyTargetValidator`
   re-validates every upstream server-side (http(s) only; cloud-metadata and
   link-local blocked; private/loopback gated by policy) before config is
   written to the proxy.
5. **CSP + security headers over HTTP — implemented.** `SecurityHeadersMiddleware`
   emits a strict JSON-only CSP and hardening headers on every response; HSTS +
   HTTPS redirect are enabled in production.

Remaining wiring: point the React app's data layer at the API via
[`services/apiClient.ts`](services/apiClient.ts) and retire the mock hooks.
