import os from 'node:os';
import path from 'node:path';
import { defineConfig, devices } from '@playwright/test';

// The browser tests run the production build, with its CSP, against a real
// Development control plane seeded with demo data (Seed:Demo). Each run gets a
// new database, so the one-time bootstrap key is there to claim. Workers
// inherit SSLRP_E2E_RUN from the main process, so all of them agree on the path.
process.env.SSLRP_E2E_RUN ??= String(Date.now());
export const e2eDatabase = path.join(os.tmpdir(), `sslrp-e2e-${process.env.SSLRP_E2E_RUN}.db`);

// The proxy runs only when SSLRP_TEST_CADDY names a Caddy binary with the caddy-ratelimit plugin.
// It listens on unprivileged ports and issues from its own CA, with its config and data under the run's temp directory.
export const caddyPath = process.env.SSLRP_TEST_CADDY || undefined;
export const proxyHttpPort = 8780;
const proxyHttpsPort = 8743;
const proxyDir = path.join(os.tmpdir(), `sslrp-e2e-${process.env.SSLRP_E2E_RUN}-proxy`);

export default defineConfig({
  testDir: 'e2e',
  workers: 1,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: 'http://localhost:4173',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 1000 } } },
  ],
  webServer: [
    {
      command: 'dotnet run --project server/src/SslReverseProxy.Api --launch-profile http',
      url: 'http://localhost:5195/api/health',
      timeout: 240_000,
      env: {
        ConnectionStrings__AppDb: `Data Source=${e2eDatabase}`,
        Seed__Demo: 'true',
        ...(caddyPath ? { Proxy__CaddyPath: caddyPath } : {}),
        Proxy__HttpPort: String(proxyHttpPort),
        Proxy__HttpsPort: String(proxyHttpsPort),
        Proxy__CertificateIssuer: 'internal',
        Proxy__TrafficSampleSeconds: '2',
        Proxy__ConfigDirectory: path.join(proxyDir, 'config'),
        XDG_DATA_HOME: path.join(proxyDir, 'data'),
      },
    },
    {
      // No VITE_API_BASE_URL: the build calls /api on its own origin and preview proxies it to :5195.
      command: 'bun run build && bun run preview --port 4173 --strictPort',
      url: 'http://localhost:4173',
      timeout: 120_000,
      env: { VITE_API_BASE_URL: '' },
    },
  ],
});
