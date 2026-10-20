import os from 'node:os';
import path from 'node:path';
import { defineConfig, devices } from '@playwright/test';

// The browser tests run the production build, with its CSP, against a real
// Development control plane seeded with demo data (Seed:Demo). Each run gets a
// new database, so the one-time bootstrap key is there to claim. Workers
// inherit SSLRP_E2E_RUN from the main process, so all of them agree on the path.
process.env.SSLRP_E2E_RUN ??= String(Date.now());
export const e2eDatabase = path.join(os.tmpdir(), `sslrp-e2e-${process.env.SSLRP_E2E_RUN}.db`);

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
