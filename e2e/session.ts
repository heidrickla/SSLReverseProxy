import fs from 'node:fs';
import http from 'node:http';
import { request, type APIRequestContext, type Page } from '@playwright/test';
import { e2eDatabase, proxyHttpPort } from '../playwright.config';

const keyFile = `${e2eDatabase}.key`;

// The bootstrap key answers once per database, so it is claimed by the first
// test that needs it and kept beside the run's throwaway database for the rest.
export async function adminKey(): Promise<string> {
  if (fs.existsSync(keyFile)) return fs.readFileSync(keyFile, 'utf8');
  const api = await request.newContext({ baseURL: 'http://localhost:4173' });
  const res = await api.get('/api/bootstrap-key');
  if (!res.ok()) throw new Error(`Bootstrap key claim answered ${res.status()}`);
  const { apiKey } = await res.json();
  await api.dispose();
  fs.writeFileSync(keyFile, apiKey);
  return apiKey;
}

/** Signs the page in with the run's admin key and picks the theme, before any page script runs. */
export async function signIn(page: Page, mode: 'dark' | 'light'): Promise<void> {
  const key = await adminKey();
  await page.addInitScript(([k, m]) => {
    sessionStorage.setItem('sslrp-api-key', k);
    localStorage.setItem('proxyadmin-mode', m);
    localStorage.setItem('sidebarCollapsed', 'false');
  }, [key, mode] as const);
  // Avatars come from api.dicebear.com; a stand-in keeps the run off the network.
  await page.route('https://api.dicebear.com/**', route =>
    route.fulfill({ contentType: 'image/svg+xml', body: '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>' }));
}

export const views = [
  { nav: 'Dashboard', heading: 'Key metrics' },
  { nav: 'Proxy', heading: 'Proxy control' },
  { nav: 'Servers', heading: 'Servers' },
  { nav: 'SSL', heading: 'SSL certificates' },
  { nav: 'Users', heading: 'Users' },
  { nav: 'API keys', heading: 'API keys' },
  { nav: 'Audit log', heading: 'Audit log' },
  { nav: 'Settings', heading: 'Settings' },
] as const;

export async function openView(page: Page, nav: string, heading: string): Promise<void> {
  await page.locator('aside nav').getByRole('button', { name: nav, exact: true }).click();
  await page.locator('main h2', { hasText: heading }).first().waitFor();
}

/** An API client signed in with the run's admin key. */
export async function controlPlane(): Promise<APIRequestContext> {
  return request.newContext({
    baseURL: 'http://localhost:4173',
    extraHTTPHeaders: { 'X-Api-Key': await adminKey() },
  });
}

/** One request to the proxy's HTTP port, as a client asking for `host`. */
export function proxyGet(host: string, path = '/'): Promise<{ status: number; location?: string }> {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port: proxyHttpPort, path, headers: { Host: host } }, res => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode ?? 0, location: res.headers.location }));
    });
    req.setTimeout(5000, () => req.destroy(new Error(`proxy request for ${host} timed out`)));
    req.on('error', reject);
  });
}

/**
 * Sends demo traffic through the running proxy: `plain` requests to the
 * plaintext host, which are proxied, and `redirected` to a TLS host, which
 * the HTTP port answers with a redirect.
 */
export async function sendDemoTraffic(plain: number, redirected: number) {
  const results = [];
  for (let i = 0; i < plain; i++) results.push(await proxyGet('status.example.com', '/api/health'));
  for (let i = 0; i < redirected; i++) results.push(await proxyGet('app.example.com', '/'));
  return results;
}
