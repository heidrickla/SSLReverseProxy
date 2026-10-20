import fs from 'node:fs';
import { request, type Page } from '@playwright/test';
import { e2eDatabase } from '../playwright.config';

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
  { nav: 'Audit log', heading: 'Audit log' },
  { nav: 'Settings', heading: 'Settings' },
] as const;

export async function openView(page: Page, nav: string, heading: string): Promise<void> {
  await page.locator('aside nav').getByRole('button', { name: nav, exact: true }).click();
  await page.locator('main h2', { hasText: heading }).first().waitFor();
}
