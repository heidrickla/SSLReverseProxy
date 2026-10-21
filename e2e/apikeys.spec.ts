import { expect, request, test, type Page } from '@playwright/test';
import { openView, signIn } from './session';

const asKey = (token: string) =>
  request.newContext({ baseURL: 'http://localhost:4173', extraHTTPHeaders: { 'X-Api-Key': token } });

async function issued(page: Page): Promise<string> {
  const token = await page.getByLabel('Issued key', { exact: true }).inputValue();
  expect(token).toMatch(/^srp\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  await page.getByRole('button', { name: 'Done' }).click();
  return token;
}

test.describe.serial('API keys', () => {
  let token = '';
  const name = `Home Assistant ${Date.now()}`;

  test('a Home Assistant key is issued with a preset and a lifetime, one click each', async ({ page }) => {
    await signIn(page, 'dark');
    await page.goto('/');
    await openView(page, 'API keys', 'API keys');

    await page.getByRole('button', { name: 'New key' }).first().click();
    const dialog = page.getByRole('dialog', { name: 'New API key' });
    await dialog.getByLabel('Name').fill(name);
    await dialog.getByRole('radiogroup', { name: 'Expires after' }).getByRole('radio', { name: '90 days' }).click();
    await dialog.getByRole('radiogroup', { name: 'Scope' }).getByRole('radio', { name: /^Home Assistant/ }).click();
    await expect(dialog.getByRole('list', { name: 'Granted permissions' }).getByRole('listitem')).toHaveText([
      'Read servers, rules and traffic', 'Read certificates', 'Preview, validate and reload', 'Renew certificates',
    ]);
    await dialog.getByRole('button', { name: 'Issue key' }).click();
    token = await issued(page);

    const row = page.locator('tbody tr', { hasText: name });
    await expect(row).toContainText('Home Assistant');
    await expect(row).toContainText('in 90 days');
    await expect(row).toContainText('active');
  });

  test('the key holds exactly its scopes', async () => {
    const key = await asKey(token);
    const who = await (await key.get('/api/whoami')).json();
    expect(who.permissions).toEqual(['ServerRead', 'CertRead', 'ProxyReload', 'CertRenew']);
    expect((await key.get('/api/servers')).status()).toBe(200);
    expect((await key.post('/api/proxy/start')).status()).toBe(403);
    expect((await key.post('/api/proxy/stop')).status()).toBe(403);
    expect((await key.get('/api/apikeys')).status()).toBe(403);
    expect((await key.post('/api/proxy/reload')).status()).not.toBe(403);
    await key.dispose();
  });

  test('signed in with the key, the UI offers only what it holds', async ({ page }) => {
    await page.addInitScript(k => {
      sessionStorage.setItem('sslrp-api-key', k);
      localStorage.setItem('sidebarCollapsed', 'false');
    }, token);
    await page.goto('/');
    await page.locator('main h2', { hasText: 'Key metrics' }).waitFor();
    await expect(page.locator('aside nav').getByRole('button', { name: 'API keys' })).toHaveCount(0);
    await openView(page, 'Proxy', 'Proxy control');
    await expect(page.getByRole('button', { name: 'Reload' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Validate' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Start' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Stop' })).toHaveCount(0);
  });

  test('rotating keeps the scope, takes a new lifetime and ends the old key', async ({ page }) => {
    await signIn(page, 'dark');
    await page.goto('/');
    await openView(page, 'API keys', 'API keys');
    await page.locator('tbody tr', { hasText: name }).getByRole('button', { name: 'Rotate' }).click();

    const dialog = page.getByRole('dialog', { name: `Rotate ${name}` });
    await expect(dialog.getByRole('radio', { name: /^Home Assistant/ })).toHaveAttribute('aria-checked', 'true');
    await expect(dialog.getByRole('radio', { name: '90 days' })).toHaveAttribute('aria-checked', 'true');
    await dialog.getByRole('radio', { name: '30 days' }).click();
    await dialog.getByRole('button', { name: 'Rotate key' }).click();
    const rotated = await issued(page);

    await expect(page.locator('tbody tr', { hasText: name })).toContainText('in 30 days');
    const oldKey = await asKey(token);
    expect((await oldKey.get('/api/whoami')).status()).toBe(401);
    const newKey = await asKey(rotated);
    expect((await (await newKey.get('/api/whoami')).json()).permissions).toEqual(['ServerRead', 'CertRead', 'ProxyReload', 'CertRenew']);
    await oldKey.dispose();
    await newKey.dispose();
    token = rotated;
  });

  test('revoking ends the key at once', async ({ page }) => {
    await signIn(page, 'dark');
    await page.goto('/');
    await openView(page, 'API keys', 'API keys');
    await page.locator('tbody tr', { hasText: name }).getByRole('button', { name: 'Revoke' }).click();
    await page.getByRole('dialog', { name: 'Revoke key' }).getByRole('button', { name: 'Revoke' }).click();
    await expect(page.locator('tbody tr', { hasText: name })).toHaveCount(0);

    await page.getByLabel('Show revoked and expired').check();
    await expect(page.locator('tbody tr', { hasText: name }).first()).toContainText('revoked');
    const key = await asKey(token);
    expect((await key.get('/api/whoami')).status()).toBe(401);
    await key.dispose();
  });
});
