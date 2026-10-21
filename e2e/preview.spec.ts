import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { caddyPath } from '../playwright.config';
import { controlPlane, openView, signIn } from './session';

// CI sets SSLRP_REQUIRE_CADDY=1, so a missing binary fails these instead of skipping them.
test.skip(!caddyPath && process.env.SSLRP_REQUIRE_CADDY !== '1', 'set SSLRP_TEST_CADDY to run the proxy');

// No traffic goes through the proxy here: e2e/traffic.spec.ts counts every request the run sends.
test.describe.serial('push preview against the running Caddy', () => {
  let api: APIRequestContext;
  let serverId = '';
  const stamp = Date.now();
  const first = `preview-a-${stamp}.example.com`;
  const second = `preview-b-${stamp}.example.com`;

  const changes = async () => (await (await api.get('/api/proxy/preview')).json()).changes as { group: string; kind: string }[];
  const addRule = async (domain: string) =>
    expect((await api.post(`/api/servers/${serverId}/rules`, {
      data: { domain, upstreamUrl: 'http://127.0.0.1:5195', enableTls: false, enabled: true },
    })).status()).toBe(201);

  async function proxyView(page: Page) {
    await signIn(page, 'dark');
    await page.goto('/');
    await openView(page, 'Proxy', 'Proxy control');
  }

  async function openReload(page: Page) {
    await proxyView(page);
    await page.getByRole('button', { name: 'Reload', exact: true }).click();
    return page.getByRole('dialog', { name: 'Reload preview' });
  }

  test.beforeAll(async () => {
    api = await controlPlane();
    const started = await (await api.post('/api/proxy/start')).json();
    expect(started.state, started.message ?? '').toBe('Running');
    serverId = (await (await api.post('/api/servers', { data: { name: `Preview ${stamp}`, host: '192.0.2.41', os: 'linux' } })).json()).id;
  });

  test.afterAll(async () => {
    if (serverId) await api.delete(`/api/servers/${serverId}`);
    await api.post('/api/proxy/stop');
    await api.dispose();
  });

  test('the config Caddy reports back matches the pushed one: no changes after a push', async ({ page }) => {
    expect((await api.post('/api/proxy/reload')).status()).toBe(200);
    const after = await changes();
    expect(after, JSON.stringify(after)).toEqual([]);
    const dialog = await openReload(page);
    await expect(dialog.getByText(/No changes: Caddy already runs this config/)).toBeVisible();
  });

  test('a new rule shows as one route, and Reload pushes it', async ({ page }) => {
    await addRule(first);
    const dialog = await openReload(page);
    const route = dialog.getByRole('region', { name: `${first} (http)` });
    await expect(route).toContainText('added');
    await expect(route).toContainText('whole entry');
    await expect(route).toContainText('127.0.0.1:5195');
    await expect(dialog.getByRole('region')).toHaveCount(1);

    await dialog.getByRole('button', { name: 'Reload', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    expect(await changes()).toEqual([]);
  });

  test('a rule added while the preview is open is caught before the push', async ({ page }) => {
    const dialog = await openReload(page);
    await expect(dialog.getByText(/No changes/)).toBeVisible();
    await addRule(second);

    await dialog.getByRole('button', { name: 'Reload', exact: true }).click();
    await expect(dialog.getByRole('status')).toContainText('changed after this preview');
    await expect(dialog.getByRole('region', { name: `${second} (http)` })).toContainText('added');

    await dialog.getByRole('button', { name: 'Reload', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    expect(await changes()).toEqual([]);
  });

  test('a rollback shows what it removes, then restores the snapshot', async ({ page }) => {
    // Newest first: the two reloads above, then the first test's reload, which held neither rule.
    const snapshots = (await (await api.get('/api/proxy/snapshots')).json()) as { id: number }[];
    const target = snapshots[2].id;

    await proxyView(page);
    await page.getByRole('button', { name: `Roll back to snapshot ${target}` }).click();
    const dialog = page.getByRole('dialog', { name: `Roll back to snapshot ${target}` });
    await expect(dialog.getByRole('region', { name: `${first} (http)` })).toContainText('removed');
    await expect(dialog.getByRole('region', { name: `${second} (http)` })).toContainText('removed');
    await expect(dialog.getByRole('region')).toHaveCount(2);

    await dialog.getByRole('button', { name: 'Roll back', exact: true }).click();
    await expect(dialog).toHaveCount(0);

    // Caddy now runs the snapshot; the rows still hold both rules, so a Reload would add them back.
    const back = await changes();
    expect(back.map(c => `${c.group} ${c.kind}`).sort()).toEqual([`${first} (http) added`, `${second} (http) added`]);
  });
});
