import { expect, test, type Page } from '@playwright/test';
import { caddyPath } from '../playwright.config';
import { controlPlane, openView, sendDemoTraffic, signIn } from './session';

// Retakes the README screenshots from the demo data: `bun run screenshots`.
test.skip(!process.env.SCREENSHOTS, 'set SCREENSHOTS=1 to retake docs/screenshots');

const shot = (page: Page, name: string) =>
  page.screenshot({ path: `docs/screenshots/${name}.png`, animations: 'disabled' });

test('README screenshots', async ({ page }) => {
  // With Caddy, the dashboard shows traffic the proxy served; without it, its empty states.
  const api = await controlPlane();
  if (caddyPath) {
    expect((await (await api.post('/api/proxy/start')).json()).state).toBe('Running');
    await sendDemoTraffic(40, 6);
    await expect.poll(async () => (await (await api.get('/api/proxy/traffic')).json()).requests,
      { timeout: 20_000 }).toBe(46);
  }

  await signIn(page, 'dark');
  await page.goto('/');
  await page.locator('main h2', { hasText: 'Key metrics' }).waitFor();
  await page.waitForTimeout(2500); // chart animations
  await shot(page, 'dashboard');

  await openView(page, 'Proxy', 'Proxy control');
  await page.locator('main').getByText('Engine', { exact: true }).waitFor();
  await shot(page, 'proxy-control');

  await openView(page, 'Servers', 'Servers');
  await page.locator('[data-status="error"]').waitFor();
  await shot(page, 'servers');
  await page.locator('tbody tr', { hasText: 'Web Applications' }).click();
  await page.getByRole('button', { name: 'Add proxy rule', exact: true }).waitFor();
  await page.waitForTimeout(500); // pane slide-in
  await shot(page, 'proxy-rules');

  if (caddyPath) {
    await page.getByRole('button', { name: 'Requests to status.example.com', exact: true }).click();
    const requests = page.getByRole('dialog', { name: 'Requests to status.example.com' });
    await expect(requests.getByRole('table', { name: 'Recent requests' }).locator('tbody tr').first()).toBeVisible();
    await shot(page, 'recent-requests');
    await requests.getByRole('button', { name: 'Close' }).click();
    await requests.waitFor({ state: 'hidden' });
  }

  await page.getByRole('button', { name: 'Add proxy rule', exact: true }).click();
  const rule = page.getByRole('dialog', { name: 'Add proxy rule' });
  await rule.getByLabel('Domain').fill('wiki.example.com');
  await rule.getByLabel('Upstream address').fill('http://192.0.2.20:3000');
  await rule.getByLabel('Sign-in').selectOption('authelia');
  await rule.getByLabel('Authelia address').fill('http://authelia.internal:9091');
  await shot(page, 'rule-sign-in');
  await rule.getByRole('button', { name: 'Cancel' }).click();
  await page.mouse.click(200, 500);

  await openView(page, 'SSL', 'SSL certificates');
  await shot(page, 'certificates');
  await openView(page, 'Users', 'Users');
  await shot(page, 'users');

  // Two scoped keys beside the bootstrap key, revoked again afterwards.
  const options = await (await api.get('/api/apikeys/options')).json() as { presets: { id: string; scopes: string[] | null }[] };
  const owners = await (await api.get('/api/apikeys/owners')).json() as { id: string; role: string }[];
  const owner = owners.find(o => o.role === 'Admin')!;
  const issued: string[] = [];
  for (const [name, preset, lifetimeDays] of [['Home Assistant', 'home-assistant', 90], ['Deploy pipeline', 'rules-editor', 30]] as const) {
    const scopes = options.presets.find(p => p.id === preset)!.scopes;
    const r = await api.post('/api/apikeys', { data: { userId: owner.id, name, lifetimeDays, scopes } });
    expect(r.status()).toBe(201);
    issued.push((await r.json()).id);
  }
  await openView(page, 'API keys', 'API keys');
  await expect(page.locator('tbody tr')).toHaveCount(3);
  await shot(page, 'api-keys');
  await page.getByRole('button', { name: 'New key' }).first().click();
  const key = page.getByRole('dialog', { name: 'New API key' });
  await key.getByLabel('Name').fill('Home Assistant');
  await key.getByRole('radiogroup', { name: 'Expires after' }).getByRole('radio', { name: '90 days' }).click();
  await key.getByRole('radiogroup', { name: 'Scope' }).getByRole('radio', { name: /^Home Assistant/ }).click();
  await shot(page, 'api-key-new');
  await key.getByRole('button', { name: 'Close' }).click();
  await key.waitFor({ state: 'hidden' });
  for (const id of issued) expect((await api.post(`/api/apikeys/${id}/revoke`)).ok()).toBe(true);

  await openView(page, 'Settings', 'Settings');
  await page.getByRole('heading', { name: 'Backup', exact: true }).evaluate(e => e.scrollIntoView({ block: 'start' }));
  await shot(page, 'backup');

  await openView(page, 'Audit log', 'Audit log');
  await shot(page, 'audit-log');

  if (caddyPath) {
    // One added rule, so the preview has a change to show; removed again afterwards.
    const servers = await (await api.get('/api/servers')).json() as { id: string; name: string }[];
    const web = servers.find(s => s.name === 'Web Applications')!;
    const added = await (await api.post(`/api/servers/${web.id}/rules`, {
      data: { domain: 'portal.example.com', upstreamUrl: 'http://127.0.0.1:5195', enableTls: false, enabled: true },
    })).json() as { id: string };
    await openView(page, 'Proxy', 'Proxy control');
    await page.getByRole('button', { name: 'Reload', exact: true }).click();
    const preview = page.getByRole('dialog', { name: 'Reload preview' });
    await preview.getByRole('region').first().waitFor();
    await shot(page, 'reload-preview');
    await preview.getByRole('button', { name: 'Close' }).click();
    await api.delete(`/api/servers/${web.id}/rules/${added.id}`);
    await api.post('/api/proxy/stop');
  }
  await api.dispose();
});
