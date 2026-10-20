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
  await page.mouse.click(200, 500);

  await openView(page, 'SSL', 'SSL certificates');
  await shot(page, 'certificates');
  await openView(page, 'Users', 'Users');
  await shot(page, 'users');
  await openView(page, 'Audit log', 'Audit log');
  await shot(page, 'audit-log');

  if (caddyPath) await api.post('/api/proxy/stop');
  await api.dispose();
});
