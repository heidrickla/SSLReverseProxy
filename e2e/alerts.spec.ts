import http from 'node:http';
import { expect, test } from '@playwright/test';
import { alertListenerPort } from '../playwright.config';
import { openView, signIn } from './session';

interface Received { path: string; authorization: string | undefined; body: Record<string, unknown> }

// playwright.config.ts points the run's one alert target, "e2e", at this listener.
test.describe.serial('alerts', () => {
  const received: Received[] = [];
  let listener: http.Server;

  test.beforeAll(async () => {
    listener = http.createServer((req, res) => {
      let data = '';
      req.on('data', chunk => { data += chunk; });
      req.on('end', () => {
        received.push({ path: req.url ?? '', authorization: req.headers.authorization, body: JSON.parse(data || '{}') });
        res.writeHead(200).end();
      });
    });
    await new Promise<void>(resolve => listener.listen(alertListenerPort, '127.0.0.1', resolve));
  });

  test.afterAll(async () => {
    await new Promise(resolve => listener.close(resolve));
  });

  test('Settings sends a test alert to the configured webhook', async ({ page }) => {
    await signIn(page, 'dark');
    await page.goto('/');
    await openView(page, 'Settings', 'Settings');

    await expect(page.getByText('server.up', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Send a test alert to e2e' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'HTTP' })).toHaveText('Delivered (HTTP 200)');

    const hit = received.find(r => r.body.type === 'test');
    expect(hit?.path).toBe('/api/webhook/e2e-hook');
    expect(hit?.authorization).toBe('Bearer e2e-alert-token');
    expect(hit?.body.subject).toBe('e2e');
  });
});
