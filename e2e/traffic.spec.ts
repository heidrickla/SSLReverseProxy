import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { caddyPath } from '../playwright.config';
import { controlPlane, proxyGet, sendDemoTraffic, signIn } from './session';

// CI sets SSLRP_REQUIRE_CADDY=1, so a missing binary fails these instead of skipping them.
test.skip(!caddyPath && process.env.SSLRP_REQUIRE_CADDY !== '1', 'set SSLRP_TEST_CADDY to run the proxy');

test.describe.serial('the running proxy', () => {
  let api: APIRequestContext;

  test.beforeAll(async () => {
    api = await controlPlane();
    const started = await (await api.post('/api/proxy/start')).json();
    expect(started.state, started.message ?? '').toBe('Running');
  });

  test.afterAll(async () => {
    await api.post('/api/proxy/stop');
    await api.dispose();
  });

  test('serves plaintext hosts over HTTP and redirects TLS hosts to HTTPS', async () => {
    const plain = await proxyGet('status.example.com', '/api/health');
    expect(plain.status).toBe(200);

    // A TLS host's route on the HTTP port would proxy it in plaintext. Caddy redirects to the
    // standard port: its https_port is the listener behind whatever forwards 443.
    const tls = await proxyGet('app.example.com', '/path');
    expect(tls.status).toBe(308);
    expect(tls.location).toBe('https://app.example.com/path');
  });

  test('the dashboard shows the traffic the proxy served', async ({ page }) => {
    const sent = await sendDemoTraffic(12, 3);
    expect(sent.map(r => r.status)).toEqual([...Array(12).fill(200), ...Array(3).fill(308)]);

    // The run's database is new and only this file sends traffic: these 15 and the previous test's 2.
    // Samples land every 2 s; the dashboard refetches every 5 s.
    const expected = 17;
    await expect.poll(async () => (await (await api.get('/api/proxy/traffic')).json()).requests,
      { timeout: 20_000 }).toBe(expected);

    await signIn(page, 'dark');
    await page.goto('/');
    const card = (title: string) => page.locator('main .card')
      .filter({ has: page.getByRole('heading', { name: title, exact: true }) });

    await expect(card('Total requests').locator('p').first()).toHaveText(String(expected), { timeout: 15_000 });
    await expect(card('Total requests')).toContainText('Last 24 hours');
    await expect(card('Requests in flight')).toContainText('At the last sample');
    await expect(card('Bandwidth').locator('p.text-xl').first()).toHaveText(/^\d+(\.\d)? (B|kB)$/);
    await expect(card('Time to first byte').locator('p').first()).toHaveText(/^\d+(\.\d)? ms$/);
    await expectNoEmptyCharts(page);
  });

  // After the dashboard test, whose request count this traffic would change.
  test('routes a path prefix to its own upstream and strips it', async () => {
    const server = await (await api.post('/api/servers', { data: { name: 'Paths', host: '192.0.2.40', os: 'linux' } })).json();
    const rule = (domain: string, upstreamUrl: string, routing: object | null) =>
      api.post(`/api/servers/${server.id}/rules`, { data: { domain, upstreamUrl, enableTls: false, enabled: true, routing } });
    // The whole-host rule goes to the discard port, so anything it serves is a 502.
    expect((await rule('paths.example.com', 'http://127.0.0.1:9', null)).status()).toBe(201);
    expect((await rule('paths.example.com', 'http://127.0.0.1:5195', { pathPrefix: '/svc', stripPathPrefix: true })).status()).toBe(201);
    expect((await rule('paths.example.com', 'http://127.0.0.1:5195', { pathPrefix: '/raw', stripPathPrefix: false })).status()).toBe(201);
    const reloaded = await (await api.post('/api/proxy/reload')).json();
    expect(reloaded.state, reloaded.message ?? '').toBe('Running');

    expect((await proxyGet('paths.example.com', '/svc/api/health')).status).toBe(200);
    expect((await proxyGet('paths.example.com', '/SVC/api/health')).status).toBe(200);
    // Unstripped, the API sees /raw/api/health; its deny-by-default fallback answers 401 for a path it does not serve.
    expect((await proxyGet('paths.example.com', '/raw/api/health')).status).toBe(401);
    expect((await proxyGet('paths.example.com', '/svcx/api/health')).status).toBe(502);
    expect((await proxyGet('paths.example.com', '/api/health')).status).toBe(502);
  });
});

async function expectNoEmptyCharts(page: Page) {
  for (const text of ['Proxy not running', 'No requests in the last 24 hours', 'First sample within'])
    await expect(page.locator('main').getByText(text)).toHaveCount(0);
  await expect(page.locator('main .recharts-area')).toHaveCount(1);
  await expect(page.locator('main .recharts-pie')).toHaveCount(1);
}
