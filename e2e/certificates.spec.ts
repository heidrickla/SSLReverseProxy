import { expect, test, type APIRequestContext } from '@playwright/test';
import { caddyPath } from '../playwright.config';
import { controlPlane, openView, signIn } from './session';

// CI sets SSLRP_REQUIRE_CADDY=1, so a missing binary fails these instead of skipping them.
test.skip(!caddyPath && process.env.SSLRP_REQUIRE_CADDY !== '1', 'set SSLRP_TEST_CADDY to run the proxy');

interface Cert {
  id: string; domain: string; status: string; issuer: string; source: string;
  serialNumber: string | null; renewPending: boolean; lastError: string | null; checkedAt: string | null;
}

// The run's Caddy issues from its own CA (Proxy:CertificateIssuer internal), so names need no DNS.
// Polls are 2 s apart: the API allows 100 requests a minute per client, and the specs after this one share it.
const poll = { timeout: 60_000, intervals: [2_000] };

test.describe.serial('certificates read from the running proxy', () => {
  test.describe.configure({ timeout: 90_000 });

  let api: APIRequestContext;
  const find = async (domain: string): Promise<Cert | undefined> =>
    ((await (await api.get('/api/certificates')).json()) as Cert[]).find(c => c.domain === domain);

  test.beforeAll(async () => {
    api = await controlPlane();
    const started = await (await api.post('/api/proxy/start')).json();
    expect(started.state, started.message ?? '').toBe('Running');
  });

  test.afterAll(async () => {
    await api.post('/api/proxy/stop');
    await api.dispose();
  });

  test("a TLS rule's host shows the certificate Caddy serves", async () => {
    // The demo row starts with made-up values; the monitor replaces them with what Caddy serves.
    await expect.poll(async () => (await find('app.example.com'))?.issuer, poll).toContain('Caddy Local Authority');
    const app = (await find('app.example.com'))!;
    expect(app.source).toBe('Rule');
    expect(app.status).toBe('Valid');
    expect(app.checkedAt).not.toBeNull();
    expect(app.serialNumber).toMatch(/^[0-9A-F]+$/);
  });

  test('a manual wildcard is issued, and Renew replaces it in place', async ({ page }) => {
    const created = await api.post('/api/certificates', { data: { domain: '*.wild.example.com', challenge: 'Http' } });
    expect(created.status(), await created.text()).toBe(201);
    await expect.poll(async () => (await find('*.wild.example.com'))?.status, poll).toBe('Valid');
    const before = (await find('*.wild.example.com'))!;

    await signIn(page, 'dark');
    await page.goto('/');
    await openView(page, 'SSL', 'SSL certificates');
    const row = page.locator('tbody tr', { hasText: '*.wild.example.com' });
    await row.getByRole('button', { name: 'Renew', exact: true }).click();
    await page.getByRole('dialog', { name: 'Renew certificate' }).getByRole('button', { name: 'Renew', exact: true }).click();

    await expect.poll(async () => {
      const now = (await find('*.wild.example.com'))!;
      return !now.renewPending && now.serialNumber !== before.serialNumber;
    }, poll).toBe(true);
    const after = (await find('*.wild.example.com'))!;
    expect(after.status).toBe('Valid');
    expect(after.lastError).toBeNull();

    // The page follows the certificate.* events without a reload.
    await row.click();
    await expect(page.locator('aside').getByText(after.serialNumber!, { exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(row.getByRole('button', { name: 'Renew', exact: true })).toBeEnabled();
  });

  test('a second renewal waits for the first', async () => {
    const wild = (await find('*.wild.example.com'))!;
    expect((await api.post(`/api/certificates/${wild.id}/renew`)).status()).toBe(202);
    const again = await api.post(`/api/certificates/${wild.id}/renew`);
    expect(again.status()).toBe(409);
    expect((await again.json()).message).toContain('already in progress');
    await expect.poll(async () => (await find('*.wild.example.com'))?.renewPending, poll).toBe(false);
  });
});
