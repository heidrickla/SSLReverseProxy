import { expect, request, test, type Page } from '@playwright/test';
import { adminKey, openView, signIn, views } from './session';

function collectErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', e => errors.push(e.message));
  return errors;
}

const serverRow = (page: Page, name: string) => page.locator('tbody tr', { hasText: name });

for (const mode of ['dark', 'light'] as const) {
  test(`every view renders without console errors, ${mode} theme`, async ({ page }) => {
    const errors = collectErrors(page);
    await signIn(page, mode);
    await page.goto('/');
    await expect(page.locator('main h2').first()).toHaveText('Key metrics');

    for (const v of views) await openView(page, v.nav, v.heading);

    // The self-hosted font loads under font-src 'self'. Not document.fonts.check(),
    // which also answers true when no such face is defined at all.
    expect(await page.evaluate(async () => {
      await document.fonts.ready;
      return [...document.fonts].some(f => f.family.includes('Plus Jakarta Sans') && f.status === 'loaded');
    })).toBe(true);

    expect(errors).toEqual([]);
  });
}

test('server statuses come from the control plane', async ({ page }) => {
  await signIn(page, 'dark');
  await page.goto('/');

  // Demo data: one server per status (server/.../DemoSeeder.cs).
  const cardValue = (title: string) => page.locator('main button')
    .filter({ has: page.getByRole('heading', { name: title, exact: true }) })
    .locator('p').first();
  await expect(cardValue('Active servers')).toHaveText('1');
  await expect(cardValue('Inactive servers')).toHaveText('1');
  await expect(cardValue('Server errors')).toHaveText('1');

  await openView(page, 'Servers', 'Servers');
  await expect(serverRow(page, 'Web Applications').locator('[data-status]')).toHaveAttribute('data-status', 'active');
  await expect(serverRow(page, 'Internal Services').locator('[data-status]')).toHaveAttribute('data-status', 'error');
  await expect(serverRow(page, 'Windows Services').locator('[data-status]')).toHaveAttribute('data-status', 'inactive');
});

test('buttons given a className keep their variant styles', async ({ page }) => {
  await signIn(page, 'dark');
  await page.goto('/');
  await openView(page, 'Servers', 'Servers');
  await serverRow(page, 'Web Applications').click();

  // Both pass className="w-full"; a Button that let className replace its classes rendered them transparent.
  for (const name of ['Add proxy rule', 'Delete server']) {
    const background = await page.getByRole('button', { name, exact: true })
      .evaluate(el => getComputedStyle(el).backgroundColor);
    expect(background, name).not.toBe('rgba(0, 0, 0, 0)');
  }
});

test('a status change made elsewhere reaches the open page over the event stream', async ({ page }) => {
  await signIn(page, 'dark');
  await page.goto('/');
  await openView(page, 'Servers', 'Servers');
  const badge = serverRow(page, 'Windows Services').locator('[data-status]');
  await expect(badge).toHaveAttribute('data-status', 'inactive');

  // Enable the server's one rule through the API, not the page, so only the event stream can tell the page.
  const api = await request.newContext({
    baseURL: 'http://localhost:4173',
    extraHTTPHeaders: { 'X-Api-Key': await adminKey() },
  });
  const servers: { id: string; name: string }[] = await (await api.get('/api/servers')).json();
  const windows = servers.find(s => s.name === 'Windows Services')!;
  const [rule]: { id: string }[] = await (await api.get(`/api/servers/${windows.id}/rules`)).json();
  const toggle = (enabled: boolean) =>
    api.patch(`/api/servers/${windows.id}/rules/${rule.id}/enabled`, { data: { enabled } });

  try {
    expect((await toggle(true)).ok()).toBe(true);
    await expect(badge).toHaveAttribute('data-status', 'active', { timeout: 10_000 });
  } finally {
    await toggle(false);
    await api.dispose();
  }
});
