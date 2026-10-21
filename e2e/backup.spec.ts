import fs from 'node:fs';
import { expect, test, type APIRequestContext } from '@playwright/test';
import { controlPlane, openView, signIn } from './session';

// Merge only: a replace would remove the rows other specs leave in the run's database.
test.describe.serial('backup export and import through the Settings card', () => {
  let api: APIRequestContext;
  let serverId = '';
  const stamp = Date.now();
  const name = `Backup ${stamp}`;
  const domain = `backup-${stamp}.example.com`;

  test.beforeAll(async () => {
    api = await controlPlane();
    serverId = (await (await api.post('/api/servers', { data: { name, host: '192.0.2.42', os: 'linux' } })).json()).id;
    expect((await api.post(`/api/servers/${serverId}/rules`, {
      data: { domain, upstreamUrl: 'http://127.0.0.1:5196', enableTls: false, enabled: true },
    })).status()).toBe(201);
  });

  test.afterAll(async () => {
    if (serverId) await api.delete(`/api/servers/${serverId}`);
    await api.dispose();
  });

  test('a server removed after the export comes back with its id and rule', async ({ page }) => {
    await signIn(page, 'dark');
    await page.goto('/');
    await openView(page, 'Settings', 'Settings');
    const card = page.locator('.card', { has: page.getByRole('heading', { name: 'Backup', exact: true }) });

    const [download] = await Promise.all([
      page.waitForEvent('download'),
      card.getByRole('button', { name: 'Export backup' }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/^sslrp-backup-\d{8}-\d{6}\.json$/);
    const file = await download.path();
    const exported = JSON.parse(fs.readFileSync(file, 'utf8'));
    const server = exported.servers.find((s: { id: string }) => s.id === serverId);
    expect(server.name).toBe(name);
    expect(server.rules.map((r: { domain: string }) => r.domain)).toEqual([domain]);

    expect((await api.delete(`/api/servers/${serverId}`)).status()).toBe(204);

    await card.getByLabel('Backup file').setInputFiles(file);
    await card.getByRole('button', { name: 'Check file' }).click();
    await expect(card.getByText(/^2 to add, 0 to change, 0 to remove, \d+ unchanged\.$/)).toBeVisible();
    const list = card.getByRole('list', { name: 'Import changes' });
    await expect(list.getByRole('listitem')).toHaveCount(2);
    await expect(list).toContainText(name);
    await expect(list).toContainText(domain);

    await card.getByRole('button', { name: 'Import', exact: true }).click();
    await expect(card.getByRole('status')).toHaveText('Imported: 2 added, 0 changed, 0 removed. Rule changes take effect at the next Reload.');

    const servers = await (await api.get('/api/servers')).json();
    expect(servers.find((s: { id: string }) => s.id === serverId)?.name).toBe(name);
    const rules = await (await api.get(`/api/servers/${serverId}/rules`)).json();
    expect(rules.map((r: { domain: string; upstreamUrl: string }) => [r.domain, r.upstreamUrl])).toEqual([[domain, 'http://127.0.0.1:5196']]);
  });
});
