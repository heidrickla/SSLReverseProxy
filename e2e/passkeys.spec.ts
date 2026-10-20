import { expect, test } from '@playwright/test';
import { adminKey, openView } from './session';

// A CDP virtual authenticator stands in for a platform passkey: resident keys and user verification, always approved.
test('a passkey registered in Settings signs in to a cookie session that survives a reload', async ({ page, request }) => {
  await page.route('https://api.dicebear.com/**', route =>
    route.fulfill({ contentType: 'image/svg+xml', body: '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>' }));
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    },
  });

  await page.goto('/');
  await page.getByLabel('API key').fill(await adminKey());
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await openView(page, 'Settings', 'Settings');
  await page.getByLabel('Name').fill('e2e authenticator');
  await page.getByRole('button', { name: 'Add passkey' }).click();
  await expect(page.getByText('e2e authenticator')).toBeVisible();
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  expect(credentials).toHaveLength(1);
  expect(credentials[0].isResidentCredential).toBe(true);

  await page.getByRole('button', { name: /User Avatar/ }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
  await page.locator('aside nav').waitFor();
  expect(await page.evaluate(() => sessionStorage.getItem('sslrp-api-key'))).toBeNull();

  const cookie = (await page.context().cookies()).find(c => c.name === '__Host-sslrp-session');
  expect(cookie).toMatchObject({ httpOnly: true, secure: true, sameSite: 'Strict', path: '/' });

  // A reload recovers the session and its CSRF token; a write through the UI carries the token.
  await page.reload();
  await openView(page, 'Proxy', 'Proxy control');
  await page.getByRole('button', { name: 'Validate' }).click();
  await expect(page.getByText(/Validated by the Caddy engine|Structural checks only/)).toBeVisible();
  const bare = await page.evaluate(() => fetch('/api/proxy/validate', { method: 'POST' }).then(r => r.status));
  expect(bare).toBe(403);

  await openView(page, 'Settings', 'Settings');
  await expect(page.getByText(/last used/)).toBeVisible();

  // Sign-out revokes the session: the old cookie value no longer authenticates. The page signs out first.
  const revoked = page.waitForResponse(r => r.url().endsWith('/api/auth/logout'));
  await page.getByRole('button', { name: /User Avatar/ }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  expect((await revoked).status()).toBe(204);
  await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeVisible();
  const replay = await page.request.get('/api/whoami', { headers: { Cookie: `${cookie!.name}=${cookie!.value}` } });
  expect(replay.status()).toBe(401);
  await page.reload();
  await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeVisible();

  // An API key loaded beside a live session: sign-out forgets the key and revokes the session.
  await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
  await page.locator('aside nav').waitFor();
  const second = (await page.context().cookies()).find(c => c.name === '__Host-sslrp-session');
  expect(second?.value).not.toBe(cookie!.value);
  const key = await adminKey();
  await page.evaluate(k => sessionStorage.setItem('sslrp-api-key', k), key);
  await page.reload();
  await page.locator('aside nav').waitFor();
  const revokedSecond = page.waitForResponse(r => r.url().endsWith('/api/auth/logout'));
  await page.getByRole('button', { name: /User Avatar/ }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  expect((await revokedSecond).status()).toBe(204);
  await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toBeVisible();
  await expect(page.getByRole('status')).toHaveCount(0);
  expect(await page.evaluate(() => sessionStorage.getItem('sslrp-api-key'))).toBeNull();
  const replaySecond = await page.request.get('/api/whoami', { headers: { Cookie: `${second!.name}=${second!.value}` } });
  expect(replaySecond.status()).toBe(401);

  // A sign-out the server never receives leaves the session live and says so; the next passkey sign-in ends it first.
  await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
  await page.locator('aside nav').waitFor();
  const third = (await page.context().cookies()).find(c => c.name === '__Host-sslrp-session');
  await page.route('**/api/auth/logout', route => route.abort());
  await page.getByRole('button', { name: /User Avatar/ }).click();
  await page.getByRole('menuitem', { name: 'Sign out' }).click();
  await expect(page.getByRole('status')).toContainText('did not confirm the passkey session ended');
  // The test's own request context holds no cookies, so only the replayed one is sent.
  expect((await request.get('/api/whoami', { headers: { Cookie: `${third!.name}=${third!.value}` } })).status()).toBe(200);
  await page.unroute('**/api/auth/logout');
  await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
  await page.locator('aside nav').waitFor();
  expect((await request.get('/api/whoami', { headers: { Cookie: `${third!.name}=${third!.value}` } })).status()).toBe(401);
});
