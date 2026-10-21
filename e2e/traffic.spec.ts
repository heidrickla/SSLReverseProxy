import crypto from 'node:crypto';
import http from 'node:http';
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { caddyPath, signInStubPort } from '../playwright.config';
import { controlPlane, openView, proxyGet, proxyRequest, sendDemoTraffic, signIn } from './session';

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

  test("a rule's recent requests show what its route served, without the query", async ({ page }) => {
    const server = await (await api.post('/api/servers', { data: { name: 'Requests', host: '192.0.2.43', os: 'linux' } })).json();
    const rule = await (await api.post(`/api/servers/${server.id}/rules`, {
      data: { domain: 'requests.example.com', upstreamUrl: 'http://127.0.0.1:5195', enableTls: false, enabled: true },
    })).json();
    const reloaded = await (await api.post('/api/proxy/reload')).json();
    expect(reloaded.state, reloaded.message ?? '').toBe('Running');

    expect((await proxyGet('requests.example.com', '/api/health?token=e2e-query-secret')).status).toBe(200);
    expect((await proxyGet('requests.example.com', '/missing')).status).toBe(401);
    // Another rule's request is not this rule's.
    expect((await proxyGet('status.example.com', '/api/health')).status).toBe(200);

    const url = `/api/servers/${server.id}/rules/${rule.id}/requests`;
    await expect.poll(async () => (await (await api.get(url)).json()).requests
      .map((r: { method: string; host: string; path: string; status: number; clientIp: string }) => `${r.method} ${r.host}${r.path} ${r.status} ${r.clientIp}`),
    { timeout: 10_000 }).toEqual(['GET requests.example.com/missing 401 127.0.0.1', 'GET requests.example.com/api/health 200 127.0.0.1']);
    expect(await (await api.get(url)).text()).not.toContain('e2e-query-secret');

    await signIn(page, 'dark');
    await page.goto('/');
    await openView(page, 'Servers', 'Servers');
    await page.locator('tbody tr', { hasText: 'Requests' }).click();
    await page.getByRole('button', { name: 'Requests to requests.example.com', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Requests to requests.example.com' });
    const rows = dialog.getByRole('table', { name: 'Recent requests' }).locator('tbody tr');
    await expect(rows).toHaveCount(2);
    await expect(rows.first()).toContainText('/missing');
    await dialog.getByRole('radio', { name: '2xx' }).click();
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('/api/health');
    await expect(rows.first()).toContainText('200');
  });

  test('rules sign in through their identity provider', async ({ page }) => {
    const stub = signInStub();
    await new Promise<void>(resolve => stub.server.listen(signInStubPort, '127.0.0.1', resolve));
    try {
      const server = await (await api.post('/api/servers', { data: { name: 'Sign-in', host: '192.0.2.44', os: 'linux' } })).json();
      const verifier = `http://127.0.0.1:${signInStubPort}`;
      const add = async (domain: string, signIn: object) => {
        const r = await api.post(`/api/servers/${server.id}/rules`, { data: { domain, upstreamUrl: verifier, enableTls: false, enabled: true, signIn } });
        expect(r.status(), await r.text()).toBe(201);
      };
      await add('authelia.example.com', { provider: 'authelia', verifierUrl: verifier });
      await add('oauth2.example.com', { provider: 'oauth2-proxy', verifierUrl: verifier });
      await add('cf.example.com', { provider: 'cloudflare-access', teamDomain: stub.team, audience: stub.audience });
      const reloaded = await (await api.post('/api/proxy/reload')).json();
      expect(reloaded.state, reloaded.message ?? '').toBe('Running');
      const echo = (r: { body: string }) => JSON.parse(r.body) as { path: string; headers: Record<string, string | undefined> };

      // Authelia: its redirect reaches the client; once signed in its identity replaces the client's.
      const away = await proxyRequest('authelia.example.com', '/whoami?x=1', { 'Remote-User': 'mallory' });
      expect(away.status).toBe(302);
      expect(away.headers.location).toBe('https://auth.example.com/');
      expect(stub.verified.at(-1)).toEqual({ path: '/api/authz/forward-auth', method: 'GET', uri: '/whoami?x=1', user: undefined });
      const alice = await proxyRequest('authelia.example.com', '/whoami', { Cookie: 'idp=ok', 'Remote-User': 'mallory', 'Remote-Name': 'Mallory' });
      expect(alice.status).toBe(200);
      expect(echo(alice).path).toBe('/whoami');
      expect(echo(alice).headers['remote-user']).toBe('alice');
      expect(echo(alice).headers['remote-groups']).toBe('admins');
      expect(echo(alice).headers['remote-name']).toBeUndefined();

      // oauth2-proxy: a 401 goes to its sign-in page, which this host proxies to it.
      const signInRedirect = await proxyRequest('oauth2.example.com', '/whoami');
      expect(signInRedirect.status).toBe(302);
      expect(signInRedirect.headers.location).toBe('/oauth2/sign_in?rd=http://oauth2.example.com/whoami');
      const page2 = await proxyRequest('oauth2.example.com', '/oauth2/sign_in?rd=x', { 'X-Auth-Request-User': 'mallory', 'Remote-User': 'mallory' });
      expect(page2.status).toBe(200);
      expect(page2.body).toBe('oauth2-proxy sign-in');
      expect(stub.signInPage.at(-1)).toEqual({ user: undefined, remoteUser: undefined, uri: '/oauth2/sign_in?rd=x' });
      const bob = await proxyRequest('oauth2.example.com', '/whoami', { Cookie: 'idp=ok', 'X-Auth-Request-User': 'mallory' });
      expect(bob.status).toBe(200);
      expect(echo(bob).headers['x-auth-request-user']).toBe('bob');

      // Cloudflare Access: the control plane checks the token against the team's keys.
      const refused = await proxyRequest('cf.example.com', '/whoami', { 'Cf-Access-Authenticated-User-Email': 'mallory@example.com' });
      expect(refused.status).toBe(403);
      expect(refused.body).toBe('Sign-in required.');
      expect((await proxyRequest('cf.example.com', '/whoami', { 'Cf-Access-Jwt-Assertion': stub.token('carol@example.com', true) })).status).toBe(403);
      // Another provider's identity headers from the client never reach the upstream.
      const carol = await proxyRequest('cf.example.com', '/whoami', {
        'Cf-Access-Jwt-Assertion': stub.token('carol@example.com'),
        'Cf-Access-Authenticated-User-Email': 'mallory@example.com',
        'Remote-User': 'mallory',
        'X-Authentik-Username': 'mallory',
      });
      expect(carol.status, carol.body).toBe(200);
      expect(echo(carol).headers['cf-access-authenticated-user-email']).toBe('carol@example.com');
      expect(echo(carol).headers['remote-user']).toBeUndefined();
      expect(echo(carol).headers['x-authentik-username']).toBeUndefined();

      await signIn(page, 'dark');
      await page.goto('/');
      await openView(page, 'Servers', 'Servers');
      await page.locator('tbody tr', { hasText: 'Sign-in' }).click();
      await expect(page.getByText('Cloudflare Access sign-in')).toBeVisible();
      await page.getByText('Authelia sign-in', { exact: true }).click();
      const dialog = page.getByRole('dialog', { name: 'Edit proxy rule' });
      await expect(dialog.getByLabel('Sign-in')).toHaveValue('authelia');
      await expect(dialog.getByLabel('Authelia address')).toHaveValue(verifier);
    } finally {
      await new Promise(resolve => stub.server.close(resolve));
    }
  });
});

/**
 * Stands in for the providers on one port: Authelia's and oauth2-proxy's verify paths answer as theirs do, oauth2-proxy's
 * sign-in page, a Cloudflare Access team's certs, and an upstream that echoes the request it was sent.
 */
function signInStub() {
  const team = 'e2e.cloudflareaccess.com';
  const audience = '0123456789abcdef'.repeat(4);
  const key = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...key.publicKey.export({ format: 'jwk' }), kid: 'e2e', alg: 'RS256', use: 'sig' };
  const verified: { path: string; method?: string; uri?: string; user?: string }[] = [];
  const signInPage: { user?: string; remoteUser?: string; uri?: string }[] = [];
  const b64 = (v: object) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const token = (email: string, forged = false) => {
    const now = Math.floor(Date.now() / 1000);
    const signed = `${b64({ alg: 'RS256', kid: 'e2e', typ: 'JWT' })}.${b64({ iss: `https://${team}`, aud: [audience], email, iat: now, nbf: now, exp: now + 600, type: 'app' })}`;
    return `${signed}.${crypto.sign('RSA-SHA256', Buffer.from(signed), forged ? other.privateKey : key.privateKey).toString('base64url')}`;
  };
  const server = http.createServer((req, res) => {
    const url = req.url ?? '/';
    // Caddy's rewrite to the verify path keeps the client's query, as the providers expect.
    const path = url.split('?')[0];
    const signedIn = (req.headers.cookie ?? '').includes('idp=ok');
    if (path === '/api/authz/forward-auth' || path === '/oauth2/auth') {
      verified.push({
        path, method: req.headers['x-forwarded-method'] as string, uri: req.headers['x-forwarded-uri'] as string,
        user: req.headers['remote-user'] as string | undefined,
      });
      if (path === '/oauth2/auth') res.writeHead(signedIn ? 202 : 401, signedIn ? { 'X-Auth-Request-User': 'bob' } : {}).end();
      else res.writeHead(signedIn ? 200 : 302, signedIn ? { 'Remote-User': 'alice', 'Remote-Groups': 'admins' } : { Location: 'https://auth.example.com/' }).end();
    } else if (path === '/oauth2/sign_in') {
      signInPage.push({
        user: req.headers['x-auth-request-user'] as string | undefined, remoteUser: req.headers['remote-user'] as string | undefined,
        uri: req.headers['x-forwarded-uri'] as string | undefined,
      });
      res.writeHead(200, { 'Content-Type': 'text/plain' }).end('oauth2-proxy sign-in');
    } else if (path === `/${team}/certs`) {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ keys: [jwk] }));
    } else {
      res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ path: url, headers: req.headers }));
    }
  });
  return { server, team, audience, token, verified, signInPage };
}

async function expectNoEmptyCharts(page: Page) {
  for (const text of ['Proxy not running', 'No requests in the last 24 hours', 'First sample within'])
    await expect(page.locator('main').getByText(text)).toHaveCount(0);
  await expect(page.locator('main .recharts-area')).toHaveCount(1);
  await expect(page.locator('main .recharts-pie')).toHaveCount(1);
}
