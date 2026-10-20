import React, { StrictMode } from 'react';
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, csrfStore } from '../services/apiClient';

const KEY = 'sslrp-api-key';
const mocks = vi.hoisted(() => ({
  bootstrapKey: vi.fn(), whoami: vi.fn(), methods: vi.fn(), session: vi.fn(),
  passkeyOptions: vi.fn(), passkeySignIn: vi.fn(), logout: vi.fn(), getPasskey: vi.fn(),
}));

vi.mock('../services/apiClient', async (importOriginal) => {
  const real = await importOriginal<typeof import('../services/apiClient')>();
  return {
    ...real,
    api: {
      ...real.api, bootstrapKey: mocks.bootstrapKey, whoami: mocks.whoami,
      auth: {
        methods: mocks.methods, session: mocks.session, passkeyOptions: mocks.passkeyOptions,
        passkeySignIn: mocks.passkeySignIn, logout: mocks.logout,
      },
    },
  };
});

vi.mock('../utils/webauthn', () => ({ getPasskey: mocks.getPasskey }));

vi.mock('../hooks/useApiData', () => ({
  default: () => ({
    servers: [], certificates: [], users: [], auditLogs: [], error: null, reload: vi.fn(),
    addServer: vi.fn(), updateServer: vi.fn(), deleteServer: vi.fn(),
    addCertificate: vi.fn(), deleteCertificate: vi.fn(), renewCertificate: vi.fn(), setCertificateChallenge: vi.fn(),
    addUser: vi.fn(),
  }),
}));

// The backend hands the bootstrap key to the first claim that completes and
// answers 404 to every other. delays[i] is when claim i completes.
const singleUseClaim = (delays: number[]) => {
  let taken = false;
  let call = 0;
  return () => {
    const delay = delays[call++] ?? 0;
    return new Promise<{ apiKey: string }>((resolve, reject) => setTimeout(() => {
      if (taken) reject(new ApiError(404, 'Not Found'));
      else { taken = true; resolve({ apiKey: 'srp.test.key' }); }
    }, delay));
  };
};

let auth: ReturnType<typeof import('./AuthContext')['useAuth']>;

const renderApp = async () => {
  // Fresh module per test: the claim is shared at module scope for one page load.
  const { AuthProvider, useAuth } = await import('./AuthContext');
  const Probe = () => {
    auth = useAuth();
    const { authReady, currentUser } = auth;
    return <div data-testid="probe">{authReady ? currentUser?.name ?? 'signed-out' : 'loading'}</div>;
  };
  render(<StrictMode><AuthProvider><Probe /></AuthProvider></StrictMode>);
  await waitFor(() => expect(screen.getByTestId('probe').textContent).not.toBe('loading'));
  // Let any claim or whoami still in flight settle before asserting on storage.
  await new Promise((r) => setTimeout(r, 50));
  return screen.getByTestId('probe').textContent;
};

beforeEach(() => {
  vi.resetModules();
  sessionStorage.clear();
  csrfStore.clear();
  mocks.whoami.mockResolvedValue({ userId: 'u1', name: 'Bootstrap Admin', role: 'Admin', permissions: [] });
  mocks.methods.mockResolvedValue({ passkeys: false });
  mocks.session.mockRejectedValue(new ApiError(401, 'Unauthorized'));
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('AuthProvider first-run bootstrap claim under StrictMode', () => {
  // [first effect run's claim, second's]: both orders the backend can answer in.
  it.each([
    ['first claim completes first', [0, 10]],
    ['second claim completes first', [10, 0]],
  ])('signs in and keeps the key when the %s', async (_label, delays) => {
    mocks.bootstrapKey.mockImplementation(singleUseClaim(delays));

    expect(await renderApp()).toBe('Bootstrap Admin');
    expect(sessionStorage.getItem(KEY)).toBe('srp.test.key');
    expect(mocks.bootstrapKey).toHaveBeenCalledTimes(1);
    // The cancelled run stops after the claim; only the live run asks whoami.
    expect(mocks.whoami).toHaveBeenCalledTimes(1);
  });

  it('ends signed out with nothing stored when the key was already claimed', async () => {
    mocks.bootstrapKey.mockRejectedValue(new ApiError(404, 'Not Found'));

    expect(await renderApp()).toBe('signed-out');
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  it('restores a stored key without claiming', async () => {
    sessionStorage.setItem(KEY, 'srp.stored.key');

    expect(await renderApp()).toBe('Bootstrap Admin');
    expect(sessionStorage.getItem(KEY)).toBe('srp.stored.key');
    expect(mocks.bootstrapKey).not.toHaveBeenCalled();
  });

  it('keeps a stored key when only the cancelled run fails whoami', async () => {
    sessionStorage.setItem(KEY, 'srp.stored.key');
    mocks.whoami.mockRejectedValueOnce(new ApiError(503, 'Service Unavailable'));

    expect(await renderApp()).toBe('Bootstrap Admin');
    expect(sessionStorage.getItem(KEY)).toBe('srp.stored.key');
  });
});

describe('AuthProvider passkey sessions', () => {
  beforeEach(() => {
    mocks.methods.mockResolvedValue({ passkeys: true });
    mocks.bootstrapKey.mockRejectedValue(new ApiError(404, 'Not Found'));
  });

  it('restores a session cookie on load and recovers its CSRF token', async () => {
    mocks.session.mockResolvedValue({ csrfToken: 'csrf-1', expiresAt: '2026-10-21T00:00:00Z' });

    expect(await renderApp()).toBe('Bootstrap Admin');
    expect(csrfStore.get()).toBe('csrf-1');
    expect(auth.passkeysEnabled).toBe(true);
    expect(mocks.bootstrapKey).not.toHaveBeenCalled();
  });

  it('does not ask for a session while an API key is held', async () => {
    sessionStorage.setItem(KEY, 'srp.stored.key');

    expect(await renderApp()).toBe('Bootstrap Admin');
    expect(mocks.session).not.toHaveBeenCalled();
    expect(csrfStore.get()).toBeNull();
  });

  it('signs in with a passkey, dropping any stored key', async () => {
    expect(await renderApp()).toBe('signed-out');
    sessionStorage.setItem(KEY, 'srp.stale.key');
    mocks.passkeyOptions.mockResolvedValue({ handle: 'h1', options: { challenge: 'AQ' } });
    mocks.getPasskey.mockResolvedValue({ id: 'cred' });
    mocks.passkeySignIn.mockResolvedValue({
      csrfToken: 'csrf-2', expiresAt: '2026-10-21T00:00:00Z',
      user: { userId: 'u2', name: 'Passkey User', role: 'Editor', permissions: [] },
    });

    await act(() => auth.loginWithPasskey());
    expect(mocks.passkeySignIn).toHaveBeenCalledWith('h1', { id: 'cred' });
    expect(screen.getByTestId('probe').textContent).toBe('Passkey User');
    expect(csrfStore.get()).toBe('csrf-2');
    expect(sessionStorage.getItem(KEY)).toBeNull();
  });

  it('revokes the session on sign-out with the CSRF token the server derives now', async () => {
    mocks.session.mockResolvedValue({ csrfToken: 'csrf-1', expiresAt: '2026-10-21T00:00:00Z' });
    await renderApp();
    csrfStore.set('csrf-stale');
    let sent: (string | null)[] = [];
    mocks.logout.mockImplementation(async () => { sent = [csrfStore.get(), sessionStorage.getItem(KEY)]; });
    await act(() => auth.logout());
    expect(mocks.logout).toHaveBeenCalledTimes(1);
    expect(sent).toEqual(['csrf-1', null]);
    expect(csrfStore.get()).toBeNull();
    expect(auth.authNotice).toBeNull();
    expect(screen.getByTestId('probe').textContent).toBe('signed-out');
  });

  it.each([
    ['an API-key sign-in over a live session', async () => {
      mocks.session.mockResolvedValue({ csrfToken: 'csrf-1', expiresAt: '2026-10-21T00:00:00Z' });
      await renderApp();
      await act(() => auth.login('srp.k.x'));
    }],
    ['a stored key loaded beside a live session', async () => {
      sessionStorage.setItem(KEY, 'srp.stored.key');
      await renderApp();
      mocks.session.mockResolvedValue({ csrfToken: 'csrf-1', expiresAt: '2026-10-21T00:00:00Z' });
    }],
  ])('sign-out after %s forgets the key and revokes the session', async (_case, arrange) => {
    await arrange();
    expect(csrfStore.get()).toBeNull();
    let sent: (string | null)[] = [];
    mocks.logout.mockImplementation(async () => { sent = [csrfStore.get(), sessionStorage.getItem(KEY)]; });
    await act(() => auth.logout());
    expect(mocks.logout).toHaveBeenCalledTimes(1);
    expect(sent).toEqual(['csrf-1', null]);
    expect(sessionStorage.getItem(KEY)).toBeNull();
    expect(auth.authNotice).toBeNull();
  });

  it.each([[401], [404]])('with no session on the cookie (%i), sign-out only forgets the key', async (status) => {
    sessionStorage.setItem(KEY, 'srp.stored.key');
    await renderApp();
    mocks.session.mockRejectedValue(new ApiError(status, 'no session'));
    await act(() => auth.logout());
    expect(mocks.logout).not.toHaveBeenCalled();
    expect(sessionStorage.getItem(KEY)).toBeNull();
    expect(auth.authNotice).toBeNull();
    expect(screen.getByTestId('probe').textContent).toBe('signed-out');
  });

  it.each([
    ['the revocation fails', () => mocks.logout.mockRejectedValue(new ApiError(403, 'Forbidden'))],
    ['the server is unreachable', () => mocks.logout.mockRejectedValue(new TypeError('Failed to fetch'))],
    ['the session lookup fails', () => mocks.session.mockRejectedValue(new ApiError(503, 'Unavailable'))],
  ])('reports a sign-out the server did not confirm when %s, until the next sign-in', async (_case, fail) => {
    mocks.session.mockResolvedValue({ csrfToken: 'csrf-1', expiresAt: '2026-10-21T00:00:00Z' });
    await renderApp();
    fail();
    await act(() => auth.logout());
    expect(screen.getByTestId('probe').textContent).toBe('signed-out');
    expect(csrfStore.get()).toBeNull();
    expect(auth.authNotice).toMatch(/did not confirm the passkey session ended/);

    await act(() => auth.login('srp.k.x'));
    expect(auth.authNotice).toBeNull();
  });
});
