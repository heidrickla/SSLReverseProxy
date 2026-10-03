import React, { StrictMode } from 'react';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../services/apiClient';

const KEY = 'sslrp-api-key';
const mocks = vi.hoisted(() => ({ bootstrapKey: vi.fn(), whoami: vi.fn() }));

vi.mock('../services/apiClient', async (importOriginal) => {
  const real = await importOriginal<typeof import('../services/apiClient')>();
  return { ...real, api: { ...real.api, bootstrapKey: mocks.bootstrapKey, whoami: mocks.whoami } };
});

vi.mock('../hooks/useApiData', () => ({
  default: () => ({
    servers: [], certificates: [], users: [], auditLogs: [], error: null, reload: vi.fn(),
    addServer: vi.fn(), updateServer: vi.fn(), deleteServer: vi.fn(),
    addCertificate: vi.fn(), deleteCertificate: vi.fn(), addUser: vi.fn(),
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

const renderApp = async () => {
  // Fresh module per test: the claim is shared at module scope for one page load.
  const { AuthProvider, useAuth } = await import('./AuthContext');
  const Probe = () => {
    const { authReady, currentUser } = useAuth();
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
  mocks.whoami.mockResolvedValue({ userId: 'u1', name: 'Bootstrap Admin', role: 'Admin', permissions: [] });
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
