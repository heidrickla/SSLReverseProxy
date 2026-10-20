import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, apiKeyStore, csrfStore, sessionsAvailable } from './apiClient';

const fetchMock = vi.fn();

beforeEach(() => {
  sessionStorage.clear();
  csrfStore.clear();
  fetchMock.mockImplementation(async () => new Response('{}', { status: 200 }));
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const sent = () => fetchMock.mock.calls[0][1] as RequestInit & { headers: Record<string, string> };

describe('request credentials', () => {
  it('sends an API key with no cookie and no CSRF token', async () => {
    apiKeyStore.set('srp.k.x');
    csrfStore.set('csrf-1');
    await api.proxy.validate();
    expect(sent().headers['X-Api-Key']).toBe('srp.k.x');
    expect(sent().headers['X-CSRF-Token']).toBeUndefined();
    expect(sent().credentials).toBe('omit');
  });

  it('sends the session cookie, with the CSRF token on unsafe methods only', async () => {
    csrfStore.set('csrf-1');
    await api.proxy.validate();
    expect(sent().credentials).toBe('same-origin');
    expect(sent().headers['X-CSRF-Token']).toBe('csrf-1');
    expect(sent().headers['X-Api-Key']).toBeUndefined();

    fetchMock.mockClear();
    await api.whoami();
    expect(sent().credentials).toBe('same-origin');
    expect(sent().headers['X-CSRF-Token']).toBeUndefined();
  });

  it('keeps the cookie off the event stream when an API key is held', async () => {
    fetchMock.mockImplementation(async () => new Response(null, { status: 401 }));
    apiKeyStore.set('srp.k.x');
    await api.events(() => {});
    expect(sent().credentials).toBe('omit');
    sessionStorage.clear();
    fetchMock.mockClear();
    await api.events(() => {});
    expect(sent().credentials).toBe('same-origin');
  });
});

describe('sessionsAvailable', () => {
  it.each([['', true], ['/', true], [window.location.origin, true], ['https://api.example.com', false]])(
    'with API base %j is %s', (base, expected) => {
      expect(sessionsAvailable(base)).toBe(expected);
    });
});
