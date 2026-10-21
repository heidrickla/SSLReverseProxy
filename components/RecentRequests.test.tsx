import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, type RecentRequest, type RecentRequests as Page } from '../services/apiClient';
import RecentRequests from './RecentRequests';

const mocks = vi.hoisted(() => ({ requests: vi.fn() }));

vi.mock('../services/apiClient', async (importOriginal) => {
  const real = await importOriginal<typeof import('../services/apiClient')>();
  return { ...real, api: { ...real.api, servers: { ...real.api.servers, rules: { ...real.api.servers.rules, requests: mocks.requests } } } };
});

const entry = (seq: number, over: Partial<RecentRequest> = {}): RecentRequest => ({
  seq, at: '2026-10-21T09:08:07Z', method: 'GET', host: 'app.example.com', path: `/p${seq}`, status: 200,
  durationMs: 12.5, size: 2048, clientIp: '198.51.100.7', ...over,
});
const page = (requests: RecentRequest[], next: number | null = null, message: string | null = null): Page => ({ requests, next, message });

const rows = () => within(screen.getByRole('table', { name: 'Recent requests' })).getAllByRole('row').slice(1);

// A returned function would run as a cleanup hook.
beforeEach(() => { mocks.requests.mockReset(); });
afterEach(cleanup);

describe('RecentRequests', () => {
  it('lists the newest page for the rule', async () => {
    mocks.requests.mockResolvedValue(page([entry(2, { status: 502, clientIp: null }), entry(1)]));
    render(<RecentRequests serverId="s" ruleId="r" refreshMs={0} />);
    await waitFor(() => expect(rows()).toHaveLength(2));
    expect(mocks.requests).toHaveBeenCalledWith('s', 'r', { take: 50, status: undefined, before: undefined });
    expect(rows()[0].textContent).toContain('/p2');
    expect(rows()[0].textContent).toContain('502');
    expect(rows()[0].textContent).toContain('unknown');
    expect(rows()[1].textContent).toContain('12.5 ms');
    expect(rows()[1].textContent).toContain('2.0 kB');
  });

  it('filters by status class from the top', async () => {
    mocks.requests.mockResolvedValueOnce(page([entry(2), entry(1)]));
    render(<RecentRequests serverId="s" ruleId="r" refreshMs={0} />);
    await waitFor(() => expect(rows()).toHaveLength(2));
    mocks.requests.mockResolvedValueOnce(page([entry(1, { status: 503 })]));
    fireEvent.click(within(screen.getByRole('radiogroup', { name: 'Status' })).getByRole('radio', { name: '5xx' }));
    await waitFor(() => expect(rows()).toHaveLength(1));
    expect(mocks.requests).toHaveBeenLastCalledWith('s', 'r', { take: 50, status: '5xx', before: undefined });
  });

  it('appends older pages, and stops refreshing while they are shown', async () => {
    mocks.requests.mockImplementation(async (_s: string, _r: string, q: { before?: number }) =>
      q.before === undefined ? page([entry(3)], 3) : page([entry(1)]));
    render(<RecentRequests serverId="s" ruleId="r" refreshMs={30} />);
    await waitFor(() => expect(rows()).toHaveLength(1));
    fireEvent.click(screen.getByRole('button', { name: 'Older requests' }));
    await waitFor(() => expect(rows()).toHaveLength(2));
    expect(mocks.requests).toHaveBeenLastCalledWith('s', 'r', { take: 50, status: undefined, before: 3 });
    expect(screen.queryByRole('button', { name: 'Older requests' })).toBeNull();
    const calls = mocks.requests.mock.calls.length;
    await new Promise(r => setTimeout(r, 120));
    expect(mocks.requests.mock.calls.length).toBe(calls);
    expect(rows()).toHaveLength(2);
  });

  it('refreshes the newest page on its own', async () => {
    mocks.requests.mockResolvedValue(page([entry(2), entry(1)])).mockResolvedValueOnce(page([entry(1)]));
    render(<RecentRequests serverId="s" ruleId="r" refreshMs={30} />);
    await waitFor(() => expect(rows()).toHaveLength(1));
    await waitFor(() => expect(rows()).toHaveLength(2));
    expect(rows()[0].textContent).toContain('/p2');
  });

  it("says why a rule's requests are not recorded, or that there were none", async () => {
    mocks.requests.mockResolvedValueOnce(page([], null, 'This host skips the access log, so its requests are not recorded.'));
    render(<RecentRequests serverId="s" ruleId="r" refreshMs={0} />);
    expect((await screen.findByRole('status')).textContent).toBe('This host skips the access log, so its requests are not recorded.');
    cleanup();

    mocks.requests.mockResolvedValueOnce(page([]));
    render(<RecentRequests serverId="s" ruleId="r" refreshMs={0} />);
    await screen.findByText('No requests in the last 24 hours.');
  });

  it('shows a failed load', async () => {
    mocks.requests.mockRejectedValueOnce(new ApiError(403, 'Forbidden'));
    render(<RecentRequests serverId="s" ruleId="r" refreshMs={0} />);
    expect((await screen.findByRole('alert')).textContent).toBeTruthy();
  });
});
