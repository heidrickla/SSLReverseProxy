import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../services/apiClient';
import AlertsCard, { describeDelivery } from './AlertsCard';

const mocks = vi.hoisted(() => ({ list: vi.fn(), test: vi.fn() }));

vi.mock('../services/apiClient', async (importOriginal) => {
  const real = await importOriginal<typeof import('../services/apiClient')>();
  return { ...real, api: { ...real.api, alerts: { list: mocks.list, test: mocks.test } } };
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('AlertsCard', () => {
  it('lists targets and sends a test to the one asked for', async () => {
    mocks.list.mockResolvedValue({
      targets: [
        { name: 'ha', kind: 'webhook', events: [], problem: null },
        { name: 'phone', kind: 'ntfy', events: ['server.down'], problem: null },
        { name: 'old', kind: 'email', events: [], problem: 'Kind must be webhook or ntfy.' },
      ],
      events: ['server.down'],
    });
    mocks.test.mockResolvedValue([{ target: 'ha', delivered: true, status: 200, error: null, attempts: 1 }]);
    render(<AlertsCard />);

    expect(await screen.findAllByText('All events')).toHaveLength(2);
    expect(screen.getByText('server.down')).toBeTruthy();
    expect(screen.getByText('Kind must be webhook or ntfy.')).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Send a test alert to old' }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(screen.getByRole('button', { name: 'Send a test alert to ha' }));
    await waitFor(() => expect(mocks.test).toHaveBeenCalledWith('ha'));
    expect((await screen.findByRole('status')).textContent).toBe('Delivered (HTTP 200)');
  });

  it('says when no target is configured, and shows a refused test', async () => {
    mocks.list.mockResolvedValueOnce({ targets: [], events: [] });
    render(<AlertsCard />);
    expect(await screen.findByText('No alert targets are configured.')).toBeTruthy();
    cleanup();

    mocks.list.mockResolvedValueOnce({ targets: [{ name: 'ha', kind: 'webhook', events: [], problem: null }], events: [] });
    mocks.test.mockRejectedValue(new ApiError(404, "No alert target is named 'ha'."));
    render(<AlertsCard />);
    fireEvent.click(await screen.findByRole('button', { name: 'Send a test alert to ha' }));
    expect((await screen.findByRole('status')).textContent).toBe("Not delivered: No alert target is named 'ha'.");
  });

  it('describes failed deliveries with the try count', () => {
    expect(describeDelivery({ target: 'ha', delivered: false, status: 503, error: 'HTTP 503', attempts: 3 }))
      .toBe('Not delivered: HTTP 503 after 3 tries');
  });
});
