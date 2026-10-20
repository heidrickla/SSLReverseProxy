import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../services/apiClient';
import PasskeysCard from './PasskeysCard';

const mocks = vi.hoisted(() => ({
  list: vi.fn(), options: vi.fn(), register: vi.fn(), remove: vi.fn(), create: vi.fn(), logout: vi.fn(),
}));

vi.mock('../services/apiClient', async (importOriginal) => {
  const real = await importOriginal<typeof import('../services/apiClient')>();
  return {
    ...real,
    api: { ...real.api, passkeys: { list: mocks.list, options: mocks.options, register: mocks.register, remove: mocks.remove } },
  };
});

vi.mock('../utils/webauthn', async (importOriginal) => {
  const real = await importOriginal<typeof import('../utils/webauthn')>();
  return { ...real, createPasskey: mocks.create, passkeysSupported: () => true };
});

vi.mock('../contexts/AuthContext', () => ({ useAuth: () => ({ logout: mocks.logout }) }));

const laptop = { id: 'p1', name: 'Laptop', createdAt: '2026-10-20T10:00:00Z', lastUsedAt: null, backedUp: true };

beforeEach(() => {
  mocks.list.mockResolvedValue([laptop]);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.restoreAllMocks();
});

describe('PasskeysCard', () => {
  it('lists passkeys and registers a new one under the given name', async () => {
    mocks.options.mockResolvedValue({ handle: 'h1', options: { challenge: 'AQ' } });
    mocks.create.mockResolvedValue({ id: 'cred' });
    mocks.register.mockResolvedValue({});
    render(<PasskeysCard />);
    expect(await screen.findByText('Laptop')).toBeTruthy();
    expect(screen.getByText(/not used yet/)).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: '  Phone ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add passkey' }));
    await waitFor(() => expect(mocks.register).toHaveBeenCalledWith('h1', 'Phone', { id: 'cred' }));
    expect(mocks.create).toHaveBeenCalledWith({ challenge: 'AQ' });
    await waitFor(() => expect(mocks.list).toHaveBeenCalledTimes(2));
  });

  it('shows nothing when the browser prompt is dismissed', async () => {
    mocks.options.mockResolvedValue({ handle: 'h1', options: {} });
    mocks.create.mockRejectedValue(new DOMException('dismissed', 'NotAllowedError'));
    render(<PasskeysCard />);
    await screen.findByText('Laptop');
    fireEvent.click(screen.getByRole('button', { name: 'Add passkey' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Add passkey' })).toHaveProperty('disabled', false));
    expect(screen.queryByRole('alert')).toBeNull();
    expect(mocks.register).not.toHaveBeenCalled();
  });

  it('shows the server refusal', async () => {
    mocks.options.mockResolvedValue({ handle: 'h1', options: {} });
    mocks.create.mockResolvedValue({});
    mocks.register.mockRejectedValue(new ApiError(400, 'The passkey could not be verified.'));
    render(<PasskeysCard />);
    await screen.findByText('Laptop');
    fireEvent.click(screen.getByRole('button', { name: 'Add passkey' }));
    expect((await screen.findByRole('alert')).textContent).toBe('The passkey could not be verified.');
  });

  it('removes after confirmation, and signs out when that ended the session', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    mocks.remove.mockResolvedValue(undefined);
    render(<PasskeysCard />);
    await screen.findByText('Laptop');
    mocks.list.mockRejectedValue(new ApiError(401, 'Unauthorized'));
    fireEvent.click(screen.getByRole('button', { name: 'Remove passkey Laptop' }));
    await waitFor(() => expect(mocks.logout).toHaveBeenCalled());
    expect(mocks.remove).toHaveBeenCalledWith('p1');
  });

  it('keeps the passkey when removal is not confirmed', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    render(<PasskeysCard />);
    await screen.findByText('Laptop');
    fireEvent.click(screen.getByRole('button', { name: 'Remove passkey Laptop' }));
    expect(mocks.remove).not.toHaveBeenCalled();
  });
});
