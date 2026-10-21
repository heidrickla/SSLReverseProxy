import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ApiKeyOptions } from '../services/apiClient';
import ApiKeys from './ApiKeys';

const mocks = vi.hoisted(() => ({ list: vi.fn(), options: vi.fn(), owners: vi.fn() }));

vi.mock('../services/apiClient', async (importOriginal) => {
  const real = await importOriginal<typeof import('../services/apiClient')>();
  return { ...real, api: { ...real.api, apiKeys: { ...real.api.apiKeys, ...mocks } } };
});

// A dashboard signed in with a key holding ApiKeyManage and not UserWrite: the user list is empty.
vi.mock('../contexts/AuthContext', () => ({
  useAuth: () => ({
    currentUser: { id: 'u-me', name: 'Key manager', role: 'Admin', permissions: ['ServerRead', 'ApiKeyManage'] },
    users: [],
  }),
}));

const options: ApiKeyOptions = {
  lifetimeDays: [1, 7, 30, 90, 365], defaultLifetimeDays: 30, maxLifetimeDays: 365,
  presets: [{ id: 'full', name: 'Full access', description: 'All.', scopes: null }],
  permissions: ['ServerRead', 'ApiKeyManage'],
  roles: { Viewer: ['ServerRead'], Admin: ['ServerRead', 'ApiKeyManage'] },
};

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('ApiKeys', () => {
  it('offers every owner the keys endpoint lists, without the user list', async () => {
    mocks.list.mockResolvedValue([]);
    mocks.options.mockResolvedValue(options);
    mocks.owners.mockResolvedValue([
      { id: 'u-me', name: 'Key manager', role: 'Admin' },
      { id: 'u-guest', name: 'Guest', role: 'Viewer' },
    ]);
    render(<ApiKeys />);
    await waitFor(() => expect(mocks.owners).toHaveBeenCalled());
    fireEvent.click((await screen.findAllByRole('button', { name: 'New key' }))[0]);
    const owner = await screen.findByLabelText('Owner');
    expect(within(owner).getAllByRole('option').map(o => o.textContent)).toEqual(['Key manager (Admin)', 'Guest (Viewer)']);
  });
});
