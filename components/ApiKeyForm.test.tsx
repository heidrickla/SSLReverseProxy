import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ApiKey, ApiKeyOptions } from '../services/apiClient';
import ApiKeyForm from './ApiKeyForm';
import { expiresIn, expiryFor, keptLifetime, keyState, matchPreset, scopeProblem } from '../utils/apiKeys';

const mocks = vi.hoisted(() => ({ create: vi.fn(), rotate: vi.fn() }));

vi.mock('../services/apiClient', async (importOriginal) => {
  const real = await importOriginal<typeof import('../services/apiClient')>();
  return { ...real, api: { ...real.api, apiKeys: { ...real.api.apiKeys, create: mocks.create, rotate: mocks.rotate } } };
});

const all = ['ProxyControl', 'ServerRead', 'ServerWrite', 'RuleWrite', 'CertRead', 'CertWrite', 'UserWrite',
  'ApiKeyManage', 'AuditRead', 'AlertManage', 'ProxyReload', 'CertRenew'];
const options: ApiKeyOptions = {
  lifetimeDays: [1, 7, 30, 90, 365], defaultLifetimeDays: 30, maxLifetimeDays: 365,
  presets: [
    { id: 'read-only', name: 'Read only', description: 'Reads.', scopes: ['ServerRead', 'CertRead'] },
    { id: 'home-assistant', name: 'Home Assistant', description: 'HA.', scopes: ['ServerRead', 'CertRead', 'ProxyReload', 'CertRenew'] },
    { id: 'rules-editor', name: 'Rules editor', description: 'Rules.', scopes: ['ServerRead', 'RuleWrite', 'ProxyReload'] },
    { id: 'full', name: 'Full access', description: 'All.', scopes: null },
  ],
  permissions: all,
  roles: {
    Viewer: ['ServerRead', 'CertRead', 'AuditRead'],
    Editor: ['ProxyControl', 'ServerRead', 'ServerWrite', 'RuleWrite', 'CertRead', 'CertWrite', 'AuditRead', 'ProxyReload', 'CertRenew'],
    Admin: all,
  },
};
const owners = [
  { id: 'u-admin', name: 'Lewis', role: 'Admin' },
  { id: 'u-viewer', name: 'Guest', role: 'Viewer' },
];
const admin = { permissions: all };
const NOW = new Date('2026-10-21T12:00:00Z');
const now = () => NOW;

const renderForm = (props: Partial<React.ComponentProps<typeof ApiKeyForm>> = {}) => {
  const onIssued = vi.fn();
  render(<ApiKeyForm options={options} owners={owners} defaultOwnerId="u-admin" caller={admin}
    onCancel={() => undefined} onIssued={onIssued} now={now} {...props} />);
  return { onIssued };
};

const radio = (group: string, name: string) =>
  within(screen.getByRole('radiogroup', { name: group })).getByRole('radio', { name: new RegExp(`^${name}`) });
const granted = () => within(screen.getByRole('list', { name: 'Granted permissions' })).getAllByRole('listitem').map(li => li.textContent);

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('ApiKeyForm', () => {
  it('issues a Home Assistant key for 90 days with two clicks', async () => {
    mocks.create.mockResolvedValue({ id: 'k1', name: 'HA', token: 'srp.a.b', expiresAt: null, scopes: null });
    const { onIssued } = renderForm();
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: ' HA ' } });
    fireEvent.click(radio('Expires after', '90 days'));
    fireEvent.click(radio('Scope', 'Home Assistant'));
    expect(radio('Scope', 'Home Assistant').getAttribute('aria-checked')).toBe('true');
    expect(granted()).toEqual(['Read servers, rules and traffic', 'Read certificates', 'Preview, validate and reload', 'Renew certificates']);

    fireEvent.click(screen.getByRole('button', { name: 'Issue key' }));
    await waitFor(() => expect(mocks.create).toHaveBeenCalledWith('u-admin', 'HA',
      { lifetimeDays: 90, scopes: ['ServerRead', 'CertRead', 'ProxyReload', 'CertRenew'] }));
    expect(onIssued).toHaveBeenCalled();
  });

  it('defaults to Read only for 30 days', () => {
    renderForm();
    expect(radio('Expires after', '30 days').getAttribute('aria-checked')).toBe('true');
    expect(radio('Scope', 'Read only').getAttribute('aria-checked')).toBe('true');
    expect(screen.getByText(/^Expires .+\.$/).textContent).toContain(new Date(NOW.getTime() + 30 * 86_400_000).toLocaleString());
  });

  it('offers no never-expiring choice', () => {
    renderForm();
    const choices = within(screen.getByRole('radiogroup', { name: 'Expires after' })).getAllByRole('radio').map(r => r.textContent);
    expect(choices).toEqual(['1 day', '7 days', '30 days', '90 days', '1 year', 'Custom date']);
  });

  it('sends a picked date as the end of that day', async () => {
    mocks.create.mockResolvedValue({ id: 'k1', name: 'x', token: 't', expiresAt: null, scopes: null });
    renderForm();
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'dated' } });
    fireEvent.click(radio('Expires after', 'Custom date'));
    fireEvent.change(screen.getByLabelText('Expiry date'), { target: { value: '2026-12-01' } });
    fireEvent.click(screen.getByRole('button', { name: 'Issue key' }));
    await waitFor(() => expect(mocks.create).toHaveBeenCalled());
    const grant = mocks.create.mock.calls[0][2];
    expect(grant.lifetimeDays).toBeUndefined();
    expect(new Date(grant.expiresAt).getTime()).toBe(new Date(2026, 11, 1, 23, 59).getTime());
  });

  it('disables presets the owner\'s role cannot hold and says why', () => {
    renderForm();
    fireEvent.change(screen.getByLabelText('Owner'), { target: { value: 'u-viewer' } });
    expect(radio('Scope', 'Read only')).toHaveProperty('disabled', false);
    expect(radio('Scope', 'Home Assistant')).toHaveProperty('disabled', true);
    expect(radio('Scope', 'Home Assistant').textContent).toContain('Viewer role');
    expect(radio('Scope', 'Full access')).toHaveProperty('disabled', false);
  });

  it('builds a custom set from the chosen preset, one permission at a time', async () => {
    mocks.create.mockResolvedValue({ id: 'k1', name: 'x', token: 't', expiresAt: null, scopes: null });
    renderForm();
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'custom' } });
    fireEvent.click(radio('Scope', 'Rules editor'));
    fireEvent.click(radio('Scope', 'Custom'));
    const box = (label: string) => screen.getByRole('checkbox', { name: label }) as HTMLInputElement;
    expect(box('Edit rules').checked).toBe(true);
    fireEvent.click(box('Edit rules'));
    fireEvent.click(box('Read the audit log'));
    expect(granted()).toEqual(['Read servers, rules and traffic', 'Read the audit log', 'Preview, validate and reload']);
    fireEvent.click(screen.getByRole('button', { name: 'Issue key' }));
    await waitFor(() => expect(mocks.create.mock.calls[0][2].scopes).toEqual(['ServerRead', 'AuditRead', 'ProxyReload']));
  });

  it('blocks a custom permission outside the owner\'s role', () => {
    renderForm();
    fireEvent.change(screen.getByLabelText('Owner'), { target: { value: 'u-viewer' } });
    fireEvent.click(radio('Scope', 'Custom'));
    expect(screen.getByRole('checkbox', { name: 'Edit rules' })).toHaveProperty('disabled', true);
    expect(screen.getByRole('checkbox', { name: 'Read the audit log' })).toHaveProperty('disabled', false);
  });

  it('refuses an empty custom set', () => {
    renderForm();
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'empty' } });
    fireEvent.click(radio('Scope', 'Custom'));
    for (const b of screen.getAllByRole('checkbox') as HTMLInputElement[]) if (b.checked) fireEvent.click(b);
    expect(screen.getByRole('alert').textContent).toContain('at least one');
    expect(screen.getByRole('button', { name: 'Issue key' })).toHaveProperty('disabled', true);
  });

  it('keeps a narrower caller to what it holds, full access included', () => {
    renderForm({ caller: { permissions: ['ServerRead', 'CertRead', 'ApiKeyManage'] } });
    expect(radio('Scope', 'Home Assistant')).toHaveProperty('disabled', true);
    expect(radio('Scope', 'Read only')).toHaveProperty('disabled', false);
    fireEvent.click(radio('Scope', 'Full access'));
    expect(granted()).toEqual(['Read servers, rules and traffic', 'Read certificates', 'Manage API keys']);
  });

  it('says a full-access key is fixed when issued', () => {
    renderForm();
    fireEvent.click(radio('Scope', 'Full access'));
    expect(screen.getByText(/A later promotion of Lewis adds nothing/)).toBeTruthy();
    expect(granted()).toHaveLength(all.length);
  });

  it('rotates a key holding its owner\'s whole role as full access', async () => {
    mocks.rotate.mockResolvedValue({ id: 'k2', name: 'All', token: 't', expiresAt: null, scopes: all });
    const key: ApiKey = {
      id: 'k1', name: 'All', prefix: 'abcd', userId: 'u-viewer', userName: 'Guest', createdAt: '2026-10-14T12:00:00Z',
      expiresAt: '2026-10-21T12:00:00Z', revokedAt: null, lastUsedAt: null, scopes: ['AuditRead', 'CertRead', 'ServerRead'],
    };
    renderForm({ rotating: key, rotatingOwner: owners[1] });
    expect(radio('Scope', 'Full access').getAttribute('aria-checked')).toBe('true');
    fireEvent.click(screen.getByRole('button', { name: 'Rotate key' }));
    await waitFor(() => expect(mocks.rotate).toHaveBeenCalledWith('k1', { lifetimeDays: 7, scopes: null }));
  });

  it('rotates with the old key\'s scope and lifetime selected', async () => {
    mocks.rotate.mockResolvedValue({ id: 'k2', name: 'HA', token: 't', expiresAt: null, scopes: null });
    const key: ApiKey = {
      id: 'k1', name: 'HA', prefix: 'abcd', userId: 'u-admin', userName: 'Lewis', createdAt: '2026-07-23T12:00:00Z',
      expiresAt: '2026-10-21T12:00:00Z', revokedAt: null, lastUsedAt: null,
      scopes: ['ServerRead', 'CertRead', 'ProxyReload', 'CertRenew'],
    };
    renderForm({ rotating: key, rotatingOwner: owners[0] });
    expect(screen.queryByLabelText('Name')).toBeNull();
    expect(radio('Scope', 'Home Assistant').getAttribute('aria-checked')).toBe('true');
    expect(radio('Expires after', '90 days').getAttribute('aria-checked')).toBe('true');
    fireEvent.click(screen.getByRole('button', { name: 'Rotate key' }));
    await waitFor(() => expect(mocks.rotate).toHaveBeenCalledWith('k1',
      { lifetimeDays: 90, scopes: ['ServerRead', 'CertRead', 'ProxyReload', 'CertRenew'] }));
  });
});

describe('api key helpers', () => {
  it('holds a picked date inside the limit and refuses the past', () => {
    expect(expiryFor({ kind: 'date', date: '2030-01-01' }, NOW, 365)!.getTime()).toBe(NOW.getTime() + 365 * 86_400_000 - 60_000);
    expect(expiryFor({ kind: 'date', date: '2026-10-01' }, NOW, 365)).toBeNull();
    expect(expiryFor({ kind: 'date', date: 'nonsense' }, NOW, 365)).toBeNull();
  });

  it('matches presets exactly, order aside', () => {
    expect(matchPreset(['CertRead', 'ServerRead'], options.presets)?.id).toBe('read-only');
    expect(matchPreset(['ServerRead'], options.presets)).toBeNull();
    expect(matchPreset(null, options.presets)?.id).toBe('full');
    expect(matchPreset(options.roles.Viewer, options.presets)).toBeNull();
    expect(matchPreset([...options.roles.Viewer].reverse(), options.presets, options.roles.Viewer)?.id).toBe('full');
    expect(matchPreset(['ServerRead'], options.presets, options.roles.Viewer)).toBeNull();
  });

  it('names the problem with a scope set', () => {
    const viewer = { name: 'Guest', role: 'Viewer', permissions: options.roles.Viewer };
    expect(scopeProblem(['ServerRead'], viewer, admin)).toBeNull();
    expect(scopeProblem(['RuleWrite'], viewer, admin)).toContain('Viewer');
    expect(scopeProblem(null, viewer, { permissions: ['ServerRead'] })).toBeNull();
    expect(scopeProblem(null, viewer, { permissions: ['UserWrite'] })).toContain('none of the Viewer');
  });

  it('reads a key\'s state and time left', () => {
    expect(keyState({ revokedAt: '2026-10-01T00:00:00Z', expiresAt: null }, NOW)).toBe('revoked');
    expect(keyState({ revokedAt: null, expiresAt: '2026-10-25T00:00:00Z' }, NOW)).toBe('expiring');
    expect(keyState({ revokedAt: null, expiresAt: '2026-10-20T00:00:00Z' }, NOW)).toBe('expired');
    expect(keyState({ revokedAt: null, expiresAt: null }, NOW)).toBe('active');
    expect(expiresIn('2026-10-22T00:00:00Z', NOW)).toBe('in 12 hours');
    expect(expiresIn('2026-11-20T12:00:00Z', NOW)).toBe('in 30 days');
  });

  it('starts a rotation from the old lifetime, a date when it was custom', () => {
    expect(keptLifetime({ createdAt: '2026-01-01T00:00:00Z', expiresAt: '2026-01-08T00:00:00Z' }, options, NOW)).toEqual({ kind: 'days', days: 7 });
    expect(keptLifetime({ createdAt: '2026-01-01T00:00:00Z', expiresAt: '2026-02-15T00:00:00Z' }, options, NOW).kind).toBe('date');
    expect(keptLifetime({ createdAt: '2026-01-01T00:00:00Z', expiresAt: null }, options, NOW)).toEqual({ kind: 'days', days: 30 });
  });
});
