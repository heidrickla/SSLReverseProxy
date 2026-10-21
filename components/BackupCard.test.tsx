import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, type BackupDryRun } from '../services/apiClient';
import BackupCard, { backupFileName, summarize } from './BackupCard';

const mocks = vi.hoisted(() => ({ export: vi.fn(), dryRun: vi.fn(), import: vi.fn() }));

vi.mock('../services/apiClient', async (importOriginal) => {
  const real = await importOriginal<typeof import('../services/apiClient')>();
  return { ...real, api: { ...real.api, backup: { export: mocks.export, dryRun: mocks.dryRun, import: mocks.import } } };
});

const document = { formatVersion: 1, servers: [], certificates: [] };
const dryRun = (over: Partial<BackupDryRun> = {}): BackupDryRun => ({
  mode: 'merge', unchanged: 2, problems: {}, revision: 'r1',
  changes: [
    { kind: 'rule', action: 'update', id: 'r', name: 'app.example.com on Web', fields: [{ field: 'upstreamUrl', before: '"http://10.0.0.5"', after: '"http://10.0.0.9"' }] },
    { kind: 'server', action: 'add', id: 's', name: 'Docs', fields: [] },
  ],
  preview: { runningAvailable: true, message: null, truncated: false, digest: 'd', changes: [
    { group: 'app.example.com (https)', kind: 'changed', path: '/handle/reverse_proxy/upstreams/0/dial', before: '"10.0.0.5:80"', after: '"10.0.0.9:80"' },
  ] },
  ...over,
});

const NOW = new Date('2026-10-21T09:08:07Z');

const choose = async (content: string, name = 'backup.json') => {
  const input = screen.getByLabelText('Backup file');
  fireEvent.change(input, { target: { files: [new File([content], name, { type: 'application/json' })] } });
  await waitFor(() => expect((screen.getByRole('button', { name: 'Check file' }) as HTMLButtonElement).disabled).toBe(false));
};

const checked = async (dry = dryRun()) => {
  mocks.dryRun.mockResolvedValueOnce(dry);
  render(<BackupCard now={() => NOW} />);
  await choose(JSON.stringify(document));
  fireEvent.click(screen.getByRole('button', { name: 'Check file' }));
  await screen.findByText(summarize(dry));
};

beforeEach(() => { mocks.export.mockReset(); mocks.dryRun.mockReset(); mocks.import.mockReset(); });
afterEach(cleanup);

describe('BackupCard', () => {
  it('downloads the export under a dated name', async () => {
    mocks.export.mockResolvedValue(document);
    const urls = { create: vi.fn(() => 'blob:x'), revoke: vi.fn() };
    Object.assign(URL, { createObjectURL: urls.create, revokeObjectURL: urls.revoke });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      expect(this.download).toBe('sslrp-backup-20261021-090807.json');
      expect(this.href).toBe('blob:x');
    });
    render(<BackupCard now={() => NOW} />);
    fireEvent.click(screen.getByRole('button', { name: 'Export backup' }));
    await waitFor(() => expect(click).toHaveBeenCalled());
    expect(urls.revoke).toHaveBeenCalledWith('blob:x');
    click.mockRestore();
  });

  it('names the file when it is not JSON, and checks nothing', async () => {
    render(<BackupCard now={() => NOW} />);
    const input = screen.getByLabelText('Backup file');
    fireEvent.change(input, { target: { files: [new File(['not json'], 'notes.txt')] } });
    expect((await screen.findByRole('alert')).textContent).toBe('notes.txt is not JSON.');
    expect((screen.getByRole('button', { name: 'Check file' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('shows the dry run, then imports with its mode and revision', async () => {
    await checked();
    expect(mocks.dryRun).toHaveBeenCalledWith(document, 'merge');
    const list = screen.getByRole('list', { name: 'Import changes' });
    expect(within(list).getByText('app.example.com on Web')).toBeTruthy();
    expect(within(list).getByText('"http://10.0.0.5" → "http://10.0.0.9"')).toBeTruthy();
    expect(screen.getByRole('region', { name: 'app.example.com (https)' })).toBeTruthy();

    mocks.import.mockResolvedValue({ added: 1, updated: 1, removed: 0, unchanged: 2, reloadNeeded: true, proxy: null });
    fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    expect((await screen.findByRole('status')).textContent).toMatch(/1 added, 1 changed, 0 removed\. Rule changes take effect at the next Reload\./);
    expect(mocks.import).toHaveBeenCalledWith(document, 'merge', 'r1');
  });

  it('lists the problems and will not import', async () => {
    await checked(dryRun({ problems: { 'servers[0].rules[1].upstreamUrl': ['Link-local / metadata addresses are not allowed as upstreams.'] }, preview: null }));
    expect(screen.getByRole('alert', { name: 'Problems' }).textContent).toContain('servers[0].rules[1].upstreamUrl: Link-local');
    expect((screen.getByRole('button', { name: 'Import' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('checks in the mode picked, and marks an import that removes rows', async () => {
    mocks.dryRun.mockResolvedValueOnce(dryRun({ mode: 'replace', changes: [{ kind: 'server', action: 'remove', id: 'x', name: 'Old', fields: [] }] }));
    render(<BackupCard now={() => NOW} />);
    await choose(JSON.stringify(document));
    fireEvent.click(within(screen.getByRole('radiogroup', { name: 'Import mode' })).getByRole('radio', { name: /^Replace/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Check file' }));
    await screen.findByText(/1 to remove/);
    expect(mocks.dryRun).toHaveBeenCalledWith(document, 'replace');
    expect(screen.getByRole('button', { name: 'Import' }).className).toContain('bg-danger');
  });

  it('drops the dry run when the mode changes', async () => {
    await checked();
    fireEvent.click(screen.getByRole('radio', { name: /^Replace/ }));
    expect(screen.queryByRole('button', { name: 'Import' })).toBeNull();
  });

  it('on a stale dry run, checks again and imports only with the new revision', async () => {
    await checked();
    mocks.import.mockRejectedValueOnce(new ApiError(409, 'The dry run is out of date'));
    mocks.dryRun.mockResolvedValueOnce(dryRun({ revision: 'r2', unchanged: 5 }));
    fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    expect((await screen.findByRole('status')).textContent).toMatch(/rows changed after the check/);
    await screen.findByText(/5 unchanged/);

    mocks.import.mockResolvedValueOnce({ added: 0, updated: 1, removed: 0, unchanged: 5, reloadNeeded: true, proxy: null });
    fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    await screen.findByText(/Imported:/);
    expect(mocks.import.mock.calls.map(c => c[2])).toEqual(['r1', 'r2']);
  });

  it('says when Caddy refused the certificate changes', async () => {
    await checked();
    mocks.import.mockResolvedValue({ added: 1, updated: 0, removed: 0, unchanged: 0, reloadNeeded: false, proxy: { state: 'Faulted', engine: 'caddy', processId: null, startedAt: null, activeRuleCount: 0, message: 'refused' } });
    fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    expect((await screen.findByRole('status')).textContent).toMatch(/Caddy did not take the certificate changes: refused\./);
  });
});

describe('backup helpers', () => {
  it('names the file by the UTC time', () => {
    expect(backupFileName(NOW)).toBe('sslrp-backup-20261021-090807.json');
  });

  it('counts each action', () => {
    expect(summarize(dryRun())).toBe('1 to add, 1 to change, 0 to remove, 2 unchanged.');
  });
});
