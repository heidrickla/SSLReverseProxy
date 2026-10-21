import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, type ProxyPreview } from '../services/apiClient';
import PushPreview, { groupChanges } from './PushPreview';

const preview = (over: Partial<ProxyPreview> = {}): ProxyPreview => ({
  runningAvailable: true, message: null, truncated: false, digest: 'd1',
  changes: [
    { group: 'b.example.com (https)', kind: 'added', path: '', before: null, after: '{"handle":{}}' },
    { group: 'a.example.com (https)', kind: 'changed', path: '/handle/reverse_proxy/upstreams/0/dial', before: '"10.0.0.5:80"', after: '"10.0.0.6:80"' },
    { group: 'b.example.com (https)', kind: 'changed', path: '/handle/authentication/providers/http_basic/accounts/0/password', before: '[masked]', after: '[masked]' },
  ],
  ...over,
});

const stale = () => new ApiError(409, 'The preview is out of date', { title: 'The preview is out of date', detail: 'Preview again.' });

const renderPreview = (load: () => Promise<ProxyPreview>, apply = vi.fn().mockResolvedValue({})) => {
  const onApplied = vi.fn();
  render(<PushPreview load={load} apply={apply} applyLabel="Reload" onApplied={onApplied} onCancel={() => undefined} />);
  return { apply, onApplied };
};

afterEach(cleanup);

describe('PushPreview', () => {
  it('lists the changes by group, in the order the server gave them', async () => {
    renderPreview(() => Promise.resolve(preview()));
    const list = await screen.findByLabelText('Changes');
    const groups = within(list).getAllByRole('heading').map(h => h.textContent);
    expect(groups).toEqual(['b.example.com (https)', 'a.example.com (https)']);
    const a = within(list).getByRole('region', { name: 'a.example.com (https)' });
    expect(within(a).getByText('changed')).toBeTruthy();
    expect(within(a).getByLabelText('Before').textContent).toBe('"10.0.0.5:80"');
    expect(within(a).getByLabelText('After').textContent).toBe('"10.0.0.6:80"');
    const b = within(list).getByRole('region', { name: 'b.example.com (https)' });
    expect(within(b).getByText('whole entry')).toBeTruthy();
    expect(within(b).getAllByLabelText('Before').map(e => e.textContent)).toEqual(['[masked]']);
    expect(screen.getByText(/3 changes to Caddy's running config/)).toBeTruthy();
  });

  it('says so when Caddy already runs the config', async () => {
    renderPreview(() => Promise.resolve(preview({ changes: [] })));
    expect(await screen.findByText(/No changes: Caddy already runs this config/)).toBeTruthy();
    expect(screen.queryByLabelText('Changes')).toBeNull();
  });

  it('shows the server message when there is no running config', async () => {
    renderPreview(() => Promise.resolve(preview({ runningAvailable: false, message: 'Caddy is not running.', changes: [] })));
    expect(await screen.findByText('Caddy is not running.')).toBeTruthy();
    expect(screen.queryByText(/No changes/)).toBeNull();
  });

  it('says when the list was cut', async () => {
    renderPreview(() => Promise.resolve(preview({ truncated: true })));
    expect(await screen.findByText(/Only the first ones are listed/)).toBeTruthy();
  });

  it('applies with the digest of the preview on screen', async () => {
    const { apply, onApplied } = renderPreview(() => Promise.resolve(preview()));
    await screen.findByLabelText('Changes');
    fireEvent.click(screen.getByRole('button', { name: 'Reload' }));
    await waitFor(() => expect(onApplied).toHaveBeenCalled());
    expect(apply).toHaveBeenCalledWith('d1');
  });

  it('cannot apply before the preview has loaded', () => {
    renderPreview(() => new Promise(() => undefined));
    expect((screen.getByRole('button', { name: 'Reload' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('on a stale preview, shows the new one and applies only with its digest', async () => {
    const load = vi.fn()
      .mockResolvedValueOnce(preview())
      .mockResolvedValueOnce(preview({ digest: 'd2', changes: [{ group: 'c.example.com (https)', kind: 'added', path: '', before: null, after: '{}' }] }));
    const apply = vi.fn().mockRejectedValueOnce(stale()).mockResolvedValueOnce({});
    const { onApplied } = renderPreview(load, apply);
    await screen.findByLabelText('Changes');

    fireEvent.click(screen.getByRole('button', { name: 'Reload' }));
    expect((await screen.findByRole('status')).textContent).toMatch(/changed after this preview/);
    await screen.findByRole('region', { name: 'c.example.com (https)' });
    expect(onApplied).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'Reload' }));
    await waitFor(() => expect(onApplied).toHaveBeenCalled());
    expect(apply.mock.calls.map(c => c[0])).toEqual(['d1', 'd2']);
  });

  it('reports any other failure and stays open', async () => {
    const apply = vi.fn().mockRejectedValue(new ApiError(500, 'Caddy refused the config'));
    const { onApplied } = renderPreview(() => Promise.resolve(preview()), apply);
    await screen.findByLabelText('Changes');
    fireEvent.click(screen.getByRole('button', { name: 'Reload' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/Caddy refused the config/);
    expect(onApplied).not.toHaveBeenCalled();
  });

  it('reports a config that cannot be built, with the reason', async () => {
    renderPreview(() => Promise.reject(new ApiError(409, 'Config cannot be built', { title: 'Config cannot be built', detail: "Rule 'a.example.com' has '{'." })));
    expect((await screen.findByRole('alert')).textContent).toBe("Config cannot be built: Rule 'a.example.com' has '{'.");
    expect((screen.getByRole('button', { name: 'Reload' }) as HTMLButtonElement).disabled).toBe(true);
  });
});

describe('groupChanges', () => {
  it('keeps first-seen order and every change', () => {
    const g = groupChanges(preview().changes);
    expect(g.map(([name, items]) => [name, items.length])).toEqual([['b.example.com (https)', 2], ['a.example.com (https)', 1]]);
  });
});
