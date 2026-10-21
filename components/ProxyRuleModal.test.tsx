import React from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Rule } from '../services/apiClient';
import ProxyRuleModal from './ProxyRuleModal';

const AUD = '0123456789abcdef'.repeat(4);

const rule = (over: Partial<Rule> = {}): Rule => ({
  id: 'r', serverId: 's', domain: 'app.example.com', upstreamUrl: 'http://10.0.0.5', enableTls: true, enabled: true,
  allowedCidrs: null, deniedCidrs: null, rateLimitPerMinute: null, basicAuthEnabled: false, basicAuthUsername: null,
  hardening: {} as Rule['hardening'], routing: { pathPrefix: null, stripPathPrefix: false }, signIn: null, version: 1, ...over,
});

const onSave = vi.fn();
const open = (initial: Rule | null) =>
  render(<ProxyRuleModal isOpen onClose={() => {}} onSave={onSave} initialRule={initial} />);
const type = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } });
const save = () => fireEvent.click(screen.getByRole('button', { name: /Save changes|Add rule/ }));

beforeEach(() => {
  onSave.mockReset();
  vi.spyOn(window, 'alert').mockImplementation(() => {});
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('ProxyRuleModal sign-in', () => {
  it('sends a forward-auth provider with its address', () => {
    open(rule());
    expect(screen.queryByLabelText('Authelia address')).toBeNull();
    type('Sign-in', 'authelia');
    type('Authelia address', ' http://authelia:9091 ');
    save();
    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ signIn: { provider: 'authelia', verifierUrl: 'http://authelia:9091' } }));
  });

  it('sends Cloudflare Access with its team and audience, and no address', () => {
    open(null);
    type('Domain', 'app.example.com');
    type('Upstream address', 'http://10.0.0.5');
    type('Sign-in', 'cloudflare-access');
    expect(screen.queryByLabelText(/address$/, { selector: '#rule-verifierUrl' })).toBeNull();
    type('Team domain', 'home.cloudflareaccess.com');
    type('Application audience (AUD tag)', AUD);
    save();
    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({
      signIn: { provider: 'cloudflare-access', teamDomain: 'home.cloudflareaccess.com', audience: AUD },
    }));
  });

  it("shows a rule's sign-in, and None removes it", () => {
    open(rule({ signIn: { provider: 'oauth2-proxy', verifierUrl: 'http://oauth2:4180', teamDomain: null, audience: null } }));
    expect((screen.getByLabelText('Sign-in') as HTMLSelectElement).value).toBe('oauth2-proxy');
    expect((screen.getByLabelText('oauth2-proxy address') as HTMLInputElement).value).toBe('http://oauth2:4180');
    type('Sign-in', '');
    save();
    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ signIn: { provider: null } }));
  });

  it.each([
    ['authentik', { 'Authentik address': 'http://authentik:9000/outpost' }],
    ['oauth2-proxy', { 'oauth2-proxy address': '' }],
    ['cloudflare-access', { 'Team domain': 'home.example.com', 'Application audience (AUD tag)': AUD }],
    ['cloudflare-access', { 'Team domain': 'home.cloudflareaccess.com', 'Application audience (AUD tag)': 'abc' }],
  ])('refuses a %s sign-in that cannot work', (provider, fields) => {
    open(rule());
    type('Sign-in', provider);
    for (const [label, value] of Object.entries(fields)) type(label, value);
    save();
    expect(onSave).not.toHaveBeenCalled();
    expect(window.alert).toHaveBeenCalledOnce();
  });
});
