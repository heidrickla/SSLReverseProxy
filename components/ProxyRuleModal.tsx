import React, { useState, useEffect } from 'react';
import { Rule, RuleRouting, RuleSignInInput, SignInProvider } from '../services/apiClient';
import Modal from './Modal';
import Button from './Button';
import ToggleSwitch from './icons/ToggleSwitch';
import { isValidDomain, validateProxyTarget } from '../utils/validation';

// This form edits the host, path, upstream and sign-in; the rest of a rule (access control,
// rate limit, basic auth, hardening) is preserved by the caller rather than shown here.
export type ProxyRuleFormData = { domain: string; upstreamUrl: string; enableTls: boolean; routing: RuleRouting; signIn: RuleSignInInput };

export const SIGN_IN_PROVIDERS: { value: SignInProvider; label: string; example?: string; help: string }[] = [
  { value: 'authelia', label: 'Authelia', example: 'http://authelia:9091', help: 'Caddy checks each request at /api/authz/forward-auth.' },
  { value: 'authentik', label: 'Authentik', example: 'http://authentik-server:9000', help: 'Caddy checks each request at the outpost, and /outpost.goauthentik.io on this host goes to it.' },
  { value: 'oauth2-proxy', label: 'oauth2-proxy', example: 'http://oauth2-proxy:4180', help: 'Caddy checks each request at /oauth2/auth and sends a 401 to /oauth2/sign_in; /oauth2 on this host goes to it.' },
  { value: 'cloudflare-access', label: 'Cloudflare Access', help: "This service checks the token Cloudflare adds, against the team's signing keys and the application's audience." },
];

export const signInLabel = (provider: SignInProvider): string =>
  SIGN_IN_PROVIDERS.find(p => p.value === provider)?.label ?? provider;

interface ProxyRuleModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (ruleData: ProxyRuleFormData) => void;
  onDelete?: () => void;
  initialRule: Rule | null;
}

const ProxyRuleModal: React.FC<ProxyRuleModalProps> = ({
  isOpen,
  onClose,
  onSave,
  onDelete,
  initialRule
}) => {
  const [domain, setDomain] = useState('');
  const [proxyTo, setProxyTo] = useState('');
  const [ssl, setSsl] = useState(true);
  const [pathPrefix, setPathPrefix] = useState('');
  const [stripPrefix, setStripPrefix] = useState(false);
  const [provider, setProvider] = useState<SignInProvider | ''>('');
  const [verifierUrl, setVerifierUrl] = useState('');
  const [teamDomain, setTeamDomain] = useState('');
  const [audience, setAudience] = useState('');

  useEffect(() => {
    if (isOpen) {
      setDomain(initialRule?.domain || '');
      setProxyTo(initialRule?.upstreamUrl || '');
      setSsl(initialRule?.enableTls ?? true);
      setPathPrefix(initialRule?.routing?.pathPrefix ?? '');
      setStripPrefix(initialRule?.routing?.stripPathPrefix ?? false);
      setProvider(initialRule?.signIn?.provider ?? '');
      setVerifierUrl(initialRule?.signIn?.verifierUrl ?? '');
      setTeamDomain(initialRule?.signIn?.teamDomain ?? '');
      setAudience(initialRule?.signIn?.audience ?? '');
    }
  }, [isOpen, initialRule]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain || !proxyTo) {
      alert('Please fill in all fields.');
      return;
    }
    if (!isValidDomain(domain.trim())) {
      alert('Enter a valid domain, e.g. example.com.');
      return;
    }
    const targetCheck = validateProxyTarget(proxyTo);
    if (!targetCheck.ok) {
      alert(targetCheck.reason);
      return;
    }
    const prefix = pathPrefix.trim();
    if (prefix && !prefix.startsWith('/')) {
      alert('The path prefix must start with /, e.g. /api.');
      return;
    }
    const cloudflare = provider === 'cloudflare-access';
    if (provider && !cloudflare && !/^https?:\/\/[^/?#]+\/?$/i.test(verifierUrl.trim())) {
      alert("Enter the provider's address, e.g. http://authelia:9091, with no path.");
      return;
    }
    if (cloudflare && !/^[a-z0-9-]+\.cloudflareaccess\.com$/i.test(teamDomain.trim())) {
      alert('Enter the team domain, e.g. myteam.cloudflareaccess.com.');
      return;
    }
    if (cloudflare && !/^[0-9a-f]{64}$/i.test(audience.trim())) {
      alert("Enter the application's AUD tag: 64 hexadecimal characters.");
      return;
    }
    onSave({
      domain: domain.trim(),
      upstreamUrl: proxyTo.trim(),
      enableTls: ssl,
      routing: { pathPrefix: prefix || null, stripPathPrefix: !!prefix && stripPrefix },
      signIn: !provider ? { provider: null }
        : cloudflare ? { provider, teamDomain: teamDomain.trim(), audience: audience.trim() }
        : { provider, verifierUrl: verifierUrl.trim() },
    });
  };
  
  const isEditMode = initialRule !== null;
  const chosen = SIGN_IN_PROVIDERS.find(p => p.value === provider);

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={isEditMode ? 'Edit proxy rule' : 'Add proxy rule'}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="rule-domain" className="field-label">Domain</label>
          <input
            type="text"
            id="rule-domain"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="app.example.com"
            className="field"
          />
        </div>
        <div>
          <label htmlFor="rule-pathPrefix" className="field-label">Path prefix</label>
          <input
            type="text"
            id="rule-pathPrefix"
            value={pathPrefix}
            onChange={(e) => setPathPrefix(e.target.value)}
            placeholder="/api (blank for the whole host)"
            className="field"
          />
        </div>
        <div>
          <ToggleSwitch
            enabled={stripPrefix && pathPrefix.trim() !== ''}
            onChange={setStripPrefix}
            label="Strip the prefix before proxying"
            disabled={pathPrefix.trim() === ''}
          />
        </div>
        <div>
          <label htmlFor="rule-proxyTo" className="field-label">Upstream address</label>
          <input
            type="text"
            id="rule-proxyTo"
            value={proxyTo}
            onChange={(e) => setProxyTo(e.target.value)}
            placeholder="http://192.0.2.10:8080"
            className="field"
          />
        </div>
        <div className="pt-2">
            <ToggleSwitch enabled={ssl} onChange={setSsl} label="Serve over HTTPS" />
        </div>
        <div className="space-y-3 border-t border-border pt-4">
          <div>
            <label htmlFor="rule-signIn" className="field-label">Sign-in</label>
            <select id="rule-signIn" value={provider} onChange={(e) => setProvider(e.target.value as SignInProvider | '')} className="field">
              <option value="">None</option>
              {SIGN_IN_PROVIDERS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
            </select>
            {chosen && <p className="mt-1 text-xs text-on-surface-muted">{chosen.help}</p>}
          </div>
          {chosen?.example && (
            <div>
              <label htmlFor="rule-verifierUrl" className="field-label">{chosen.label} address</label>
              <input type="text" id="rule-verifierUrl" value={verifierUrl} onChange={(e) => setVerifierUrl(e.target.value)}
                placeholder={chosen.example} className="field" />
            </div>
          )}
          {provider === 'cloudflare-access' && (
            <>
              <div>
                <label htmlFor="rule-teamDomain" className="field-label">Team domain</label>
                <input type="text" id="rule-teamDomain" value={teamDomain} onChange={(e) => setTeamDomain(e.target.value)}
                  placeholder="myteam.cloudflareaccess.com" className="field" />
              </div>
              <div>
                <label htmlFor="rule-audience" className="field-label">Application audience (AUD tag)</label>
                <input type="text" id="rule-audience" value={audience} onChange={(e) => setAudience(e.target.value)}
                  placeholder="64 hexadecimal characters" className="field font-mono" />
              </div>
            </>
          )}
        </div>
        <div className="flex justify-between items-center pt-4 mt-2 border-t border-border">
          <div>
            {onDelete && (
              <Button type="button" variant="danger" onClick={onDelete}>Delete</Button>
            )}
          </div>
          <div className="flex gap-2">
            <Button type="button" variant="secondary" onClick={onClose}>Cancel</Button>
            <Button type="submit">{isEditMode ? 'Save changes' : 'Add rule'}</Button>
          </div>
        </div>
      </form>
    </Modal>
  );
};

export default ProxyRuleModal;