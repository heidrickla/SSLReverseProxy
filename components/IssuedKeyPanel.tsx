import React, { useState } from 'react';
import Button from './Button';
import type { IssuedApiKey } from '../services/apiClient';
import { permissionLabel } from '../utils/permissions';

/** The new key, shown once, with the expiry and the grants the server issued. */
const IssuedKeyPanel: React.FC<{ issued: IssuedApiKey; onDone: () => void }> = ({ issued, onDone }) => {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(issued.token);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="space-y-4">
      <p className="text-sm text-on-surface-muted">Copy the key now. It is not shown again.</p>
      <input readOnly aria-label="Issued key" value={issued.token} onFocus={e => e.target.select()}
        className="field font-mono text-xs" />
      <p className="text-xs text-on-surface-muted">
        {issued.expiresAt ? `Expires ${new Date(issued.expiresAt).toLocaleString()}.` : 'Does not expire.'}
      </p>
      <div className="rounded-xl border border-border bg-background p-3">
        <p className="text-xs font-medium text-on-surface-muted mb-1">This key can</p>
        {issued.scopes ? (
          <ul className="text-sm text-on-surface list-disc ml-5" aria-label="Issued permissions">
            {issued.scopes.map(p => <li key={p}>{permissionLabel(p)}</li>)}
          </ul>
        ) : <p className="text-sm text-on-surface">Everything the owner's role allows.</p>}
      </div>
      <div className="flex justify-end gap-2">
        <Button type="button" variant="secondary" onClick={copy}>{copied ? 'Copied' : 'Copy'}</Button>
        <Button type="button" onClick={onDone}>Done</Button>
      </div>
    </div>
  );
};

export default IssuedKeyPanel;
