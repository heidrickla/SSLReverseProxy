import React, { useState, useEffect } from 'react';
import { Rule } from '../services/apiClient';
import Modal from './Modal';
import Button from './Button';
import ToggleSwitch from './icons/ToggleSwitch';
import { isValidDomain, validateProxyTarget } from '../utils/validation';

// This form edits three fields; the rest of a rule (access control, rate limit,
// basic auth, hardening) is preserved by the caller rather than shown here.
export type ProxyRuleFormData = { domain: string; upstreamUrl: string; enableTls: boolean };

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

  useEffect(() => {
    if (isOpen) {
      setDomain(initialRule?.domain || '');
      setProxyTo(initialRule?.upstreamUrl || '');
      setSsl(initialRule?.enableTls ?? true);
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
    onSave({ domain: domain.trim(), upstreamUrl: proxyTo.trim(), enableTls: ssl });
  };
  
  const isEditMode = initialRule !== null;

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