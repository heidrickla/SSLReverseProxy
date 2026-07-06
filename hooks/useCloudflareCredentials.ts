import { useState, useEffect, useCallback } from 'react';
import { CloudflareCredential } from '../types';

const STORAGE_KEY = 'proxyadmin-cf-creds';

/**
 * Manages saved Cloudflare DNS-challenge credentials.
 *
 * SECURITY WARNING: There is NO safe way to keep a Cloudflare API token secret
 * inside a browser-only app. A token here can control DNS for an entire zone.
 * The values below are Base64-ENCODED for storage transport only — this is
 * obfuscation, NOT encryption, and provides zero protection against anyone with
 * access to the browser (DevTools, an extension, or an XSS payload can read it).
 *
 * The correct design is to hold the token in a server-side secret store and run
 * the ACME DNS-01 challenge on the backend, so the token never reaches the
 * client. Persisting here is opt-in and should be treated as temporary.
 */
export const useCloudflareCredentials = () => {
  const [credentials, setCredentials] = useState<CloudflareCredential[]>([]);

  useEffect(() => {
    try {
      const savedData = localStorage.getItem(STORAGE_KEY);
      if (savedData) {
        const decoded = atob(savedData);
        const parsed = JSON.parse(decoded);
        if (Array.isArray(parsed)) {
          setCredentials(parsed);
        }
      }
    } catch (error) {
      console.error('Failed to load saved Cloudflare credentials.');
      localStorage.removeItem(STORAGE_KEY);
    }
  }, []);

  const saveCredential = useCallback((apiToken: string, zoneId: string) => {
    // Prevent duplicates
    if (credentials.some(c => c.zoneId === zoneId)) {
        return;
    }

    const newCredential: CloudflareCredential = {
      id: zoneId,
      zoneId,
      apiToken,
      name: `DNS-01 (Cloudflare) ...${zoneId.slice(-4)}`,
    };

    setCredentials(prev => {
      const updatedCredentials = [...prev, newCredential];
      try {
        const encoded = btoa(JSON.stringify(updatedCredentials));
        localStorage.setItem(STORAGE_KEY, encoded);
      } catch (error) {
        console.error('Failed to persist Cloudflare credentials.');
      }
      return updatedCredentials;
    });
  }, [credentials]);

  return { credentials, saveCredential };
};
