// Client-side input validation for network/proxy configuration.
//
// IMPORTANT: These checks are a first line of defense for UX and to catch
// obvious mistakes/abuse in the browser. They are NOT a security boundary.
// A reverse proxy's target address is an SSRF-sensitive value, so the backend
// MUST re-validate every domain and proxy target server-side before acting on
// it. Never trust a value just because it passed these client checks.

const DOMAIN_REGEX =
  /^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*$/;

const IPV4_REGEX =
  /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

/** A syntactically valid hostname/domain (labels, no scheme, no path). */
export const isValidDomain = (value: string): boolean => {
  const v = value.trim();
  if (!v || v.length > 253) return false;
  return DOMAIN_REGEX.test(v);
};

/** A valid IPv4 address or a valid hostname (used for the server IP field). */
export const isValidHostOrIp = (value: string): boolean => {
  const v = value.trim();
  if (IPV4_REGEX.test(v)) return true;
  // Reject values shaped like a dotted-numeric IP but with out-of-range octets
  // (e.g. "999.1.1.1") instead of silently accepting them as a hostname.
  if (/^\d+(\.\d+){3}$/.test(v)) return false;
  return isValidDomain(v);
};

// Hostnames that must never be a proxy target: cloud instance-metadata
// endpoints and the IPv4/IPv6 link-local ranges used to reach them.
const isLinkLocalOrMetadata = (hostname: string): boolean => {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === '169.254.169.254' || h === 'metadata.google.internal') return true;
  if (h.startsWith('169.254.')) return true; // IPv4 link-local
  if (h.startsWith('fe80:') || h.startsWith('fd00:')) return true; // IPv6 link-local/ULA metadata
  return false;
};

export interface ProxyTargetResult {
  ok: boolean;
  reason?: string;
}

/**
 * Validates a "proxy to" target address. Requires an absolute http(s) URL with
 * a hostname and rejects schemes that can be abused (javascript:, file:, data:)
 * and cloud-metadata/link-local hosts. Loopback and private ranges are allowed
 * because proxying to an internal upstream is a normal reverse-proxy use case;
 * the authoritative allow/deny decision still belongs on the server.
 */
export const validateProxyTarget = (value: string): ProxyTargetResult => {
  const v = value.trim();
  if (!v) return { ok: false, reason: 'Proxy target is required.' };

  let url: URL;
  try {
    url = new URL(v);
  } catch {
    return { ok: false, reason: 'Enter an absolute URL, e.g. http://localhost:3000.' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: 'Only http:// and https:// targets are allowed.' };
  }
  if (!url.hostname) {
    return { ok: false, reason: 'Proxy target must include a hostname.' };
  }
  if (isLinkLocalOrMetadata(url.hostname)) {
    return { ok: false, reason: 'Cloud metadata / link-local addresses are not allowed as proxy targets.' };
  }
  return { ok: true };
};
