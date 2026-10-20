import type { Certificate } from '../types';
import type { ChallengeName } from '../services/apiClient';

export const challengeLabel: Record<ChallengeName, string> = {
    Http: 'HTTP-01',
    DnsCloudflare: 'DNS-01 (Cloudflare)',
};

/** A forced renewal starts from a served certificate and one at a time; the server enforces the same. */
export const canRenew = (cert: Certificate): boolean =>
    !cert.renewPending && cert.serialNumber !== null && cert.status !== 'issuing' && cert.status !== 'unknown';
