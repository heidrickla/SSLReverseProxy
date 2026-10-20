import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, apiErrorMessage } from '../services/apiClient';
import type { Certificate } from '../types';
import { canRenew } from '../utils/certificates';

const mocks = vi.hoisted(() => ({
  challenges: vi.fn(),
  addCertificate: vi.fn(),
  renewCertificate: vi.fn(),
  certificates: [] as Certificate[],
}));

vi.mock('../services/apiClient', async (importOriginal) => {
  const real = await importOriginal<typeof import('../services/apiClient')>();
  return { ...real, api: { ...real.api, certificates: { ...real.api.certificates, challenges: mocks.challenges } } };
});

vi.mock('../contexts/AuthContext', () => ({
  useAuth: () => ({
    certificates: mocks.certificates,
    addCertificate: mocks.addCertificate,
    deleteCertificate: vi.fn(),
    renewCertificate: mocks.renewCertificate,
    setCertificateChallenge: vi.fn(),
    hasPermission: () => true,
  }),
}));

const cert = (over: Partial<Certificate> = {}): Certificate => ({
  id: 'c1', domain: 'a.example.com', issuer: "Let's Encrypt E7", status: 'valid', daysRemaining: 60,
  issuedAt: '2026-10-01T00:00:00Z', expiresAt: '2026-12-30T00:00:00Z', serialNumber: '0A1B', algorithm: 'ECDSA 256',
  source: 'rule', challenge: 'Http', lastError: null, checkedAt: '2026-10-20T00:00:00Z', renewPending: false,
  ...over,
});

const renderSsl = async () => {
  const { default: SSL } = await import('./SSL');
  render(<SSL />);
};

beforeEach(() => {
  mocks.certificates = [];
  mocks.challenges.mockResolvedValue([
    { name: 'Http', available: true, wildcard: false, reason: null },
    { name: 'DnsCloudflare', available: false, wildcard: true, reason: 'Proxy:CloudflareApiToken is not set.' },
  ]);
  mocks.addCertificate.mockResolvedValue(undefined);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('Add certificate', () => {
  it('asks for a name and a validation method, never a token', async () => {
    await renderSsl();
    fireEvent.click(screen.getAllByRole('button', { name: 'Add certificate' })[0]);

    await waitFor(() => expect(screen.getByRole('option', { name: 'DNS-01 (Cloudflare) (not configured)' })).toBeTruthy());
    expect((screen.getByRole('option', { name: 'DNS-01 (Cloudflare) (not configured)' }) as HTMLOptionElement).disabled).toBe(true);
    expect(screen.getByText('DNS-01 (Cloudflare): Proxy:CloudflareApiToken is not set.')).toBeTruthy();
    expect(document.querySelector('input[type="password"]')).toBeNull();

    fireEvent.change(screen.getByLabelText('Domain'), { target: { value: ' app.example.com ' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Add certificate' }).at(-1)!);
    await waitFor(() => expect(mocks.addCertificate).toHaveBeenCalledWith({ domain: 'app.example.com', challenge: 'Http' }));
  });

  it('shows the server refusal in the form', async () => {
    mocks.addCertificate.mockRejectedValue(new ApiError(400, 'One or more validation errors occurred.',
      { errors: { challenge: ['A wildcard certificate needs the DnsCloudflare challenge.'] } }));
    await renderSsl();
    fireEvent.click(screen.getAllByRole('button', { name: 'Add certificate' })[0]);
    await waitFor(() => expect(mocks.challenges).toHaveBeenCalled());

    fireEvent.change(screen.getByLabelText('Domain'), { target: { value: '*.example.com' } });
    fireEvent.click(screen.getAllByRole('button', { name: 'Add certificate' }).at(-1)!);
    expect((await screen.findByRole('alert')).textContent).toBe('A wildcard certificate needs the DnsCloudflare challenge.');
  });
});

describe('Renew', () => {
  it('confirms, then asks the server', async () => {
    mocks.certificates = [cert()];
    mocks.renewCertificate.mockResolvedValue(undefined);
    await renderSsl();

    fireEvent.click(screen.getByRole('button', { name: 'Renew' }));
    fireEvent.click(screen.getAllByRole('button', { name: 'Renew' }).at(-1)!);
    await waitFor(() => expect(mocks.renewCertificate).toHaveBeenCalledWith('c1'));
  });

  it('is offered only for a served certificate with no renewal under way', () => {
    expect(canRenew(cert())).toBe(true);
    expect(canRenew(cert({ renewPending: true }))).toBe(false);
    expect(canRenew(cert({ serialNumber: null }))).toBe(false);
    expect(canRenew(cert({ status: 'issuing' }))).toBe(false);
    expect(canRenew(cert({ status: 'unknown' }))).toBe(false);
    expect(canRenew(cert({ status: 'expired' }))).toBe(true);
  });
});

describe('apiErrorMessage', () => {
  it('prefers the first field error, then the message', () => {
    expect(apiErrorMessage(new ApiError(400, 'Bad', { errors: { domain: ['Domain is not a valid hostname.'] } }))).toBe('Domain is not a valid hostname.');
    expect(apiErrorMessage(new ApiError(409, 'A renewal is already in progress.'))).toBe('A renewal is already in progress.');
    expect(apiErrorMessage(new Error('x'), 'fallback')).toBe('fallback');
  });
});
