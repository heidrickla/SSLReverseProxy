import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import LoginView from './Auth';

const auth = vi.hoisted(() => ({ login: vi.fn(), loginWithPasskey: vi.fn(), passkeysEnabled: true }));
const supported = vi.hoisted(() => ({ value: true }));

vi.mock('../contexts/AuthContext', () => ({ useAuth: () => auth }));
vi.mock('../utils/webauthn', async (importOriginal) => {
  const real = await importOriginal<typeof import('../utils/webauthn')>();
  return { ...real, passkeysSupported: () => supported.value };
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  auth.passkeysEnabled = true;
  supported.value = true;
});

describe('LoginView', () => {
  it('offers a passkey when the server and the browser both support it', async () => {
    auth.loginWithPasskey.mockResolvedValue(undefined);
    render(<LoginView />);
    fireEvent.click(screen.getByRole('button', { name: 'Sign in with a passkey' }));
    await waitFor(() => expect(auth.loginWithPasskey).toHaveBeenCalled());
    expect(screen.getByLabelText('API key')).toBeTruthy();
  });

  it.each([['the server', () => { auth.passkeysEnabled = false; }], ['the browser', () => { supported.value = false; }]])(
    'offers only the API key when %s has no passkeys', (_who, off) => {
      off();
      render(<LoginView />);
      expect(screen.queryByRole('button', { name: 'Sign in with a passkey' })).toBeNull();
      expect(screen.getByRole('button', { name: 'Sign in' })).toBeTruthy();
    });

  it('reports a failed sign-in but not a dismissed prompt', async () => {
    auth.loginWithPasskey.mockRejectedValueOnce(new DOMException('dismissed', 'NotAllowedError'));
    render(<LoginView />);
    const button = screen.getByRole('button', { name: 'Sign in with a passkey' });
    fireEvent.click(button);
    await waitFor(() => expect(button).toHaveProperty('disabled', false));
    expect(screen.queryByText(/Passkey sign-in failed/)).toBeNull();

    auth.loginWithPasskey.mockRejectedValueOnce(new Error('401'));
    fireEvent.click(button);
    expect(await screen.findByText(/Passkey sign-in failed/)).toBeTruthy();
  });
});
