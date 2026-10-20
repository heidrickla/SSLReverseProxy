import { afterEach, describe, expect, it, vi } from 'vitest';
import { createPasskey, fromBase64Url, getPasskey, isCancelled, toBase64Url, toCreationOptions, toRequestOptions } from './webauthn';

const bytes = (b: ArrayBuffer | BufferSource | undefined) => Array.from(new Uint8Array(b as ArrayBuffer));

afterEach(() => vi.unstubAllGlobals());

describe('base64url', () => {
  it.each([[[]], [[0xfb]], [[0xfb, 0xff]], [[0xfb, 0xff, 0xbf]], [[0, 1, 2, 3, 250, 251, 252, 253, 254, 255]]])(
    'round-trips %j without padding or +/',
    (input) => {
      const s = toBase64Url(new Uint8Array(input));
      expect(s).not.toMatch(/[+/=]/);
      expect(bytes(fromBase64Url(s))).toEqual(input);
    });

  it('reads the server encoding', () => {
    expect(bytes(fromBase64Url('AQID'))).toEqual([1, 2, 3]);
    expect(bytes(fromBase64Url('-_8'))).toEqual([0xfb, 0xff]);
  });
});

describe('options', () => {
  it('turns the binary fields of creation options into buffers and keeps the rest', () => {
    const o = toCreationOptions({
      rp: { id: 'localhost', name: 'SSLReverseProxy' },
      user: { id: 'AQID', name: 'a@example.com', displayName: 'A' },
      challenge: 'BAUG',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      excludeCredentials: [{ type: 'public-key', id: 'BwgJ' }],
    });
    expect(bytes(o.challenge)).toEqual([4, 5, 6]);
    expect(bytes(o.user.id)).toEqual([1, 2, 3]);
    expect(o.user.name).toBe('a@example.com');
    expect(bytes(o.excludeCredentials![0].id)).toEqual([7, 8, 9]);
    expect(o.authenticatorSelection?.userVerification).toBe('required');
  });

  it('turns the challenge of request options into a buffer', () => {
    const o = toRequestOptions({ challenge: 'BAUG', rpId: 'localhost', allowCredentials: [], userVerification: 'required' });
    expect(bytes(o.challenge)).toEqual([4, 5, 6]);
    expect(o.allowCredentials).toEqual([]);
    expect(o.userVerification).toBe('required');
  });
});

describe('ceremonies', () => {
  const buf = (...b: number[]) => new Uint8Array(b).buffer;

  it('returns the attestation as base64url JSON', async () => {
    const create = vi.fn().mockResolvedValue({
      id: 'AQI', rawId: buf(1, 2), type: 'public-key',
      response: { attestationObject: buf(3), clientDataJSON: buf(4) },
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    });
    vi.stubGlobal('navigator', { credentials: { create } });
    const json = await createPasskey({ challenge: 'AQ', user: { id: 'Ag', name: 'n', displayName: 'd' } });
    expect(bytes(create.mock.calls[0][0].publicKey.challenge)).toEqual([1]);
    expect(json).toEqual({
      id: 'AQI', rawId: 'AQI', type: 'public-key',
      response: { attestationObject: 'Aw', clientDataJSON: 'BA' },
      clientExtensionResults: { credProps: { rk: true } },
    });
  });

  it('returns the assertion with its user handle', async () => {
    const get = vi.fn().mockResolvedValue({
      id: 'AQI', rawId: buf(1, 2), type: 'public-key',
      response: { authenticatorData: buf(5), clientDataJSON: buf(6), signature: buf(7), userHandle: buf(8) },
      getClientExtensionResults: () => ({}),
    });
    vi.stubGlobal('navigator', { credentials: { get } });
    const json = await getPasskey({ challenge: 'AQ', allowCredentials: [] });
    expect(json.response).toEqual({ authenticatorData: 'BQ', clientDataJSON: 'Bg', signature: 'Bw', userHandle: 'CA' });
  });

  it('treats a dismissed prompt as cancelled, not failed', () => {
    expect(isCancelled(new DOMException('dismissed', 'NotAllowedError'))).toBe(true);
    expect(isCancelled(new DOMException('bad', 'SecurityError'))).toBe(false);
    expect(isCancelled(new Error('x'))).toBe(false);
  });
});
