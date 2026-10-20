// WebAuthn JSON <-> browser objects. The server sends options with binary fields as base64url
// strings and takes the browser's answer in the same form.

export const toBase64Url = (data: ArrayBuffer | Uint8Array): string => {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

export const fromBase64Url = (s: string): ArrayBuffer => {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const raw = atob(b64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes.buffer;
};

interface DescriptorJson { type: 'public-key'; id: string; transports?: AuthenticatorTransport[] }
export interface CreationOptionsJson {
  challenge: string;
  user: { id: string; name: string; displayName: string };
  excludeCredentials?: DescriptorJson[];
  [key: string]: unknown;
}
export interface RequestOptionsJson {
  challenge: string;
  allowCredentials?: DescriptorJson[];
  [key: string]: unknown;
}

const descriptors = (list?: DescriptorJson[]): PublicKeyCredentialDescriptor[] | undefined =>
  list?.map(d => ({ ...d, id: fromBase64Url(d.id) }));

export const toCreationOptions = (o: CreationOptionsJson): PublicKeyCredentialCreationOptions => ({
  ...(o as unknown as PublicKeyCredentialCreationOptions),
  challenge: fromBase64Url(o.challenge),
  user: { ...o.user, id: fromBase64Url(o.user.id) },
  excludeCredentials: descriptors(o.excludeCredentials),
});

export const toRequestOptions = (o: RequestOptionsJson): PublicKeyCredentialRequestOptions => ({
  ...(o as unknown as PublicKeyCredentialRequestOptions),
  challenge: fromBase64Url(o.challenge),
  allowCredentials: descriptors(o.allowCredentials),
});

export const passkeysSupported = (): boolean =>
  typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function' && !!navigator.credentials;

/** Runs the browser's registration ceremony and returns the attestation as JSON for POST /api/passkeys. */
export async function createPasskey(options: CreationOptionsJson): Promise<Record<string, unknown>> {
  const cred = (await navigator.credentials.create({ publicKey: toCreationOptions(options) })) as PublicKeyCredential | null;
  if (!cred) throw new Error('No passkey was created.');
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: toBase64Url(cred.rawId),
    type: cred.type,
    response: { attestationObject: toBase64Url(r.attestationObject), clientDataJSON: toBase64Url(r.clientDataJSON) },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

/** Runs the browser's sign-in ceremony and returns the assertion as JSON for POST /api/auth/passkey. */
export async function getPasskey(options: RequestOptionsJson): Promise<Record<string, unknown>> {
  const cred = (await navigator.credentials.get({ publicKey: toRequestOptions(options) })) as PublicKeyCredential | null;
  if (!cred) throw new Error('No passkey was chosen.');
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: toBase64Url(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: toBase64Url(r.authenticatorData),
      clientDataJSON: toBase64Url(r.clientDataJSON),
      signature: toBase64Url(r.signature),
      ...(r.userHandle ? { userHandle: toBase64Url(r.userHandle) } : {}),
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

/** True when the user dismissed the browser's passkey prompt, which is not an error worth showing. */
export const isCancelled = (e: unknown): boolean =>
  e instanceof DOMException && (e.name === 'NotAllowedError' || e.name === 'AbortError');
