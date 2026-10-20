import { describe, expect, it } from 'vitest';
import { buildCsp } from './csp';

const directive = (csp: string, name: string) =>
  csp.split('; ').find(d => d.startsWith(`${name} `));

describe('buildCsp', () => {
  it('allows only the page origin when the API is same-origin', () => {
    expect(directive(buildCsp(), 'connect-src')).toBe("connect-src 'self'");
    expect(directive(buildCsp('/api-prefix'), 'connect-src')).toBe("connect-src 'self'");
  });

  it('adds the origin of a cross-origin API base, without its path', () => {
    expect(directive(buildCsp('https://control.example.com:8443/base/'), 'connect-src'))
      .toBe("connect-src 'self' https://control.example.com:8443");
  });

  it('leaves frame-ancestors out, since a meta policy cannot carry it', () => {
    expect(directive(buildCsp(), 'frame-ancestors')).toBeUndefined();
    expect(directive(buildCsp(), 'font-src')).toBe("font-src 'self'");
  });
});
