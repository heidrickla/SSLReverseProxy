import { describe, expect, it } from 'vitest';
import { formatBytes, formatCount, formatMs, NO_VALUE } from './format';

describe('formatCount', () => {
  it.each([
    [0, '0'],
    [950, '950'],
    [12_345, '12.3K'],
    [1_400_000, '1.4M'],
  ])('%d -> %s', (n, expected) => expect(formatCount(n)).toBe(expected));

  it('renders null as a dash', () => expect(formatCount(null)).toBe(NO_VALUE));
});

describe('formatBytes', () => {
  it.each([
    [0, '0 B'],
    [999, '999 B'],
    [1_200, '1.2 kB'],
    [345_000_000, '345 MB'],
    [1.2e12, '1.2 TB'],
  ])('%d -> %s', (n, expected) => expect(formatBytes(n)).toBe(expected));

  it('renders null as a dash', () => expect(formatBytes(undefined)).toBe(NO_VALUE));
});

describe('formatMs', () => {
  it.each([
    [3.06, '3.1'],
    [17.5, '18'],
    [250, '250'],
  ])('%d -> %s', (n, expected) => expect(formatMs(n)).toBe(expected));

  it('renders null as a dash', () => expect(formatMs(null)).toBe(NO_VALUE));
});
