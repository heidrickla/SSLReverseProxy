import type { ApiKey, ApiKeyPreset } from '../services/apiClient';

const DAY_MS = 86_400_000;

/** How long a new key lasts: a preset number of days, or a date picked in the form (YYYY-MM-DD, local). */
export type Lifetime = { kind: 'days'; days: number } | { kind: 'date'; date: string };

export const lifetimeLabel = (days: number): string =>
  days === 365 ? '1 year' : days === 1 ? '1 day' : `${days} days`;

/** The local date `days` from now, as a date input's value. */
export const dateInput = (now: Date, days: number): string => {
  const d = new Date(now.getTime() + days * DAY_MS);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
};

/**
 * When a key issued now with this lifetime expires. A picked date means the end of that local day,
 * held inside the server's limit. Null when the date is not valid or not in the future.
 */
export const expiryFor = (lifetime: Lifetime, now: Date, maxDays: number): Date | null => {
  if (lifetime.kind === 'days') return new Date(now.getTime() + lifetime.days * DAY_MS);
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(lifetime.date);
  if (!m) return null;
  const end = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 0, 0);
  if (Number.isNaN(end.getTime())) return null;
  const latest = new Date(now.getTime() + maxDays * DAY_MS - 60_000);
  const at = end > latest ? latest : end;
  return at.getTime() > now.getTime() ? at : null;
};

/** Why a scope set cannot be issued for this owner by this caller, or null when it can. Null scopes mean full access. */
export const scopeProblem = (
  scopes: string[] | null,
  owner: { name: string; role: string; permissions: string[] },
  caller: { permissions: string[]; scoped: boolean },
): string | null => {
  if (scopes === null) {
    return caller.scoped ? 'Your key is limited to scopes, so it cannot issue full access.' : null;
  }
  if (scopes.length === 0) return 'Choose at least one permission.';
  const ownerLacks = scopes.filter(s => !owner.permissions.includes(s));
  if (ownerLacks.length > 0) return `The ${owner.role} role does not hold ${ownerLacks.length === 1 ? 'one of these' : `${ownerLacks.length} of these`}.`;
  const callerLacks = scopes.filter(s => !caller.permissions.includes(s));
  if (callerLacks.length > 0) return 'You do not hold every permission in this set.';
  return null;
};

/** The preset a key's scopes match exactly, else null. */
export const matchPreset = (scopes: string[] | null, presets: ApiKeyPreset[]): ApiKeyPreset | null =>
  presets.find(p => (p.scopes === null) === (scopes === null)
    && (p.scopes === null || (p.scopes.length === scopes!.length && p.scopes.every(s => scopes!.includes(s))))) ?? null;

export type KeyState = 'active' | 'expiring' | 'expired' | 'revoked';

export const keyState = (key: Pick<ApiKey, 'revokedAt' | 'expiresAt'>, now: Date): KeyState => {
  if (key.revokedAt) return 'revoked';
  if (!key.expiresAt) return 'active';
  const left = new Date(key.expiresAt).getTime() - now.getTime();
  if (left <= 0) return 'expired';
  return left <= 7 * DAY_MS ? 'expiring' : 'active';
};

/** "in 3 days", "in 5 hours", "expired", "never". */
export const expiresIn = (expiresAt: string | null, now: Date): string => {
  if (!expiresAt) return 'never';
  const left = new Date(expiresAt).getTime() - now.getTime();
  if (left <= 0) return 'expired';
  const hours = Math.ceil(left / 3_600_000);
  if (hours <= 48) return `in ${hours} hour${hours === 1 ? '' : 's'}`;
  return `in ${Math.ceil(left / DAY_MS)} days`;
};

/** The lifetime a rotation starts from: the old key's, in whole days within the limit; the default for a key that never expired. */
export const keptLifetime = (
  key: Pick<ApiKey, 'createdAt' | 'expiresAt'>,
  options: { lifetimeDays: number[]; defaultLifetimeDays: number; maxLifetimeDays: number },
  now: Date,
): Lifetime => {
  if (!key.expiresAt) return { kind: 'days', days: options.defaultLifetimeDays };
  const days = Math.min(options.maxLifetimeDays,
    Math.max(1, Math.round((new Date(key.expiresAt).getTime() - new Date(key.createdAt).getTime()) / DAY_MS)));
  return options.lifetimeDays.includes(days) ? { kind: 'days', days } : { kind: 'date', date: dateInput(now, days) };
};
