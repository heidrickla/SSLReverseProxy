// Display formatting for the dashboard's traffic figures. A null figure renders as an em dash.

export const NO_VALUE = '—';

const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 });

/** 950 -> "950", 12_345 -> "12.3K", 1_400_000 -> "1.4M". */
export const formatCount = (n: number | null | undefined): string =>
  n == null ? NO_VALUE : n < 1000 ? String(Math.round(n)) : compact.format(n);

const BYTE_UNITS = ['B', 'kB', 'MB', 'GB', 'TB', 'PB'];

/** Decimal units: 1_200 -> "1.2 kB". */
export const formatBytes = (n: number | null | undefined): string => {
  if (n == null) return NO_VALUE;
  let value = Math.max(0, n);
  let unit = 0;
  while (value >= 1000 && unit < BYTE_UNITS.length - 1) {
    value /= 1000;
    unit++;
  }
  const digits = unit === 0 || value >= 100 ? 0 : 1;
  return `${value.toFixed(digits)} ${BYTE_UNITS[unit]}`;
};

/** Milliseconds without the unit: one decimal under 10 ms, whole numbers above. */
export const formatMs = (ms: number | null | undefined): string =>
  ms == null ? NO_VALUE : ms < 10 ? ms.toFixed(1) : String(Math.round(ms));

/** Clock-hour label in the viewer's locale, e.g. "3 PM" or "15". */
export const formatHour = (iso: string): string =>
  new Date(iso).toLocaleTimeString([], { hour: 'numeric' });
