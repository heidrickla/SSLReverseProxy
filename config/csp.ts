// Content-Security-Policy injected into the production build as a <meta> tag.
// connect-src allows the page's own origin, plus the API's when the build is
// pointed at another one with VITE_API_BASE_URL. frame-ancestors is left to the
// server that serves the UI: browsers ignore it in a <meta> policy.
export function buildCsp(apiBase?: string): string {
  const connect = ["'self'"];
  if (apiBase && /^https?:\/\//i.test(apiBase)) connect.push(new URL(apiBase).origin);

  return [
    "default-src 'self'",
    "script-src 'self'",
    // 'unsafe-inline' is required for component-level <style> blocks and inline
    // styles injected by charting libs; it does not weaken script protection.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https://api.dicebear.com",
    "font-src 'self'",
    `connect-src ${connect.join(' ')}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ');
}
