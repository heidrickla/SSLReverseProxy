import path from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Content-Security-Policy applied to the production build only. The dev server
// (npm run dev) needs inline scripts for React Fast Refresh / HMR, so we do not
// inject the strict policy there. In production this should ideally also be sent
// as an HTTP response header by the serving proxy/backend for defense in depth.
const productionCsp = [
  "default-src 'self'",
  "script-src 'self'",
  // 'unsafe-inline' is required for component-level <style> blocks and inline
  // styles injected by charting libs; it does not weaken script protection.
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https://api.dicebear.com",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export default defineConfig(({ command }) => {
  return {
    plugins: [
      react(),
      {
        name: 'inject-csp-meta',
        transformIndexHtml(html) {
          if (command !== 'build') return html;
          const meta = `<meta http-equiv="Content-Security-Policy" content="${productionCsp}">`;
          return html.replace('</head>', `  ${meta}\n</head>`);
        },
      },
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
  };
});
