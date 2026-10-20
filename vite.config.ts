import path from 'path';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { buildCsp } from './config/csp';

export default defineConfig(({ command, mode }) => {
  const apiBase = loadEnv(mode, process.cwd(), 'VITE_').VITE_API_BASE_URL || undefined;

  // Without VITE_API_BASE_URL the UI calls /api on its own origin; dev and
  // preview forward it to the local control plane (SSLRP_API_TARGET overrides).
  const apiProxy = apiBase
    ? undefined
    : { '/api': { target: process.env.SSLRP_API_TARGET ?? 'http://localhost:5195' } };

  return {
    plugins: [
      react(),
      {
        // Production build only: the dev server needs inline scripts for React
        // Fast Refresh. The server that serves the UI should also send the
        // policy as a header, with frame-ancestors, which a <meta> cannot carry.
        name: 'inject-csp-meta',
        transformIndexHtml(html) {
          if (command !== 'build') return html;
          const meta = `<meta http-equiv="Content-Security-Policy" content="${buildCsp(apiBase)}">`;
          return html.replace('</head>', `  ${meta}\n</head>`);
        },
      },
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: { proxy: apiProxy },
    preview: { proxy: apiProxy },
    build: {
      // Fonts stay files: an inlined data: font is blocked by font-src 'self'.
      assetsInlineLimit: (filePath: string) => (filePath.endsWith('.woff2') ? false : undefined),
    },
  };
});
