
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

// Cloudflare tokens belong on the server; remove any this browser still holds.
try { localStorage.removeItem('proxyadmin-cf-creds'); } catch { /* storage unavailable */ }

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error("Could not find root element to mount to");
}

const root = ReactDOM.createRoot(rootElement);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
