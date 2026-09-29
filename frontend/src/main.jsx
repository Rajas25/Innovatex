import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { HashRouter } from 'react-router-dom';
import App from './App';
import './styles/global.css';

/*
 * HashRouter is used deliberately so the built SPA works from any static
 * host (file://, an S3 bucket, a GitHub Pages sub-path) without needing a
 * server-side catch-all route. Swap to BrowserRouter if you deploy behind
 * a reverse proxy that rewrites unknown paths to index.html.
 */
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <HashRouter>
      <App />
    </HashRouter>
  </StrictMode>,
);