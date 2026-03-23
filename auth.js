'use strict';

/**
 * Simple API key auth middleware for the dashboard server.
 * - Checks `x-api-key` header against `PRAETORIAN_API_KEY` env var.
 * - Static assets (HTML/CSS/JS/SVG) bypass auth.
 * - If `PRAETORIAN_API_KEY` is not set, auth is disabled (dev mode).
 */

const STATIC_EXTENSIONS = new Set(['.html', '.css', '.js', '.svg', '.png', '.ico', '.woff', '.woff2']);

function isStaticRequest(pathname) {
  const dot = pathname.lastIndexOf('.');
  if (dot === -1) return false;
  return STATIC_EXTENSIONS.has(pathname.slice(dot).toLowerCase());
}

function createAuthMiddleware() {
  const apiKey = process.env.PRAETORIAN_API_KEY;

  return function authMiddleware(req, url) {
    // Dev mode: no key configured = auth disabled
    if (!apiKey) return { ok: true };

    // Static files bypass auth
    if (isStaticRequest(url.pathname)) return { ok: true };

    // Allow benchmark and root pages without auth
    if (url.pathname === '/' || url.pathname === '/benchmark') return { ok: true };

    // Check header
    const provided = req.headers['x-api-key'];
    if (provided === apiKey) return { ok: true };

    return { ok: false, status: 401, message: 'Unauthorized: invalid or missing x-api-key header' };
  };
}

module.exports = { createAuthMiddleware };
