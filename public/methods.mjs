// methods.mjs — the three header-level auth methods as inspectable engines.
// Shared by the browser UI, the proof script, and the test suite.

import { hmacHex, sha256Hex, timingSafeEqual, b64urlEncode } from './crypto.mjs';

const encoder = new TextEncoder();
const eq = (a, b) => timingSafeEqual(encoder.encode(String(a)), encoder.encode(String(b)));

// --- 1. API key: a name tag, not an identity ----------------------------------

export function createKeyRegistry() {
  const keys = new Map(); // token -> clientId
  const secrets = new Set();
  return {
    issue(clientId, seed = `key-${keys.size}`) {
      const token = `ak_${sha256Hex(`${seed}:${clientId}`).slice(0, 24)}`;
      keys.set(token, clientId);
      secrets.add(clientId);
      return token;
    },
    authenticate(token) {
      const clientId = keys.get(token);
      return clientId ? { ok: true, clientId } : { ok: false, reason: 'unknown-key' };
    },
    revoke(token) { keys.delete(token); },
    rotate(token) {
      const clientId = keys.get(token);
      if (!clientId) return null;
      keys.delete(token);
      return this.issue(clientId, `rotated-${Date.now()}-${token.slice(0, 8)}`);
    },
    size: () => keys.size,
  };
}

// --- 2. Basic auth: credentials ride every request -----------------------------

export function basicHeader(user, pass) {
  return `Basic ${b64urlEncode(`${user}:${pass}`).replace(/-/g, '+').replace(/_/g, '/')}`;
}

export function decodeBasic(header) {
  const m = /^Basic\s+(.+)$/i.exec(header.trim());
  if (!m) return null;
  const decoded = atob(m[1]);
  const i = decoded.indexOf(':');
  return i < 0 ? null : { user: decoded.slice(0, i), pass: decoded.slice(i + 1) };
}

export function authenticateBasic(header, users) {
  const creds = decodeBasic(header);
  if (!creds) return { ok: false, reason: 'malformed' };
  const expected = users[creds.user];
  return expected !== undefined && eq(expected, creds.pass)
    ? { ok: true, user: creds.user }
    : { ok: false, reason: 'bad-credentials' };
}

// --- 5. HMAC webhook: sign the message, prove freshness ------------------------

export function signWebhook(secret, timestamp, body) {
  return `sha256=${hmacHex(secret, `${timestamp}.${body}`)}`;
}

export function verifyWebhook(secret, timestamp, body, signature, {
  now = timestamp,
  toleranceSeconds = 300,
  seenNonces = new Set(),
  nonce,
} = {}) {
  if (nonce !== undefined && seenNonces.has(nonce)) return { ok: false, reason: 'replay' };
  const age = Math.abs(now - Number(timestamp));
  if (age > toleranceSeconds) return { ok: false, reason: 'stale', age };
  const expected = signWebhook(secret, timestamp, body);
  if (!eq(expected, signature)) return { ok: false, reason: 'bad-signature' };
  if (nonce !== undefined) seenNonces.add(nonce);
  return { ok: true, reason: 'valid', age };
}
