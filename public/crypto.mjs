// crypto.mjs — pure-JS SHA-256, HMAC-SHA256, and JWT (HS256) helpers.
// Isomorphic: runs in the browser and under `node --test` with no imports.

const encoder = new TextEncoder();

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const rotr = (x, n) => (x >>> n) | (x << (32 - n));

export function sha256(data) {
  const bytes = typeof data === 'string' ? encoder.encode(data) : data;
  const bitLen = bytes.length * 8;
  const padded = new Uint8Array(((bytes.length + 9 + 63) >> 6) << 6);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  dv.setUint32(padded.length - 4, bitLen >>> 0);

  const h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const w = new Uint32Array(64);

  for (let block = 0; block < padded.length; block += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(block + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + s1 + ch + K[i] + w[i]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  h.forEach((v, i) => odv.setUint32(i * 4, v));
  return out;
}

export const hex = (bytes) => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
export const sha256Hex = (data) => hex(sha256(data));

export function hmacSha256(key, data) {
  let kb = typeof key === 'string' ? encoder.encode(key) : key;
  if (kb.length > 64) kb = sha256(kb);
  const ipad = new Uint8Array(64).fill(0x36);
  const opad = new Uint8Array(64).fill(0x5c);
  for (let i = 0; i < kb.length; i++) { ipad[i] ^= kb[i]; opad[i] ^= kb[i]; }
  const msg = typeof data === 'string' ? encoder.encode(data) : data;
  const inner = new Uint8Array(64 + msg.length);
  inner.set(ipad); inner.set(msg, 64);
  const innerHash = sha256(inner);
  const outer = new Uint8Array(64 + 32);
  outer.set(opad); outer.set(innerHash, 64);
  return sha256(outer);
}

export const hmacHex = (key, data) => hex(hmacSha256(key, data));

export function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// --- base64url ---------------------------------------------------------------

export const b64urlEncode = (data) => {
  const bytes = typeof data === 'string' ? encoder.encode(data) : data;
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

export const b64urlDecode = (s) => {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
};

// --- JWT (HS256) --------------------------------------------------------------

export function signJwt(payload, secret, { header = { alg: 'HS256', typ: 'JWT' } } = {}) {
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const sig = hmacSha256(secret, `${h}.${p}`);
  return `${h}.${p}.${b64urlEncode(sig)}`;
}

export function decodeJwt(token) {
  const [h, p, s] = token.split('.');
  if (!h || !p || !s) throw new Error('not a JWT');
  return {
    header: JSON.parse(new TextDecoder().decode(b64urlDecode(h))),
    payload: JSON.parse(new TextDecoder().decode(b64urlDecode(p))),
    signature: s,
    signingInput: `${h}.${p}`,
  };
}

export function verifyJwt(token, secret, { now = Math.floor(Date.now() / 1000) } = {}) {
  let parts;
  try { parts = decodeJwt(token); } catch { return { ok: false, reason: 'malformed' }; }
  const expected = b64urlEncode(hmacSha256(secret, parts.signingInput));
  if (!timingSafeEqual(encoder.encode(expected), encoder.encode(parts.signature))) {
    return { ok: false, reason: 'bad-signature', payload: parts.payload };
  }
  if (typeof parts.payload.exp === 'number' && parts.payload.exp <= now) {
    return { ok: false, reason: 'expired', payload: parts.payload };
  }
  return { ok: true, reason: 'valid', payload: parts.payload };
}
