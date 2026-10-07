import test from 'node:test';
import assert from 'node:assert/strict';
import { sha256Hex, hmacHex, signJwt, decodeJwt, verifyJwt, b64urlEncode, b64urlDecode } from '../public/crypto.mjs';

test('sha256 matches published vectors', () => {
  assert.equal(sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(
    sha256Hex('The quick brown fox jumps over the lazy dog'),
    'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592');
});

test('hmac-sha256 matches RFC 4231-style vectors', () => {
  assert.equal(
    hmacHex('key', 'The quick brown fox jumps over the lazy dog'),
    'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8');
  // key longer than block size exercises the key-hashing path
  const longKey = 'k'.repeat(100);
  assert.equal(hmacHex(longKey, 'msg').length, 64);
});

test('base64url round-trips and strips padding', () => {
  const s = b64urlEncode('{"sub":"u-7","role":"user"}');
  assert.ok(!/[+/=]/.test(s));
  assert.equal(new TextDecoder().decode(b64urlDecode(s)), '{"sub":"u-7","role":"user"}');
});

test('jwt sign → decode → verify round-trip', () => {
  const token = signJwt({ sub: 'u-1', role: 'user', exp: 9999999999 }, 's');
  const { header, payload } = decodeJwt(token);
  assert.equal(header.alg, 'HS256');
  assert.equal(payload.role, 'user');
  assert.equal(verifyJwt(token, 's').ok, true);
});

test('jwt payload is readable without the secret (signed, not encrypted)', () => {
  const token = signJwt({ sub: 'u-1', ssn: 'do-not-put-this-here' }, 's');
  const decoded = decodeJwt(token); // no secret required
  assert.equal(decoded.payload.ssn, 'do-not-put-this-here');
});

test('tampered payload fails verification', () => {
  const token = signJwt({ sub: 'u-1', role: 'user', exp: 9999999999 }, 's');
  const [h, , sig] = token.split('.');
  const forged = `${h}.${b64urlEncode(JSON.stringify({ sub: 'u-1', role: 'admin', exp: 9999999999 }))}.${sig}`;
  const r = verifyJwt(forged, 's');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'bad-signature');
  assert.equal(r.payload.role, 'admin'); // attacker changed it — server rejected anyway
});

test('wrong secret and expired tokens are rejected', () => {
  const token = signJwt({ sub: 'u-1', exp: 1000 }, 'real-secret');
  assert.equal(verifyJwt(token, 'guessed-secret').reason, 'bad-signature');
  assert.equal(verifyJwt(token, 'real-secret', { now: 1001 }).reason, 'expired');
  const wellFormed = signJwt({ sub: 'u-1' }, 'other-secret');
  assert.equal(verifyJwt(wellFormed, 's').reason, 'bad-signature');
  assert.equal(verifyJwt('not.a.jwt', 's').reason, 'malformed');
  assert.equal(verifyJwt('garbage', 's').reason, 'malformed');
});
