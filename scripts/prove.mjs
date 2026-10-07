// prove.mjs — runs all six methods end-to-end and prints the verdicts.
// `npm run prove` — the same engines the browser lab drives.

import { signJwt, verifyJwt } from '../public/crypto.mjs';
import { createKeyRegistry, basicHeader, authenticateBasic, signWebhook, verifyWebhook } from '../public/methods.mjs';
import { OAUTH_CODE_FLOW, oauthNeverSeesPassword, simulateHandshake } from '../public/flows.mjs';

const SECRET = 'fixture-only-signing-secret';
const mark = (ok) => (ok ? 'PASS' : 'FAIL');
const lines = [];

// 1. API key — leaked bearer credential, killed only by rotation
const reg = createKeyRegistry();
const key = reg.issue('partner-a');
lines.push(['API key', `leaked key authenticates as "${reg.authenticate(key).clientId}" — bearer credential`]);
const rotated = reg.rotate(key);
lines.push(['API key', `${mark(!reg.authenticate(key).ok && !!rotated)} rotation kills the leaked key instantly`]);

// 2. Basic auth — the password is in the header
const header = basicHeader('alice', 's3cret!');
lines.push(['Basic', `${header} — decodes to alice:s3cret!, nothing hidden`]);
lines.push(['Basic', `${mark(authenticateBasic(header, { alice: 's3cret!' }).ok)} verifies over HTTPS-or-nothing`]);

// 3. JWT — anyone reads the payload; only the secret holder can sign
const token = signJwt({ sub: 'u-7', role: 'user', exp: 9999999999 }, SECRET);
const parts = token.split('.');
const forgedPayload = Buffer.from(JSON.stringify({ sub: 'u-7', role: 'admin', exp: 9999999999 })).toString('base64url');
const forged = `${parts[0]}.${forgedPayload}.${parts[2]}`;
lines.push(['JWT', `${mark(verifyJwt(token, SECRET).ok)} valid token verifies`]);
lines.push(['JWT', `${mark(verifyJwt(forged, SECRET).reason === 'bad-signature')} role=user→admin tamper rejected`]);
const expired = signJwt({ sub: 'u-7', exp: 100 }, SECRET);
lines.push(['JWT', `${mark(verifyJwt(expired, SECRET, { now: 200 }).reason === 'expired')} expired token rejected`]);

// 5. HMAC — integrity + freshness
const body = '{"event":"payment.succeeded","amount":4200}';
const ts = 1700000000;
const sig = signWebhook(SECRET, ts, body);
lines.push(['HMAC', `${mark(verifyWebhook(SECRET, ts, body, sig, { now: ts + 5 }).ok)} authentic delivery verifies`]);
lines.push(['HMAC', `${mark(verifyWebhook(SECRET, ts, body.replace('4200', '99900'), sig, { now: ts + 5 }).reason === 'bad-signature')} tampered body rejected`]);
lines.push(['HMAC', `${mark(verifyWebhook(SECRET, ts, body, sig, { now: ts + 3600 }).reason === 'stale')} hour-old replay rejected`]);

// 4. OAuth — the app never sees the password
lines.push(['OAuth 2.0', `${mark(oauthNeverSeesPassword())} ${OAUTH_CODE_FLOW.length}-step flow: password stays at the provider`]);

// 6. mTLS — mutual verification
const okShake = simulateHandshake();
const noCert = simulateHandshake({ clientCertCa: 'unknown-ca' });
lines.push(['mTLS', `${mark(okShake.every(s => s.result === 'pass'))} both sides present certs — handshake completes`]);
lines.push(['mTLS', `${mark(noCert.at(-1).result === 'fail:client-cert')} untrusted client cert rejected at verification`]);

console.log('\n  API Auth Lab — six proofs\n');
for (const [m, line] of lines) console.log(`  ${m.padEnd(10)} ${line}`);
console.log('');
