import test from 'node:test';
import assert from 'node:assert/strict';
import { OAUTH_CODE_FLOW, oauthNeverSeesPassword, MTLS_HANDSHAKE, simulateHandshake } from '../public/flows.mjs';

test('oauth flow: the app never sees the user password', () => {
  assert.equal(oauthNeverSeesPassword(), true);
  // the password-bearing step is performed AT the provider, by the user
  const pwStep = OAUTH_CODE_FLOW.find(s => s.sees.some(x => /password/i.test(x)));
  assert.equal(pwStep.actor, 'user');
});

test('oauth flow: token exchange happens server-side with the code', () => {
  const exchange = OAUTH_CODE_FLOW.find(s => /code exchange/i.test(s.label));
  assert.ok(exchange.sees.includes('access_token'));
  assert.equal(OAUTH_CODE_FLOW.at(-1).actor, 'provider');
});

test('mtls handshake: both certs verified before data moves', () => {
  const steps = simulateHandshake();
  assert.equal(steps.length, MTLS_HANDSHAKE.length);
  assert.ok(steps.every(s => s.result === 'pass'));
  assert.equal(MTLS_HANDSHAKE[2].stage, 'CertificateRequest'); // the mTLS difference
});

test('mtls handshake: untrusted client cert fails at mutual verification', () => {
  const steps = simulateHandshake({ clientCertCa: 'rogue-ca' });
  assert.equal(steps.at(-1).result, 'fail:client-cert');
  assert.ok(steps.slice(0, -1).every(s => s.result === 'pass'));
});

test('mtls handshake: bad server cert also fails mutual verification', () => {
  const steps = simulateHandshake({ serverCertValid: false });
  assert.equal(steps.at(-1).result, 'fail:server-cert');
});
