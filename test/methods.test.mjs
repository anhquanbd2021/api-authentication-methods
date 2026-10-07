import test from 'node:test';
import assert from 'node:assert/strict';
import { createKeyRegistry, basicHeader, decodeBasic, authenticateBasic, signWebhook, verifyWebhook } from '../public/methods.mjs';

test('api key: bearer credential authenticates until rotated', () => {
  const reg = createKeyRegistry();
  const key = reg.issue('partner-a');
  assert.deepEqual(reg.authenticate(key), { ok: true, clientId: 'partner-a' });
  // anyone holding the string IS the client
  assert.equal(reg.authenticate(key).clientId, 'partner-a');
  const next = reg.rotate(key);
  assert.equal(reg.authenticate(key).ok, false);
  assert.equal(reg.authenticate(next).clientId, 'partner-a');
});

test('api key: unknown keys are denied', () => {
  const reg = createKeyRegistry();
  reg.issue('partner-a');
  assert.equal(reg.authenticate('ak_forged').reason, 'unknown-key');
});

test('basic auth: header decodes straight back to the password', () => {
  const h = basicHeader('alice', 's3cret!');
  assert.match(h, /^Basic /);
  assert.deepEqual(decodeBasic(h), { user: 'alice', pass: 's3cret!' });
});

test('basic auth: verifies only exact credentials', () => {
  const users = { alice: 's3cret!' };
  assert.equal(authenticateBasic(basicHeader('alice', 's3cret!'), users).ok, true);
  assert.equal(authenticateBasic(basicHeader('alice', 'wrong'), users).reason, 'bad-credentials');
  assert.equal(authenticateBasic(basicHeader('mallory', 's3cret!'), users).reason, 'bad-credentials');
  assert.equal(authenticateBasic('Bearer xyz', users).reason, 'malformed');
});

test('webhook hmac: authentic delivery verifies', () => {
  const body = '{"event":"invoice.paid"}';
  const sig = signWebhook('whsec', 1700000000, body);
  const r = verifyWebhook('whsec', 1700000000, body, sig, { now: 1700000005 });
  assert.equal(r.ok, true);
});

test('webhook hmac: tampered body fails the signature check', () => {
  const sig = signWebhook('whsec', 1700000000, '{"amount":100}');
  const r = verifyWebhook('whsec', 1700000000, '{"amount":999}', sig, { now: 1700000005 });
  assert.equal(r.reason, 'bad-signature');
});

test('webhook hmac: stale timestamp is rejected even with a valid signature', () => {
  const body = '{"event":"payout"}';
  const sig = signWebhook('whsec', 1700000000, body);
  const r = verifyWebhook('whsec', 1700000000, body, sig, { now: 1700000000 + 3600 });
  assert.equal(r.reason, 'stale');
});

test('webhook hmac: nonce replay is rejected on the second delivery', () => {
  const seen = new Set();
  const body = '{"id":"evt_1"}';
  const sig = signWebhook('whsec', 1700000000, body);
  assert.equal(verifyWebhook('whsec', 1700000000, body, sig, { now: 1700000001, seenNonces: seen, nonce: 'evt_1' }).ok, true);
  assert.equal(verifyWebhook('whsec', 1700000000, body, sig, { now: 1700000002, seenNonces: seen, nonce: 'evt_1' }).reason, 'replay');
});
