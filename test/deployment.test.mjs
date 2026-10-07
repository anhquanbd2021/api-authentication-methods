import test from 'node:test';
import assert from 'node:assert/strict';
import { createStaticServer } from '../app/server.js';

async function withServer(fn) {
  const server = createStaticServer();
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try { await fn(base); } finally { server.close(); }
}

test('server serves the lab, health, and version', async () => {
  await withServer(async (base) => {
    const html = await (await fetch(`${base}/`)).text();
    assert.match(html, /API Auth Lab/);
    assert.equal(await (await fetch(`${base}/health`)).text(), 'ok');
    const v = await (await fetch(`${base}/version`)).json();
    assert.equal(v.name, 'api-authentication-methods-demo');
    const mod = await fetch(`${base}/crypto.mjs`);
    assert.equal(mod.status, 200);
    assert.equal((await fetch(`${base}/missing`, { method: 'GET' })).status, 404);
  });
});

test('responses carry security headers', async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/`);
    assert.match(res.headers.get('content-security-policy'), /default-src 'self'/);
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  });
});
