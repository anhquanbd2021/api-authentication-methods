// app.js — wires the five labs to the shared engines.
import { signJwt, decodeJwt, verifyJwt, b64urlEncode } from './crypto.mjs';
import { createKeyRegistry, basicHeader, decodeBasic, authenticateBasic, signWebhook, verifyWebhook } from './methods.mjs';
import { OAUTH_CODE_FLOW, simulateHandshake } from './flows.mjs';

const $ = (id) => document.getElementById(id);
const SECRET = 'fixture-only-signing-secret';
const verdict = (el, ok, text) => {
  el.textContent = text;
  el.className = `badge ${ok === true ? 'ok' : ok === false ? 'bad' : ''}`;
};

// --- Lab 1: credentials in the header ----------------------------------------

const registry = createKeyRegistry();
const users = { alice: 's3cret!' };
let issuedKey = null;

$('basic-build').addEventListener('click', () => {
  const h = basicHeader($('basic-user').value, $('basic-pass').value);
  $('wire').textContent = `GET /v1/me HTTP/1.1\nAuthorization: ${h}`;
  const creds = decodeBasic(h);
  $('decoded').textContent = `user = "${creds.user}"\npass = "${creds.pass}"`;
  const r = authenticateBasic(h, users);
  verdict($('header-verdict'), r.ok, r.ok ? `Accepted — ${r.user}` : `Rejected — ${r.reason}`);
  $('key-status').textContent = 'Base64 is an encoding, not a cipher — the password just fell out of the header.';
});

$('key-issue').addEventListener('click', () => {
  issuedKey = registry.issue('partner-a');
  $('wire').textContent = `GET /v1/data HTTP/1.1\nX-API-Key: ${issuedKey}`;
  $('decoded').textContent = `key maps to client "${registry.authenticate(issuedKey).clientId}"\nbearer credential — anyone holding this string IS partner-a`;
  verdict($('header-verdict'), true, 'Accepted — partner-a');
  $('key-rotate').disabled = false;
  $('key-status').textContent = 'Leaked? The key keeps working for whoever finds it — until rotation.';
});

$('key-rotate').addEventListener('click', () => {
  const before = registry.authenticate(issuedKey).ok;
  const next = registry.rotate(issuedKey);
  const after = registry.authenticate(issuedKey).ok;
  $('decoded').textContent = `old key: ${before} → ${after ? 'still works' : 'dead (unknown-key)'}\nnew key issued: ${next.slice(0, 16)}…`;
  verdict($('header-verdict'), false, 'Old key rejected — rotation complete');
  $('key-status').textContent = 'Rotation is the only cleanup for a leaked bearer key.';
});

// --- Lab 2: JWT ----------------------------------------------------------------

let token = null;

$('jwt-issue').addEventListener('click', () => {
  try {
    const payload = JSON.parse($('jwt-payload').value);
    token = signJwt(payload, SECRET);
    $('jwt-token').textContent = token;
    const d = decodeJwt(token);
    $('jwt-decoded').textContent = `header:  ${JSON.stringify(d.header)}\npayload: ${JSON.stringify(d.payload, null, 1)}\n(anyone can read this — it is encoded, not encrypted)`;
    const r = verifyJwt(token, SECRET);
    verdict($('jwt-verdict'), r.ok, r.ok ? 'Verified' : `Rejected — ${r.reason}`);
    $('jwt-tamper').disabled = false;
  } catch (e) { verdict($('jwt-verdict'), false, `Payload JSON error — ${e.message}`); }
});

$('jwt-tamper').addEventListener('click', () => {
  const d = decodeJwt(token);
  const forgedPayload = { ...d.payload, role: 'admin' };
  const [h, , s] = token.split('.');
  const forged = `${h}.${b64urlEncode(JSON.stringify(forgedPayload))}.${s}`;
  $('jwt-token').textContent = forged;
  $('jwt-decoded').textContent = `attacker re-encoded payload: ${JSON.stringify(forgedPayload)}\nsignature still covers the ORIGINAL payload`;
  const r = verifyJwt(forged, SECRET);
  verdict($('jwt-verdict'), r.ok, `Rejected — ${r.reason}`);
  $('jwt-resign').disabled = false;
});

$('jwt-resign').addEventListener('click', () => {
  const d = decodeJwt($('jwt-token').textContent);
  token = signJwt(d.payload, SECRET);
  $('jwt-token').textContent = token;
  $('jwt-decoded').textContent = `re-signed by the real secret holder: ${JSON.stringify(d.payload)}`;
  verdict($('jwt-verdict'), verifyJwt(token, SECRET).ok, 'Verified — but only the secret holder could do this');
});

// --- Lab 3: HMAC webhook ---------------------------------------------------------

const WH_TS = 1700000000;
let whSig = null, whBody = null;

$('wh-sign').addEventListener('click', () => {
  whBody = $('wh-body').value;
  whSig = signWebhook(SECRET, WH_TS, whBody);
  $('wh-out').textContent = `POST /webhooks HTTP/1.1\nX-Signature: ${whSig}\nX-Timestamp: ${WH_TS}\n\n${whBody}`;
  const r = verifyWebhook(SECRET, WH_TS, whBody, whSig, { now: WH_TS + 5 });
  verdict($('wh-verdict'), r.ok, `Delivered — ${r.reason}`);
  $('wh-tamper').disabled = $('wh-replay').disabled = false;
});

$('wh-tamper').addEventListener('click', () => {
  const tampered = whBody.replace('4200', '99900');
  $('wh-out').textContent = `attacker rewrote the body:\n${tampered}\n\nsignature still covers the original`;
  const r = verifyWebhook(SECRET, WH_TS, tampered, whSig, { now: WH_TS + 5 });
  verdict($('wh-verdict'), r.ok, `Rejected — ${r.reason}`);
});

$('wh-replay').addEventListener('click', () => {
  $('wh-out').textContent = `same body, same signature, replayed at ${WH_TS + 3600}\n(timestamp tolerance: 300s)`;
  const r = verifyWebhook(SECRET, WH_TS, whBody, whSig, { now: WH_TS + 3600 });
  verdict($('wh-verdict'), r.ok, `Rejected — ${r.reason} (${r.age}s old)`);
});

// --- Labs 4-5: protocol walkthroughs ------------------------------------------------

let oauthIdx = -1;
function renderOAuth() {
  const ol = $('oauth-steps');
  ol.innerHTML = '';
  OAUTH_CODE_FLOW.forEach((s, i) => {
    const li = document.createElement('li');
    li.className = i < oauthIdx ? 'done' : i === oauthIdx ? 'active' : '';
    li.innerHTML = `<b>${i + 1}. ${s.label}</b><span>${s.actor}</span>`;
    ol.appendChild(li);
  });
  $('oauth-detail').textContent = oauthIdx >= 0
    ? `${OAUTH_CODE_FLOW[oauthIdx].detail} Sees: ${OAUTH_CODE_FLOW[oauthIdx].sees.join(', ')}.`
    : 'Step through the authorization-code flow — watch who sees the password.';
}
$('oauth-next').addEventListener('click', () => { oauthIdx = Math.min(oauthIdx + 1, OAUTH_CODE_FLOW.length - 1); renderOAuth(); });
$('oauth-prev').addEventListener('click', () => { oauthIdx = Math.max(oauthIdx - 1, -1); renderOAuth(); });
renderOAuth();

function renderMtls() {
  const rogue = $('mtls-rogue').checked;
  const steps = simulateHandshake({ clientCertCa: rogue ? 'rogue-ca' : 'corp-ca' });
  const ol = $('mtls-steps');
  ol.innerHTML = '';
  steps.forEach((s, i) => {
    const li = document.createElement('li');
    li.className = s.result === 'pass' ? 'done' : 'failed';
    li.innerHTML = `<b>${i + 1}. ${s.stage}</b><span>${s.by}</span>`;
    ol.appendChild(li);
  });
  const last = steps.at(-1);
  $('mtls-detail').textContent = last.result === 'pass'
    ? 'Handshake complete — both identities proven cryptographically before any data moves.'
    : last.result === 'fail:client-cert'
      ? 'Rejected at mutual verification: the client cert is not signed by a CA the server trusts.'
      : 'Rejected at mutual verification: the server cert failed validation.';
}
$('mtls-run').addEventListener('click', renderMtls);
$('mtls-rogue').addEventListener('change', renderMtls);
renderMtls();
