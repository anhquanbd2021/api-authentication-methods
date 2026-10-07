// flows.mjs — step models for the two methods that are protocols, not headers:
// OAuth 2.0 authorization-code flow and the mutual TLS handshake.

// --- 4. OAuth 2.0 -------------------------------------------------------------

export const OAUTH_CODE_FLOW = [
  { actor: 'app', label: 'Redirect to provider', detail: 'App sends the user to the provider with client_id, requested scope, and a redirect_uri — never a password field of its own.', sees: ['client_id', 'scope=read:profile', 'redirect_uri'] },
  { actor: 'user', label: 'User authenticates at the provider', detail: 'The password goes to Google/GitHub/etc. directly. The app is not in the room.', sees: ['password — visible to the provider only'] },
  { actor: 'provider', label: 'Consent + authorization code', detail: 'Provider shows the requested scope; on approval it redirects back carrying a short-lived, single-use code.', sees: ['code', 'approved scope'] },
  { actor: 'app', label: 'Server-side code exchange', detail: 'The app backend swaps code + client_secret for an access token. This leg never touches the browser — tokens stay out of URLs, history, and logs.', sees: ['access_token', 'expires_in', 'scope=read:profile'] },
  { actor: 'provider', label: 'Scoped API access', detail: 'The app calls the provider API with the token. Scope is enforced per request — read:profile cannot write.', sees: ['profile data only'] },
];

export function oauthNeverSeesPassword(trace = OAUTH_CODE_FLOW) {
  return trace.every(step =>
    step.actor === 'user' ||
    !step.sees.some(s => /password/i.test(s) && !/provider only/i.test(s)));
}

// --- 6. mTLS ------------------------------------------------------------------

export const MTLS_HANDSHAKE = [
  { stage: 'ClientHello', by: 'client', detail: 'Client offers TLS versions and cipher suites.' },
  { stage: 'ServerHello + Certificate', by: 'server', detail: 'Server presents its certificate chain — this half is ordinary TLS.' },
  { stage: 'CertificateRequest', by: 'server', detail: 'The mTLS difference: the server demands a client certificate and lists the CAs it trusts.' },
  { stage: 'Client Certificate + Verify', by: 'client', detail: 'Client presents its own certificate chain and proves it holds the private key.' },
  { stage: 'Mutual verification', by: 'both', detail: 'Each side validates the other\u2019s chain against its trust store. Both must pass — identity is established before any application bytes move.' },
];

export function simulateHandshake({ clientCertCa = 'corp-ca', trustedCas = ['corp-ca'], serverCertValid = true } = {}) {
  return MTLS_HANDSHAKE.map((step, i) => {
    let result = 'pass';
    if (i === 4) {
      if (!serverCertValid) result = 'fail:server-cert';
      else if (!trustedCas.includes(clientCertCa)) result = 'fail:client-cert';
    }
    return { ...step, result };
  });
}
