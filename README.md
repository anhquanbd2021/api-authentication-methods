# API Auth Lab — companion demo

Interactive lab for the article *6 Ways to Authenticate an API Call — and When
Each One Fails*. Run every method hands-on: decode a Basic-auth header, leak
and rotate an API key, tamper a JWT, replay an HMAC webhook, and step through
the OAuth 2.0 authorization-code flow and the mTLS handshake.

Zero dependencies — Node 20+ only. The crypto core (pure-JS SHA-256, HMAC,
HS256 JWT), the method engines, and the flow models are plain ES modules
shared by the browser UI, the proof script, and the test suite.

## Five labs

| Lab | What it proves |
|---|---|
| **Header lab** | Basic auth decodes straight back to the password; an API key is a bearer credential that only rotation can kill. |
| **JWT lab** | The payload is readable by anyone; a tampered claim fails signature verification; only the secret holder can re-sign. |
| **Webhook lab** | HMAC over `timestamp + body` catches tampering — and the freshness window catches replays. |
| **OAuth walkthrough** | Five steps of the authorization-code flow; the app never sees the user's password. |
| **mTLS walkthrough** | Mutual certificate verification — a client cert from an untrusted CA fails the handshake. |

## Run it

```text
npm start       # serve the lab on :3000
npm test        # crypto vectors + method engines + flows + server
npm run prove   # one-line verdict per method
npm run check   # both
```

## Honest limits

- Pure-JS SHA-256 is a teaching implementation — correct against published
  vectors, not constant-time hardware crypto.
- OAuth and mTLS model the message flow; no real TLS or provider round-trip.
- Webhook verification covers the `timestamp + body` principle, not every
  production scheme (AWS SigV4 canonicalizes the whole request).
- All secrets are fixtures. Never reuse them.

This is an educational demo, not production infrastructure.
