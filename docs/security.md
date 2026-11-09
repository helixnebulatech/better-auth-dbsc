# Security model

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## What it stops

A session cookie, or a bearer token, copied off the device and replayed from somewhere else, as long as the session was bound. Without the device key the attacker cannot renew the bound cookie, so the stolen session reads as signed out within `cookieMaxAge` (10 minutes by default) at most.

## What it does not stop

- **Malware still running on the device.** It can use the key locally, through the browser.
- **Real-time phishing of the sign-in.** The attacker signs in and binds the session to their own browser. Use passkeys against this.
- **Cross-site scripting.** Script running in your origin acts as the user, from the user's browser.
- **Sessions in browsers without DBSC.** Firefox, Safari and Chrome without a TPM stay unbound. See [Browser support](./browser-support.md).
- **Sessions created before the plugin was installed.** They are not offered registration and become device-bound at their next sign-in.
- **A failed registration.** Chrome does not retry it; the session works unbound until the next sign-in.

## What is covered

The binding is enforced on every session read through Better Auth's endpoints and `auth.api`:

- `/get-session` and every endpoint that uses `sessionMiddleware`;
- `auth.api.getSession`;
- the `bearer()` plugin;
- the cookie cache, as those endpoints read it;
- multi-session cookies;
- cookies carried in the `Better-Auth-Cookie` header (`crossDomain()`).

## Code outside Better Auth

Code that reads the session cookie without going through Better Auth is not covered:

- `getSessionCookie()`, `getCookieCache()` and `decodeCookieCache()` in edge middleware;
- verifying a JWT-strategy `session_data` cookie somewhere else;
- your own cookie parsing.

`getCookieCache()` accepts a stolen `session_data` cookie for as long as `session.cookieCache.maxAge`, without the bound cookie. Use these helpers for routing hints only, never for authorization, and authorize with `auth.api.getSession`. Keep `session.cookieCache.maxAge` at or below `cookieMaxAge`; the plugin warns otherwise.

## Your own `hooks.before`

Better Auth runs the app's `hooks.before` ahead of every plugin hook. A session read there (`getSessionFromCtx`) has not been checked yet. Do not authorize from it.

## Tokens minted from the session

Short-lived tokens minted from a session, such as JWTs from the `jwt()` plugin or the Convex token, stay valid until they expire. Minting new ones requires the device proof, so keep their lifetime short.

## Design decisions

- **Fail closed.** A failed or skipped refresh (server offline, signing quota) makes the request arrive without the bound cookie, so the session reads as signed out for that request. A binding that no secret can decrypt also fails closed: the user signs in again.
- **No database read per request.** The bound cookie is an HMAC over the session token, verified with the auth secret.
- **Replay guard.** Each binding stores the issue time of the newest accepted challenge. Older challenges are refused, and challenges expire after `challengeMaxAge`.
- **One key per session.** A key thumbprint can bind only one session.
- **Registration tickets.** Cross-site sign-ins carry a ticket sealed with XChaCha20-Poly1305 that expires after 5 minutes. It only travels in the sign-in navigation response, which page scripts cannot read. A leaked ticket could only bind that one session to another key, which signs its owner out of it, never grant access, and only until the session is bound.
- **Secrets at rest.** The session token in `dbscSession` is encrypted with the auth secret. With Better Auth's versioned `secrets`, new values use the current secret and old ones still open.
- **Never `Partitioned`.** The bound cookie is never partitioned (the spec forbids it), even when the app partitions its own cookies.
- **No 429s.** `/dbsc/start` and `/dbsc/refresh` are excluded from the rate limiter and never answer 429: Chrome before 158 treats a 429 on refresh as permanent and deletes the device-bound session.
- **Audited crypto.** ECDSA, HMAC, SHA-256 and XChaCha20-Poly1305 come from [`@noble`](https://paulmillr.com/noble/); RS256 verification uses Web Crypto.

## Deployment checklist

- [ ] HTTPS everywhere. Chrome ignores DBSC headers on plain HTTP.
- [ ] `dbsc()` in the right place in `plugins` (the plugin checks this at startup).
- [ ] `lastChallengeAt` is a 64-bit column.
- [ ] `session.cookieCache.maxAge` at or below `cookieMaxAge`.
- [ ] Authorization uses `auth.api.getSession`, never cookie helpers in middleware.
- [ ] Proxies forward the DBSC headers and never redirect `/dbsc/*`.
- [ ] No rate-limit rules on `/dbsc/start` and `/dbsc/refresh`.
- [ ] Servers in one deployment share a clock within a few seconds.
- [ ] `onEvent` sends `proof-missing` and `proof-invalid` to your logs or alerts.
