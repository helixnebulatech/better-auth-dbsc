# How it works

Infostealer malware copies session cookies and replays them from another machine. This skips passwords, 2FA and passkeys entirely, because the attacker never signs in: they reuse a session that already exists.

DBSC closes that gap. A supporting browser creates a key pair for the session and keeps the private key in hardware (a TPM on Windows, the Secure Enclave on macOS), where it cannot be exported. The server issues a short-lived cookie that only the key holder can renew. The plugin then **refuses the Better Auth session cookie of a bound session unless the request also carries that short-lived cookie**.

```
Browser                                         Server (Better Auth + dbsc)
   │  sign-in                                          │
   │ ───────────────────────────────────────────────▶  │
   │  ◀─ Set-Cookie: session                           │
   │     Secure-Session-Registration (challenge)       │
   │                                                   │
   │  POST /dbsc/start  (proof signed with new key)    │
   │ ───────────────────────────────────────────────▶  │ store public key
   │  ◀─ 200 instructions + bound cookie + challenge   │
   │                                                   │
   │  normal requests (session + bound cookie)         │
   │ ───────────────────────────────────────────────▶  │ check bound cookie
   │                                                   │
   │  bound cookie about to expire                     │
   │  POST /dbsc/refresh (proof of the last challenge) │
   │ ───────────────────────────────────────────────▶  │ verify with stored key
   │  ◀─ 200 new bound cookie + next challenge         │
```

## 1. Sign-in: the registration offer

Each session is offered registration exactly once, in the sign-in response. This covers every sign-in method: email and password, social providers, passkeys, magic links and others. The offer is a `Secure-Session-Registration` header with a challenge bound to the new session.

Two cases need more than a header on the sign-in response:

- **Cross-site sign-ins (SSO and OAuth callbacks).** The browser's registration request will not carry the `SameSite=Lax` session cookie, because it inherits the cross-site context. The offer therefore also carries a short-lived encrypted ticket, in the spec's `authorization` parameter, that tells the server which session is registering.
- **Server-side sign-ins (`auth.api`).** There is no response to the browser to attach the offer to. The plugin stores a one-time marker for 5 minutes. The first same-site `/get-session`, or a call to `auth.api.dbscRegistrationOffer`, consumes it atomically. See [Integrations](./integrations.md#apps-that-read-the-session-only-on-the-server).

The plugin never offers twice. A second offer would make Chrome start a second registration with a second key while the first one is still running.

## 2. Registration: `POST /dbsc/start`

The browser creates a key pair, signs the challenge with it and sends the proof (a `dbsc+jwt`). The plugin:

1. Verifies the signature and the challenge.
2. Stores the public key in `dbscSession`. A key can bind only one session.
3. Sets the bound cookie, 10 minutes by default.
4. Returns the session instructions (scope and bound cookie name) and the challenge for the first refresh.

Chrome logs one cosmetic `NoSessionMatch` event when it receives that challenge; see [Local testing](./local-testing.md#nosessionmatch-on-registration).

## 3. Requests: enforcement

A before hook runs on every request that carries a Better Auth session cookie. If the session is bound, the request must also carry a valid bound cookie for that session. Otherwise the plugin removes the session cookies from the request, and the session reads as signed out for that request.

- The bound cookie is an HMAC over the session token. It verifies without a database read.
- Requests sent while the registration was in flight are accepted for 10 seconds after the binding is created.
- A bound cookie is accepted up to 30 seconds past its expiry, to cover requests already in flight during a refresh.

Enforcement covers every session read through Better Auth's endpoints and `auth.api`. The [Security model](./security.md#what-is-covered) lists exactly which reads are covered and which are not.

## 4. Refresh: `POST /dbsc/refresh`

When the bound cookie has less than 2 minutes left and the browser sends an in-scope request, Chrome holds that request and refreshes first:

1. It signs the last challenge it was given with the device key.
2. The plugin verifies the proof against the stored public key and checks that the challenge is fresh and newer than the last one accepted.
3. The plugin answers 200 with a new bound cookie and the challenge for the next refresh.

If the browser has no usable challenge, the plugin answers 403 with a fresh one, and the browser signs again. An attacker with copied cookies has no key and cannot complete this step.

## Sign-out and expiry

Signing out, revoking a session or letting it expire removes the binding. The plugin's session-delete hook deletes the row, and rows whose session is gone are ignored.

## Browsers without DBSC

Browsers that do not support DBSC ignore the registration header. Their sessions are never bound and work exactly as before. See [Browser support](./browser-support.md).
