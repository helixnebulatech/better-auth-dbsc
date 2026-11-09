# Cookie cache (`session_data`) and device-bound sessions: alternatives

Design note, 2026-11-09. Status: **alternative 1 is what ships today**; 2 and 3 are not implemented.

## The problem

With `session.cookieCache.enabled`, Better Auth keeps a signed snapshot of the session in a `session_data` cookie (`maxAge` 300 s by default), so that reading the session does not need a database query.

Inside Better Auth this snapshot is safe. `getSession` uses it only together with the signed `session_token` cookie, and the plugin's `enforce` hook removes both from the request when a bound session arrives without a valid bound cookie.

Outside Better Auth it is not. `getCookieCache()` and `decodeCookieCache()` from `better-auth/cookies` read `session_data` on their own, typically in Next.js or edge middleware. They check only its signature and expiry: no `session_token`, no bound cookie, no database. No plugin code runs, so DBSC cannot intervene.

The result: an app that **authorizes** with `getCookieCache()` accepts a stolen `session_data` cookie until it expires (up to `cookieCache.maxAge` after Better Auth last issued it), even though the session is device-bound. Sign-out does not cut this short either, because nothing consults the database. This is Better Auth's generic cookie-cache behaviour and is the same without DBSC.

Measured with real Chromium (e2e, `cookieCache` enabled, `maxAge` 300): after binding, Chrome's cookie jar holds `session_data`, and `getCookieCache()` over the whole jar returns the session.

Exposure requires all of:

1. `session.cookieCache.enabled` (off by default in Better Auth);
2. app code that authorizes with `getCookieCache()` / `decodeCookieCache()` (or verifies a JWT-strategy `session_data` elsewhere), rather than using it only for routing hints;
3. use of the stolen copy before it expires: 5 minutes by default, comparable to the 10 minutes a stolen bound cookie stays valid.

## Alternative 1: document and warn (current)

What ships:

- [Security model](./security.md#code-outside-better-auth): `getCookieCache()`, `decodeCookieCache()` and JWT-verified `session_data` are listed among the readers the plugin does not cover. They should be used for routing hints only, with authorization going through `auth.api.getSession`. It also recommends keeping `session.cookieCache.maxAge` at or below `cookieMaxAge`.
- `init()` logs a warning when the cookie cache is enabled and `cookieCache.maxAge` is longer than `cookieMaxAge`.
- Regression test: "warns when the cookie cache outlives the bound cookie".

|               |                                                        |
| ------------- | ------------------------------------------------------ |
| Security      | The hole stays open for apps that ignore the guidance. |
| Cost          | None.                                                  |
| Compatibility | None.                                                  |
| Complexity    | None.                                                  |

## Alternative 2: a DBSC-aware middleware helper

An exported helper, for example `dbscGetCookieCache(request, options)`, for apps that want the full session in middleware. It would call `getCookieCache()` and then, using the `session.token` inside the snapshot:

1. compute the token hash and the bound cookie name (`<prefix>dbsc_<tag>`);
2. if that bound cookie is present, verify its MAC offline with keys derived from the Better Auth secret (the same check `enforce` does, no database);
3. accept the snapshot only when the bound cookie is valid, or when the session is known to be unbound.

The open problem is step 3. Without the database, a session with no bound cookie can be either unbound (Firefox, Safari, Chrome without DBSC) or bound with a stolen jar. The helper would have to pick one of these:

- **fail closed:** treat it as no session. Every user without DBSC then reads as signed out in middleware, which is not acceptable as a default;
- **look the binding up:** one database read per request, which removes the reason to use the cookie cache in middleware;
- **carry a marker in the snapshot:** for example a session field the plugin sets when the session is bound. This makes the snapshot self-describing. A snapshot taken before binding still claims "unbound" until it expires, unless the registration response also expires it (see alternative 3).

|  |  |
| --- | --- |
| Security | Closes the hole only for apps that switch to the helper. |
| Cost | None for apps that do not use it. Depends on the variant chosen for step 3. |
| Compatibility | Opt-in: no change for anyone who does not call it. |
| Complexity | Medium. The key derivation and cookie MAC become a public, versioned surface. A marker field would also change the schema. |

Apps that would adopt this helper have to change their middleware anyway. They could equally switch to `getSessionCookie()` (presence check, unaffected by DBSC) for routing and call `/get-session` when they need the data.

## Alternative 3: drop the cookie cache of bound sessions (`boundSessionCookieCache`)

A plugin option, for example `boundSessionCookieCache: "keep" | "drop"`. With `"drop"`, a device-bound session never keeps a `session_data` cookie, so a stolen cookie jar contains nothing `getCookieCache()` accepts.

Mechanism (prototyped, not merged):

- **`/dbsc/start` response:** call Better Auth's exported `expireCookie(ctx, ctx.context.authCookies.sessionData)` plus `createSessionStore(...).clean()` for chunks. This removes the copy set at sign-in, before the session was bound, and the copy `getSessionFromCtx` re-issues inside the same response. Building the deletion `Set-Cookie` by hand is not enough, because Better Auth appends a fresh copy after it.
- **After hook** on all non-protocol paths (not `/sign-out`): when the request carries `session_data` or the response is about to set it, and the session (`ctx.context.newSession ?? ctx.context.session`) is bound, expire it the same way. The session counts as bound if the request carries a valid bound cookie (offline check, no read) or if a binding row exists. Better Auth's own two-factor after hook uses the same pattern (`removeSetCookieEntries` via `expireCookie`).
- Unbound sessions are untouched.
- With `"drop"`, the startup warning about `cookieCache.maxAge` is skipped.

Prototype results:

- **Unit tests:** compact, jwe and jwt strategies all pass. A stolen jar yields `null` from `getCookieCache()`, unbound sessions keep their cache, a re-issued session (`/update-user`) does not get it back, and a stolen session cookie cannot mint a fresh copy.
- **Real Chromium e2e:** run with `"keep"` and with `"drop"`, both for a same-site sign-in and for a cross-site magic-link (ticket) sign-in.
  - `"keep"`: Chrome's jar holds `session_data` after binding.
  - `"drop"`: it never does.
  - In both modes registration, refresh and stolen-cookie refusal keep working.
- **Cost** measured over 5 page loads of a bound session:
  - `findSession` reads: 0 with `"keep"`, 5 with `"drop"`.
  - Extra binding reads: none in either mode.

|  |  |
| --- | --- |
| Security | Closes the hole for every app, including those that misuse `getCookieCache()`, when `"drop"` is active. |
| Cost | Bound sessions lose the cookie cache: one session read per `/get-session`, as in any Better Auth app without `cookieCache`. |
| Compatibility | Middleware that uses `getCookieCache()` sees DBSC users as signed out, which can cause redirects to the login page. Apps not using it notice only the extra read. |
| Complexity | Low to medium: about 70 lines of code, one option, and coupling to Better Auth's cookie helpers (`expireCookie`, `createSessionStore`) and its pending `Set-Cookie` layout. |

Default choice, if implemented:

- **`"drop"` by default:** secure without operator action. Breaks `getCookieCache()`-based middleware for Chrome DBSC users.
- **`"keep"` by default:** no behaviour change. The README and the startup warning would recommend `"drop"`.

## Recommendation (not yet decided)

Keep alternative 1. The exposure needs a non-default Better Auth setting plus app code that authorizes against Better Auth's guidance. With default settings the window is comparable to an already-accepted residual (a stolen bound cookie). Alternatives 2 and 3 have real costs for apps that do not have the problem.

Revisit if users report authorizing in middleware with `getCookieCache()`. In that case alternative 3 is the cheaper one to ship, opt-in with `"keep"` as the default.
