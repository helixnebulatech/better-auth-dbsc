# better-auth-dbsc

## 0.2.0

### Minor Changes

- [#7](https://github.com/helixnebulatech/better-auth-dbsc/pull/7) [`8b467ea`](https://github.com/helixnebulatech/better-auth-dbsc/commit/8b467ea1ddfe6821448e9ec2c1982d7ca83f48e5) Thanks [@helixnebulatech](https://github.com/helixnebulatech)! - Require Better Auth 1.7.25 or later (`better-auth` and `@better-auth/core` peer dependencies) and Node.js 26 or later (`engines`). `multiSession()` must now come before `dbsc()` in `plugins`; the plugin refuses to start otherwise, naming the plugin to move.

### Patch Changes

- [#7](https://github.com/helixnebulatech/better-auth-dbsc/pull/7) [`8b467ea`](https://github.com/helixnebulatech/better-auth-dbsc/commit/8b467ea1ddfe6821448e9ec2c1982d7ca83f48e5) Thanks [@helixnebulatech](https://github.com/helixnebulatech)! - Expire a session's bound cookie and unbound marker whenever a response expires a cookie that holds that session, not only on `/sign-out`. This covers Better Auth's session cookie (`/sign-out`, `/revoke-session` and `/revoke-sessions` on the current session, `/delete-user` and its emailed link, `/get-session` finding the session gone) and `multiSession()`'s `_multi-` cookies (`/multi-session/revoke`, `/multi-session/set-active` on a session that is gone, signing in again to the same account, and every account on `/sign-out`). The plugin reads this from the response, without a database read, and the last Set-Cookie for a name counts. When a response signs the browser in to another session, the plugin reads the old session once and expires its DBSC cookies if it is gone (`/change-password` with `revokeOtherSessions`); admin impersonation and switching accounts keep them. With `crossDomain()` from `@convex-dev/better-auth`, cookies already moved to `Set-Better-Auth-Cookie` count too, before the remaining Set-Cookie headers. Chrome ends its device-bound session on the next request. A sign-in held by `twoFactor()` expires the session cookie the browser had, so its DBSC cookies go too. An unbound marker is no longer handed out for a session that the same response ends. On runtimes without `Headers.getSetCookie`, the plugin falls back to the joined `Set-Cookie` header, as Better Auth does.

- [#7](https://github.com/helixnebulatech/better-auth-dbsc/pull/7) [`8b467ea`](https://github.com/helixnebulatech/better-auth-dbsc/commit/8b467ea1ddfe6821448e9ec2c1982d7ca83f48e5) Thanks [@helixnebulatech](https://github.com/helixnebulatech)! - Stop reading the database on every request of a browser without DBSC. A request with a session cookie and no bound cookie used to cost one `dbscSession` lookup each time, even with `cookieCache` enabled. Once a session can no longer register, the plugin now sets an unbound marker cookie (`dbsc_unbound_<tag>`, an HMAC over the session token, valid for 24 hours), and requests that carry it skip the lookup. The marker is never issued while the session can still become bound, so a session cookie copied before the registration still stops working as soon as the session is bound. The marker needs a lookup made after that point (a lookup shared within a request keeps the time it was made), and a registration whose binding write returns too late is rolled back (or its session revoked), so a marker never coexists with a binding.

  To make that point in time exist, a session can now only register during its first 10 minutes: registration challenges are valid for 5 minutes instead of `challengeMaxAge`, and `/dbsc/start` refuses older sessions. Chrome registers as soon as it receives the offer, so this does not change normal registrations.

  `/get-session` also no longer looks for a deferred registration offer once the offer's 5-minute lifetime has passed.

## 0.1.1

### Patch Changes

- [#4](https://github.com/helixnebulatech/better-auth-dbsc/pull/4) [`3fde539`](https://github.com/helixnebulatech/better-auth-dbsc/commit/3fde5392ed208b384570319b1867eb409d6f349d) Thanks [@helixnebulatech](https://github.com/helixnebulatech)! - Sweep dead bindings with one range condition per query, so the cleanup also runs on adapters that only query through indexes (such as Convex). It used to fail there with "cannot have more than one lower bound where clause" and never delete anything.

## 0.1.0

### Minor Changes

- [`68c2b74`](https://github.com/helixnebulatech/better-auth-dbsc/commit/68c2b740509feaa278017749266daea478b3f628) Thanks [@helixnebulatech](https://github.com/helixnebulatech)! - First release: Device Bound Session Credentials (DBSC) for Better Auth.

### Patch Changes

- [`68c2b74`](https://github.com/helixnebulatech/better-auth-dbsc/commit/68c2b740509feaa278017749266daea478b3f628) Thanks [@helixnebulatech](https://github.com/helixnebulatech)! - Close several ways a stolen session cookie could still be used after the session was bound:

  - Cookie values are read exactly as Better Auth reads them (a quoted value no longer slips past the check).
  - Cookies in `Better-Auth-Cookie` and in the Cookie header are checked separately, so one cannot hide the other.
  - A bearer token is checked against the session it actually resolves to, so a case-swapped or otherwise loosely matching copy of a bound token is refused on databases with case-insensitive collations.
  - Refused cookies are also removed from the headers later before hooks read, and `dbsc()` must now come before `anonymous()` and `username()` and after `crossDomain()`.
  - Every multi-session cookie multiSession() reads is checked, including on `/sign-out`, with a bounded number of lookups per request.
  - The binding cleanup in `/dbsc/start` no longer deletes the binding of a session Better Auth extended; the stored expiry is kept in sync.
  - `lastChallengeAt` is a `bigint` column (millisecond timestamps overflow a 32-bit INTEGER on Postgres, MySQL and MSSQL). Regenerate or migrate the `dbscSession` table.
  - Concurrent registrations on databases without unique indexes can no longer bind two keys to one session, and a binding that cannot be stored is logged as an error.
  - `Secure-Session-Skipped` reports are capped, de-duplicated and ignored on the protocol endpoints.
  - A warning is logged when `session.cookieCache.maxAge` is longer than `cookieMaxAge`.
