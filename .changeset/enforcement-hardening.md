---
"better-auth-dbsc": patch
---

Close several ways a stolen session cookie could still be used after the session was bound:

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
