# Binding lookups for browsers without DBSC: alternatives

Design note, 2026-11-11. Status: **alternative 4 is what ships**; the others are not implemented. Alternative 3 was prototyped and replaced.

## The problem

The `enforce` hook has to know whether a session is bound. A valid bound cookie answers that offline. A request with a session cookie and no bound cookie did not: it cost one lookup in `dbscSession`, on every request, even with `session.cookieCache` enabled. Firefox, Safari and Chrome without DBSC never have a bound cookie, so they paid that lookup for the whole life of the session. A Better Auth maintainer reported it and suggested storing an "unbound" flag in the `session_data` cookie cache.

A second read had the same shape: every same-site `/get-session` looked for a deferred registration offer, bound or not. That one has a fix with no trade-off (the offer cannot exist once the session is 5 minutes 10 seconds old, so the read is skipped) and is not discussed further.

## The constraint

Any fix caches the answer "this session is not bound" somewhere the request can present it. That answer is a bearer value, and it can change: a session goes from unbound to bound when the browser registers, shortly after sign-in. A cached "unbound" that outlives the registration lets a copied session cookie through, which is the one thing the plugin exists to prevent.

The server cannot tell at sign-in whether the session will register. Chrome does not announce DBSC support in its requests; the offer is sent to every browser and the ones without DBSC ignore it.

So a cached "unbound" is safe only if it is written when the answer can no longer change, or if it lives in state every server shares and registration updates.

## What was required

1. No weakening. Today a session cookie copied before the registration stops working as soon as the session is bound. That must stay true.
2. As few reads as possible.
3. No change to Better Auth's own tables, and no security check that depends on the format of Better Auth's cookies.

## Alternative 1: keep the lookup and document it

|            |                                                 |
| ---------- | ----------------------------------------------- |
| Security   | Unchanged.                                      |
| Reads      | One per request for every browser without DBSC. |
| Complexity | None.                                           |

Rejected: it leaves the reported cost in place.

## Alternative 2: an "unbound" flag in `session_data`

The maintainer's suggestion. The plugin would mark the cached session as unbound, and `enforce` would trust the mark.

- **The flag is stale by construction.** Better Auth writes `session_data` at sign-in, before the registration, so every session of a DBSC browser starts with a snapshot that says "unbound", valid for `cookieCache.maxAge` (5 minutes by default). A cookie jar copied before the registration would keep working for that long. The victim's own stale snapshot would also stay in the jar after the registration, and replacing it in the `/dbsc/start` response is not a plain deletion: Better Auth appends a fresh copy in the same response.
- **There is nowhere to put it.** The payload has a fixed shape (`session`, `user`, `updatedAt`, `version`). The flag needs a new field on the `session` table, or the plugin has to intercept and re-sign the cookie.
- **Reading it is fragile.** `enforce` would have to decode the three cache strategies (compact, JWE, JWT, plus a custom signer) and chunked cookies before the endpoint runs.
- **It only helps apps with `cookieCache`**, which is off by default.

|  |  |
| --- | --- |
| Security | A copy made before the registration works for up to `cookieCache.maxAge`. |
| Reads | One per `cookieCache.maxAge`, only with the cookie cache enabled. |
| Complexity | High: session schema change or cookie re-signing, and decoding Better Auth's cache. |

Rejected. Writing the flag only once the session can no longer register would remove the first problem, but that is alternative 4 with the other three problems added.

## Alternative 3: a marker cookie issued by the first lookup

A cookie owned by the plugin (`dbsc_unbound_<tag>`, an HMAC over the session token under its own key), set as soon as a lookup finds no binding and valid for `cookieMaxAge`. Prototyped, with tests.

It fixes the container: no schema change, no dependence on `session_data`, and it works without the cookie cache. It does not fix the timing. A marker issued in the moment between sign-in and registration keeps a copied session cookie working for up to `cookieMaxAge`, and a response already in flight can put the marker back after `/dbsc/start` has removed it.

|  |  |
| --- | --- |
| Security | A copy made before the registration works for up to `cookieMaxAge`. |
| Reads | One per `cookieMaxAge`, from the first request. |
| Complexity | Low. |

Rejected: it fails requirement 1.

## Alternative 4: a marker cookie issued once the session can no longer register (current)

The same cookie, issued only when what it says can no longer change.

- **A session can only register during its first 10 minutes 10 seconds.** A registration needs a challenge, and the plugin issues one only in the sign-in response or when a deferred offer is collected, which is possible for 5 minutes 10 seconds. Registration challenges are valid for 5 minutes (they used `challengeMaxAge`, 15 minutes by default). `/dbsc/start` also refuses any session older than that window, right before it writes the binding, so the limit is a rule and not a side effect of how offers are made.
- **The marker is issued one minute after the window ends**, when a lookup for that request found no binding. The minute covers clock differences between servers, a registration that passed the window check and is still writing its binding, and replica lag.
- **It is issued in an after hook.** `enforce` only has the token; the after hook has the session and its creation time. It reuses the lookup `enforce` made and never reads on its own.
- **It is valid for 24 hours.** What it says stays true, so the lifetime only limits how long the marker of a replaced session stays in the browser.

A session cookie copied before the registration has no marker to go with it, because none exists yet. A stolen cookie of a bound session cannot obtain one, because the lookup finds the binding.

|  |  |
| --- | --- |
| Security | Unchanged. |
| Reads | One per request during the first 11 minutes of a session, then one per 24 hours. |
| Complexity | Medium: a window check in `/dbsc/start`, a shorter registration challenge, and an after hook. |

Costs that remain:

- Browsers without DBSC still pay the lookup during the first 11 minutes of each session.
- A registration that arrives more than 5 minutes after its offer fails, and the session stays unbound until the next sign-in. Chrome registers as soon as it receives the offer, and the ticket of a cross-site sign-in already had the same limit.
- The marker reaches the browser only in responses that can set cookies. An app that reads the session only with `auth.api.getSession` in server components keeps paying the lookup until a browser request to Better Auth sets it.
- With `multiSession()`, only the active session gets a marker. The other sessions' cookies still cost a lookup on the multi-session routes.
- Signing in again without signing out leaves the old session's marker in the browser for up to 24 hours.

It rests on two assumptions: servers in one deployment share a clock within a few seconds (already in the [deployment checklist](./security.md#deployment-checklist)), and writing a binding does not take close to a minute.

## Alternative 5: a bound flag on the session row

Store the binding state in the `session` table. Without the cookie cache Better Auth reads that row on every request anyway, so the answer would be free and always current.

|  |  |
| --- | --- |
| Security | Unchanged without the cookie cache. With it, the cached row is alternative 2 again. |
| Reads | None extra without the cookie cache. |
| Complexity | Very high: a migration of the `session` table for every app, and enforcement moved after the read. |

Rejected: it fails requirement 3, and enforcement after the session read would let other plugins' hooks see a session before it is refused.

## Alternative 6: a server-side cache

- **In memory:** a cached "unbound" does not learn of a binding created on another instance, so it has the staleness of alternative 3, and serverless deployments keep no memory between requests.
- **In `secondaryStorage`:** correct if registration deletes the entry, but it is still one network call per request, and only apps that configure secondary storage have it.

Rejected: either unsafe or not a saved call.

## Alternative 7: rotate the session token on registration

If registration issued a new session token, the old token would never be bound and a marker for it would never be wrong.

Rejected: it breaks requests in flight, multi-session cookies and everything that refers to the session id, Better Auth has no primitive for it, and with the cookie cache the old token keeps working until `cookieCache.maxAge`.

## Alternative 8: decide by browser at sign-in

Offer registration only to browsers that look like Chromium (a `Sec-CH-UA` header) and mark every other session unbound from the start.

Rejected: a wrong guess leaves that session unprotected for good, and the list of browsers would need maintenance as others add DBSC. A header from the client saying it does not support DBSC is no better: whoever replays a stolen cookie would send it too.

## Tests

In `plugin.node.test.ts`, under "unbound marker" and "registration window":

- lookups stop once the session cannot register, and resume after 24 hours;
- `/get-session` reads nothing with the cookie cache on, bound or not;
- a copy made before the registration stops working at once;
- a bound session never gets a marker, and a marker only fits its own session;
- the marker and the bound cookie never verify as each other;
- a registration challenge lives 5 minutes whatever `challengeMaxAge` is;
- a session past the window is never bound, even with a fresh challenge.

## When to revisit

- If browsers start announcing DBSC support in requests, sessions that will never register could get the marker at sign-in.
- If the plugin ever offers registration again to existing sessions, the window check in `/dbsc/start` and the marker have to change together: the marker is only correct because an old session can never become bound.
