# API reference

## `better-auth-dbsc`

| Export | Kind | Description |
| --- | --- | --- |
| `dbsc(options?)` | function | The server plugin. Options are in [Configuration](./configuration.md). |
| `dbscRefreshNeeded(auth, headers)` | function | `Promise<boolean>`. True when a request is a cross-site navigation of a bound session that arrived without a valid bound cookie. See [Links from other sites](./integrations.md#links-from-other-sites). |
| `dbscRefreshPage()` | function | `Response`. A minimal HTML page that reloads itself once with a meta refresh (`Cache-Control: no-store`). |
| `DBSC_PATHS` | constant | Endpoint paths: `start`, `refresh`, `refreshNeeded`, `status`. |
| `DBSC_ERROR_CODES` | constant | Error codes, see [below](#error-codes). |
| `DBSC_MODEL` | constant | `"dbscSession"`, the model name. |
| `SUPPORTED_ALGORITHMS` | constant | `["ES256", "RS256"]`. |
| `DbscOptions` | type | Plugin options. |
| `DbscEvent` | type | Union of the events passed to `onEvent`. |
| `DbscScopeRule` | type | One `scope.rules` entry. |
| `DbscAlgorithm` | type | `"ES256" \| "RS256"`. |
| `DbscSessionRecord` | type | A row of the `dbscSession` table. |

## `better-auth-dbsc/client`

| Export | Description |
| --- | --- |
| `dbscClient()` | Client plugin for `createAuthClient`. Adds `authClient.dbsc.status()` and the plugin's error codes. |
| `DBSC_ERROR_CODES` | Same as the server export. |

## Endpoints

Paths are relative to Better Auth's base path (`/api/auth` by default).

| Endpoint | Method | Called by | Description |
| --- | --- | --- | --- |
| `/dbsc/start` | POST | the browser | Registration. Verifies the proof, stores the key, sets the bound cookie and returns the session instructions. |
| `/dbsc/refresh` | POST | the browser | Refresh. Verifies the proof and returns a new bound cookie, or 403 with a fresh challenge. |
| `/dbsc/status` | GET | your client | Requires a session. Returns `{ bound: boolean, algorithm: "ES256" \| "RS256" \| null, boundAt: Date \| null }`. |
| `/dbsc/refresh-needed` | GET | your server | Returns `{ refreshNeeded: boolean }`, the HTTP form of `dbscRefreshNeeded`. |
| `auth.api.dbscRegistrationOffer` | — | your server | Server-only, no HTTP route. Returns `{ name, value }` (a header to copy onto a page response) at most once per session, or `null`. |

`/dbsc/start` and `/dbsc/refresh` speak the DBSC protocol and are not meant to be called by your code. They are excluded from Better Auth's rate limiter.

## Events

`onEvent` receives one of these objects:

| `type` | Fields | When |
| --- | --- | --- |
| `session-registered` | `userId`, `sessionId`, `dbscSessionId` | A session was bound to a device key. |
| `session-refreshed` | `userId`, `sessionId`, `dbscSessionId` | A bound cookie was renewed. |
| `proof-invalid` | `userId`, `sessionId`, `dbscSessionId` | A proof's signature failed against the stored key. |
| `proof-missing` | `userId?`, `sessionId?`, `path?` | A bound session was used without a valid bound cookie: a stolen cookie, or a browser whose refresh failed. The session cookie was ignored for that request. |
| `refresh-skipped` | `reason`, `dbscSessionId` | The browser reported a skipped refresh in `Secure-Session-Skipped`. `reason` is `unreachable`, `server_error` or `quota_exceeded`. |

`refresh-skipped` events are client hints: anyone can send that header. Only a few well-formed session ids per request are reported, and never on the protocol endpoints. Do not page on them alone.

## Error codes

| Code | Message |
| --- | --- |
| `ALREADY_BOUND` | This session is already bound to a device |
| `DEVICE_PROOF_REQUIRED` | This session is bound to a device and the request has no device proof |
| `INVALID_CHALLENGE` | The device proof does not answer a valid challenge |
| `INVALID_PROOF` | The device proof is invalid |
| `KEY_ALREADY_USED` | This device key is already bound to another session |
| `MISSING_PROOF` | The Secure-Session-Response header is missing |
| `MISSING_SESSION_ID` | The Sec-Secure-Session-Id header is missing |
| `SESSION_NOT_FOUND` | The device-bound session does not exist or has ended |
| `UNAUTHORIZED` | A signed-in session is required |

## Database table

One row per bound session, in `dbscSession`. It is kept apart from `session`, so session writes can never overwrite the binding and keys never reach session payloads.

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | Primary key. |
| `userId` | string | References `user.id`, cascade on delete. Indexed. |
| `sessionId` | string | Better Auth session id. Indexed. No foreign key: with `secondaryStorage` the session row may not exist in the database. |
| `dbscSessionId` | string | `session_identifier` sent to the browser. Unique. |
| `tokenHash` | string | base64url(SHA-256(session token)). Unique. |
| `sessionTokenEncrypted` | string | Session token, encrypted with the auth secret. |
| `publicKey` | string | Minimal public JWK, as JSON. |
| `keyThumbprint` | string | RFC 7638 thumbprint. Unique: a key binds only one session. |
| `algorithm` | string | `ES256` or `RS256`. |
| `lastChallengeAt` | bigint | Issue time, in epoch milliseconds, of the newest accepted challenge. Replay guard. |
| `refreshCount` | number | Successful refreshes. |
| `expiresAt` | date | Session expiry, kept in step with the session. Indexed. |
| `createdAt`, `updatedAt` | date |  |

`lastChallengeAt` must be a 64-bit column. Tables created with a 32-bit `integer` (Postgres, MySQL, MSSQL) cannot store any binding: regenerate the schema or alter the column to `bigint`. The plugin logs an error when it cannot store a binding.

## HTTP headers

| Header | Direction | Purpose |
| --- | --- | --- |
| `Secure-Session-Registration` | response | Registration offer. |
| `Secure-Session-Challenge` | response | Challenge for the next proof. |
| `Secure-Session-Response` | request | The signed proof (`dbsc+jwt`). |
| `Sec-Secure-Session-Id` | request | The DBSC session being refreshed. |
| `Secure-Session-Skipped` | request | The browser skipped a refresh. |

Proxies in front of Better Auth must forward all of them.
