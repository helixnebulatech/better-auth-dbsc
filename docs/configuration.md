# Configuration

All options are optional. `dbsc()` validates them at startup and throws on invalid values, because Chrome rejects, and on refresh deletes, sessions with malformed instructions.

```ts
import { dbsc } from "better-auth-dbsc";

dbsc({
  algorithms: ["ES256", "RS256"],
  cookieMaxAge: 600,
  challengeMaxAge: 900,
  registerOnGetSession: true,
  scope: { includeSite: false },
  allowedRefreshInitiators: [],
  onEvent(event) {},
  schema: {},
});
```

## `algorithms`

- **Type:** `("ES256" | "RS256")[]`
- **Default:** `["ES256", "RS256"]`

Signature algorithms offered to the browser, in order of preference. RS256 covers TPMs without ECC support and uses Web Crypto. Must not be empty.

## `cookieMaxAge`

- **Type:** `number` (seconds, integer from 300 to 86400)
- **Default:** `600`

Lifetime of the bound cookie. This is how long a stolen bound cookie stays useful, so keep it short.

Chrome refreshes when less than 120 seconds are left, and signs at most 6 proofs per 9 minutes per site. Values below 300 would exhaust that quota, and a skipped refresh makes the session read as signed out.

## `challengeMaxAge`

- **Type:** `number` (seconds, integer)
- **Default:** `cookieMaxAge + 300`
- **Minimum:** `cookieMaxAge + 120`

How long a challenge stays valid. The browser keeps the challenge from one refresh until the next, so a challenge must outlive the cookie.

## `registerOnGetSession`

- **Type:** `boolean`
- **Default:** `true`

When a sign-in response cannot carry the registration offer (cross-site SSO and OAuth callbacks, sign-ins made server-side with `auth.api`), offer it once from the first same-site `/get-session` instead. Each session is offered registration exactly once either way.

Turn it off only if you deliver the offer yourself with `auth.api.dbscRegistrationOffer` (see [Integrations](./integrations.md#apps-that-read-the-session-only-on-the-server)).

## `scope`

- **Type:** `{ origin?: string; includeSite?: boolean; rules?: DbscScopeRule[] }`
- **Default:** `{ includeSite: false }`

The DBSC scope sent to the browser: the requests for which the browser keeps the bound cookie fresh.

| Field | Description |
| --- | --- |
| `origin` | Scope origin, as a bare origin (`https://app.example.com`, no path or trailing slash). Defaults to the origin that serves the instructions. |
| `includeSite` | Cover the whole site instead of one origin. The origin must then be the registrable domain. Registering from a subdomain also needs `/.well-known/device-bound-sessions` on the registrable domain, listing that origin in `registering_origins`. |
| `rules` | Include and exclude rules, most general first. Each rule is `{ type: "include" \| "exclude", domain?: string, path?: string }`. `domain` is `*`, `*.example.com` or `example.com` (default `*`); `path` is a prefix starting with `/` (default `/`). |

Example: skip refreshes for static assets.

```ts
dbsc({
  scope: {
    rules: [{ type: "exclude", path: "/assets/" }],
  },
});
```

Excluded requests still carry the session cookie, but they are not refreshed, so they can arrive without a valid bound cookie and read as signed out. Exclude only paths that do not need the session.

## `allowedRefreshInitiators`

- **Type:** `string[]` (`*`, `*.example.com` or `example.com`)
- **Default:** none

Other hosts allowed to trigger a refresh. By default, only requests started by the session's own origin (or the user typing the URL) trigger one. The spec advises keeping this list narrow: any listed site can learn whether the user has a session.

## `onEvent`

- **Type:** `(event: DbscEvent) => void | Promise<void>`
- **Default:** none

Called for security-relevant events. Errors thrown by the callback are logged and swallowed. The events are listed in the [API reference](./api-reference.md#events).

## `schema`

- **Type:** Better Auth's `InferOptionSchema` for the `dbscSession` table
- **Default:** none

Rename the table or its fields, as with any Better Auth plugin:

```ts
dbsc({
  schema: {
    dbscSession: {
      modelName: "device_bound_session",
      fields: { userId: "user_id" },
    },
  },
});
```

## Related Better Auth settings

- **`session.cookieCache.maxAge`** should be at or below `cookieMaxAge`. The plugin logs a warning otherwise. See the [Security model](./security.md#code-outside-better-auth).
- **`secrets`** (versioned secrets) are supported. New values are signed with the current secret and old ones are still accepted.
- **`rateLimit`**: do not add rules for the DBSC endpoints. See [Integrations](./integrations.md#proxies-and-separate-auth-services).
