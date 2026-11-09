# Getting started

## Requirements

- Better Auth 1.7.18 or later, with a database. Stateless sessions are not supported: the plugin stores one row per bound session.
- Node.js 22 or later, or another runtime Better Auth supports (Bun, Cloudflare Workers, edge runtimes, Convex).
- HTTPS in production. Chrome ignores DBSC headers on plain HTTP.

## 1. Install

```sh
npm install better-auth-dbsc
# or: pnpm add / yarn add / bun add better-auth-dbsc
```

## 2. Add the server plugin

```ts
// auth.ts
import { betterAuth } from "better-auth";
import { dbsc } from "better-auth-dbsc";
import { anonymous, bearer, twoFactor } from "better-auth/plugins";

export const auth = betterAuth({
  // database, emailAndPassword, socialProviders…
  plugins: [
    bearer(),
    twoFactor(),
    dbsc(), // after bearer(), twoFactor() and crossDomain()
    anonymous(), // plugins whose hooks read the session go after dbsc()
  ],
});
```

Order matters. `dbsc()` must come after `bearer()`, `twoFactor()` and `crossDomain()`, and before `anonymous()` and `username()`. The plugin checks this at startup and throws if the order is wrong.

## 3. Create the table

The plugin adds one table, `dbscSession`. Generate or apply it with the Better Auth CLI:

```sh
npx auth generate   # Drizzle, Prisma, Convex…
npx auth migrate    # built-in Kysely adapter
```

The table is described in the [API reference](./api-reference.md#database-table).

## 4. Optional: add the client plugin

The browser runs the protocol by itself from response headers, so no client code is required. The client plugin only adds a typed status call and the plugin's error codes:

```ts
import { dbscClient } from "better-auth-dbsc/client";
import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient({ plugins: [dbscClient()] });

const { data } = await authClient.dbsc.status();
// { bound: true, algorithm: "ES256", boundAt: Date }
```

## 5. Check that it works

1. Open the app in Chrome on Windows or macOS over HTTPS, and sign in.
2. Open DevTools, then **Application → Device Bound Sessions**. The new session is listed with its scope and bound cookie.
3. Call `authClient.dbsc.status()`: `bound` is `true`.

No TPM, or developing on Linux? See [Local testing](./local-testing.md).

## 6. Watch for stolen cookies

Pass `onEvent` to log or alert on security events. A `proof-missing` event means a bound session was used without the device proof: a stolen cookie, or a browser whose refresh failed.

```ts
dbsc({
  onEvent(event) {
    if (event.type === "proof-missing") {
      logger.warn("dbsc: session used without device proof", event);
    }
  },
});
```

The event types are listed in the [API reference](./api-reference.md#events).

## Next steps

- Using Convex, a proxy, server components or SSO? Read [Integrations](./integrations.md).
- Tune cookie lifetime and scope in [Configuration](./configuration.md).
- Read the [Security model](./security.md) before relying on the plugin.
