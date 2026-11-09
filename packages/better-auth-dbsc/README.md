# better-auth-dbsc

[Device Bound Session Credentials](https://w3c.github.io/webappsec-dbsc/) (DBSC) for [Better Auth](https://better-auth.com).

Infostealer malware copies session cookies and replays them from another machine, which skips passwords, 2FA and passkeys entirely. With DBSC, a supporting browser binds each session to a private key kept in hardware (TPM, Secure Enclave). This plugin then **refuses the Better Auth session cookie of a bound session unless the request also carries a short-lived cookie that only the key holder can renew**. A stolen session cookie stops working on any other device.

- Implements the current W3C editor's draft (`Secure-Session-*` headers, `dbsc+jwt` proofs) as Chrome ships it.
- Enforces the binding on every session read through Better Auth's endpoints and `auth.api`.
- Works with every sign-in method, including SSO and OAuth callbacks and server-side sign-ins.
- Progressive: browsers without DBSC keep working exactly as before.
- Runs anywhere Better Auth runs (Node, Bun, Cloudflare Workers, edge runtimes, Convex). Crypto by [`@noble`](https://paulmillr.com/noble/) and [`@scure/base`](https://github.com/paulmillr/scure-base).

**[Read the documentation](https://github.com/helixnebulatech/better-auth-dbsc/tree/main/docs)**

## Install

```sh
npm install better-auth-dbsc
```

## Usage

```ts
// auth.ts
import { betterAuth } from "better-auth";
import { dbsc } from "better-auth-dbsc";
import { anonymous, bearer, twoFactor } from "better-auth/plugins";

export const auth = betterAuth({
  plugins: [
    bearer(),
    twoFactor(),
    dbsc(), // after bearer(), twoFactor() and crossDomain()
    anonymous(), // plugins whose hooks read the session go after dbsc()
  ],
});
```

`dbsc()` checks the plugin order at startup. Then create the `dbscSession` table:

```sh
npx auth generate   # Drizzle, Prisma, Convex…
npx auth migrate    # built-in Kysely adapter
```

That is all: the browser runs the protocol from response headers. The optional client plugin adds a typed status call:

```ts
import { dbscClient } from "better-auth-dbsc/client";
import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient({ plugins: [dbscClient()] });

const { data } = await authClient.dbsc.status(); // { bound, algorithm, boundAt }
```

## Browser support

DBSC works in Chrome on Windows (TPM) and macOS (Secure Enclave), and in Edge on Windows. Firefox and Safari do not support it yet: their sessions are not bound and work as before, without this protection. [Details](https://github.com/helixnebulatech/better-auth-dbsc/blob/main/docs/browser-support.md).

## Documentation

- [Getting started](https://github.com/helixnebulatech/better-auth-dbsc/blob/main/docs/getting-started.md)
- [How it works](https://github.com/helixnebulatech/better-auth-dbsc/blob/main/docs/how-it-works.md)
- [Integrations](https://github.com/helixnebulatech/better-auth-dbsc/blob/main/docs/integrations.md): Convex, proxies, server components, links from other sites, subdomains
- [Configuration](https://github.com/helixnebulatech/better-auth-dbsc/blob/main/docs/configuration.md)
- [API reference](https://github.com/helixnebulatech/better-auth-dbsc/blob/main/docs/api-reference.md)
- [Security model](https://github.com/helixnebulatech/better-auth-dbsc/blob/main/docs/security.md): read it before relying on the plugin
- [Local testing and troubleshooting](https://github.com/helixnebulatech/better-auth-dbsc/blob/main/docs/local-testing.md)

## Security

Report vulnerabilities privately: see [SECURITY.md](https://github.com/helixnebulatech/better-auth-dbsc/blob/main/SECURITY.md).

## Credits

Built and maintained by [Helix Nebula](https://helixnebula.dev).

## License

MIT
