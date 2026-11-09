# better-auth-dbsc

[![npm](https://img.shields.io/npm/v/better-auth-dbsc)](https://www.npmjs.com/package/better-auth-dbsc) [![CI](https://github.com/helixnebulatech/better-auth-dbsc/actions/workflows/ci.yml/badge.svg)](https://github.com/helixnebulatech/better-auth-dbsc/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

**Stolen session cookies stop working.** A [Better Auth](https://better-auth.com) plugin for [Device Bound Session Credentials](https://w3c.github.io/webappsec-dbsc/) (DBSC).

Infostealer malware copies session cookies and replays them from another machine, skipping passwords, 2FA and passkeys. With DBSC, the browser binds each session to a private key kept in hardware (TPM, Secure Enclave). This plugin refuses the session cookie of a bound session unless the request also carries a short-lived cookie that only the key holder can renew.

- **One line of config.** No client code: the browser runs the protocol from response headers.
- **Covers every session read** through Better Auth: `/get-session`, `auth.api.getSession`, `sessionMiddleware`, the bearer plugin, the cookie cache and multi-session.
- **Every sign-in method,** including SSO and OAuth callbacks and server-side sign-ins.
- **Progressive.** Browsers without DBSC keep working exactly as before.
- **Runs anywhere Better Auth runs:** Node, Bun, Cloudflare Workers, edge runtimes and Convex.
- **Small and audited dependencies:** crypto from [`@noble`](https://paulmillr.com/noble/) and [`@scure/base`](https://github.com/paulmillr/scure-base) only.
- **Tested against real Chromium:** registration, refresh and stolen-cookie replay run end to end in CI.

## Quick start

```sh
npm install better-auth-dbsc
```

```ts
import { betterAuth } from "better-auth";
import { dbsc } from "better-auth-dbsc";

export const auth = betterAuth({
  plugins: [dbsc()],
});
```

```sh
npx auth generate   # or: npx auth migrate
```

Sign in with Chrome on Windows or macOS over HTTPS and open DevTools → **Application → Device Bound Sessions**: the session is bound.

## Documentation

|  |  |
| --- | --- |
| [Getting started](./docs/getting-started.md) | Install, plugin order, the table, the client plugin. |
| [How it works](./docs/how-it-works.md) | Registration, enforcement and refresh. |
| [Integrations](./docs/integrations.md) | Convex, proxies, server components, links from other sites, subdomains. |
| [Configuration](./docs/configuration.md) | Every option. |
| [API reference](./docs/api-reference.md) | Exports, endpoints, events, error codes, table. |
| [Browser support](./docs/browser-support.md) | Chrome and Edge today; what happens elsewhere. |
| [Security model](./docs/security.md) | What it stops, what it does not, deployment checklist. |
| [Local testing](./docs/local-testing.md) | DBSC without a TPM, DevTools, troubleshooting. |

## Repository

```
packages/
  better-auth-dbsc/   the plugin (server and client entry points)
docs/                 user documentation and protocol notes
```

```sh
bun install
bun run build
bun run test
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for the end-to-end tests, changesets and releases. Releases are published from GitHub Actions with npm Trusted Publishing and provenance. Release notes are in the [changelog](./packages/better-auth-dbsc/CHANGELOG.md).

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](./SECURITY.md).

## Credits

Built and maintained by [Helix Nebula](https://helixnebula.dev).

Thanks to the authors of the [DBSC specification](https://github.com/w3c/webappsec-dbsc), to Scott Helme for documenting [DBSC in production](https://scotthelme.co.uk/), and to the [Better Auth](https://better-auth.com) team.

## License

[MIT](./LICENSE)
