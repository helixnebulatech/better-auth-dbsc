# Documentation

`better-auth-dbsc` adds [Device Bound Session Credentials](https://w3c.github.io/webappsec-dbsc/) (DBSC) to [Better Auth](https://better-auth.com). It binds each session to a key in the user's hardware, so a session cookie copied off the device stops working anywhere else.

## Guides

1. [Getting started](./getting-started.md): install, configure and verify the plugin.
2. [How it works](./how-it-works.md): sign-in, registration, enforcement and refresh, step by step.
3. [Integrations](./integrations.md): Convex, proxies, apps that read the session only on the server, links from other sites, and subdomains.
4. [Configuration](./configuration.md): every option, with defaults and limits.
5. [API reference](./api-reference.md): exports, endpoints, client plugin, events, error codes and the database table.
6. [Browser support](./browser-support.md): which browsers bind sessions and what happens in the others.
7. [Security model](./security.md): what the plugin stops, what it does not, and how to deploy it safely.
8. [Local testing and troubleshooting](./local-testing.md): run DBSC without a TPM, read DevTools, and fix common problems.

## Reference material

- [Protocol notes](./dbsc-spec-notes.md): a digest of the W3C editor's draft and Chrome's implementation, used to build the plugin. Read it before changing protocol code.
