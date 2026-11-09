# Security policy

`better-auth-dbsc` is a security control: it decides whether a session cookie is accepted. We treat bugs that weaken it as vulnerabilities.

## Supported versions

| Version            | Supported                          |
| ------------------ | ---------------------------------- |
| Latest `0.x` minor | Yes                                |
| Older releases     | No. Upgrade to the latest version. |

While the package is `0.x`, fixes ship only in the latest minor release. Once `1.0` is released, this table will list the supported major versions.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub: go to the repository's **Security** tab and choose **[Report a vulnerability](https://github.com/helixnebulatech/better-auth-dbsc/security/advisories/new)**.

Please include:

- the affected version and your Better Auth version;
- the browser and operating system, if the issue involves the browser;
- steps to reproduce, or a proof of concept;
- the impact, as you understand it.

## What to expect

- We acknowledge your report within 3 business days.
- We confirm or rule out the issue, and keep you updated while we work on a fix.
- We publish a fixed release, then a GitHub security advisory with a CVE when one applies. We credit you in the advisory unless you prefer otherwise.

Please give us reasonable time to release a fix before you disclose the issue publicly. We will agree on a disclosure date with you.

## Scope

In scope: anything that lets a session of a bound device be used without the device key, or that weakens the protocol checks. Examples:

- accepting a stolen session cookie or bearer token of a bound session without a valid bound cookie;
- forging or replaying a bound cookie, a registration ticket or a device proof;
- binding someone else's session to an attacker's key;
- a crash or bypass triggered by crafted DBSC headers or proofs.

Out of scope: the limits documented in the [security model](./docs/security.md#what-it-does-not-stop), such as malware still running on the device, browsers without DBSC, and code that reads the session cookie without going through Better Auth. Vulnerabilities in Better Auth itself or in a browser's DBSC implementation should go to those projects; tell us too if they affect this plugin.

## Supply chain

- Every release is published from GitHub Actions with npm Trusted Publishing and carries a [provenance attestation](https://docs.npmjs.com/generating-provenance-statements). No npm token exists. Check a release with `npm audit signatures`.
- Runtime dependencies are limited to `@noble/*` and `@scure/base`.
- The repository pins GitHub Actions to commit SHAs and installs only dependency versions that are at least 2 days old.
