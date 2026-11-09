# Browser support

DBSC is a browser feature: the browser holds the key and runs the protocol. The plugin can only bind sessions in browsers that implement it.

| Browser | Status |
| --- | --- |
| Chrome on Windows | Supported. Keys in the TPM. Public since Chrome 146. |
| Chrome on macOS | Supported. Keys in the Secure Enclave. Rolling out gradually since Chrome 147. |
| Microsoft Edge on Windows | Listed as supported since Edge 147. |
| Chrome on Linux, Android, ChromeOS | Not enabled by default. Linux has no TPM key provider. |
| Firefox | No support. |
| Safari | No support. |

Sources and versions are in the [protocol notes](./dbsc-spec-notes.md#7-chrome-specifics-limits-testing). Availability changes with each browser release.

## What happens in other browsers

Browsers without DBSC ignore the `Secure-Session-Registration` header. Their sessions are never bound, so they work exactly as before, and they are not protected against cookie theft. Nothing breaks, and no client code is needed to detect support.

Chrome on a machine without a usable TPM behaves the same way: registration does not happen and the session stays unbound.

To see whether the current session is protected, call `authClient.dbsc.status()` (see [Getting started](./getting-started.md#4-optional-add-the-client-plugin)).

## Why not a JavaScript polyfill

A polyfill could keep a non-extractable Web Crypto key in IndexedDB and sign requests from script. It does not give the same protection: infostealers copy the browser profile, and the IndexedDB key goes with it. DBSC keys live in hardware and never leave the device. The plugin does not ship a polyfill.
