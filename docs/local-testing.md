# Local testing and troubleshooting

## Run DBSC without a TPM

Chrome only processes DBSC headers over **HTTPS with a valid certificate**. Plain `http://localhost` is ignored, even though the spec allows it. Use [mkcert](https://github.com/FiloSottile/mkcert) or a similar tool for local HTTPS.

Chrome on Linux, or any machine without a TPM, can use software keys. Enable both flags and restart Chrome:

```
chrome://flags/#enable-standard-device-bound-session-credentials                  → Enabled - For developers
chrome://flags/#enable-bound-session-credentials-software-keys-for-manual-testing → Enabled
```

"For developers" also turns off the signing quota and the `.well-known` check. Software keys are not secure; use them for testing only.

## Inspect sessions in DevTools

Open DevTools, then **Application → Device Bound Sessions**. It lists each session with its scope, bound cookie and events (registration, refreshes, challenges).

### `NoSessionMatch` on registration

Each registration shows one failed challenge event with `NoSessionMatch`, just before the session is created. This is expected.

The registration response carries the challenge for the first refresh, as the spec allows. Chrome looks at that header before it creates the session it belongs to, and logs the mismatch. Once the session exists, Chrome processes the header again and keeps the challenge, so the first refresh signs without an extra 403. Browsers that drop the challenge instead get it with a 403 on their first refresh.

## End-to-end tests

The repository's end-to-end tests drive a real Chromium through registration, refresh and a stolen-cookie replay, using those flags and a throwaway certificate:

```sh
cd packages/better-auth-dbsc
bun x playwright install chromium
bun run build
bun run test:e2e
```

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| No session in DevTools after sign-in | Plain HTTP or an invalid certificate; DBSC disabled in this Chrome (Linux, or a gradual rollout on macOS); the sign-in response did not reach the browser with the `Secure-Session-Registration` header (a proxy dropped it). |
| No registration after an SSO or server-side sign-in | The offer is delivered by the first same-site `/get-session`. Apps that read the session only on the server must call `auth.api.dbscRegistrationOffer`. See [Integrations](./integrations.md#apps-that-read-the-session-only-on-the-server). |
| Startup error about plugin order | Move `dbsc()` after `bearer()`, `twoFactor()` and `crossDomain()`, and before `anonymous()` and `username()`. |
| The plugin logs that it cannot store a binding | `lastChallengeAt` is a 32-bit column. Alter it to `bigint`. |
| Signed out after following a link from another site | Expected for server-rendered pages without the helper. Use `dbscRefreshNeeded` and `dbscRefreshPage`. See [Integrations](./integrations.md#links-from-other-sites). |
| Signed out at random, `proof-missing` events for real users | Refreshes fail. Check that proxies forward the DBSC headers, never redirect `/dbsc/*` and never answer 429, and that server clocks agree. A `cookieMaxAge` below the default spends Chrome's signing quota faster. |
| Session disappears from DevTools after a refresh | Chrome deletes the session when the refresh answers with a redirect, an invalid instruction body, or (before Chrome 158) a 429. |
| macOS: registration never fires, no request at all | Some Chrome field trials turn off the key service. Start Chrome with `--enable-features=DeviceBoundSessions,UseUnexportableKeyServiceInBrowserProcess,PersistDeviceBoundSessions`. |

Other tools: `chrome://net-export` and `chrome://histograms/Net.DeviceBoundSessions.Refresh.Network.Result`.
