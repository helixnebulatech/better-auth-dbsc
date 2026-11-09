# DBSC (Device Bound Session Credentials): server-side normative digest

Compiled 2026-11-08 for a Better Auth server plugin.

## 0. Versions read

| Source | Version / date | URL |
| --- | --- | --- |
| **Editor's Draft (authoritative here)** | ED, **8 September 2026** (last commit `f873903` "Derive .well-known URLs strictly from canonical origins (#268)") | https://w3c.github.io/webappsec-dbsc/ |
| W3C TR (FPWD) | 21 August 2025, **stale**: still has `aud`/`iat`/`key`/`sub` JWT claims, `provider_id`, no `none` alg | https://www.w3.org/TR/dbsc-1/ |
| Repo / explainer | `main` README (partly stale, see §8) | https://github.com/w3c/webappsec-dbsc |
| Chrome dev guide | "Last updated 2025-04-15" (examples partly simplified) | https://developer.chrome.com/docs/web-platform/device-bound-session-credentials |
| Chrome Windows launch blog | Chrome 145 on Windows, page updated 2026-03-03 | https://developer.chrome.com/blog/dbsc-windows-announcement |
| Chromium source (shipping behaviour) | `main` @ 2026-11-08 (chrome/VERSION = 159.0.8151.0). **Stable 146/147 may differ in feature defaults.** | https://source.chromium.org/chromium/chromium/src/+/main:net/device_bound_sessions/ |
| Scott Helme, "Everything I Learned Shipping DBSC" | 10 Aug 2026 | https://scotthelme.co.uk/everything-i-learned-shipping-device-bound-session-credentials/ |
| Scott Helme, "DBSC lands in Chrome on macOS" | 11 Aug 2026 | https://scotthelme.co.uk/device-bound-session-credentials-lands-in-chrome-on-macos/ |

Spec anchors used below: ED section numbers (§9.1 and so on), e.g. https://w3c.github.io/webappsec-dbsc/#header-secure-session-registration. The ED says "All of the text of this specification is normative except sections explicitly marked as non-normative, examples, and notes". Lowercase "must"/"should" carry RFC 2119 meaning ("these words do not appear in all uppercase letters").

**Important history (ignore all old material):**

- `Sec-Session-Registration`, `Sec-Session-Challenge`, `Sec-Session-Response` and `Sec-Session-Id` were renamed to `Secure-Session-*` in PR #160 (2025-05-05) and #224 (2025-09-24). The only header that keeps `Sec-` is the request header **`Sec-Secure-Session-Id`**.
- The JWT format changed in PR #216 (2025-09-03, https://github.com/w3c/webappsec-dbsc/pull/216). It removed `aud`, `iat`, payload `key` and `sub`, and moved the public key to the JOSE header `jwk`. TR/2025 and many blog posts still show the old format.
- `provider_id` was renamed to `provider_session_id` (#213). The `none` alg was added in #229 (2025-10-15). The `jwk` rules for `none` keys came in #246 (2026-02-17).

---

## 1. Registration header: `Secure-Session-Registration` (response header)

Spec: ED §9.1 https://w3c.github.io/webappsec-dbsc/#header-secure-session-registration, processing §8.10 https://w3c.github.io/webappsec-dbsc/#algo-process-registration

- **Name:** `Secure-Session-Registration`. It is an RFC 9651 **List** Structured Field: `SecureSessionRegistration = sf-list`.
- **Each list member MUST be an inner list.** Each inner-list item "MUST be an sf-token representing a supported algorithm (`ES256`, `RS256`, `none`). Only these three values are currently supported." The params hang on the inner list:
  - `path` (sf-string, **required in practice**): "Entries without this parameter will be ignored". It may be relative to the response URL or absolute. It is resolved against the response's URL.
  - `challenge` (sf-string, optional): becomes the `jti` claim of the registration JWT.
  - `authorization` (sf-string, optional): "will be copied into the registration JWT" as the `authorization` claim.
  - `provider_key`, `provider_session_id`, `provider_url` (sf-string): federated key sharing. **Out of scope** for a first version, see §6.
  - If `challenge` or `authorization` is present but not an sf-string, the entry is skipped. Other params are ignored.
- Several registrations are allowed, either as several header lines or as comma-separated members. Each one yields a separate registration attempt (§8.10 loops over the list).
- Examples (ED §9.1):
  ```
  Secure-Session-Registration: (ES256);path="reg";challenge="cv";authorization="ac"
  Secure-Session-Registration: (ES256 RS256);path="reg";challenge="cv"
  ```
- **Where it may be sent:** the spec processes it on _any_ HTTP response (Fetch hook "After step 14 in the current HTTP-network fetch … Run § 8.10 Process session registration and § 8.7 Cache challenge", §10.1). The normal pattern is the response that completes sign-in (Chrome guide step 1).
- **Algorithms:** the client picks one it supports from the list (§8.11). If none match, registration fails silently. `none` means no key pair (session key pair = null).

**Chrome deviations (verified in source):**

- Chrome only maps `ES256` and `RS256` (`FromJoseAlgorithm` in `session_binding_utils.cc`). **`none` is not implemented.** A `(none)` registration is dropped because the algorithm list is empty. Send `(ES256 RS256)`. ES256 is what TPMs and the Secure Enclave produce in practice; the explainer's studies used ECDSA P-256. https://source.chromium.org/chromium/chromium/src/+/main:net/device_bound_sessions/session_binding_utils.cc
- Chrome requires the resolved registration endpoint to be **secure (https or localhost) and same-site with the response URL**, otherwise the entry is ignored (`ResolveRegistrationEndpoint`). https://source.chromium.org/chromium/chromium/src/+/main:net/device_bound_sessions/registration_fetcher_param.cc
- Chrome also parses a non-standard boolean param for attestation (AIK) when `DeviceBoundSessionsForSingleSignOn` is on (off by default). This is Google SSO / enterprise only. Ignore it.

---

## 2. Registration request (browser → server)

Spec: §8.8 "Send request" https://w3c.github.io/webappsec-dbsc/#algo-session-request, §9.3, §9.10

**Request as specified:**

- `POST` to the `path` URL (resolved against the URL of the response that carried the header). Redirect mode `follow`. Initiator and origin are copied from the originating request.
- `Secure-Session-Response: <DBSC proof JWT>`. **It is only present if `challenge` or `authorization` was non-null**: "If challenge or authorization is non-null, let session response be the result of creating a DBSC proof". **If you send neither, the browser sends no JWT and therefore no public key.** → The server MUST always include `challenge` (or `authorization`) in the registration header. Chromium does exactly this (`StartFetch` only signs if challenge or authorization is present).
- `Authorization: <authorization>` when `authorization` is non-null (spec §8.8). **Chrome does NOT send this header. It only puts the value in the JWT claim.** Open issue #269 asks to remove it from the spec. → The server must read `authorization` from the verified JWT payload, not from the HTTP header.
- No `Sec-Secure-Session-Id` (the session id is null at registration).
- Body: none.
- **Cookies:** these are ordinary credentialed requests in the context of the originating request. Chrome copies `site_for_cookies`, isolation info and initiator, and adds `Origin`, `Sec-Fetch-Mode: no-cors`, `Sec-Fetch-Dest: empty` and `Sec-Fetch-Site` (computed relative to the referring origin). It also sets `LOAD_DISABLE_CACHE`. (`registration_fetcher.cc` `ConfigureRequest`/`SetupCommonFetchMetadata`.) SameSite=Lax/Strict cookies follow the normal rules for a POST in that context. See the SSO pitfall in §7.
- Header encoding: the spec says `Secure-Session-Response` is an **sf-string** (`"eyJ…"`). **Chrome sends the raw JWT without quotes** (`SetExtraRequestHeaderByName(kJwtSessionHeaderName, token)`). → Accept both: strip one pair of surrounding `"` if present.

**DBSC proof JWT (ED §9.10, current):** compact JWS, `header.payload.signature`, base64url without padding.

JOSE header:

| field | rule |
| --- | --- |
| `typ` | MUST be `"dbsc+jwt"` |
| `alg` | MUST be `"RS256"`, `"ES256"` or `"none"` |
| `jwk` | "MUST be present for registration requests if the algorithm is RS256 or ES256. It MUST not be present on registration requests if the algorithm is none. It MUST not be present for refresh requests." **This is where the session public key goes** (RFC 7517 JWK). |

Payload:

| claim | rule |
| --- | --- |
| `jti` | "a copy of the challenge value sent in the registration header" (for refresh: the cached challenge). Spec says "MUST contain at least" this claim. Chrome omits it if no challenge was given (authorization-only registration). |
| `authorization` | "MUST be present if present in the Secure-Session-Registration header", a direct copy. |

ED example:

```
// Header
{ "alg": "ES256", "typ": "dbsc+jwt",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "6_GB2...", "y": "..." } }
// Payload
{ "jti": "cv", "authorization": "ac" }
```

- **No `aud`, `iat`, `exp`, `sub` or `key` in the current spec.** Chrome code still has an `aud` claim (URL without query and fragment) behind `DeviceBoundSessionsIncludeAudienceClaim`, which is **disabled by default** (flag `#enable-standard-device-bound-session-credentials-audience`). Treat `aud` as optional: if present, you MAY check it against your endpoint URL. Never require it. https://source.chromium.org/chromium/chromium/src/+/main:net/base/features.cc
- ES256 signatures are raw `r||s` (Chrome converts DER to raw, as JWS requires).
- Chrome's own Google-only attested flow uses an outer JWT with `typ: "dbsc+aik"`. Standard sites never get it unless the SSO/attestation feature is used.

**Server validation (derived from the spec plus security reasoning; the spec does not list server steps for registration beyond §5 "Persist and associate the request's public key with the session identifier"):**

1. Parse the header, strip optional SF quotes, and split the JWS. Parse the **protected header only**. Require `typ == "dbsc+jwt"`, require `alg` ∈ the algorithms you offered, and refuse `none` unless you deliberately support it. Require `jwk` (for ES256: `kty=EC`, `crv=P-256`, `x`/`y`; for RS256: `kty=RSA`, `n`/`e`; reject private members like `d`). Its key type must match `alg`.
2. Verify the signature with that `jwk` (self-signed proof of possession).
3. Require `payload.jti` to equal a challenge **you issued for this registration**, still unexpired, and not yet consumed. Consume it.
4. If you sent `authorization`, require `payload.authorization` to equal it. Use it (or the cookie on the request) to link to the authenticated Better Auth session.
5. Authenticate the request through your normal session cookie (or the authorization token). Registration must bind to an _existing_ signed-in session.
6. Store `{session_identifier → public JWK (or RFC 7638 thumbprint plus JWK), alg, linked auth session id, created_at}`. Respond `200` with JSON session instructions (§3) and `Set-Cookie` for the short-lived bound cookie.

**Registration response handling by the browser (§8.8 and §8.9):**

- Network error, 407 or 429 → nothing happens (registration abandoned).
- 3xx (after following redirects) → abandoned.
- **403 at registration:** the spec "restarts with cached challenge" only if a session id exists, so at registration it does nothing. Chrome reports `kRegistrationAttemptedChallenge` and fails. **You cannot challenge during registration. Put the challenge in the registration header instead.**
- Other 4xx → abandoned. 5xx → abandoned.
- 2xx with an **empty body → failure at registration** (Chrome `kEmptySessionConfig`).
- 2xx with a body → parsed as JSON session instructions (§3).
- Chrome treats only exactly **200** as success for some error-reporting paths (`FillSessionError` checks `!= 200`), and its status logic is "<200 → error; 429/≥500 → transient; 300–499 → persistent". → **Always use 200.**
- A `Secure-Session-Challenge` on the 200 (with the new session's `id`) is cached once the session exists (§8.9, #225), so the first refresh can sign without a 403. Chrome 156 and 158 (verified in `e2e/chrome.e2e.mjs`) first processes the header before the session exists and logs a failed challenge event (`NoSessionMatch`), then processes it again after creation and uses it. The plugin sends it; the failed event is cosmetic.
- Chrome timeouts: 20 s for interactive (user-blocking) fetches and 30 s in the background (`kInteractiveFetchTimeout`, `kBackgroundFetchTimeout`).

---

## 3. JSON session instructions (registration and refresh response bodies)

Spec: §9.6–§9.9 https://w3c.github.io/webappsec-dbsc/#format-session-instructions, creation/validation §8.9 https://w3c.github.io/webappsec-dbsc/#algo-create-session. "If the response contains session instructions, it MUST be in JSON format." Recommended headers: `Content-Type: application/json`, `Cache-Control: no-store` (explainer).

### Root object

| key | type | req. | semantics |
| --- | --- | --- | --- |
| `session_identifier` | string | MUST, except when `continue` is false | Registration: the id for the new session. Refresh: "MUST be the identifier for the current session". The browser terminates if it doesn't match (§8.9: "If session id is non-null, it must match session identifier"). Unique per registrable domain. |
| `refresh_url` | string | OPTIONAL | Absolute, or relative to the URL serving the instructions. Default: the request URL (i.e. the registration URL becomes the refresh URL). |
| `continue` | bool | OPTIONAL, default `true` | `false` → terminate the session. |
| `scope` | object | MUST, except when `continue` is false | See below. |
| `credentials` | array | MUST, except when `continue` is false | See below. |
| `allowed_refresh_initiators` | string[] | OPTIONAL, default `[]` | Host patterns of **out-of-scope** initiators allowed to trigger refresh (§8.3). Patterns: `*`, `*.example.com` (a leading `*.` only), or an exact host. `example.com` does NOT match `*.example.com`. |

### `scope` (§9.7)

| key | type | req. | semantics |
| --- | --- | --- | --- |
| `origin` | string | OPTIONAL | Default: the origin of the URL serving the instructions (registration URL or refresh URL). Must be a valid non-opaque origin and **same-site with the registration/refresh URL**. |
| `include_site` | bool | **MUST be present** | `false` = origin-scoped, `true` = whole site. Takes precedence over scope rules. |
| `scope_specification` | array | OPTIONAL, default `[]` | Rules, evaluated **last-to-first** (reverse order; first match wins, so list them from most general to most specific). If no rule matches → "include". |

Scope rule (§9.8): `type` MUST be `"include"` or `"exclude"`. `domain` is optional (default `*`; supports `*.example.com`). `path` is optional (default `/`). A path matches if it is exactly equal, if the pattern ends in `/` and is a prefix, or if the path starts with the pattern followed by `/`. The **refresh URL is always excluded from scope** (§8.2).

`include_site: true` validation (§8.9): the origin's host must equal the registrable domain (eTLD+1). If the registration endpoint's host is a subdomain (and this is a registration, not a refresh), the browser fetches `https://<eTLD+1>/.well-known/device-bound-sessions` (credentials omitted). It must return status 200 and a JSON dict whose `registering_origins` contains the registration endpoint's origin. Otherwise the session is terminated (not created). The well-known is **not** checked on refresh (#208).

### `credentials[]` (§9.9)

| key | rule |
| --- | --- |
| `type` | MUST be present and be `"cookie"`. Anything else → terminate. |
| `name` | MUST be present and nonempty. This is the bound cookie name. |
| `attributes` | OPTIONAL string, default `""`. Parsed like a Set-Cookie attribute string "using the same default values". When the browser checks whether a request has the credential, it compares **Domain, Path, Secure, HttpOnly, SameSite** of the request cookie against these (§8.6). Max-Age/Expires "will not contribute". MUST NOT contain `Partitioned` (§8.9 → terminate). |

Bound-cookie semantics (§8.6): a request "is missing" a credential if a cookie with those attributes _would_ be attached to the request, but no cookie with that name and matching Domain/Path/Secure/HttpOnly/SameSite is present. That triggers a deferral and refresh. → **Your `Set-Cookie` attributes must match `attributes` exactly** (same Domain, Path, Secure, HttpOnly and SameSite). Otherwise the browser sees the cookie as missing on every request and refreshes forever (rate-limited) or never.

ED example (§9.6):

```json
{
  "session_identifier": "session_id",
  "refresh_url": "/RefreshEndpoint",
  "scope": {
    "origin": "https://example.com",
    "include_site": true,
    "scope_specification": [
      {
        "type": "include",
        "domain": "trusted.example.com",
        "path": "/only_trusted_path"
      },
      { "type": "exclude", "domain": "untrusted.example.com", "path": "/" },
      { "type": "exclude", "domain": "*.example.com", "path": "/static" }
    ]
  },
  "credentials": [
    {
      "type": "cookie",
      "name": "auth_cookie",
      "attributes": "Domain=example.com; Path=/; Secure; HttpOnly; SameSite=None"
    }
  ],
  "allowed_refresh_initiators": [
    "example.com",
    "*.example.com",
    "site-embedding-example.com"
  ]
}
```

### Browser validation (§8.9). Any failure → "terminate the session and return" (on refresh this deletes the existing session)

- Body is not JSON, or required keys are missing → terminate.
- `continue: false` → terminate.
- `session_identifier` ≠ current id (refresh) → terminate.
- Scope origin is opaque or not same-site with the destination → terminate.
- `refresh_url` must be "HTTPS or localhost" **and same-site with destination**.
- Any credential has `Partitioned` → terminate. Any `type` ≠ `"cookie"` → terminate.
- `include_site` checks (see above).
- **Bound cookie settable check:** the new session is only stored if, for at least one credential, "a cookie with credential's attributes could … be set by response" (§8.9, last loop). Otherwise the state is not updated. Chrome reports `kBoundCookieSetForbidden` (non-fatal for an existing session).
- After creating or updating, the browser **re-runs "Cache challenge"** on the same response (added in #225). A `Secure-Session-Challenge` on the registration response is therefore valid per spec (but see the Helme note in §7).
- On a successful refresh with a body, the new instructions **replace** the old config (explainer: "The new set of instructions replaces any previous instructions").

### Chrome-specific extra strictness (session_json_utils.cc, session.cc, cookie_craving.cc, session_inclusion_rules.cc)

- `session_identifier` must be a **non-empty string even when `continue:false`**. It is checked _before_ `continue`. A bare `{"continue": false}` still ends the session in practice (Chrome classifies it as invalid params, which also deletes it), but the termination is logged as "invalid params" rather than "server requested". → Always send `{"session_identifier": "<id>", "continue": false}`.
- `credentials` must be **non-empty** (`kNoCredentials`).
- `scope.origin` must not contain a path or a trailing `/` (`"https://example.com/"` is rejected with `kScopeOriginContainsPath`).
- If the scope origin is not same-origin with the fetcher URL, `include_site` must be `true` (`kCrossOriginRegistrationSiteNotIncluded`).
- `include_site: true` is only allowed if the origin's host is the eTLD+1 (`kInvalidScopeIncludeSite`).
- Scope rule: an empty `domain` or `path` is an error. The type must be include or exclude. Host patterns can't have internal or multiple wildcards. For origin-scoped sessions the rule's domain pattern must match the origin host, and for site-scoped sessions it must be same-site.
- **`attributes` may only contain `Domain`, `Path`, `Secure`, `HttpOnly`, `SameSite`.** Anything else, **including `Max-Age`/`Expires`**, fails with `kInvalidCredentialsCookieUnpermittedAttribute`. The spec example comment is misleading; this was confirmed by an editor in issue #230 (https://github.com/w3c/webappsec-dbsc/issues/230). Put Max-Age only in `Set-Cookie`.
- The cookie name must be valid. Cookie prefixes are validated (`__Host-` requires Secure, no Domain and Path=/; `__Secure-` requires Secure).
- `allowed_refresh_initiators` entries must be strings and valid host patterns.
- JSON parse depth is limited to 5 (`JSON_PARSE_RFC`, `max_depth=5`).

---

## 4. Refresh flow

Spec: §5 (server considerations), §8.5 (needs refresh), §8.7 (cache challenge), §8.8 (send request), §10.1 (Fetch integration), §9.2–§9.4.

### When the browser refreshes

- For each request: if the URL is in scope of a session (§8.2), **and** the request is allowed to refresh (initiator same-site or same-origin with the scope, or matching `allowed_refresh_initiators`, §8.3), **and** a bound credential is missing (§8.6), then the request is **deferred**. The browser runs the refresh, then **restarts the original fetch** (§10.1). Each (domain, session id) pair is refreshed at most once per request (`deferred device bound session ids`), so a request is never deferred twice by the same session.
- "Sites should not assume that a refresh will only happen when a bound cookie is expired" (§5). The browser MAY refresh proactively. **Chrome refreshes proactively when an in-scope request is made and a bound cookie expires within 120 s** (`kProactiveRefreshThreshold`). It does not defer that request. There are no background refreshes without a request (privacy), except the Google-only DSE prewarmer.
- Recommended UA behaviour (§6): only one pending refresh per session. Chrome also waits on an in-flight refresh instead of starting a second one. Still, **concurrent refresh requests do reach servers** (multiple tabs or profiles, races, retries; see Helme).

### Refresh request

```
POST <refresh_url>
Sec-Secure-Session-Id: "session-id"          ; spec: sf-string. Chrome: raw, unquoted
Secure-Session-Response: <JWT>               ; only if a cached challenge exists
Cookie: …                                    ; normal cookies (not the expired bound one)
```

- `Sec-Secure-Session-Id` (§9.4): an sf-string with the session identifier. "Any parameters SHOULD be ignored". **Chrome sends the bare id** (`SetExtraRequestHeaderByName(kSessionIdHeaderName, *session_identifier_)`; the Chrome guide shows `Sec-Secure-Session-Id: session_id`). → Parse both: if it starts with `"`, SF-parse it, otherwise take it verbatim. Pick session ids that are SF-string-safe (printable ASCII without `"` or `\`), e.g. base64url, so both encodings are unambiguous.
- `Secure-Session-Response`: refresh JWT = header `{alg, typ:"dbsc+jwt"}` (**no `jwk`**, MUST NOT be present), payload `{jti: <cached challenge>}` (plus `aud` only if Chrome's flag is on). The server MUST verify it with the **stored** public key for the session id taken from `Sec-Secure-Session-Id`. Never use any key from the token itself. PR #216 removed `key`/`sub` for exactly this reason.
- CORS (§5): the refresh fetch implicitly carries credentials. "It's also recommended to set a narrow CORS policy on this endpoint and not allow cross-site origins to make requests with credentials". Also "recommended that the refresh endpoint refuse to be embedded via the X-Frame-Options or Cross-Origin-Resource-Policy headers". The server "can check for a valid Sec-Secure-Session-Id header to ensure that incoming requests are initiated by the user agent and not a cross-site request" (`Sec-` headers are forbidden to page JS).

### Challenges: `Secure-Session-Challenge` (response header, §9.2, §8.7)

- Syntax: a Structured Field whose members are sf-strings with a **required `id` param** (the session identifier): `Secure-Session-Challenge: "new challenge";id="my session"`. Processing parses it as a **List**, so multiple challenges (for several sessions) can be comma-separated or put on separate lines. "Challenges MUST have an sf-parameter named "id" … Any other sf-parameters SHOULD be ignored." Without `id` (or with an unknown id) the challenge is ignored (Chrome `ChallengeResult::kNoSessionId`/`kNoSessionMatch`).
- It is processed on **any** response (§10.1), not only refresh responses. That allows proactive challenges, e.g. on every authenticated page or on the refresh 200. It is only cached if the response could set one of the session's bound cookies (§8.7; Chrome `kCantSetBoundCookie`). So it must come from a URL/site where the bound cookie is settable.
- The cached challenge is used as `jti` the next time a proof is sent.

### Status handling for a refresh (§8.8, verified against Chromium `registration_fetcher.cc::OnRequestComplete`)

| Server response | Browser behaviour |
| --- | --- |
| network error / 407 | Keep the session, no refresh; the deferred request continues without the bound cookie. Spec says "return". Chrome: `kNetError`/`kProxyError`, not deleted, may add `Secure-Session-Skipped: unreachable`. Optional retry with 60–140 ms delay behind `DeviceBoundSessionsRetryTransientRefreshErrors` (off by default). |
| **403** | "restart this algorithm … replacing challenge with session's cached challenge". **The 403 must carry `Secure-Session-Challenge: "<c>";id="<session id>"`** (or a challenge must already be cached). Chrome: if no cached challenge exists → `kInvalidChallenge` → **session deleted (fatal)**. Max challenge rounds per refresh: Chrome `kMaxChallenges = 5` (counter must stay < 5, so at most 4 signed attempts) → `kTooManyChallenges` → **session deleted**. |
| 3xx | Spec: "return" (no termination). Redirect mode is follow, so this only applies to a final 3xx. Chrome: `kPersistentHttpError` → **session deleted**. ⚠ Redirecting the refresh to an in-scope URL (e.g. `/login`) can deadlock the deferred navigation (Helme; Chrome added `DeviceBoundSessionsBypassDeferralsForRefreshRequests`, default on; spec issue #255). **Never redirect refresh or registration endpoints.** |
| 401 / 4xx (not 403, 407 or 429) | "terminate the session and return" → session deleted; deferred requests are released without the cookie. This is **the clean way to say "auth session gone"** (Helme: 401 recovers, 302 deadlocks). |
| 429 | Spec: same as a network error (keep the session). Chrome (and open spec PR #270): treated like 5xx, `kTransientHttpError`, kept, with backoff. |
| 5xx | Keep the session; "User agents may choose to trigger a backoff mechanism". Chrome: transient, exponential backoff (ignores the first 3 errors, then 500 ms × 1.5^n with 20% jitter, max 8 min); `Secure-Session-Skipped: server_error`. |
| 2xx, **empty body** | Success with no config change (spec: "If session id is non-null, and response's body is empty, return"). The cookies set in that response apply. |
| 2xx with JSON | §8.9: replace the config (or terminate if `continue:false` or invalid). |

### What a successful refresh response MUST contain

- `200` + `Set-Cookie` re-issuing every bound credential cookie (same name and **same Domain/Path/Secure/HttpOnly/SameSite as `attributes`**) with a fresh short Max-Age. The spec has no explicit "cookie must change" rule (see §8), but if the cookie isn't set the request proceeds without it and the next request triggers another refresh. Rotate the value anyway (Helme reports Chrome terminating when the value is unchanged. I could not find such a check in Chromium `main`; treat it as a cheap safety measure).
- Optionally a JSON body (updated config). An empty body means "no change".
- Strongly recommended: a **new `Secure-Session-Challenge` for the next refresh** on this 200 (saves the 403 round trip next time). Helme's convergence analysis relies on it.

### Server validation for refresh (§5 "expected behavior")

1. Look up the session by `Sec-Secure-Session-Id`; if it is unknown → `401` (terminates the browser session).
2. If there is no `Secure-Session-Response` → `403` + a new challenge.
3. Verify the JWS with the **stored** key and alg (`typ == "dbsc+jwt"`, `alg` == the stored alg, reject a `jwk` header on refresh). If the signature is bad → treat it as an attack: `401` and revoke the binding (and probably the auth session).
4. Check `jti` against the "recent challenges" for this session: "it's possible to receive a signature for an old challenge after issuing a new challenge" (§5). "New challenges issued should have a short lifetime. The server should reject signed responses that use a stale challenge" (§5, added Nov 2025 #233). A stale or mismatched challenge **with a valid signature** → `403` + a fresh challenge (benign; Helme). Not 401.
5. Check that the linked Better Auth session is still valid; if not → `401` (or `200` `{"session_identifier":…, "continue":false}`).
6. Issue new bound cookie(s) and a new challenge → `200`.

- Note the UA "MAY reuse cached results from a previous signing if all inputs are the same" (§8.8). Chrome caches the signed JWT per (session, challenge, key). So **the same JWT may legitimately arrive twice**, and with no `iat` there is no freshness except the challenge. Single-use challenges plus a short TTL are the only replay protection.

### Point-in-time step-up (non-normative, §5, #237)

"returning an HTTP 307 to the same endpoint with a Set-Cookie header expiring the cookie will force a DBSC refresh before the redirect completes."

### Debug header from the browser: `Secure-Session-Skipped` (request header, §9.5)

An sf-list of tokens `unreachable` | `server_error` | `quota_exceeded`, each with `session_identifier="<id>"`, e.g. `Secure-Session-Skipped: unreachable;session_identifier="123"`. It is sent on the request that went ahead **without** the bound cookie because the UA skipped the refresh. Servers can log it and decide whether to fall back (Chrome guide "Alternative integration pattern").

---

## 5. Termination

**Server-initiated:**

- Refresh (or registration) response `200` with `{"session_identifier":"<id>","continue":false}` (§9.6 "Registration and refresh endpoints can set this to false to terminate a session").
- Any 4xx other than 403/407/429 on refresh → terminate (§8.8).
- Invalid instructions on refresh → terminate (§8.9).
- `Clear-Site-Data: "cookies"` / `"storage"` (§10.2: Clear-Site-Data clears device bound sessions whose scope matches; explainer "Ending a session").
- A new registration with the same `session_identifier` replaces the old session (§8.9 "Call terminate the session to remove the existing session" then store; Chrome `DeletionReason::kReplaced`).

**What the browser does on termination:** removes the session (and its key) from the store and releases deferred requests without the bound cookie. Explainer: "stop triggering any refreshes … release any deferred requests without the short-term cookie, and clean up … including the binding key". There are no further refreshes for that id.

**Errors / outages (keep the session):** network error, 407, 429, 5xx → keep the session, skip this refresh, optional backoff, `Secure-Session-Skipped`. The deferred request continues **without** the bound cookie, so your app sees a request lacking the short cookie (→ fall back to the long-lived cookie or treat it as signed out, per your policy). UA quota: Chrome allows **6 signings per 9 minutes per site** (`kSigningQuota`, `kSigningQuotaInterval`). Above that → `quota_exceeded`, no signing. Cached signatures don't count.

**Other Chrome deletions:** session unused for **400 days** (`kSessionTtl`, renewed on use), failure to unwrap the key (TPM reset), clear browsing data, DevTools.

---

## 6. Security and privacy requirements for the server

From the spec (§2, §3, §5) and the issues; normative level noted:

- **Challenge freshness:** "New challenges issued should have a short lifetime. The server should reject signed responses that use a stale challenge" (SHOULD, §5). Track "recent challenges" per session (§5), tolerating an old-but-recent one because of races. Bind each challenge to one session id (#201 discussion: "site operators can mostly manage this themselves (e.g. prefix challenges with session ids)").
  - Practical: challenge TTL must exceed the cookie lifetime (plus the 120 s proactive window), because the browser caches the challenge until the next refresh (Helme). Otherwise every refresh pays a 403 round trip. That is harmless but slow.
- **Never trust a key from the refresh JWT.** Look it up by session id (PR #216 rationale: "limits the risk of incorrect JWT validation by using a key in the JWT on refresh").
- **Bind the DBSC session to the auth session:** the registration must be authenticated (cookie or `authorization`). Store the link, so that revoking the auth session revokes DBSC and vice versa.
- **Key per session:** the UA creates a new key for each session ("Each session has a separate new key created, and it should not be possible to detect that different sessions are from the same device", §3). The server must not try to correlate keys. It is also good practice to reject the same JWK being registered for two different sessions (except in federated mode).
- **No attestation:** the standard protocol carries no TPM attestation ("DBSC is not designed to give hosts any sort of guarantee about the specific device", §2.1). A server cannot tell a hardware key from a software key. Malware present at registration defeats it (§2.1 non-goals).
- **Login-state timing leak:** use `allowed_refresh_initiators` narrowly. Use a narrow CORS policy, no `Access-Control-Allow-Credentials` on refresh, and XFO/CORP on refresh (§3.2, §5).
- **`authorization` param:** an opaque string, chosen by the server, that links registration to a prior sign-in (e.g. a one-time code minted at login). The explainer says "allows passing a bearer token that allows the server to link registration with some preceding sign in flow, as an alternative to the more traditional use of cookies". Make it single-use, short-lived and bound to the auth session.
- **Federated / key sharing (§3.3, §8.11, `/.well-known/device-bound-sessions`):** an RP registers with `provider_key` (base64url **SHA-256** RFC 7638 JWK thumbprint, no padding; #266), `provider_session_id` and `provider_url`. The RP well-known must have `provider_origin`, and the SP well-known must list `relying_origins`. The UA SHOULD cap the number of registrable labels in `relying_origins` (Chrome: 5). It needs a permission ("device-bound-session-key-sharing"). RPs "should only accept sessions registered with the appropriate public keys they received from the SP" (§5). **Optional → out of scope for v1.** The only well-known part a v1 might need is `registering_origins`, if you register `include_site: true` sessions from a subdomain (e.g. `auth.example.com`).
- **Clear-site-data:** browsers MUST clear sessions and keys with site data (§3). The server must handle sessions disappearing at any time (fall back to a fresh registration on the next login).

---

## 7. Chrome specifics, limits, testing

**Availability:** Chrome 145 on Windows (TPM, gradual rollout), public availability Chrome 146 on Windows (Google Security blog, Apr 2026), Chrome 147 on macOS (Secure Enclave, gradual Finch rollout). In Chromium `main`, `kDeviceBoundSessions` is enabled by default on **Windows and Mac only**; it is disabled on Linux, Android and ChromeOS. Sources: https://developer.chrome.com/blog/dbsc-windows-announcement, https://scotthelme.co.uk/device-bound-session-credentials-lands-in-chrome-on-macos/, `net/base/features.cc`. Edge lists DBSC in 147 (secondary source: https://thehackernews.com/2026/04/google-rolls-out-dbsc-in-chrome-146-to.html). Firefox/Safari: no support; the header is ignored, which is safe (fail-open by design).

**Limits and constants (Chromium main, `net/device_bound_sessions/`):**

| what | value | file |
| --- | --- | --- |
| signing quota | 6 signatures / 9 min / site (cached signatures exempt) | session_service_impl.cc |
| proactive refresh | when a bound cookie expires within 120 s and an in-scope request happens | session_service_impl.cc |
| fetch timeout | 20 s interactive, 30 s background | registration_fetcher.cc |
| challenge rounds per refresh | `kMaxChallenges = 5` (fails on the 5th) | registration_fetcher.cc |
| refresh backoff | after 3 consecutive errors: 500 ms × 1.5ⁿ, ±20%, max 8 min | session.cc |
| session TTL | 400 days since last use | session.cc |
| federated `relying_origins` labels | 5 | registration_fetcher.cc |
| JSON depth | 5 | session_json_utils.cc |
| max sessions per site | **no explicit limit found** | — |

TPM signing latency is P50 200 ms / P95 600 ms (explainer). Refreshes block the deferred request for that long plus your RTT.

**Chrome vs spec deviations (summary):**

1. `none` alg not supported (only ES256/RS256).
2. No `Authorization` request header; `authorization` appears only in the JWT (spec issue #269).
3. `Sec-Secure-Session-Id` and `Secure-Session-Response` are sent as raw strings, not quoted sf-strings.
4. `aud` claim behind a flag (default off). No `iat`.
5. Strict `attributes` whitelist (no Max-Age/Expires).
6. `session_identifier` is required even with `continue:false`. Non-empty `credentials` is required.
7. A final 3xx on refresh is a fatal error that deletes the session (spec: just return).
8. 429 is treated like 5xx (spec text: like a network error; PR #270 pending).
9. Registration and refresh endpoints must be same-site and secure (or localhost) relative to the response that registered them.

**Testing without a TPM (verified in source):**

- `chrome://flags/#enable-standard-device-bound-session-credentials` → `net::features::kDeviceBoundSessions`. Available on Mac, Win and Linux. Its variation **"- For developers"** sets `RefreshQuota=false` and `CheckSubdomainRegistration=false` (plus legacy `RequireOriginTrialTokens=false`). This turns off the signing quota and the well-known check. https://source.chromium.org/chromium/chromium/src/+/main:chrome/browser/about_flags.cc
- **Software keys:** `chrome://flags/#enable-bound-session-credentials-software-keys-for-manual-testing` (feature `EnableBoundSessionCredentialsSoftwareKeysForManualTesting`, Mac/Win/Linux). Description: "Enables mock software-backed cryptographic keys … (not secure). This is intended to be used for manual testing only." When it is on, `UnexportableKeyTaskManager::GetUnexportableKeyProvider` returns `crypto::GetSoftwareUnsecureUnexportableKeyProvider()`. Standard DBSC uses that same task manager (`net/device_bound_sessions/unexportable_key_service_factory.cc`), so it applies to standard DBSC. **Linux has no TPM provider, so it needs both flags** (or `--enable-features=DeviceBoundSessions,EnableBoundSessionCredentialsSoftwareKeysForManualTesting`).
- `#enable-standard-device-bound-session-credentials-audience` → adds the `aud` claim (useful for testing optional `aud` handling).
- `#enable-standard-device-bound-session-credentials-federated-sessions` ("For developers" sets `CheckWellKnown=false`).
- Mac Finch control arms disable `UseUnexportableKeyServiceInBrowserProcess`. In that case the registration silently never fires, with no request at all. Fix: `--enable-features=DeviceBoundSessions,UseUnexportableKeyServiceInBrowserProcess,PersistDeviceBoundSessions`, and check `chrome://version/?show-variations-cmd` (Helme macOS post).
- Debugging: DevTools → Application → "Device Bound Sessions" (a DevTools-debugging flag was mentioned in issue #243 in early 2026; I did not find it in current `about_flags.cc`, so it may have been removed or folded in). Other tools: `chrome://net-export`, `chrome://histograms/Net.DeviceBoundSessions.Refresh.Network.Result`.
- localhost counts as secure for registration and refresh URLs (spec "HTTPS or localhost"; Chrome `IsSecure` = cryptographic or localhost).

**Practical gotchas (Scott Helme, 10 Aug 2026; Report URI production experience, PHP lib `report-uri/dbsc-php`):**

- The **403 then 200 refresh** is the normal path. Registration is a single round trip.
- **Store DBSC state separately** from the session blob. The post-login navigation races the `/register` POST, and last-writer-wins clobbers the binding, which silently downgrades the session to a bearer cookie. In Better Auth terms: a separate table or keys, not fields rewritten together with the session row.
- **Rotate the cookie value and the challenge on every refresh.** Helme says Chrome terminates on an unchanged cookie; this is not verified in Chromium source.
- **Challenge on the registration response:** Helme says Chrome reported "Challenge Error" and the session didn't start, so his lib never sends one. Spec #225 (Sept 2025) and current Chromium explicitly re-process challenges after creating the session. The likely explanation: the first pass (before the session exists) logs a challenge error event (`kNoSessionMatch`) in DevTools, then the re-pass succeeds. **Verified (Chrome 156 and 158, this plugin's e2e):** the session is created, DevTools shows one cosmetic `NoSessionMatch` challenge event just before the creation event, and the first refresh signs the cached challenge without a 403. The plugin therefore sends it.
- **Grace for the previous cookie value:** requests already in flight during a refresh carry the old cookie. Accept the immediately-previous bound-cookie value until its own natural expiry. Otherwise you get spurious "stolen cookie" logouts that only show up with real latency.
- **Never redirect DBSC endpoints.** Auth middleware must answer `401`, not `302 → /login` (Chromium bug 534027936; spec issue #255).
- **A challenge mismatch after a valid signature is benign** (concurrent refreshes, lost responses). Answer `403` with a fresh challenge. Only a bad signature is terminal.
- **SSO/SAML/OIDC callbacks:** the registration POST inherits the cross-site context, so Lax cookies are not sent → 401 → **Chrome marks a persistent error and won't retry**. Defer the registration offer to the first same-site document response (check `Sec-Fetch-Site` is not `cross-site`).
- **Fail-closed on a corrupt binding.** "Missing" must be distinct from "unparseable". Don't validate claims the spec doesn't define (`iat`/`exp`/`aud`). Set `Content-Type` even on empty 403s (avoids dev toolbars injecting HTML).
- Chrome's guide suggests keeping a long-lived non-DBSC cookie alongside the short bound one, for resilience. Decide policy (fallback vs. deny) per route sensitivity.

---

## 8. Open questions and ambiguities

1. **`Authorization` header (spec §8.8) vs. Chrome (JWT only):** open issue #269 (https://github.com/w3c/webappsec-dbsc/issues/269). Read it from the JWT. Optionally also accept the header.
2. **SF quoting of `Sec-Secure-Session-Id` / `Secure-Session-Response`:** the spec says sf-string, Chrome sends raw. Accept both.
3. **`jti` "MUST" vs. authorization-only registrations:** Chrome omits `jti` when there is no challenge. Without a challenge or authorization, no JWT or key is sent at all. Always send a `challenge` at registration.
4. **`continue:false` without `session_identifier`:** valid per spec, but Chrome flags it as invalid params (it still deletes). Include the id.
5. **429 handling:** spec text (keep, as "unreachable") vs. Chrome and PR #270 (keep, as server error, with backoff). Either way the session is kept.
6. **3xx on refresh:** spec "return" (keep) vs. Chrome persistent error (delete), plus the deadlock risk. Avoid.
7. **`Max-Age`/`Expires` in `attributes`:** spec prose suggests they are ignored, Chrome rejects them (#230). Omit them.
8. **Cookie rotation requirement:** not in the spec or in Chromium source as a check (only Helme's observation). Rotate anyway.
9. **Challenge on the registration response:** spec-valid since #225. Helme saw errors, but Chrome 156 and 158 accept it (one cosmetic `NoSessionMatch` event, see §7). Resolved: the plugin sends it.
10. **`aud`:** removed from the spec, present behind a Chrome flag. May reappear. Validate only if present.
11. **Replay window:** with no `iat` and allowed signature caching, freshness relies entirely on the server's challenge lifecycle. The spec only says "should have a short lifetime". Issue #210 ("Make challenge lifetime browser-enforced") is open.
12. **Multiple sessions per site and overlapping scopes** can deadlock (issue #255). Chrome mitigates by bypassing deferral for refresh requests. Keep one session per auth session and scope refresh URLs carefully.
13. **Partitioned cookies:** unsupported (§8.9 terminate; issue #234 open).
14. **Federated RP session lifetime when the SP session ends** is unspecified (issue #259). Out of scope for v1.
15. **TLS-error connections:** issue #264 proposes ignoring DBSC headers on them. Not a server concern.
16. The ED example well-known JSON has trailing commas (invalid JSON; issue #271 open). Serve valid JSON.
17. The explainer (README) is partly stale: Authorization header, older shapes. Prefer the ED.
