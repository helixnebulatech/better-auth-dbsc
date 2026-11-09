# Integrations

## Convex (`@convex-dev/better-auth`)

The plugin works with the Convex component, including `crossDomain()`. Cookies carried in the `Better-Auth-Cookie` header are checked too.

1. Place `dbsc()` after `crossDomain()` in `plugins`. The plugin refuses to start otherwise.
2. Add the `dbscSession` table to the component schema. From the backend package, run:

   ```sh
   npx auth generate --output convex/betterAuth/generatedSchema.ts
   ```

   Or copy only the `dbscSession` table that it prints.

3. If the web app proxies `/api/auth/*` to Convex, the proxy must forward:
   - the request headers `Sec-Secure-Session-Id` and `Secure-Session-Response`;
   - the response headers `Secure-Session-Registration` and `Secure-Session-Challenge`.

   The framework handlers of `@convex-dev/better-auth` already do this. Server-side `getToken()` forwards the whole `Cookie` header, so server rendering sees the bound cookie.

The refresh endpoint updates the binding with `adapter.incrementOne`. Component versions without a native `incrementOne` fall back to Better Auth's compare-and-swap. This works, but costs extra round trips.

## Proxies and separate auth services

When Better Auth runs behind your own proxy, forward the same headers listed for Convex above, and do not follow or rewrite redirects on `/dbsc/start` and `/dbsc/refresh`. Chrome treats a redirect on refresh as fatal and deletes the device-bound session.

Do not add rate-limit rules for `/dbsc/start` and `/dbsc/refresh`. Chrome before version 158 treats a 429 on refresh as permanent and deletes the device-bound session. The plugin already excludes both paths from Better Auth's rate limiter.

## Apps that read the session only on the server

Some apps never call `/get-session` from the browser, for example Next.js server components that use `auth.api.getSession`. Sessions signed in server-side then have no response that can carry the registration offer. Ask for it while building a page response and copy it onto that response:

```ts
const offer = await auth.api.dbscRegistrationOffer({
  headers: await headers(),
});
if (offer) {
  response.headers.set(offer.name, offer.value);
}
```

It returns an offer at most once per session, and `null` otherwise, so calling it on every page is safe.

## Links from other sites

Chrome only refreshes a bound cookie for requests that the app's own origin starts, or that the user starts by typing the URL. A link followed from another site (a search result, a webmail) after the bound cookie expired arrives without it. A server-rendered page would then show the user signed out for that one load.

Check for this case before rendering HTML pages, and answer with a page that reloads itself:

```ts
import { dbscRefreshNeeded, dbscRefreshPage } from "better-auth-dbsc";

// In your server's request handling, for GET page navigations:
if (await dbscRefreshNeeded(auth, request.headers)) {
  return dbscRefreshPage(); // a no-script meta refresh, Cache-Control: no-store
}
```

The reload is started by your own origin, so Chrome refreshes the bound cookie first. The reload is same-origin, so it never matches again and cannot loop. The page uses a meta refresh, without script, so it works under any Content Security Policy.

Single-page apps that fetch the session from the browser recover by themselves on the next same-origin request. The helper only makes the first server-rendered page right.

### When Better Auth runs elsewhere

When Better Auth runs behind a proxy or in another service (for example Convex), ask over HTTP instead. Forward the page request's `Cookie`, `Sec-Fetch-Dest` and `Sec-Fetch-Site` headers:

```ts
const response = await fetch(`${authUrl}/api/auth/dbsc/refresh-needed`, {
  headers: {
    cookie: request.headers.get("cookie") ?? "",
    // Node's fetch overwrites Sec-Fetch-Mode; Sec-Fetch-Dest survives.
    "sec-fetch-dest": request.headers.get("sec-fetch-dest") ?? "",
    "sec-fetch-site": request.headers.get("sec-fetch-site") ?? "",
  },
});
const { refreshNeeded } = await response.json();
if (refreshNeeded) {
  return dbscRefreshPage();
}
```

Only ask for cross-site GET navigations that carry the session cookie. Every other request can skip the round trip.

## SSO, OAuth and SAML

Cross-site sign-ins need no setup. The registration offer carries an encrypted ticket, so the registration works even though the browser does not send the `SameSite=Lax` session cookie on it. See [How it works](./how-it-works.md#1-sign-in-the-registration-offer).

## Subdomains and site-wide sessions

By default a session covers the origin that serves the instructions. To cover the whole site:

```ts
dbsc({ scope: { includeSite: true } });
```

- `includeSite` needs the origin to be the registrable domain (`example.com`, not `app.example.com`).
- To register a site-wide session from a subdomain, the registrable domain must serve `/.well-known/device-bound-sessions` and list that origin in `registering_origins`.
- With Better Auth's `crossSubDomainCookies` and the default origin scope, requests to sibling subdomains do not trigger refreshes.

See the `scope` and `allowedRefreshInitiators` options in [Configuration](./configuration.md).

## Multi-session

With Better Auth's `multiSession()` plugin, every signed-in account is bound and refreshed on its own, and each one spends Chrome's signing quota separately.

## Other plugins

| Plugin | Notes |
| --- | --- |
| `bearer()` | Place before `dbsc()`. Bearer tokens of bound sessions are refused without the bound cookie. |
| `twoFactor()` | Place before `dbsc()`. |
| `crossDomain()` | Place before `dbsc()`. |
| `anonymous()`, `username()` | Place after `dbsc()`: their hooks read the session. |
| `jwt()` | JWTs already minted stay valid until they expire. Minting new ones needs the device proof. Keep their lifetime short. |
