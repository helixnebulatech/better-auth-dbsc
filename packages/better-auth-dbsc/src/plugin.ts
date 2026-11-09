import type {
  AuthContext,
  BetterAuthPlugin,
  GenericEndpointContext,
  HookEndpointContext,
} from "@better-auth/core";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  getSessionFromCtx,
  sessionMiddleware,
} from "better-auth/api";
import { mergeSchema } from "better-auth/db";

import {
  parseCookieHeader,
  parseCookiePairs,
  readBearerToken,
  readSignedCookieToken,
} from "./cookies";
import {
  assertAlgorithmsSupported,
  jwkThumbprint,
  parsePublicJwk,
  verifySignature,
} from "./crypto/jwk";
import type { DbscAlgorithm, PublicJwk } from "./crypto/jwk";
import { buildKeyring, hashToken } from "./crypto/keys";
import type { DerivedKeys, Keyring } from "./crypto/keys";
import { DBSC_ERROR_CODES } from "./error-codes";
import { resolveOptions } from "./options";
import type { DbscEvent, DbscOptions } from "./options";
import {
  CHALLENGE_HEADER,
  parseSkippedHeader,
  REGISTRATION_HEADER,
  readStringHeader,
  RESPONSE_HEADER,
  SESSION_ID_HEADER,
  SKIPPED_HEADER,
  serializeChallengeHeader,
  serializeRegistrationHeader,
} from "./protocol/headers";
import {
  buildSessionInstructions,
  normalizeSameSite,
  serializeSetCookie,
} from "./protocol/instructions";
import type { BoundCookie } from "./protocol/instructions";
import { InvalidProofError, parseProof } from "./protocol/jwt";
import { createSchema, DBSC_MODEL } from "./schema";
import type { DbscSessionRecord } from "./schema";
import {
  cookieNameTag,
  createBoundCookieValue,
  createChallenge,
  createDbscSessionId,
  decryptSessionToken,
  encryptSessionToken,
  openRegistrationTicket,
  sealRegistrationTicket,
  verifyBoundCookieValue,
  verifyChallenge,
} from "./tokens";
import type { ChallengePurpose } from "./tokens";
import { PACKAGE_VERSION } from "./version";

declare module "@better-auth/core" {
  // oxlint-disable-next-line no-unused-vars -- shape required by the registry
  interface BetterAuthPluginRegistry<AuthOptions, Options> {
    dbsc: { creator: typeof dbsc };
  }
}

export const DBSC_PATHS = {
  refresh: "/dbsc/refresh",
  refreshNeeded: "/dbsc/refresh-needed",
  start: "/dbsc/start",
  status: "/dbsc/status",
} as const;

const GET_SESSION_PATH = "/get-session";
/** `Sec-Fetch-Site` values of a response the browser itself receives. */
const BROWSER_FETCH_SITES = new Set(["same-origin", "same-site", "none"]);
/**
 * How long a deferred offer (server-side sign-in) waits for the first page
 * the browser loads, normally seconds. Kept short: until it is consumed, a
 * stolen cookie of that still-unbound session could claim it. A lost offer
 * only means the session stays unbound (it keeps working) until the next
 * sign-in.
 */
const DEFERRED_OFFER_TTL_MS = 5 * 60 * 1000;
/** Lifetime of a registration ticket (`authorization`); Chrome uses it at once. */
const REGISTRATION_TICKET_TTL_MS = 5 * 60 * 1000;
/**
 * Requests the page sent while the registration was in flight arrive after
 * the binding exists but without the bound cookie. They are let through for
 * this long after the binding is created (dbsc-php does the same).
 */
const REGISTRATION_GRACE_MS = 10 * 1000;
/**
 * A bound cookie still counts this long after its expiry: a request sent
 * just before it expired can arrive just after. The value is MAC-bound to
 * the session, so this only stretches its life by these seconds.
 */
const BOUND_COOKIE_LEEWAY_MS = 30 * 1000;
/**
 * A session counts as created by this request when its `createdAt` is no
 * earlier than the request start minus this slack. Server-side calls without
 * a request use "the last few seconds" instead.
 */
const SESSION_CREATION_SLACK_MS = 1000;
const SERVER_SIDE_CREATION_WINDOW_MS = 10 * 1000;
const TRAILING_SLASHES = /\/+$/u;

/**
 * A top-level page navigation, by its Fetch Metadata. `Sec-Fetch-Dest` is
 * checked too because Node's `fetch` (undici) overwrites `Sec-Fetch-Mode`
 * with "cors" when a proxy forwards the browser's request, while keeping
 * `Sec-Fetch-Dest` and `Sec-Fetch-Site`. Cross-site `fetch()` calls carry
 * `Sec-Fetch-Dest: empty`, so they never qualify.
 */
const isPageNavigation = (headers: Headers) =>
  headers.get("sec-fetch-mode") === "navigate" ||
  headers.get("sec-fetch-dest") === "document";
const SIGN_OUT_PATH = "/sign-out";
const MULTI_SESSION_PREFIX = "/multi-session/";
/**
 * multiSession() treats every cookie whose name contains this as a signed
 * session token, and reads them on its own routes and when signing out.
 */
const MULTI_SESSION_COOKIE_MARKER = "_multi-";
/** multiSession()'s default `maximumSessions`. */
const DEFAULT_MAXIMUM_SESSIONS = 5;
/**
 * At most this many `Secure-Session-Skipped` members are reported per
 * request: the header is an unauthenticated client hint.
 */
const MAX_SKIPPED_REPORTS = 4;
/** `createDbscSessionId`: 16 random bytes, unpadded base64url. */
const DBSC_SESSION_ID_PATTERN = /^[\w-]{22}$/u;
/**
 * Request headers other plugins turn into cookies: `crossDomain()` from
 * @convex-dev/better-auth reads `Better-Auth-Cookie`.
 */
const COOKIE_CARRIER_HEADERS = ["better-auth-cookie"] as const;
const COOKIE_BASE_NAME = "dbsc";
const MS_PER_SECOND = 1000;
/** Better Auth's default `session.cookieCache.maxAge`, in seconds. */
const DEFAULT_COOKIE_CACHE_MAX_AGE = 300;

/** Plugins whose hooks must run before the DBSC hooks. */
const PLUGINS_BEFORE_DBSC = {
  bearer: "bearer()",
  // @convex-dev/better-auth: its before hooks return headers rebuilt from
  // the request as sent, which would put back a cookie dbsc refused.
  "cross-domain": "crossDomain()",
  "two-factor": "twoFactor()",
} as const;

/**
 * Plugins whose before hooks read the session: they must run after the DBSC
 * hooks, or they would see a refused session before it is refused.
 */
const PLUGINS_AFTER_DBSC = {
  anonymous: "anonymous()",
  username: "username()",
} as const;

const PROTOCOL_HEADERS = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-Content-Type-Options": "nosniff",
} as const;

type AnyContext = GenericEndpointContext | HookEndpointContext;
/** The parts of Better Auth's context the cookie and key helpers read. */
interface CookieContext extends Pick<
  AuthContext,
  "authCookies" | "createAuthCookie" | "secret" | "secretConfig"
> {
  adapter: Pick<AuthContext["adapter"], "findOne">;
}
interface WithContext {
  context: AuthContext;
}

const protocolResponse = (
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
  setCookies: string[] = []
): Response => {
  const responseHeaders = new Headers({ ...PROTOCOL_HEADERS, ...headers });
  for (const cookie of setCookies) {
    responseHeaders.append("Set-Cookie", cookie);
  }
  return Response.json(body, { headers: responseHeaders, status });
};

const errorBody = (error: { code: string; message: string }) => ({
  code: error.code,
  message: error.message,
});

/* -------------------------------------------------------------------------- */
/* Keys                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Signs and seals with the current Better Auth secret, verifies and opens
 * with every secret it still accepts (`secrets` versions and the legacy
 * `BETTER_AUTH_SECRET`), so a rotation keeps existing bindings working.
 */
const keyringFor = (context: CookieContext): Keyring => {
  const config = context.secretConfig;
  const accepted =
    typeof config === "string"
      ? [config]
      : [
          ...config.keys.values(),
          ...(config.legacySecret ? [config.legacySecret] : []),
        ];
  return buildKeyring(context.secret, accepted);
};

const firstOpened = <T>(
  ring: Keyring,
  open: (keys: DerivedKeys) => T | null
): T | null => {
  for (const keys of ring.all) {
    const opened = open(keys);
    if (opened !== null) {
      return opened;
    }
  }
  return null;
};

const verifyChallengeAny = (
  ring: Keyring,
  value: string,
  input: {
    purpose: ChallengePurpose;
    subject: string;
    maxAgeMs: number;
    now: number;
  }
) => firstOpened(ring, (keys) => verifyChallenge(keys, value, input));

const boundCookieIsValid = (
  ring: Keyring,
  value: string,
  tokenHash: string,
  now: number
) =>
  ring.all.some((keys) =>
    verifyBoundCookieValue(keys, value, tokenHash, now - BOUND_COOKIE_LEEWAY_MS)
  );

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

const deferredOfferId = (tokenHash: string) => `dbsc-offer:${tokenHash}`;

/** Marks a session whose sign-in response could not carry the offer. */
const deferOffer = async (ctx: WithContext, tokenHash: string) => {
  try {
    await ctx.context.internalAdapter.createVerificationValue({
      expiresAt: new Date(Date.now() + DEFERRED_OFFER_TTL_MS),
      identifier: deferredOfferId(tokenHash),
      value: "1",
    });
  } catch (error) {
    // Never fail a sign-in over DBSC: the session simply stays unbound.
    ctx.context.logger.error(
      "[dbsc] Could not defer the registration offer",
      error
    );
  }
};

/**
 * Claims the deferred offer of an unbound session. Atomic: of several
 * concurrent callers only one gets `true`. Reads first, so the common case
 * (nothing deferred) costs no write.
 */
const takeDeferredOffer = async (ctx: WithContext, tokenHash: string) => {
  const identifier = deferredOfferId(tokenHash);
  const pending =
    await ctx.context.internalAdapter.findVerificationValue(identifier);
  if (!pending) {
    return false;
  }
  const binding = await ctx.context.adapter.findOne<DbscSessionRecord>({
    model: DBSC_MODEL,
    where: [{ field: "tokenHash", value: tokenHash }],
  });
  if (binding) {
    return false;
  }
  const consumed =
    await ctx.context.internalAdapter.consumeVerificationValue(identifier);
  return consumed !== null;
};

const isProtocolPath = (path: string | undefined) =>
  path === DBSC_PATHS.start || path === DBSC_PATHS.refresh;

const tokenFromReturned = (returned: unknown): string | undefined => {
  if (typeof returned !== "object" || returned === null) {
    return;
  }
  const { session } = returned as { session?: { token?: unknown } };
  return typeof session?.token === "string" ? session.token : undefined;
};

const authPath = (ctx: WithContext, path: string) =>
  `${new URL(ctx.context.baseURL).pathname.replace(TRAILING_SLASHES, "")}${path}`;

/**
 * The bound cookie of one session. Attributes follow Better Auth's cookie
 * settings, except Partitioned: DBSC credentials cannot be partitioned (ED
 * §8.9), so it is left out even when the app partitions its own cookies.
 */
const boundCookieFor = (
  context: CookieContext,
  tokenHash: string
): BoundCookie => {
  const base = context.createAuthCookie(COOKIE_BASE_NAME);
  return {
    attributes: {
      domain: base.attributes.domain || undefined,
      httpOnly: base.attributes.httpOnly !== false,
      path: base.attributes.path ?? "/",
      sameSite: normalizeSameSite(base.attributes.sameSite),
      secure: Boolean(base.attributes.secure),
    },
    name: `${base.name}_${cookieNameTag(tokenHash)}`,
  };
};

/**
 * A refresh challenge for the session. It is issued strictly after
 * `lastAcceptedAt`: the replay guard only accepts challenges newer than the
 * last one used, so one minted in the same millisecond would be refused.
 */
const challengeHeader = (
  keys: DerivedKeys,
  dbscSessionId: string,
  lastAcceptedAt: number
) => ({
  [CHALLENGE_HEADER]: serializeChallengeHeader(
    createChallenge(
      keys,
      "f",
      dbscSessionId,
      Math.max(Date.now(), lastAcceptedAt + 1)
    ).value,
    dbscSessionId
  ),
});

const findBindingByTokenHash = (context: CookieContext, tokenHash: string) =>
  context.adapter.findOne<DbscSessionRecord>({
    model: DBSC_MODEL,
    where: [{ field: "tokenHash", value: tokenHash }],
  });

/** Bindings younger than the registration grace still accept the cookie alone. */
const inRegistrationGrace = (binding: DbscSessionRecord, now: number) =>
  new Date(binding.createdAt).getTime() + REGISTRATION_GRACE_MS > now;

/**
 * The session a registration is for. A registration offered cross-site
 * names it with a ticket (signed into the proof by the device key), because
 * the browser sends no SameSite=Lax session cookie then; otherwise the
 * session cookie does.
 */
const registeringSession = async (
  ctx: GenericEndpointContext,
  authorization: string | undefined,
  ring: Keyring,
  now: number
) => {
  if (authorization === undefined) {
    return await getSessionFromCtx(ctx, { disableCookieCache: true });
  }
  const ticketToken = firstOpened(ring, (keys) =>
    openRegistrationTicket(keys, authorization, now)
  );
  const found = ticketToken
    ? await ctx.context.internalAdapter.findSession(ticketToken)
    : null;
  return found && new Date(found.session.expiresAt).getTime() > now
    ? found
    : null;
};

const findRivals = (
  ctx: GenericEndpointContext,
  data: Pick<DbscSessionRecord, "keyThumbprint" | "tokenHash">
) =>
  Promise.all([
    ctx.context.adapter.findMany<DbscSessionRecord>({
      model: DBSC_MODEL,
      where: [{ field: "tokenHash", value: data.tokenHash }],
    }),
    ctx.context.adapter.findMany<DbscSessionRecord>({
      model: DBSC_MODEL,
      where: [{ field: "keyThumbprint", value: data.keyThumbprint }],
    }),
  ]);

/**
 * Stores a binding, or returns null when a concurrent registration for the
 * same session (or with the same key) got in. Databases with the unique
 * indexes reject the second insert. Those without (Convex, memory) keep both
 * rows, so a creator that sees any other row backs out: of two creators, the
 * one that inserted second always sees the first, so two can never both win
 * (in a full overlap both back out and the session stays unbound).
 */
const createBinding = async (
  ctx: GenericEndpointContext,
  data: Omit<DbscSessionRecord, "id">
) => {
  let created: DbscSessionRecord;
  try {
    created = await ctx.context.adapter.create<
      Omit<DbscSessionRecord, "id">,
      DbscSessionRecord
    >({ data, model: DBSC_MODEL });
  } catch (error) {
    const [byToken, byKey] = await findRivals(ctx, data).catch(() => [[], []]);
    if (byToken.length > 0 || byKey.length > 0) {
      // Lost a race against a unique index: expected.
      ctx.context.logger.debug("[dbsc] Binding not created", error);
    } else {
      // Nothing explains the failure: the binding table is broken (missing,
      // or a column type that cannot hold the values), and no session can be
      // bound until it is fixed.
      ctx.context.logger.error(
        "[dbsc] Could not store a binding: sessions stay unprotected",
        error
      );
    }
    return null;
  }
  const backOut = async () => {
    await ctx.context.adapter.delete({
      model: DBSC_MODEL,
      where: [{ field: "id", value: created.id }],
    });
    return null;
  };
  let rivals: Awaited<ReturnType<typeof findRivals>>;
  try {
    rivals = await findRivals(ctx, data);
  } catch (error) {
    // Unverified rows must not stay: the browser never gets the instructions
    // and its owner would be locked out once the grace period ends.
    ctx.context.logger.error("[dbsc] Could not verify a new binding", error);
    return await backOut();
  }
  const isRival = (row: DbscSessionRecord) =>
    String(row.id) !== String(created.id);
  const [byToken, byKey] = rivals;
  if (byToken.some(isRival) || byKey.some(isRival)) {
    return await backOut();
  }
  return created;
};

const findMultiSession = (context: AuthContext) =>
  context.options.plugins?.find((plugin) => plugin.id === "multi-session") as
    | { options?: { maximumSessions?: number } }
    | undefined;

/** Whether multiSession() is installed and reads its cookies on this path. */
const readsMultiSessionCookies = (
  context: AuthContext,
  path: string | undefined
) =>
  findMultiSession(context) !== undefined &&
  (path === SIGN_OUT_PATH || (path?.startsWith(MULTI_SESSION_PREFIX) ?? false));

/**
 * How many multi-session cookies a request may carry: one per session
 * multiSession() keeps, plus the one being added. Beyond that they are
 * dropped unchecked (failing closed), so a request cannot cost more than
 * this many lookups.
 */
const multiSessionCookieLimit = (context: AuthContext) =>
  (findMultiSession(context)?.options?.maximumSessions ??
    DEFAULT_MAXIMUM_SESSIONS) + 1;

/**
 * The cookies of a request, per source and merged. Every source is checked
 * on its own: the Cookie header, which Better Auth reads, and the headers
 * that crossDomain() merges into it in its own before hook. A merged view
 * alone would let a value in one source hide a bound token in the other.
 * In the merged view carried cookies win, as they do in crossDomain(): it
 * finds bound cookies and is what the endpoint reads once a cookie is dropped.
 */
const readCookieSources = (headers: Headers) => {
  const headerValues = [
    ...COOKIE_CARRIER_HEADERS.map((name) => headers.get(name)),
    headers.get("cookie"),
  ].filter((value): value is string => Boolean(value));
  const sources = headerValues.map((value) => parseCookieHeader(value));
  const merged = new Map<string, string>();
  /** The original `name=value` text of each merged cookie. */
  const mergedPairs = new Map<string, string>();
  for (const value of headerValues) {
    for (const [name, pair] of parseCookiePairs(value)) {
      if (!mergedPairs.has(name)) {
        mergedPairs.set(name, pair);
      }
    }
  }
  for (const source of sources) {
    for (const [name, value] of source) {
      if (!merged.has(name)) {
        merged.set(name, value);
      }
    }
  }
  return { merged, mergedPairs, sources };
};

/** Every session token a cookie name carries, across all sources. */
const tokensIn = (sources: Map<string, string>[], name: string) => {
  const tokens = new Set<string>();
  for (const source of sources) {
    // The signature is not checked here: Better Auth rejects a forged value
    // anyway, and refusing one only affects the sender's request.
    const token = readSignedCookieToken(source.get(name));
    if (token) {
      tokens.add(token);
    }
  }
  return tokens;
};

/**
 * The session cookies to check and their tokens. Multi-session cookies past
 * the limit are returned apart, to be dropped without a lookup.
 */
const sessionTokenCookies = (input: {
  checksMulti: boolean;
  merged: Map<string, string>;
  multiLimit: number;
  sessionCookieName: string;
  sources: Map<string, string>[];
}) => {
  const overLimit = new Set<string>();
  const tokensByName = new Map<string, Set<string>>();
  let multiCount = 0;
  // The app's own multi-session cookies count first toward the limit, so
  // unrelated `_multi-` cookies on a shared domain cannot push them out.
  const ownPrefix = `${input.sessionCookieName}${MULTI_SESSION_COOKIE_MARKER}`;
  const names = [...input.merged.keys()].toSorted(
    (left, right) =>
      Number(!left.startsWith(ownPrefix)) - Number(!right.startsWith(ownPrefix))
  );
  for (const name of names) {
    const isMulti =
      input.checksMulti &&
      name !== input.sessionCookieName &&
      name.includes(MULTI_SESSION_COOKIE_MARKER);
    if (name === input.sessionCookieName || isMulti) {
      multiCount += isMulti ? 1 : 0;
      if (isMulti && multiCount > input.multiLimit) {
        overLimit.add(name);
      } else {
        tokensByName.set(name, tokensIn(input.sources, name));
      }
    }
  }
  return { overLimit, tokensByName };
};

/**
 * Removes refused cookies from the request. Later before hooks get the
 * shared request headers, not a hook's returned context (Better Auth applies
 * that only after every hook), so they are stripped in place; the copy is
 * the hook's result, applied last.
 */
const stripCookies = (
  headers: Headers,
  pairs: Map<string, string>,
  isDropped: (name: string) => boolean
) => {
  headers.set(
    "cookie",
    [...pairs]
      .filter(([name]) => !isDropped(name))
      .map(([, pair]) => pair)
      .join("; ")
  );
  for (const name of COOKIE_CARRIER_HEADERS) {
    headers.delete(name);
  }
  return new Headers(headers);
};

/* -------------------------------------------------------------------------- */
/* Arrivals from other sites                                                  */
/* -------------------------------------------------------------------------- */

/** See {@link dbscRefreshNeeded}. */
const refreshNeededFor = async (
  context: CookieContext,
  headers: Headers
): Promise<boolean> => {
  if (
    headers.get("sec-fetch-site") !== "cross-site" ||
    !isPageNavigation(headers)
  ) {
    return false;
  }
  const cookies = parseCookieHeader(headers.get("cookie"));
  const token = readSignedCookieToken(
    cookies.get(context.authCookies.sessionToken.name)
  );
  if (!token) {
    return false;
  }
  const tokenHash = hashToken(token);
  const now = Date.now();
  const bound = cookies.get(boundCookieFor(context, tokenHash).name);
  if (bound && boundCookieIsValid(keyringFor(context), bound, tokenHash, now)) {
    return false;
  }
  const binding = await findBindingByTokenHash(context, tokenHash);
  return binding !== null && !inRegistrationGrace(binding, now);
};

/**
 * Chrome only refreshes a bound cookie for requests initiated by the session's
 * own origin (or site), or by the user typing the URL. A link followed from
 * another site (search result, webmail) after the bound cookie expired
 * therefore arrives without it, and the session reads as signed out for that
 * one page load.
 *
 * True when this request is exactly that case: a cross-site navigation whose
 * session is device-bound and carries no valid bound cookie. Answer it with
 * {@link dbscRefreshPage}: the page reloads itself, the reload is initiated by
 * the app's own origin, so Chrome refreshes before sending it. The reload is
 * same-origin, so it never matches again and cannot loop.
 *
 * Only for GET navigations of HTML pages, before rendering them.
 */
export const dbscRefreshNeeded = async (
  auth: { $context: Promise<CookieContext> },
  headers: Headers
): Promise<boolean> => refreshNeededFor(await auth.$context, headers);

/**
 * The response for {@link dbscRefreshNeeded}: a minimal page that reloads
 * itself once with a meta refresh (no script, so it works under any CSP).
 */
export const dbscRefreshPage = (): Response =>
  new Response(
    '<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0"><title>Loading…</title>',
    {
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": "text/html; charset=utf-8",
        "Referrer-Policy": "same-origin",
      },
      status: 200,
    }
  );

/* -------------------------------------------------------------------------- */
/* Plugin                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Device Bound Session Credentials (W3C DBSC) for Better Auth.
 *
 * Supporting browsers bind each new session to a non-exportable key. The
 * plugin then refuses the Better Auth session cookie of a bound session
 * unless the request also carries the short-lived cookie that only the key
 * holder can renew, so a stolen session cookie stops working elsewhere.
 *
 * Place it after `bearer()` and `twoFactor()` in `plugins`.
 */
export const dbsc = (options?: DbscOptions) => {
  const resolvedOptions = resolveOptions(options);

  /**
   * Binding lookups made while handling one HTTP request. The pending read
   * is cached, so concurrent checks of one token share a single query.
   */
  const lookupCache = new WeakMap<
    Request,
    Map<string, Promise<DbscSessionRecord | null>>
  >();
  /** When each HTTP request reached the plugin, to tell new sessions apart. */
  const requestStarts = new WeakMap<Request, number>();

  const emit = async (ctx: WithContext, event: DbscEvent) => {
    if (!resolvedOptions.onEvent) {
      return;
    }
    try {
      await resolvedOptions.onEvent(event);
    } catch (error) {
      ctx.context.logger.error("[dbsc] onEvent failed", error);
    }
  };

  const issueBoundCookie = (
    cookie: BoundCookie,
    keys: DerivedKeys,
    tokenHash: string
  ) =>
    serializeSetCookie(
      cookie,
      createBoundCookieValue(
        keys,
        tokenHash,
        Date.now() + resolvedOptions.cookieMaxAgeMs
      ),
      resolvedOptions.cookieMaxAgeMs / MS_PER_SECOND
    );

  const findBinding = (
    ctx: AnyContext,
    field: "tokenHash" | "dbscSessionId",
    value: string
  ): Promise<DbscSessionRecord | null> => {
    const lookup = () =>
      ctx.context.adapter.findOne<DbscSessionRecord>({
        model: DBSC_MODEL,
        where: [{ field, value }],
      });
    const request = field === "tokenHash" ? ctx.request : undefined;
    if (!request) {
      return lookup();
    }
    let perRequest = lookupCache.get(request);
    if (!perRequest) {
      perRequest = new Map();
      lookupCache.set(request, perRequest);
    }
    const cached = perRequest.get(value);
    if (cached) {
      return cached;
    }
    const pending = lookup();
    perRequest.set(value, pending);
    // A failed read is not remembered: the next check asks again.
    pending.catch(() => perRequest.delete(value));
    return pending;
  };

  /**
   * True when the token may be used for this request: its session is not
   * device-bound, the request carries a valid bound cookie for it, or the
   * binding was created moments ago (requests already in flight). The bound
   * cookie verifies offline, so DBSC browsers cost no reads.
   */
  const mayUseToken = async (
    ctx: HookEndpointContext,
    cookies: Map<string, string>,
    ring: Keyring,
    token: string
  ): Promise<boolean> => {
    const tokenHash = hashToken(token);
    const now = Date.now();
    const boundCookie = cookies.get(
      boundCookieFor(ctx.context, tokenHash).name
    );
    if (boundCookie && boundCookieIsValid(ring, boundCookie, tokenHash, now)) {
      return true;
    }
    const binding = await findBinding(ctx, "tokenHash", tokenHash);
    if (!binding || inRegistrationGrace(binding, now)) {
      return true;
    }
    await emit(ctx, {
      path: ctx.path,
      sessionId: binding.sessionId,
      type: "proof-missing",
      userId: binding.userId,
    });
    return false;
  };

  /* ------------------------------------------------------------------------ */
  /* Enforcement                                                              */
  /* ------------------------------------------------------------------------ */

  /**
   * Like {@link mayUseToken} for a bearer token. The bearer plugin signs
   * whatever token it is given, and the database may match it loosely (a
   * case-insensitive collation finds the session for a case-swapped copy),
   * so the binding is checked for the token the session is stored under.
   */
  const mayUseBearer = async (
    ctx: HookEndpointContext,
    cookies: Map<string, string>,
    ring: Keyring,
    token: string
  ): Promise<boolean> => {
    if (!(await mayUseToken(ctx, cookies, ring, token))) {
      return false;
    }
    const found = await ctx.context.internalAdapter.findSession(token);
    const stored = found?.session.token;
    return (
      !stored ||
      stored === token ||
      (await mayUseToken(ctx, cookies, ring, stored))
    );
  };

  /** Checks each token once; returns those the request may not use. */
  const refusedTokens = async (
    ctx: HookEndpointContext,
    cookies: Map<string, string>,
    ring: Keyring,
    tokensByName: Map<string, Set<string>>
  ) => {
    const unique = new Set(
      [...tokensByName.values()].flatMap((tokens) => [...tokens])
    );
    const refused = new Set<string>();
    await Promise.all(
      [...unique].map(async (token) => {
        if (!(await mayUseToken(ctx, cookies, ring, token))) {
          refused.add(token);
        }
      })
    );
    return refused;
  };

  const enforce = createAuthMiddleware(async (ctx) => {
    if (ctx.request && !requestStarts.has(ctx.request)) {
      requestStarts.set(ctx.request, Date.now());
    }
    const { headers } = ctx;
    if (!headers) {
      return;
    }
    const ring = keyringFor(ctx.context);
    const {
      merged: cookies,
      mergedPairs,
      sources,
    } = readCookieSources(headers);

    // A bound session's token must not work as a bearer token either: that is
    // exactly what an attacker would do with a stolen cookie value.
    const bearerToken = readBearerToken(headers);
    if (bearerToken && !(await mayUseBearer(ctx, cookies, ring, bearerToken))) {
      throw APIError.from(
        "UNAUTHORIZED",
        DBSC_ERROR_CODES.DEVICE_PROOF_REQUIRED
      );
    }
    if (cookies.size === 0) {
      return;
    }

    const sessionCookieName = ctx.context.authCookies.sessionToken.name;
    const { overLimit, tokensByName } = sessionTokenCookies({
      checksMulti: readsMultiSessionCookies(ctx.context, ctx.path),
      merged: cookies,
      multiLimit: multiSessionCookieLimit(ctx.context),
      sessionCookieName,
      sources,
    });
    const refused = await refusedTokens(ctx, cookies, ring, tokensByName);
    const dropped = new Set(overLimit);
    for (const [name, tokens] of tokensByName) {
      if ([...tokens].some((token) => refused.has(token))) {
        dropped.add(name);
      }
    }
    if (dropped.size === 0) {
      return;
    }
    const dropsSession = dropped.has(sessionCookieName);
    const sessionDataName = ctx.context.authCookies.sessionData.name;
    const nextHeaders = stripCookies(
      headers,
      mergedPairs,
      (name) =>
        dropped.has(name) ||
        // The cookie cache must not stand in for a refused session.
        (dropsSession &&
          (name === sessionDataName || name.startsWith(`${sessionDataName}.`)))
    );
    if (dropsSession) {
      ctx.context.session = null;
    }
    return { context: { headers: nextHeaders } };
  });

  /* ------------------------------------------------------------------------ */
  /* Registration offer, sign-out, diagnostics                                */
  /* ------------------------------------------------------------------------ */

  const registrationHeaderValue = (
    ctx: WithContext,
    tokenHash: string,
    authorization?: string
  ) =>
    serializeRegistrationHeader({
      algorithms: resolvedOptions.algorithms,
      authorization,
      challenge: createChallenge(
        keyringFor(ctx.context).current,
        "r",
        tokenHash,
        Date.now()
      ).value,
      path: authPath(ctx, DBSC_PATHS.start),
    });

  const setRegistrationHeader = (
    ctx: WithContext & { setHeader: (name: string, value: string) => void },
    tokenHash: string,
    authorization?: string
  ) => {
    ctx.setHeader(
      REGISTRATION_HEADER,
      registrationHeaderValue(ctx, tokenHash, authorization)
    );
  };

  /**
   * Whether `createdAt` belongs to a session this very request created, as
   * opposed to an existing session whose cookie an endpoint re-issued
   * (`/update-user`, `/update-session`, multi-session `set-active`, …).
   */
  const createdByThisRequest = (
    ctx: AnyContext,
    session: { token: string; createdAt: Date | string }
  ) => {
    // The request already carried this session: its cookie is being
    // re-issued (`/update-user`, `/update-session`, a refresh), not created.
    const incoming = readSignedCookieToken(
      parseCookieHeader(
        (ctx.request?.headers ?? ctx.headers)?.get("cookie")
      ).get(ctx.context.authCookies.sessionToken.name)
    );
    if (incoming === session.token) {
      return false;
    }
    // Switching to another existing session (multi-session `set-active`):
    // it was created by an earlier request.
    const startedAt = ctx.request ? requestStarts.get(ctx.request) : undefined;
    const since =
      startedAt === undefined
        ? Date.now() - SERVER_SIDE_CREATION_WINDOW_MS
        : startedAt - SESSION_CREATION_SLACK_MS;
    return new Date(session.createdAt).getTime() >= since;
  };

  /**
   * Offers registration exactly once per session, in the first response the
   * browser itself receives. Chrome starts a separate registration (a new key)
   * for every offer, so offering twice races the first registration.
   *
   * Only sessions created by the current request are offered; responses that
   * merely re-issue an existing session's cookie never are.
   *
   * - Sign-in answered to the browser, same-site: offer right there.
   * - Sign-in by a cross-site navigation (SSO/OAuth callback): offer right
   *   there too, with a short-lived ticket as `authorization`, because the
   *   registration POST will not carry the SameSite=Lax session cookie.
   * - Sign-in server-side (`auth.api.*`, no request): store a one-time
   *   marker. The first same-site `/get-session`, or the app through
   *   `auth.api.dbscRegistrationOffer`, consumes it atomically and offers.
   * - Anything else (clients that are not browsers, cross-site fetches such as
   *   `crossDomain()` clients): nothing, they cannot hold a DBSC session.
   */
  type OfferContext = Parameters<Parameters<typeof createAuthMiddleware>[0]>[0];

  const fetchMetadata = (ctx: OfferContext) => {
    const headers = ctx.request?.headers;
    const site = headers?.get("sec-fetch-site") ?? null;
    return {
      browserReceives: site !== null && BROWSER_FETCH_SITES.has(site),
      crossSiteNavigation:
        site === "cross-site" &&
        headers !== undefined &&
        isPageNavigation(headers),
    };
  };

  /** A sign-in (or 2FA step) that created a session in this request. */
  const offerForNewSession = async (
    ctx: OfferContext,
    session: { token: string; createdAt: Date | string }
  ) => {
    if (!createdByThisRequest(ctx, session)) {
      return;
    }
    const { browserReceives, crossSiteNavigation } = fetchMetadata(ctx);
    const serverSide = !ctx.request;
    if (!(browserReceives || crossSiteNavigation || serverSide)) {
      return;
    }
    const tokenHash = hashToken(session.token);
    if (await findBinding(ctx, "tokenHash", tokenHash)) {
      return;
    }
    if (serverSide) {
      await deferOffer(ctx, tokenHash);
      return;
    }
    setRegistrationHeader(
      ctx,
      tokenHash,
      crossSiteNavigation
        ? sealRegistrationTicket(
            keyringFor(ctx.context).current,
            session.token,
            Date.now() + REGISTRATION_TICKET_TTL_MS
          )
        : undefined
    );
  };

  /** A same-site `/get-session` delivering a server-side sign-in's offer. */
  const offerDeferred = async (ctx: OfferContext) => {
    if (
      !(
        resolvedOptions.registerOnGetSession &&
        fetchMetadata(ctx).browserReceives
      )
    ) {
      return;
    }
    const token = tokenFromReturned(ctx.context.returned);
    if (!token) {
      return;
    }
    const tokenHash = hashToken(token);
    if (await takeDeferredOffer(ctx, tokenHash)) {
      setRegistrationHeader(ctx, tokenHash);
    }
  };

  const offerRegistration = createAuthMiddleware(async (ctx) => {
    const { newSession } = ctx.context;
    if (newSession && ctx.path !== GET_SESSION_PATH) {
      await offerForNewSession(ctx, newSession.session);
    } else if (ctx.path === GET_SESSION_PATH) {
      await offerDeferred(ctx);
    }
  });

  const expireOnSignOut = createAuthMiddleware(async (ctx) => {
    const token = await ctx.getSignedCookie(
      ctx.context.authCookies.sessionToken.name,
      ctx.context.secret
    );
    if (!token) {
      return;
    }
    const { name, attributes } = boundCookieFor(ctx.context, hashToken(token));
    ctx.setCookie(name, "", {
      domain: attributes.domain,
      httpOnly: attributes.httpOnly,
      maxAge: 0,
      path: attributes.path,
      sameSite: attributes.sameSite,
      secure: attributes.secure,
    });
  });

  /**
   * `Secure-Session-Skipped` is an unauthenticated hint from the client:
   * anyone can send it. Only a few well-formed, distinct session ids per
   * request are reported, one after the other.
   */
  const reportSkippedRefreshes = createAuthMiddleware(async (ctx) => {
    const reported = new Set<string>();
    for (const skipped of parseSkippedHeader(
      ctx.headers?.get(SKIPPED_HEADER) ?? null
    )) {
      if (reported.size >= MAX_SKIPPED_REPORTS) {
        break;
      }
      if (
        DBSC_SESSION_ID_PATTERN.test(skipped.sessionId) &&
        !reported.has(skipped.sessionId)
      ) {
        reported.add(skipped.sessionId);
        // oxlint-disable-next-line no-await-in-loop -- deliberately sequential
        await emit(ctx, {
          dbscSessionId: skipped.sessionId,
          reason: skipped.reason,
          type: "refresh-skipped",
        });
      }
    }
  });

  /* ------------------------------------------------------------------------ */
  /* Protocol endpoints                                                       */
  /* ------------------------------------------------------------------------ */

  const instructionsFor = (
    ctx: WithContext,
    dbscSessionId: string,
    cookie: BoundCookie
  ) =>
    buildSessionInstructions({
      cookie,
      options: resolvedOptions,
      refreshUrl: authPath(ctx, DBSC_PATHS.refresh),
      sessionId: dbscSessionId,
    });

  const start = createAuthEndpoint(
    DBSC_PATHS.start,
    {
      disableBody: true,
      metadata: { scope: "server" },
      method: "POST",
      requireHeaders: true,
    },
    async (ctx) => {
      // Chrome never retries a failed registration and a 403 means nothing to
      // it here, so every failure is a plain 4xx.
      const proofHeader = readStringHeader(ctx.headers, RESPONSE_HEADER);
      if (!proofHeader) {
        return protocolResponse(400, errorBody(DBSC_ERROR_CODES.MISSING_PROOF));
      }
      let proof: ReturnType<typeof parseProof>;
      try {
        proof = parseProof(
          proofHeader,
          "registration",
          resolvedOptions.algorithms
        );
      } catch (error) {
        ctx.context.logger.debug(
          "[dbsc] Rejected registration proof",
          error instanceof InvalidProofError ? error.message : error
        );
        return protocolResponse(400, errorBody(DBSC_ERROR_CODES.INVALID_PROOF));
      }
      const jwk = proof.jwk as PublicJwk;
      if (
        !(await verifySignature(
          proof.algorithm,
          jwk,
          proof.signingInput,
          proof.signature
        ))
      ) {
        return protocolResponse(400, errorBody(DBSC_ERROR_CODES.INVALID_PROOF));
      }

      const ring = keyringFor(ctx.context);
      const now = Date.now();
      const session = await registeringSession(
        ctx,
        proof.authorization,
        ring,
        now
      );
      if (!session) {
        return protocolResponse(401, errorBody(DBSC_ERROR_CODES.UNAUTHORIZED));
      }
      const tokenHash = hashToken(session.session.token);
      const challengeIssuedAt = verifyChallengeAny(ring, proof.jti, {
        maxAgeMs: resolvedOptions.challengeMaxAgeMs,
        now,
        purpose: "r",
        subject: tokenHash,
      });
      if (challengeIssuedAt === null) {
        return protocolResponse(
          400,
          errorBody(DBSC_ERROR_CODES.INVALID_CHALLENGE)
        );
      }
      // Also the replay guard: a registration challenge is bound to this
      // session token, and a bound session cannot register again.
      if (await findBinding(ctx, "tokenHash", tokenHash)) {
        return protocolResponse(400, errorBody(DBSC_ERROR_CODES.ALREADY_BOUND));
      }
      const keyThumbprint = jwkThumbprint(jwk);
      const keyInUse = await ctx.context.adapter.findOne<DbscSessionRecord>({
        model: DBSC_MODEL,
        where: [{ field: "keyThumbprint", value: keyThumbprint }],
      });
      if (keyInUse) {
        return protocolResponse(
          400,
          errorBody(DBSC_ERROR_CODES.KEY_ALREADY_USED)
        );
      }

      // Bindings outlive sessions kept only in secondary storage (no delete
      // hook fires there): sweep the dead ones while we write anyway. The
      // stored expiry alone cannot prove a session dead, because Better Auth
      // extends sessions without telling the binding. Every request that can
      // extend a bound session carries a bound cookie, and every bound cookie
      // comes from a start or refresh that sets updatedAt. So a row untouched
      // for longer than a session can last past its last bound cookie belongs
      // to a session that is gone.
      const lastPossibleUse =
        now -
        ctx.context.sessionConfig.expiresIn * MS_PER_SECOND -
        resolvedOptions.cookieMaxAgeMs -
        BOUND_COOKIE_LEEWAY_MS;
      await ctx.context.adapter
        .deleteMany({
          model: DBSC_MODEL,
          where: [
            { field: "expiresAt", operator: "lt", value: new Date(now) },
            {
              field: "updatedAt",
              operator: "lt",
              value: new Date(lastPossibleUse),
            },
          ],
        })
        .catch((error: unknown) => {
          ctx.context.logger.warn("[dbsc] Could not sweep bindings", error);
        });

      const dbscSessionId = createDbscSessionId();
      const created = await createBinding(ctx, {
        algorithm: proof.algorithm,
        createdAt: new Date(now),
        dbscSessionId,
        expiresAt: new Date(session.session.expiresAt),
        keyThumbprint,
        lastChallengeAt: challengeIssuedAt,
        publicKey: JSON.stringify(jwk),
        refreshCount: 0,
        sessionId: session.session.id,
        sessionTokenEncrypted: encryptSessionToken(
          ring.current,
          session.session.token,
          dbscSessionId
        ),
        tokenHash,
        updatedAt: new Date(now),
        userId: session.user.id,
      });
      if (!created) {
        return protocolResponse(400, errorBody(DBSC_ERROR_CODES.ALREADY_BOUND));
      }

      await emit(ctx, {
        dbscSessionId,
        sessionId: session.session.id,
        type: "session-registered",
        userId: session.user.id,
      });

      const cookie = boundCookieFor(ctx.context, tokenHash);
      return protocolResponse(
        200,
        instructionsFor(ctx, dbscSessionId, cookie),
        // Spec §8.9: the browser caches this challenge once the session
        // exists, so the first refresh can sign without taking a 403.
        challengeHeader(ring.current, dbscSessionId, challengeIssuedAt),
        [issueBoundCookie(cookie, ring.current, tokenHash)]
      );
    }
  );

  const refresh = createAuthEndpoint(
    DBSC_PATHS.refresh,
    {
      disableBody: true,
      metadata: { scope: "server" },
      method: "POST",
      requireHeaders: true,
    },
    async (ctx) => {
      // Status codes follow ED §8.8 as Chrome implements it: 403 + challenge
      // retries, 401 ends the browser session, redirects are never used, and
      // no 429 is ever sent (Chrome before 158 deletes the session on it).
      const dbscSessionId = readStringHeader(ctx.headers, SESSION_ID_HEADER);
      if (!dbscSessionId) {
        return protocolResponse(
          400,
          errorBody(DBSC_ERROR_CODES.MISSING_SESSION_ID)
        );
      }
      const binding = await findBinding(ctx, "dbscSessionId", dbscSessionId);
      if (!binding) {
        return protocolResponse(
          401,
          errorBody(DBSC_ERROR_CODES.SESSION_NOT_FOUND)
        );
      }

      const ring = keyringFor(ctx.context);
      const now = Date.now();
      // Not from the cookie: the SameSite=Lax session cookie is absent when a
      // cross-site navigation triggers the refresh.
      const token = firstOpened(ring, (keys) =>
        decryptSessionToken(keys, binding.sessionTokenEncrypted, dbscSessionId)
      );
      if (token === null) {
        // Sealed under a secret Better Auth no longer accepts. Fail closed:
        // the binding stays, so the session needs a new sign-in rather than
        // silently losing its device binding.
        ctx.context.logger.warn(
          "[dbsc] A binding cannot be opened with the current secrets"
        );
        return protocolResponse(
          401,
          errorBody(DBSC_ERROR_CODES.SESSION_NOT_FOUND)
        );
      }
      const authSession = await ctx.context.internalAdapter.findSession(token);
      const sessionAlive =
        authSession !== null &&
        hashToken(token) === binding.tokenHash &&
        new Date(authSession.session.expiresAt).getTime() > now;
      if (!(sessionAlive && authSession)) {
        await ctx.context.adapter.delete({
          model: DBSC_MODEL,
          where: [{ field: "id", value: binding.id }],
        });
        return protocolResponse(
          401,
          errorBody(DBSC_ERROR_CODES.SESSION_NOT_FOUND)
        );
      }

      const proofHeader = readStringHeader(ctx.headers, RESPONSE_HEADER);
      if (!proofHeader) {
        return protocolResponse(
          403,
          errorBody(DBSC_ERROR_CODES.MISSING_PROOF),
          challengeHeader(ring.current, dbscSessionId, binding.lastChallengeAt)
        );
      }

      const algorithm = binding.algorithm as DbscAlgorithm;
      let proof: ReturnType<typeof parseProof>;
      let storedKey: PublicJwk;
      try {
        proof = parseProof(proofHeader, "refresh", [algorithm]);
        storedKey = parsePublicJwk(JSON.parse(binding.publicKey), algorithm);
      } catch (error) {
        ctx.context.logger.debug(
          "[dbsc] Rejected refresh proof",
          error instanceof Error ? error.message : error
        );
        return protocolResponse(401, errorBody(DBSC_ERROR_CODES.INVALID_PROOF));
      }
      if (
        !(await verifySignature(
          algorithm,
          storedKey,
          proof.signingInput,
          proof.signature
        ))
      ) {
        // Not the key holder. The binding stays: deleting it would let anyone
        // who knows the session id strip the device binding.
        await emit(ctx, {
          dbscSessionId,
          sessionId: binding.sessionId,
          type: "proof-invalid",
          userId: binding.userId,
        });
        return protocolResponse(401, errorBody(DBSC_ERROR_CODES.INVALID_PROOF));
      }

      const challengeIssuedAt = verifyChallengeAny(ring, proof.jti, {
        maxAgeMs: resolvedOptions.challengeMaxAgeMs,
        now,
        purpose: "f",
        subject: dbscSessionId,
      });
      // Atomic replay guard: only a challenge newer than the last accepted one
      // moves the binding forward. A stale or reused challenge with a valid
      // signature is benign (races, lost responses): ask again.
      const advanced =
        challengeIssuedAt === null
          ? null
          : await ctx.context.adapter.incrementOne<DbscSessionRecord>({
              increment: { refreshCount: 1 },
              model: DBSC_MODEL,
              set: {
                expiresAt: new Date(authSession.session.expiresAt),
                lastChallengeAt: challengeIssuedAt,
                updatedAt: new Date(now),
              },
              where: [
                { field: "id", value: binding.id },
                {
                  field: "lastChallengeAt",
                  operator: "lt",
                  value: challengeIssuedAt,
                },
              ],
            });
      if (!advanced) {
        return protocolResponse(
          403,
          errorBody(DBSC_ERROR_CODES.INVALID_CHALLENGE),
          challengeHeader(ring.current, dbscSessionId, binding.lastChallengeAt)
        );
      }

      await emit(ctx, {
        dbscSessionId,
        sessionId: binding.sessionId,
        type: "session-refreshed",
        userId: binding.userId,
      });
      const cookie = boundCookieFor(ctx.context, binding.tokenHash);
      return protocolResponse(
        200,
        instructionsFor(ctx, dbscSessionId, cookie),
        // The next refresh can sign straight away instead of taking a 403.
        challengeHeader(
          ring.current,
          dbscSessionId,
          challengeIssuedAt ?? binding.lastChallengeAt
        ),
        [issueBoundCookie(cookie, ring.current, binding.tokenHash)]
      );
    }
  );

  /**
   * For apps that read the session only on the server (no browser call to
   * `/get-session`): call while building a page response and copy the
   * returned header onto it. Returns the pending offer of a server-side
   * sign-in at most once per session, and null otherwise.
   */
  const registrationOffer = createAuthEndpoint.serverOnly(
    { method: "GET", requireHeaders: true },
    async (ctx) => {
      const session = await getSessionFromCtx(ctx);
      if (!session) {
        return ctx.json(null);
      }
      const tokenHash = hashToken(session.session.token);
      if (!(await takeDeferredOffer(ctx, tokenHash))) {
        return ctx.json(null);
      }
      return ctx.json({
        name: REGISTRATION_HEADER,
        value: registrationHeaderValue(ctx, tokenHash),
      });
    }
  );

  /**
   * {@link dbscRefreshNeeded} over HTTP, for apps whose Better Auth runs
   * elsewhere (a proxy to Convex, a separate auth service): forward the page
   * request's Cookie and Sec-Fetch-* headers and answer with
   * {@link dbscRefreshPage} when `refreshNeeded` is true. Reads the request
   * as sent, before the plugin's own enforcement strips the session cookie.
   */
  const refreshNeeded = createAuthEndpoint(
    DBSC_PATHS.refreshNeeded,
    {
      metadata: { noStore: true, scope: "server" },
      method: "GET",
      requireHeaders: true,
    },
    async (ctx) =>
      ctx.json({
        refreshNeeded: await refreshNeededFor(
          ctx.context,
          ctx.request?.headers ?? ctx.headers
        ),
      })
  );

  const status = createAuthEndpoint(
    DBSC_PATHS.status,
    { method: "GET", requireHeaders: true, use: [sessionMiddleware] },
    async (ctx) => {
      const binding = await findBinding(
        ctx,
        "tokenHash",
        hashToken(ctx.context.session.session.token)
      );
      return ctx.json({
        algorithm: (binding?.algorithm as DbscAlgorithm | undefined) ?? null,
        bound: binding !== null,
        boundAt: binding ? new Date(binding.createdAt) : null,
      });
    }
  );

  return {
    $ERROR_CODES: DBSC_ERROR_CODES,
    endpoints: {
      dbscRefresh: refresh,
      dbscRefreshNeeded: refreshNeeded,
      dbscRegistrationOffer: registrationOffer,
      dbscStart: start,
      dbscStatus: status,
    },
    hooks: {
      after: [
        {
          handler: offerRegistration,
          matcher: (ctx) => !isProtocolPath(ctx.path),
        },
        {
          handler: expireOnSignOut,
          matcher: (ctx) => ctx.path === SIGN_OUT_PATH,
        },
      ],
      before: [
        // The refresh endpoint authenticates with the device key alone, and
        // refresh-needed inspects the request as sent.
        {
          handler: enforce,
          matcher: (ctx) =>
            ctx.path !== DBSC_PATHS.refresh &&
            ctx.path !== DBSC_PATHS.refreshNeeded,
        },
        {
          handler: reportSkippedRefreshes,
          // Chrome sends the header on the deferred ordinary request, never on
          // the protocol POSTs, which the rate limiter does not cover.
          matcher: (ctx) =>
            Boolean(
              resolvedOptions.onEvent &&
              !isProtocolPath(ctx.path) &&
              ctx.headers?.has(SKIPPED_HEADER)
            ),
        },
      ],
    },
    id: "dbsc",
    init(ctx) {
      const pluginIds = (ctx.options.plugins ?? []).map((plugin) => plugin.id);
      const ownIndex = pluginIds.indexOf("dbsc");
      for (const [id, label] of Object.entries(PLUGINS_BEFORE_DBSC)) {
        if (pluginIds.indexOf(id) > ownIndex) {
          throw new Error(
            `[dbsc] Place dbsc() after ${label} in \`plugins\`: its hooks must run first`
          );
        }
      }
      for (const [id, label] of Object.entries(PLUGINS_AFTER_DBSC)) {
        const index = pluginIds.indexOf(id);
        if (index !== -1 && index < ownIndex) {
          throw new Error(
            `[dbsc] Place dbsc() before ${label} in \`plugins\`: its hooks read the session`
          );
        }
      }
      const cookieCache = ctx.options.session?.cookieCache;
      const cookieCacheMaxAgeMs =
        (cookieCache?.maxAge ?? DEFAULT_COOKIE_CACHE_MAX_AGE) * MS_PER_SECOND;
      if (
        cookieCache?.enabled &&
        cookieCacheMaxAgeMs > resolvedOptions.cookieMaxAgeMs
      ) {
        ctx.logger.warn(
          "[dbsc] session.cookieCache.maxAge is longer than cookieMaxAge: a stolen session_data cookie stays valid that long for getCookieCache() and other readers outside Better Auth's endpoints. Keep it at or below cookieMaxAge."
        );
      }
      assertAlgorithmsSupported(resolvedOptions.algorithms);
      // The browser's protocol POSTs may come without an Origin (Chrome 146)
      // or from a cross-site context (SSO sign-ins). They are authenticated by
      // the device key and a challenge bound to the session instead.
      const existing = ctx.skipOriginCheck;
      const skipOriginCheck =
        existing === true
          ? true
          : [
              ...(Array.isArray(existing) ? existing : []),
              DBSC_PATHS.start,
              DBSC_PATHS.refresh,
            ];
      return {
        context: {
          // Never rate limit the protocol endpoints: Chrome before 158 treats
          // a 429 on refresh as fatal and deletes the device-bound session,
          // and the limiter can share one bucket between all users when it
          // cannot see client IPs. Rules the app sets for these paths win.
          rateLimit: {
            ...ctx.rateLimit,
            customRules: {
              [DBSC_PATHS.refresh]: false,
              [DBSC_PATHS.start]: false,
              ...ctx.rateLimit.customRules,
            },
          },
          skipOriginCheck,
        },
        options: {
          databaseHooks: {
            session: {
              delete: {
                async after(session, hookCtx) {
                  const adapter = hookCtx?.context.adapter ?? ctx.adapter;
                  await adapter.deleteMany({
                    model: DBSC_MODEL,
                    where: [{ field: "sessionId", value: session.id }],
                  });
                },
              },
              // Keep the stored expiry in step when Better Auth extends a
              // session, so cleanup never mistakes a live session for a dead one.
              update: {
                async after(session, hookCtx) {
                  if (!(session?.id && session.expiresAt)) {
                    return;
                  }
                  const adapter = hookCtx?.context.adapter ?? ctx.adapter;
                  await adapter
                    .updateMany({
                      model: DBSC_MODEL,
                      update: { expiresAt: new Date(session.expiresAt) },
                      where: [{ field: "sessionId", value: session.id }],
                    })
                    .catch((error: unknown) => {
                      ctx.logger.warn(
                        "[dbsc] Could not update a binding's expiry",
                        error
                      );
                    });
                },
              },
            },
          },
        },
      };
    },
    options,
    schema: mergeSchema(createSchema(), options?.schema),
    version: PACKAGE_VERSION,
  } satisfies BetterAuthPlugin;
};
