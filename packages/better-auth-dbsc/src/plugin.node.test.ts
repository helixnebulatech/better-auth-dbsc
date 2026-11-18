import type { BetterAuthOptions, BetterAuthPlugin } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import {
  parseCookies,
  setRequestCookie,
  splitSetCookieHeader,
} from "better-auth/cookies";
import {
  admin,
  anonymous,
  bearer,
  multiSession,
  twoFactor,
  username,
} from "better-auth/plugins";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it, vi } from "vitest";

import {
  BASE_URL,
  Browser,
  parseChallengeHeader,
  parseRegistrationHeader,
} from "./__fixtures__/browser";
import { createDeviceKey } from "./__fixtures__/device-key";
import type { DeviceKey } from "./__fixtures__/device-key";
import type { DbscAlgorithm } from "./crypto/jwk";
import { deriveKeys, hashToken } from "./crypto/keys";
import type { DbscEvent, DbscOptions } from "./options";
import { dbsc, dbscRefreshNeeded, dbscRefreshPage } from "./plugin";
import { createSchema, DBSC_MODEL } from "./schema";
import { createChallenge } from "./tokens";

const AUTH_PREFIX = "/api/auth";
/** Past the plugin's registration grace (requests in flight are let through). */
const PAST_REGISTRATION_GRACE_MS = 11_000;

const pastRegistrationGrace = () => {
  vi.setSystemTime(Date.now() + PAST_REGISTRATION_GRACE_MS);
};
const SESSION_COOKIE = "better-auth.session_token";

interface Instructions {
  session_identifier: string;
  refresh_url: string;
  scope: { include_site: boolean };
  credentials: { type: string; name: string; attributes: string }[];
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

const sessionCookieOnly = (browser: Browser) =>
  browser.cookieHeader((name) => name === SESSION_COOKIE);

const getSession = async (browser: Browser, cookies?: string) => {
  const response = await browser.fetch("/get-session", { cookies });
  const body = (await response.json()) as {
    user?: { email: string };
  } | null;
  return { body, response };
};

const sessionToken = async (browser: Browser) => {
  const response = await browser.fetch("/get-session");
  const body = (await response.json()) as { session: { token: string } };
  return body.session.token;
};

const multiCookies = (browser: Browser) =>
  browser.cookieHeader((name) => name.includes("_multi-"));

const sessionUser = async (browser: Browser, cookies?: string) => {
  const { body } = await getSession(browser, cookies);
  return body?.user;
};

const fetchJson = async (browser: Browser, path: string) => {
  const response = await browser.fetch(path);
  return response.json();
};

const refresh = (
  browser: Browser,
  sessionId: string,
  proof?: string,
  cookies = ""
) =>
  browser.fetch("/dbsc/refresh", {
    cookies,
    headers: {
      "Sec-Secure-Session-Id": sessionId,
      ...(proof ? { "Secure-Session-Response": proof } : {}),
    },
    method: "POST",
  });

const refreshStatus = async (browser: Browser, sessionId: string) => {
  const response = await refresh(browser, sessionId);
  return response.status;
};

const challengeFrom = async (pending: Promise<Response>) => {
  const { headers } = await pending;
  return parseChallengeHeader(headers.get("Secure-Session-Challenge"))
    .challenge;
};

/** Answers the registration offer in `response` the way Chrome does. */
const completeRegistration = async (
  browser: Browser,
  response: Response,
  deviceKey: DeviceKey,
  { keepGrace = false }: { keepGrace?: boolean } = {}
) => {
  const offer = parseRegistrationHeader(
    response.headers.get("Secure-Session-Registration")
  );
  const proof = await deviceKey.prove({
    jti: offer.challenge,
    mode: "registration",
  });
  const startResponse = await browser.fetch(
    offer.path.slice(AUTH_PREFIX.length),
    { headers: { "Secure-Session-Response": proof }, method: "POST" }
  );
  const instructions = (await startResponse.json()) as Instructions;
  if (startResponse.status === 200 && !keepGrace) {
    pastRegistrationGrace();
  }
  return { instructions, offer, startResponse };
};

const RANGE_OPERATORS = new Set(["lt", "lte", "gt", "gte"]);
const WHERE_METHODS = [
  "count",
  "delete",
  "deleteMany",
  "findMany",
  "findOne",
  "incrementOne",
  "update",
  "updateMany",
] as const;

interface AdapterQuery {
  model: string;
  where?: { operator?: string }[];
}

/**
 * Makes the adapter refuse plugin queries with more than one range condition,
 * as index-only adapters (Convex, key-value stores) do. Better Auth's memory
 * adapter accepts them, which would hide the problem.
 */
const enforceSingleRangeQueries = (context: { adapter: object }) => {
  const adapter = context.adapter as unknown as Record<
    string,
    ((query: AdapterQuery) => Promise<unknown>) | undefined
  >;
  for (const method of WHERE_METHODS) {
    const original = adapter[method]?.bind(adapter);
    if (!original) {
      continue;
    }
    adapter[method] = (query) => {
      const ranges = (query.where ?? []).filter(
        (clause) => clause.operator && RANGE_OPERATORS.has(clause.operator)
      );
      if (query.model === DBSC_MODEL && ranges.length > 1) {
        return Promise.reject(
          new Error(`${method} on ${query.model} has ${ranges.length} ranges`)
        );
      }
      return original(query);
    };
  }
};

const setup = async (
  options: DbscOptions = {},
  authOptions: Partial<BetterAuthOptions> = {},
  { after = [] }: { after?: BetterAuthPlugin[] } = {}
) => {
  const events: DbscEvent[] = [];
  const instance = await getTestInstance({
    ...authOptions,
    plugins: [
      ...(authOptions.plugins ?? []),
      dbsc({
        ...options,
        onEvent: (event) => {
          events.push(event);
        },
      }),
      ...after,
    ],
  });
  enforceSingleRangeQueries(await instance.auth.$context);
  const handler = (request: Request) => instance.auth.handler(request);
  const { email, password } = instance.testUser;

  const signIn = async (
    headers: Record<string, string> = {},
    browser = new Browser(handler)
  ) => {
    const response = await browser.fetch("/sign-in/email", {
      body: { email, password },
      headers,
    });
    expect(response.status).toBe(200);
    return { browser, response };
  };

  const register = async (
    algorithm: DbscAlgorithm = "ES256",
    key?: DeviceKey,
    existing?: Browser
  ) => {
    const { browser, response } = await signIn({}, existing);
    const deviceKey = key ?? (await createDeviceKey(algorithm));
    return {
      browser,
      deviceKey,
      ...(await completeRegistration(browser, response, deviceKey)),
    };
  };

  return { events, handler, instance, register, signIn };
};

/* -------------------------------------------------------------------------- */
/* Registration                                                               */
/* -------------------------------------------------------------------------- */

describe("registration", () => {
  it("offers registration on sign-in and binds the session", async () => {
    const { register, events } = await setup();
    const { offer, startResponse, instructions, browser } = await register();

    expect(offer.algorithms).toStrictEqual(["ES256", "RS256"]);
    expect(offer.path).toBe("/api/auth/dbsc/start");
    expect(startResponse.status).toBe(200);
    expect(startResponse.headers.get("cache-control")).toBe("no-store");
    expect(instructions.refresh_url).toBe("/api/auth/dbsc/refresh");
    expect(instructions.scope).toStrictEqual({ include_site: false });

    const [credential] = instructions.credentials;
    expect(credential?.type).toBe("cookie");
    expect(credential?.name).toMatch(/^better-auth\.dbsc_[\w-]{12}$/u);
    // The Set-Cookie must carry exactly the attributes the browser was told.
    const issued = browser.setCookies.find(
      (cookie) => cookie.name === credential?.name
    );
    expect(
      issued?.attributes
        .filter((attribute) => !attribute.startsWith("Max-Age"))
        .join("; ")
    ).toBe(credential?.attributes);
    expect(issued?.attributes).toContain("Max-Age=600");
    expect(events.map((event) => event.type)).toStrictEqual([
      "session-registered",
    ]);
  });

  it("works with RS256 keys", async () => {
    const { register } = await setup();
    const { startResponse } = await register("RS256");
    expect(startResponse.status).toBe(200);
  });

  it("does not offer registration in a cross-site context", async () => {
    const { signIn } = await setup();
    const { response } = await signIn({ "Sec-Fetch-Site": "cross-site" });
    expect(response.headers.get("Secure-Session-Registration")).toBeNull();
  });

  it("rejects a foreign challenge, re-registration and key reuse", async () => {
    const { signIn, register } = await setup();
    const first = await register();

    // Re-registering the same session.
    const again = await first.deviceKey.prove({
      jti: first.offer.challenge,
      mode: "registration",
    });
    const reRegister = await first.browser.fetch("/dbsc/start", {
      headers: { "Secure-Session-Response": again },
      method: "POST",
    });
    expect(reRegister.status).toBe(400);
    await expect(reRegister.json()).resolves.toMatchObject({
      code: "ALREADY_BOUND",
    });

    // A second session presenting the first session's challenge.
    const { browser } = await signIn();
    const strangerKey = await createDeviceKey();
    const stolenChallenge = await strangerKey.prove({
      jti: first.offer.challenge,
      mode: "registration",
    });
    const wrong = await browser.fetch("/dbsc/start", {
      headers: { "Secure-Session-Response": stolenChallenge },
      method: "POST",
    });
    await expect(wrong.json()).resolves.toMatchObject({
      code: "INVALID_CHALLENGE",
    });

    // The same device key cannot bind two sessions.
    const reuse = await register("ES256", first.deviceKey);
    expect(reuse.startResponse.status).toBe(400);
    expect(reuse.instructions).toMatchObject({ code: "KEY_ALREADY_USED" });
  });

  it("requires a signed-in session and a proof", async () => {
    const { handler } = await setup();
    const browser = new Browser(handler);
    const deviceKey = await createDeviceKey();
    const noSession = await browser.fetch("/dbsc/start", {
      headers: {
        "Secure-Session-Response": await deviceKey.prove({
          jti: "anything",
          mode: "registration",
        }),
      },
      method: "POST",
    });
    expect(noSession.status).toBe(401);
    const noProof = await browser.fetch("/dbsc/start", { method: "POST" });
    expect(noProof.status).toBe(400);
  });

  it("accepts Origin-less protocol POSTs with the origin check on", async () => {
    const { signIn } = await setup(
      {},
      { advanced: { disableOriginCheck: false } }
    );
    const { browser, response } = await signIn();
    const offer = parseRegistrationHeader(
      response.headers.get("Secure-Session-Registration")
    );
    const deviceKey = await createDeviceKey();
    const startResponse = await browser.fetch("/dbsc/start", {
      headers: {
        "Secure-Session-Response": await deviceKey.prove({
          jti: offer.challenge,
          mode: "registration",
        }),
        origin: "",
      },
      method: "POST",
    });
    expect(startResponse.status).toBe(200);
  });
});

/* -------------------------------------------------------------------------- */
/* Registration offers                                                        */
/* -------------------------------------------------------------------------- */

const REGISTRATION = "Secure-Session-Registration";

const offerOf = async (pending: Promise<Response>) => {
  const { headers } = await pending;
  return headers.get(REGISTRATION);
};

/** A session created server-side (`auth.api`), handed to a browser jar. */
const serverSide = async () => {
  const context = await setup();
  const serverSignIn = async () => {
    const { headers } = await context.instance.auth.api.signInEmail({
      body: {
        email: context.instance.testUser.email,
        password: context.instance.testUser.password,
      },
      returnHeaders: true,
    });
    expect(headers.get(REGISTRATION)).toBeNull();
    const browser = new Browser(context.handler);
    for (const cookie of headers.getSetCookie()) {
      const [pair = ""] = cookie.split(";");
      const index = pair.indexOf("=");
      browser.cookies.set(pair.slice(0, index), pair.slice(index + 1));
    }
    return browser;
  };
  return { ...context, serverSignIn };
};

describe("registration offers", () => {
  it("offers once: not again from /get-session after a same-site sign-in", async () => {
    const { signIn } = await setup();
    const { browser, response } = await signIn();
    const offer = parseRegistrationHeader(response.headers.get(REGISTRATION));
    expect(offer.authorization).toBeUndefined();
    // The app's /get-session races Chrome's registration: no second offer.
    await expect(offerOf(browser.fetch("/get-session"))).resolves.toBeNull();
  });

  it("offers a cross-site sign-in right away, with a ticket instead of the cookie", async () => {
    const { signIn } = await setup();
    const { browser, response } = await signIn({
      "sec-fetch-mode": "navigate",
      "sec-fetch-site": "cross-site",
    });
    const offer = parseRegistrationHeader(response.headers.get(REGISTRATION));
    expect(offer.authorization).toMatch(/^t1\./u);

    // Chrome's registration POST from a cross-site context carries no
    // SameSite=Lax session cookie: the ticket in the proof names the session.
    const deviceKey = await createDeviceKey();
    const start = await browser.fetch("/dbsc/start", {
      cookies: "",
      headers: {
        "Secure-Session-Response": await deviceKey.prove({
          jti: offer.challenge,
          mode: "registration",
          payload: { authorization: offer.authorization },
        }),
      },
      method: "POST",
    });
    expect(start.status).toBe(200);
    pastRegistrationGrace();
    await expect(sessionUser(browser)).resolves.toBeDefined();
    await expect(
      sessionUser(browser, sessionCookieOnly(browser))
    ).resolves.toBeUndefined();
    await expect(offerOf(browser.fetch("/get-session"))).resolves.toBeNull();
  });

  it("rejects forged tickets and tickets for another session", async () => {
    const { signIn } = await setup();
    const a = await signIn({
      "sec-fetch-mode": "navigate",
      "sec-fetch-site": "cross-site",
    });
    const b = await signIn({
      "sec-fetch-mode": "navigate",
      "sec-fetch-site": "cross-site",
    });
    const offerA = parseRegistrationHeader(
      a.response.headers.get(REGISTRATION)
    );
    const offerB = parseRegistrationHeader(
      b.response.headers.get(REGISTRATION)
    );
    const deviceKey = await createDeviceKey();
    const register = async (jti: string, authorization: string) => {
      const response = await a.browser.fetch("/dbsc/start", {
        cookies: "",
        headers: {
          "Secure-Session-Response": await deviceKey.prove({
            jti,
            mode: "registration",
            payload: { authorization },
          }),
        },
        method: "POST",
      });
      return response.status;
    };
    const tampered = `${offerA.authorization?.slice(0, -2)}AA`;
    await expect(register(offerA.challenge, tampered)).resolves.toBe(401);
    await expect(register(offerA.challenge, "t1.0.a.b")).resolves.toBe(401);
    // B's ticket with A's challenge: the challenge is bound to A's session.
    await expect(
      register(offerA.challenge, offerB.authorization ?? "")
    ).resolves.toBe(400);
  });

  it("defers a server-side sign-in's offer to the first same-site /get-session", async () => {
    const { serverSignIn } = await serverSide();
    const browser = await serverSignIn();
    const first = await browser.fetch("/get-session");
    expect(first.headers.get(REGISTRATION)).toMatch(/^\(ES256 RS256\)/u);
    await expect(offerOf(browser.fetch("/get-session"))).resolves.toBeNull();
    const { startResponse } = await completeRegistration(
      browser,
      first,
      await createDeviceKey()
    );
    expect(startResponse.status).toBe(200);
  });

  it("gives a deferred offer to exactly one of concurrent /get-session calls", async () => {
    const { serverSignIn } = await serverSide();
    const browser = await serverSignIn();
    const offers = await Promise.all(
      Array.from({ length: 4 }, () => offerOf(browser.fetch("/get-session")))
    );
    expect(offers.filter(Boolean)).toHaveLength(1);
  });

  it("does not spend a deferred offer on a server-side /get-session", async () => {
    const { serverSignIn } = await serverSide();
    const browser = await serverSignIn();
    // An SSR loader forwarding cookies: no Fetch Metadata.
    await expect(
      offerOf(
        browser.fetch("/get-session", { headers: { "sec-fetch-site": "" } })
      )
    ).resolves.toBeNull();
    await expect(offerOf(browser.fetch("/get-session"))).resolves.toBeTruthy();
  });

  it("hands a deferred offer to the app once through auth.api", async () => {
    const { serverSignIn, instance } = await serverSide();
    const browser = await serverSignIn();
    const headers = new Headers({ cookie: browser.cookieHeader() });
    const offer = await instance.auth.api.dbscRegistrationOffer({ headers });
    expect(offer?.name).toBe(REGISTRATION);
    expect(offer?.value).toMatch(/^\(ES256 RS256\)/u);
    await expect(
      instance.auth.api.dbscRegistrationOffer({ headers })
    ).resolves.toBeNull();
    await expect(offerOf(browser.fetch("/get-session"))).resolves.toBeNull();
  });

  it("stores nothing for clients that are not browsers", async () => {
    const { signIn, instance } = await setup();
    const context = await instance.auth.$context;
    const deferredOffers = async () => {
      const rows = await context.adapter.findMany<{ identifier: string }>({
        model: "verification",
      });
      return rows.filter((row) => row.identifier.startsWith("dbsc-offer:"))
        .length;
    };
    // getTestInstance signs the test user up server-side, which defers one.
    const before = await deferredOffers();
    const { browser, response } = await signIn({ "sec-fetch-site": "" });
    expect(response.headers.get(REGISTRATION)).toBeNull();
    await expect(deferredOffers()).resolves.toBe(before);
    await expect(offerOf(browser.fetch("/get-session"))).resolves.toBeNull();
  });
});

/* -------------------------------------------------------------------------- */
/* Enforcement                                                                */
/* -------------------------------------------------------------------------- */

describe("enforcement", () => {
  it("ignores a bound session's cookie without the device cookie", async () => {
    const { register, events } = await setup();
    const { browser } = await register();

    await expect(sessionUser(browser)).resolves.toBeDefined();
    await expect(
      sessionUser(browser, sessionCookieOnly(browser))
    ).resolves.toBeUndefined();
    expect(events.at(-1)).toMatchObject({
      path: "/get-session",
      type: "proof-missing",
    });

    // Endpoints behind sessionMiddleware.
    const list = await browser.fetch("/list-sessions", {
      cookies: sessionCookieOnly(browser),
    });
    expect(list.status).toBe(401);
    const listWithProof = await browser.fetch("/list-sessions");
    expect(listWithProof.status).toBe(200);
  });

  it("covers server-side auth.api.getSession", async () => {
    const { register, instance } = await setup();
    const { browser } = await register();
    const stolen = await instance.auth.api.getSession({
      headers: new Headers({ cookie: sessionCookieOnly(browser) }),
    });
    expect(stolen).toBeNull();
    const genuine = await instance.auth.api.getSession({
      headers: new Headers({ cookie: browser.cookieHeader() }),
    });
    expect(genuine?.user).toBeDefined();
  });

  it("refuses the stolen token as a bearer token", async () => {
    const { register } = await setup();
    const { browser } = await register();
    const token = browser.cookies.get(SESSION_COOKIE) ?? "";
    const response = await browser.fetch("/get-session", {
      cookies: "",
      headers: { Authorization: `Bearer ${decodeURIComponent(token)}` },
    });
    expect(response.status).toBe(401);
  });

  it("does not let the cookie cache stand in for a refused session", async () => {
    const { register } = await setup(
      {},
      { session: { cookieCache: { enabled: true, maxAge: 300 } } }
    );
    const { browser } = await register();
    expect(browser.cookies.has("better-auth.session_data")).toBeTruthy();
    const stolen = browser.cookieHeader((name) =>
      name.startsWith("better-auth.session_")
    );
    await expect(sessionUser(browser, stolen)).resolves.toBeUndefined();
  });

  it("leaves unbound sessions (browsers without DBSC) alone", async () => {
    const { signIn } = await setup();
    const { browser } = await signIn();
    await expect(
      sessionUser(browser, sessionCookieOnly(browser))
    ).resolves.toBeDefined();
  });

  it("reports the binding through /dbsc/status", async () => {
    const { register, signIn } = await setup();
    const { browser } = await register();
    await expect(fetchJson(browser, "/dbsc/status")).resolves.toMatchObject({
      algorithm: "ES256",
      bound: true,
    });
    const unbound = await signIn();
    await expect(
      fetchJson(unbound.browser, "/dbsc/status")
    ).resolves.toMatchObject({ bound: false });
  });
});

/* -------------------------------------------------------------------------- */
/* Refresh                                                                    */
/* -------------------------------------------------------------------------- */

describe("refresh", () => {
  it("challenges, then rotates the cookie without the session cookie", async () => {
    const { register, events } = await setup();
    const { browser, deviceKey, instructions } = await register();
    const sessionId = instructions.session_identifier;
    const cookieName = instructions.credentials[0]?.name ?? "";
    const firstValue = browser.cookies.get(cookieName);
    browser.cookies.delete(cookieName);

    // No cookies at all: a cross-site navigation drops the Lax session cookie.
    const challenged = await refresh(browser, sessionId);
    expect(challenged.status).toBe(403);
    const { challenge, sessionId: challengeId } = parseChallengeHeader(
      challenged.headers.get("Secure-Session-Challenge")
    );
    expect(challengeId).toBe(sessionId);

    const proof = await deviceKey.prove({ jti: challenge, mode: "refresh" });
    const refreshed = await refresh(browser, sessionId, proof);
    expect(refreshed.status).toBe(200);
    await expect(refreshed.json()).resolves.toMatchObject({
      session_identifier: sessionId,
    });
    const secondValue = browser.cookies.get(cookieName);
    expect(secondValue).toBeDefined();
    expect(secondValue).not.toBe(firstValue);
    await expect(sessionUser(browser)).resolves.toBeDefined();

    // The same proof again is a replay: benign 403 with a new challenge.
    const replay = await refresh(browser, sessionId, proof);
    expect(replay.status).toBe(403);
    expect(replay.headers.get("Secure-Session-Challenge")).toBeTruthy();

    // The challenge sent with the 200 lets the next refresh skip the 403.
    const next = parseChallengeHeader(
      refreshed.headers.get("Secure-Session-Challenge")
    );
    const direct = await refresh(
      browser,
      sessionId,
      await deviceKey.prove({ jti: next.challenge, mode: "refresh" })
    );
    expect(direct.status).toBe(200);
    expect(
      events.filter((event) => event.type === "session-refreshed")
    ).toHaveLength(2);
  });

  it("sends a challenge with the registration so the first refresh skips the 403", async () => {
    const { register, events } = await setup();
    const { browser, deviceKey, instructions, startResponse } =
      await register();
    const sessionId = instructions.session_identifier;
    const { challenge, sessionId: challengeId } = parseChallengeHeader(
      startResponse.headers.get("Secure-Session-Challenge")
    );
    expect(challengeId).toBe(sessionId);

    browser.cookies.delete(instructions.credentials[0]?.name ?? "");
    const refreshed = await refresh(
      browser,
      sessionId,
      await deviceKey.prove({ jti: challenge, mode: "refresh" })
    );
    expect(refreshed.status).toBe(200);
    expect(events.at(-1)).toMatchObject({ type: "session-refreshed" });

    // Spent: the same proof again is a replay.
    const replay = await refresh(
      browser,
      sessionId,
      await deviceKey.prove({ jti: challenge, mode: "refresh" })
    );
    expect(replay.status).toBe(403);
  });

  it("accepts the spec's quoted Sec-Secure-Session-Id", async () => {
    const { register } = await setup();
    const { browser, instructions } = await register();
    await expect(
      refreshStatus(browser, `"${instructions.session_identifier}"`)
    ).resolves.toBe(403);
  });

  it("answers a forged signature with 401 and keeps the binding", async () => {
    const { register, events } = await setup();
    const { browser, deviceKey, instructions } = await register();
    const sessionId = instructions.session_identifier;
    const challenge = await challengeFrom(refresh(browser, sessionId));

    const attacker = await createDeviceKey();
    const forged = await refresh(
      browser,
      sessionId,
      await attacker.prove({ jti: challenge, mode: "refresh" })
    );
    expect(forged.status).toBe(401);
    expect(events.at(-1)).toMatchObject({ type: "proof-invalid" });

    const genuine = await refresh(
      browser,
      sessionId,
      await deviceKey.prove({ jti: challenge, mode: "refresh" })
    );
    expect(genuine.status).toBe(200);
  });

  it("rejects a challenge minted for another DBSC session", async () => {
    const { register } = await setup();
    const a = await register();
    const b = await register();
    const challenge = await challengeFrom(
      refresh(a.browser, a.instructions.session_identifier)
    );
    const response = await refresh(
      b.browser,
      b.instructions.session_identifier,
      await b.deviceKey.prove({ jti: challenge, mode: "refresh" })
    );
    expect(response.status).toBe(403);
  });

  it("ends the browser session with 401 once the auth session is gone", async () => {
    const { register } = await setup();
    const { browser, instructions } = await register();
    const signOut = await browser.fetch("/sign-out", { method: "POST" });
    expect(signOut.status).toBe(200);
    // The bound cookie is expired on sign-out.
    expect(
      browser.cookies.has(instructions.credentials[0]?.name ?? "")
    ).toBeFalsy();
    await expect(
      refreshStatus(browser, instructions.session_identifier)
    ).resolves.toBe(401);
  });

  it("answers an unknown session id with 401 and a missing one with 400", async () => {
    const { handler } = await setup();
    const browser = new Browser(handler);
    await expect(refreshStatus(browser, "unknown")).resolves.toBe(401);
    const missing = await browser.fetch("/dbsc/refresh", { method: "POST" });
    expect(missing.status).toBe(400);
  });
});

/* -------------------------------------------------------------------------- */
/* Session end                                                                */
/* -------------------------------------------------------------------------- */

const boundCookieName = (instructions: Instructions) =>
  instructions.credentials[0]?.name ?? "";

describe("when Better Auth ends the session", () => {
  it.each([
    ["/sign-out", "the session"],
    ["/revoke-session", "the current session"],
    ["/revoke-sessions", "every session"],
    ["/delete-user", "the user"],
  ])("%s ending %s expires the bound cookie", async (path) => {
    const { register } = await setup(
      {},
      { user: { deleteUser: { enabled: true } } }
    );
    const { browser, instructions } = await register();
    const boundName = boundCookieName(instructions);
    expect(browser.cookies.has(boundName)).toBeTruthy();
    const token = await sessionToken(browser);
    const response = await browser.fetch(path, {
      body: path === "/revoke-session" ? { token } : {},
    });
    expect(response.status).toBe(200);
    expect(browser.cookies.has(SESSION_COOKIE)).toBeFalsy();
    expect(browser.cookies.has(boundName)).toBeFalsy();
    await expect(
      refreshStatus(browser, instructions.session_identifier)
    ).resolves.toBe(401);
  });

  it("revoking another session keeps the current one's bound cookie", async () => {
    const { register, signIn } = await setup();
    const { browser, instructions } = await register();
    const boundName = boundCookieName(instructions);
    const other = await signIn();
    const response = await browser.fetch("/revoke-session", {
      body: { token: await sessionToken(other.browser) },
    });
    expect(response.status).toBe(200);
    expect(browser.cookies.has(SESSION_COOKIE)).toBeTruthy();
    expect(browser.cookies.has(boundName)).toBeTruthy();
    await expect(sessionUser(browser)).resolves.toBeDefined();
    await expect(sessionUser(other.browser)).resolves.toBeUndefined();
  });

  it("a request that fails keeps the bound cookie", async () => {
    const { register } = await setup(
      {},
      { user: { deleteUser: { enabled: true } } }
    );
    const { browser, instructions } = await register();
    const response = await browser.fetch("/delete-user", {
      body: { password: "not-the-password" },
    });
    expect(response.status).toBe(400);
    expect(browser.cookies.has(boundCookieName(instructions))).toBeTruthy();
    await expect(sessionUser(browser)).resolves.toBeDefined();
  });

  it.each([
    ["without a callback", ""],
    ["with a callback redirect", "&callbackURL=%2Fgoodbye"],
  ])(
    "deleting the user through the emailed link %s expires the bound cookie",
    async (_label, query) => {
      let deleteToken = "";
      const { register } = await setup(
        {},
        {
          user: {
            deleteUser: {
              enabled: true,
              sendDeleteAccountVerification: ({ token }) => {
                deleteToken = token;
                return Promise.resolve();
              },
            },
          },
        }
      );
      const { browser, instructions } = await register();
      await browser.fetch("/delete-user", { body: {} });
      expect(deleteToken).not.toBe("");
      expect(browser.cookies.has(boundCookieName(instructions))).toBeTruthy();
      const response = await browser.fetch(
        `/delete-user/callback?token=${deleteToken}${query}`
      );
      expect(response.status).toBe(query ? 302 : 200);
      expect(browser.cookies.has(SESSION_COOKIE)).toBeFalsy();
      expect(browser.cookies.has(boundCookieName(instructions))).toBeFalsy();
    }
  );

  it("get-session finding the session gone expires the bound cookie", async () => {
    const { register, instance } = await setup();
    const { browser, instructions } = await register();
    const context = await instance.auth.$context;
    await context.internalAdapter.deleteSession(await sessionToken(browser));
    await expect(sessionUser(browser)).resolves.toBeUndefined();
    expect(browser.cookies.has(SESSION_COOKIE)).toBeFalsy();
    expect(browser.cookies.has(boundCookieName(instructions))).toBeFalsy();
  });

  it("a response that replaces a session that is gone expires its bound cookie", async () => {
    const { register, instance, events } = await setup();
    const { browser, instructions } = await register();
    const oldToken = await sessionToken(browser);
    pastRegistrationGrace();
    // revokeOtherSessions deletes every session, this one included, and
    // signs the browser in to a new one.
    const response = await browser.fetch("/change-password", {
      body: {
        currentPassword: instance.testUser.password,
        newPassword: ["a", "new", "password"].join("-"),
        revokeOtherSessions: true,
      },
    });
    expect(response.status).toBe(200);
    await expect(sessionToken(browser)).resolves.not.toBe(oldToken);
    expect(browser.cookies.has(boundCookieName(instructions))).toBeFalsy();
    // The new session works, and is offered registration like any other.
    expect(response.headers.get("Secure-Session-Registration")).not.toBeNull();
    await expect(sessionUser(browser)).resolves.toBeDefined();
    expect(events.some((event) => event.type === "proof-missing")).toBeFalsy();
  });

  it("a response that replaces a session that is gone works with secondary storage", async () => {
    // Sessions only in secondary storage: Better Auth runs no delete hooks.
    const store = new Map<string, string>();
    const { register, instance } = await setup(
      {},
      {
        secondaryStorage: {
          delete: (key) => {
            store.delete(key);
          },
          get: (key) => store.get(key) ?? null,
          getAndDelete: (key) => {
            const value = store.get(key) ?? null;
            store.delete(key);
            return value;
          },
          increment: (key) => {
            const next = Number(store.get(key) ?? 0) + 1;
            store.set(key, String(next));
            return next;
          },
          set: (key, value) => {
            store.set(key, value);
          },
        },
      }
    );
    const { browser, instructions } = await register();
    pastRegistrationGrace();
    const response = await browser.fetch("/change-password", {
      body: {
        currentPassword: instance.testUser.password,
        newPassword: ["a", "new", "password"].join("-"),
        revokeOtherSessions: true,
      },
    });
    expect(response.status).toBe(200);
    expect(browser.cookies.has(boundCookieName(instructions))).toBeFalsy();
    await expect(sessionUser(browser)).resolves.toBeDefined();
  });

  it("a response that replaces a session that is still alive keeps its bound cookie", async () => {
    const { register, signIn } = await setup();
    const { browser, instructions } = await register();
    const oldToken = await sessionToken(browser);
    // Signing in again leaves the old session in the database.
    await signIn({}, browser);
    await expect(sessionToken(browser)).resolves.not.toBe(oldToken);
    expect(browser.cookies.has(boundCookieName(instructions))).toBeTruthy();
  });

  it("a response that re-sets the same session reads no session", async () => {
    // A short updateAge makes /get-session refresh the session and set its
    // cookie again, with the same token.
    const { signIn, instance } = await setup(
      {},
      { session: { updateAge: 60 } }
    );
    const { browser } = await signIn();
    pastRegistrationWindow();
    const context = await instance.auth.$context;
    const findSession = vi.spyOn(context.internalAdapter, "findSession");
    const setCookiesBefore = browser.setCookies.length;
    await expect(sessionUser(browser)).resolves.toBeDefined();
    expect(
      browser.setCookies
        .slice(setCookiesBefore)
        .some((cookie) => cookie.name === SESSION_COOKIE && !cookie.expired)
    ).toBeTruthy();
    // Better Auth's own read only.
    expect(findSession).toHaveBeenCalledOnce();
    findSession.mockRestore();
  });

  it("a response that replaces an expired session expires its unbound marker", async () => {
    const SESSION_EXPIRES_IN_SECONDS = 3600;
    const { signIn } = await setup(
      {},
      { session: { expiresIn: SESSION_EXPIRES_IN_SECONDS } }
    );
    const { browser } = await signIn();
    pastRegistrationWindow();
    await sessionUser(browser);
    const [markerName = ""] = markerOf(browser) ?? [];
    expect(markerName).not.toBe("");
    // The session expires; its row stays until something deletes it, and
    // the marker (24 hours) outlives it.
    vi.setSystemTime(Date.now() + SESSION_EXPIRES_IN_SECONDS * 1000);
    await signIn({}, browser);
    expect(browser.cookies.has(markerName)).toBeFalsy();
  });

  it("works with __Secure- cookies", async () => {
    const { register } = await setup(
      {},
      { advanced: { useSecureCookies: true } }
    );
    const { browser, instructions } = await register();
    const boundName = boundCookieName(instructions);
    expect(boundName.startsWith("__Secure-")).toBeTruthy();
    expect(browser.cookies.has(boundName)).toBeTruthy();
    await browser.fetch("/revoke-sessions", { body: {} });
    expect(browser.cookies.has(`__Secure-${SESSION_COOKIE}`)).toBeFalsy();
    expect(browser.cookies.has(boundName)).toBeFalsy();
  });

  it("works for server-side auth.api calls", async () => {
    const { register, instance } = await setup();
    const { browser, instructions } = await register();
    const { headers } = await instance.auth.api.revokeSessions({
      headers: new Headers({ cookie: browser.cookieHeader() }),
      returnHeaders: true,
    });
    const expired = headers
      .getSetCookie()
      .filter((cookie) => /max-age=0/iu.test(cookie))
      .map((cookie) => cookie.slice(0, cookie.indexOf("=")));
    expect(expired).toContain(SESSION_COOKIE);
    expect(expired).toContain(boundCookieName(instructions));
  });

  it("works on runtimes without Headers.getSetCookie", async () => {
    const { register, instance } = await setup();
    const { browser, instructions } = await register();
    const cookie = browser.cookieHeader();
    const descriptor = Object.getOwnPropertyDescriptor(
      Headers.prototype,
      "getSetCookie"
    );
    Reflect.deleteProperty(Headers.prototype, "getSetCookie");
    let response: Response;
    let setCookie: string;
    try {
      // Read the session too: every request runs the after hook.
      const read = await instance.auth.handler(
        new Request(`${BASE_URL}${AUTH_PREFIX}/get-session`, {
          headers: { cookie },
        })
      );
      expect(read.status).toBe(200);
      response = await instance.auth.handler(
        new Request(`${BASE_URL}${AUTH_PREFIX}/revoke-sessions`, {
          body: "{}",
          headers: {
            "content-type": "application/json",
            cookie,
            origin: BASE_URL,
          },
          method: "POST",
        })
      );
      setCookie = response.headers.get("set-cookie") ?? "";
    } finally {
      if (descriptor) {
        Object.defineProperty(Headers.prototype, "getSetCookie", descriptor);
      }
    }
    expect(response.status).toBe(200);
    const expired = splitSetCookieHeader(setCookie)
      .filter((entry) => /max-age=0/iu.test(entry))
      .map((entry) => entry.slice(0, entry.indexOf("=")));
    expect(expired).toContain(SESSION_COOKIE);
    expect(expired).toContain(boundCookieName(instructions));
  });

  it("admin impersonation keeps the admin's bound cookie for the way back", async () => {
    const { register, instance, handler, events } = await setup(
      {},
      { plugins: [admin()] }
    );
    const { browser, instructions } = await register();
    const boundName = boundCookieName(instructions);
    const context = await instance.auth.$context;
    const adminSession = await context.internalAdapter.findSession(
      await sessionToken(browser)
    );
    await context.internalAdapter.updateUser(adminSession?.user.id ?? "", {
      role: "admin",
    });
    const target = new Browser(handler);
    const signUp = await target.fetch("/sign-up/email", {
      body: {
        email: ["impersonated", "example.com"].join("@"),
        name: "impersonated",
        password: ["impersonated", "account", "password"].join("-"),
      },
    });
    const { user: targetUser } = (await signUp.json()) as {
      user: { id: string };
    };

    const impersonate = await browser.fetch("/admin/impersonate-user", {
      body: { userId: targetUser.id },
    });
    expect(impersonate.status).toBe(200);
    expect(browser.cookies.has(boundName)).toBeTruthy();
    const impersonated = await getSession(browser);
    expect(impersonated.body?.user?.email).toBe(
      ["impersonated", "example.com"].join("@")
    );

    pastRegistrationGrace();
    const stop = await browser.fetch("/admin/stop-impersonating", {
      body: {},
    });
    expect(stop.status).toBe(200);
    expect(browser.cookies.has(boundName)).toBeTruthy();
    // Back as the admin, whose session is bound: accepted, not refused.
    await expect(sessionUser(browser)).resolves.toMatchObject({
      email: instance.testUser.email,
    });
    expect(events.some((event) => event.type === "proof-missing")).toBeFalsy();
  });
});

/* -------------------------------------------------------------------------- */
/* Other plugins                                                              */
/* -------------------------------------------------------------------------- */

describe("with twoFactor()", () => {
  it("offers registration only once the second factor is verified", async () => {
    let otp = "";
    const { signIn, handler, instance } = await setup(
      {},
      {
        plugins: [
          twoFactor({
            otpOptions: {
              sendOTP: ({ otp: code }) => {
                otp = code;
              },
            },
            skipVerificationOnEnable: true,
          }),
        ],
      }
    );
    const setupBrowser = new Browser(handler);
    await signIn({}, setupBrowser);
    const enabled = await setupBrowser.fetch("/two-factor/enable", {
      body: { password: instance.testUser.password },
    });
    expect(enabled.status).toBe(200);

    // First factor: the session waits for 2FA, so nothing is offered.
    const browser = new Browser(handler);
    const firstFactor = await browser.fetch("/sign-in/email", {
      body: {
        email: instance.testUser.email,
        password: instance.testUser.password,
      },
    });
    await expect(firstFactor.json()).resolves.toMatchObject({
      twoFactorRedirect: true,
    });
    expect(firstFactor.headers.get("Secure-Session-Registration")).toBeNull();

    // Second factor creates the real session, which is offered and binds.
    await browser.fetch("/two-factor/send-otp", { body: {} });
    const verified = await browser.fetch("/two-factor/verify-otp", {
      body: { code: otp },
    });
    expect(verified.status).toBe(200);
    const { startResponse } = await completeRegistration(
      browser,
      verified,
      await createDeviceKey()
    );
    expect(startResponse.status).toBe(200);
    await expect(sessionUser(browser)).resolves.toBeDefined();
    await expect(
      sessionUser(browser, sessionCookieOnly(browser))
    ).resolves.toBeUndefined();
  });
});

/**
 * The before hook of `crossDomain()` from @convex-dev/better-auth: cookies
 * kept in localStorage arrive in a `Better-Auth-Cookie` header and are merged
 * into the request's Cookie header.
 */
const CROSS_DOMAIN_RESPONSE_HEADER = "x-better-auth-cross-domain";
const carriesCrossDomainCookie = (ctx: { headers?: Headers }) =>
  Boolean(ctx.headers?.has("better-auth-cookie"));

/**
 * @convex-dev/better-auth's crossDomain(), cookie handling only: its before
 * hook reads `Better-Auth-Cookie`, its after hook moves the Set-Cookie
 * headers set so far to `Set-Better-Auth-Cookie`, and `onResponse` moves the
 * ones set later (by plugins listed after it, such as dbsc()).
 */
const crossDomainLike = (): BetterAuthPlugin => ({
  hooks: {
    after: [
      {
        handler: createAuthMiddleware(async (ctx) => {
          ctx.setHeader(CROSS_DOMAIN_RESPONSE_HEADER, "1");
          const setCookie = ctx.context.responseHeaders?.get("set-cookie");
          if (!setCookie) {
            return;
          }
          ctx.context.responseHeaders?.delete("set-cookie");
          ctx.setHeader("Set-Better-Auth-Cookie", setCookie);
          await Promise.resolve();
        }),
        matcher: carriesCrossDomainCookie,
      },
    ],
    before: [
      {
        handler: createAuthMiddleware(async (ctx) => {
          const headers = new Headers(ctx.headers);
          const carried = headers.get("better-auth-cookie") ?? "";
          for (const [name, value] of parseCookies(carried)) {
            setRequestCookie(headers, name, value);
          }
          await Promise.resolve();
          return { context: { headers } };
        }),
        matcher: carriesCrossDomainCookie,
      },
    ],
  },
  id: "cross-domain",
  onResponse: async (response) => {
    if (!response.headers.has(CROSS_DOMAIN_RESPONSE_HEADER)) {
      return;
    }
    const headers = new Headers(response.headers);
    headers.delete(CROSS_DOMAIN_RESPONSE_HEADER);
    const setCookie = headers.get("set-cookie");
    if (setCookie) {
      const moved = headers.get("set-better-auth-cookie");
      headers.delete("set-cookie");
      headers.set(
        "Set-Better-Auth-Cookie",
        moved ? `${moved}, ${setCookie}` : setCookie
      );
    }
    await Promise.resolve();
    return {
      response: new Response(response.body, {
        headers,
        status: response.status,
        statusText: response.statusText,
      }),
    };
  },
});

/**
 * A request from a cross-domain client: every cookie of `browser` goes in
 * `Better-Auth-Cookie`, and the cookies the response sets come back in
 * `Set-Better-Auth-Cookie`, which is applied to the jar (last one wins).
 */
const crossDomainFetch = async (
  browser: Browser,
  path: string,
  body?: unknown
) => {
  const response = await browser.fetch(path, {
    body,
    cookies: "",
    headers: { "Better-Auth-Cookie": browser.cookieHeader() },
  });
  const moved = splitSetCookieHeader(
    response.headers.get("set-better-auth-cookie") ?? ""
  ).map((entry) => {
    const name = entry.slice(0, entry.indexOf("=")).trim();
    const expired = /;\s*max-age=0\s*(?:;|$)/iu.test(entry);
    if (expired) {
      browser.cookies.delete(name);
    } else {
      browser.cookies.set(
        name,
        entry.slice(name.length + 1, entry.indexOf(";")).trim()
      );
    }
    return { expired, name };
  });
  return { moved, response };
};

/** Whether the last cookie of that name in `moved` expires it. */
const expiresIn = (moved: { expired: boolean; name: string }[], name: string) =>
  moved.findLast((cookie) => cookie.name === name)?.expired === true;

describe("with crossDomain()", () => {
  it("refuses a stolen token carried in Better-Auth-Cookie", async () => {
    const { register } = await setup({}, { plugins: [crossDomainLike()] });
    const { browser } = await register();
    const response = await browser.fetch("/get-session", {
      cookies: "",
      headers: { "Better-Auth-Cookie": sessionCookieOnly(browser) },
    });
    await expect(response.json()).resolves.toBeNull();
  });

  it("still serves unbound sessions through Better-Auth-Cookie", async () => {
    const { signIn } = await setup({}, { plugins: [crossDomainLike()] });
    const { browser } = await signIn();
    const response = await browser.fetch("/get-session", {
      cookies: "",
      headers: { "Better-Auth-Cookie": sessionCookieOnly(browser) },
    });
    await expect(response.json()).resolves.toMatchObject({
      user: expect.any(Object),
    });
  });

  it.each([
    ["/sign-out", false],
    ["/revoke-session", true],
    ["/revoke-sessions", false],
  ])(
    "%s expires the bound cookie in Set-Better-Auth-Cookie",
    async (path, withToken) => {
      const { register } = await setup({}, { plugins: [crossDomainLike()] });
      const { browser, instructions } = await register();
      const boundName = boundCookieName(instructions);
      const token = await sessionToken(browser);
      const { moved, response } = await crossDomainFetch(
        browser,
        path,
        withToken ? { token } : {}
      );
      expect(response.status).toBe(200);
      // Everything goes to the cross-domain client, nothing as Set-Cookie.
      expect(response.headers.getSetCookie()).toStrictEqual([]);
      expect(expiresIn(moved, SESSION_COOKIE)).toBeTruthy();
      expect(expiresIn(moved, boundName)).toBeTruthy();
      expect(browser.cookies.has(boundName)).toBeFalsy();
    }
  );

  it("revoke-sessions expires the unbound marker and does not hand it out again", async () => {
    const { signIn } = await setup({}, { plugins: [crossDomainLike()] });
    const { browser } = await signIn();
    pastRegistrationWindow();
    const { moved: issued } = await crossDomainFetch(browser, "/get-session");
    const markerName = issued.find((cookie) =>
      cookie.name.includes(UNBOUND_MARKER)
    )?.name;
    expect(markerName).toBeDefined();
    const { moved, response } = await crossDomainFetch(
      browser,
      "/revoke-sessions",
      {}
    );
    expect(response.status).toBe(200);
    expect(response.headers.getSetCookie()).toStrictEqual([]);
    const markerCookies = moved.filter((cookie) => cookie.name === markerName);
    expect(markerCookies).toStrictEqual([{ expired: true, name: markerName }]);
  });

  it("a session cookie expired after crossDomain() moved its new value still counts", async () => {
    // crossDomain() moves the new session cookie of the sign-in, then
    // twoFactor() (listed after it) expires it as a plain Set-Cookie, which
    // the client applies last.
    let otp = "";
    const { signIn, handler, instance } = await setup(
      {},
      {
        plugins: [
          crossDomainLike(),
          twoFactor({
            otpOptions: {
              sendOTP: ({ otp: code }) => {
                otp = code;
              },
            },
            skipVerificationOnEnable: true,
          }),
        ],
      }
    );
    const setupBrowser = new Browser(handler);
    await signIn({}, setupBrowser);
    const enabled = await setupBrowser.fetch("/two-factor/enable", {
      body: { password: instance.testUser.password },
    });
    expect(enabled.status).toBe(200);
    // A browser whose session passed 2FA and is bound.
    const browser = new Browser(handler);
    await browser.fetch("/sign-in/email", {
      body: {
        email: instance.testUser.email,
        password: instance.testUser.password,
      },
    });
    await browser.fetch("/two-factor/send-otp", { body: {} });
    const verified = await browser.fetch("/two-factor/verify-otp", {
      body: { code: otp },
    });
    const { instructions } = await completeRegistration(
      browser,
      verified,
      await createDeviceKey()
    );
    const boundName = boundCookieName(instructions);
    expect(browser.cookies.has(boundName)).toBeTruthy();
    pastRegistrationGrace();

    const { moved, response } = await crossDomainFetch(
      browser,
      "/sign-in/email",
      {
        email: instance.testUser.email,
        password: instance.testUser.password,
      }
    );
    await expect(response.json()).resolves.toMatchObject({
      twoFactorRedirect: true,
    });
    expect(expiresIn(moved, SESSION_COOKIE)).toBeTruthy();
    expect(expiresIn(moved, boundName)).toBeTruthy();
  });

  it("admin impersonation keeps the admin's bound cookie", async () => {
    const { register, instance, handler } = await setup(
      {},
      { plugins: [crossDomainLike(), admin()] }
    );
    const { browser, instructions } = await register();
    const context = await instance.auth.$context;
    const adminSession = await context.internalAdapter.findSession(
      await sessionToken(browser)
    );
    await context.internalAdapter.updateUser(adminSession?.user.id ?? "", {
      role: "admin",
    });
    const target = new Browser(handler);
    const signUp = await target.fetch("/sign-up/email", {
      body: {
        email: ["impersonated", "example.com"].join("@"),
        name: "impersonated",
        password: ["impersonated", "account", "password"].join("-"),
      },
    });
    const { user } = (await signUp.json()) as { user: { id: string } };
    const { moved, response } = await crossDomainFetch(
      browser,
      "/admin/impersonate-user",
      { userId: user.id }
    );
    expect(response.status).toBe(200);
    expect(expiresIn(moved, SESSION_COOKIE)).toBeFalsy();
    expect(
      moved.some((cookie) => cookie.name === boundCookieName(instructions))
    ).toBeFalsy();
  });

  it("multi-session revoke expires the revoked session's bound cookie", async () => {
    const { register } = await setup(
      {},
      { plugins: [crossDomainLike(), multiSession()] }
    );
    const first = await register();
    const { browser } = first;
    const signUp = await browser.fetch("/sign-up/email", {
      body: {
        email: ["second", "example.com"].join("@"),
        name: "Second",
        password: ["second", "account", "password"].join("-"),
      },
    });
    const second = await completeRegistration(
      browser,
      signUp,
      await createDeviceKey()
    );
    pastRegistrationGrace();
    const { moved, response } = await crossDomainFetch(
      browser,
      "/multi-session/revoke",
      { sessionToken: await sessionToken(browser) }
    );
    expect(response.status).toBe(200);
    expect(response.headers.getSetCookie()).toStrictEqual([]);
    expect(expiresIn(moved, boundCookieName(second.instructions))).toBeTruthy();
    expect(
      browser.cookies.has(boundCookieName(first.instructions))
    ).toBeTruthy();
  });
});

describe("with multiSession()", () => {
  it("binds each session separately and guards the multi-session cookies", async () => {
    const { register } = await setup({}, { plugins: [multiSession()] });
    const first = await register();
    const { browser } = first;
    // multiSession keeps one session per user, so add a second account.
    const signUp = await browser.fetch("/sign-up/email", {
      body: {
        email: ["second", "example.com"].join("@"),
        name: "Second",
        password: ["second", "account", "password"].join("-"),
      },
    });
    const second = await completeRegistration(
      browser,
      signUp,
      await createDeviceKey()
    );

    // One DBSC session, and one bound cookie, per Better Auth session.
    const names = [first, second].map(
      (bound) => bound.instructions.credentials[0]?.name
    );
    expect(new Set(names).size).toBe(2);

    const genuine = await browser.fetch("/multi-session/list-device-sessions");
    await expect(genuine.json()).resolves.toHaveLength(2);

    // A thief holding every session cookie but no bound cookie gets nothing.
    const stolen = [sessionCookieOnly(browser), multiCookies(browser)].join(
      "; "
    );
    const listed = await browser.fetch("/multi-session/list-device-sessions", {
      cookies: stolen,
    });
    await expect(listed.json()).resolves.toStrictEqual([]);

    const firstToken = decodeURIComponent(
      [...browser.cookies]
        .find(([name]) => name.includes("_multi-"))?.[1]
        ?.split(".")[0] ?? ""
    );
    const switched = await browser.fetch("/multi-session/set-active", {
      body: { sessionToken: firstToken },
      cookies: stolen,
    });
    expect(switched.status).toBe(401);
  });
});

describe("with multiSession(), when a session ends", () => {
  const SECOND_EMAIL = ["second", "example.com"].join("@");

  /** One browser with two bound accounts; the second one is active. */
  const twoBoundAccounts = async () => {
    const context = await setup({}, { plugins: [multiSession()] });
    const first = await context.register();
    const { browser } = first;
    const signUp = await browser.fetch("/sign-up/email", {
      body: {
        email: SECOND_EMAIL,
        name: "Second",
        password: ["second", "account", "password"].join("-"),
      },
    });
    const second = await completeRegistration(
      browser,
      signUp,
      await createDeviceKey()
    );
    const secondToken = await sessionToken(browser);
    const firstToken = [...browser.cookies]
      .filter(([name]) => name.includes("_multi-"))
      .map(([, value]) => decodeURIComponent(value).split(".")[0] ?? "")
      .find((token) => token !== secondToken);
    expect(firstToken).toBeDefined();
    pastRegistrationGrace();
    return {
      ...context,
      browser,
      firstBound: boundCookieName(first.instructions),
      firstToken: firstToken ?? "",
      secondBound: boundCookieName(second.instructions),
      secondToken,
    };
  };

  it("revoking the active session expires its bound cookie and keeps the other's", async () => {
    const { browser, firstBound, secondBound, secondToken, instance, events } =
      await twoBoundAccounts();
    const response = await browser.fetch("/multi-session/revoke", {
      body: { sessionToken: secondToken },
    });
    expect(response.status).toBe(200);
    expect(browser.cookies.has(secondBound)).toBeFalsy();
    expect(browser.cookies.has(firstBound)).toBeTruthy();
    // multiSession() switched to the first account, still bound: accepted.
    await expect(sessionUser(browser)).resolves.toMatchObject({
      email: instance.testUser.email,
    });
    expect(events.some((event) => event.type === "proof-missing")).toBeFalsy();
  });

  it("revoking another session expires its bound cookie and keeps the active one's", async () => {
    const { browser, firstBound, secondBound, firstToken } =
      await twoBoundAccounts();
    const response = await browser.fetch("/multi-session/revoke", {
      body: { sessionToken: firstToken },
    });
    expect(response.status).toBe(200);
    expect(browser.cookies.has(firstBound)).toBeFalsy();
    expect(browser.cookies.has(secondBound)).toBeTruthy();
    await expect(sessionUser(browser)).resolves.toMatchObject({
      email: SECOND_EMAIL,
    });
  });

  it("a failed revoke keeps every bound cookie", async () => {
    const { browser, firstBound, secondBound } = await twoBoundAccounts();
    const response = await browser.fetch("/multi-session/revoke", {
      body: { sessionToken: "not-a-session" },
    });
    expect(response.status).toBe(401);
    expect(browser.cookies.has(firstBound)).toBeTruthy();
    expect(browser.cookies.has(secondBound)).toBeTruthy();
  });

  it("switching to a session that is gone expires its bound cookie", async () => {
    const { browser, firstBound, secondBound, firstToken, instance } =
      await twoBoundAccounts();
    const context = await instance.auth.$context;
    await context.internalAdapter.deleteSession(firstToken);
    const response = await browser.fetch("/multi-session/set-active", {
      body: { sessionToken: firstToken },
    });
    expect(response.status).toBe(401);
    expect(browser.cookies.has(firstBound)).toBeFalsy();
    expect(browser.cookies.has(secondBound)).toBeTruthy();
  });

  it("sign-out expires every account's bound cookie", async () => {
    const { browser, firstBound, secondBound } = await twoBoundAccounts();
    const response = await browser.fetch("/sign-out", { body: {} });
    expect(response.status).toBe(200);
    expect(browser.cookies.has(firstBound)).toBeFalsy();
    expect(browser.cookies.has(secondBound)).toBeFalsy();
    expect(
      [...browser.cookies.keys()].some((name) => name.includes("_multi-"))
    ).toBeFalsy();
  });

  it("sign-out matches _multi- cookies the way multiSession() does", async () => {
    const { browser, firstBound, firstToken } = await twoBoundAccounts();
    // A `_multi-` cookie under another prefix (say, left from before
    // useSecureCookies changed): multiSession() still signs it out.
    const [ownName = "", value = ""] =
      [...browser.cookies].find(([name]) =>
        name.endsWith(`_multi-${firstToken.toLowerCase()}`)
      ) ?? [];
    browser.cookies.delete(ownName);
    browser.cookies.set(`legacy_multi-${firstToken.toLowerCase()}`, value);
    const response = await browser.fetch("/sign-out", { body: {} });
    expect(response.status).toBe(200);
    expect(browser.cookies.has(firstBound)).toBeFalsy();
  });

  it("switching accounts keeps both bound cookies", async () => {
    const { browser, firstBound, secondBound, firstToken, instance, events } =
      await twoBoundAccounts();
    const switched = await browser.fetch("/multi-session/set-active", {
      body: { sessionToken: firstToken },
    });
    expect(switched.status).toBe(200);
    expect(browser.cookies.has(firstBound)).toBeTruthy();
    expect(browser.cookies.has(secondBound)).toBeTruthy();
    await expect(sessionUser(browser)).resolves.toMatchObject({
      email: instance.testUser.email,
    });
    expect(events.some((event) => event.type === "proof-missing")).toBeFalsy();
  });

  it.each([
    ["its own", ""],
    ["another", "legacy"],
  ])(
    "signing in again to an account expires its old session's bound cookie (%s _multi- prefix)",
    async (_label, prefix) => {
      // multiSession() deletes the account's older sessions in its after
      // hook, which runs before dbsc()'s.
      const { browser, firstBound, firstToken, instance } =
        await twoBoundAccounts();
      if (prefix) {
        const [ownName = "", value = ""] =
          [...browser.cookies].find(([name]) =>
            name.endsWith(`_multi-${firstToken.toLowerCase()}`)
          ) ?? [];
        browser.cookies.delete(ownName);
        browser.cookies.set(
          `${prefix}_multi-${firstToken.toLowerCase()}`,
          value
        );
      }
      const response = await browser.fetch("/sign-in/email", {
        body: {
          email: instance.testUser.email,
          password: instance.testUser.password,
        },
      });
      expect(response.status).toBe(200);
      const context = await instance.auth.$context;
      await expect(
        context.internalAdapter.findSession(firstToken)
      ).resolves.toBeNull();
      expect(browser.cookies.has(firstBound)).toBeFalsy();
    }
  );
});

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

/* -------------------------------------------------------------------------- */
/* Audit fixes                                                                */
/* -------------------------------------------------------------------------- */

describe("robustness", () => {
  it("never rate limits the protocol endpoints (Chrome < 158 deletes on 429)", async () => {
    const { register } = await setup(
      {},
      { rateLimit: { enabled: true, max: 1, window: 60 } }
    );
    const { browser, instructions } = await register();
    const statuses = await Promise.all(
      Array.from({ length: 5 }, () =>
        refreshStatus(browser, instructions.session_identifier)
      )
    );
    expect(statuses).not.toContain(429);
    // The limiter itself is on: an ordinary endpoint does get limited.
    const listed = await Promise.all(
      Array.from({ length: 3 }, async () => {
        const response = await browser.fetch("/list-sessions");
        return response.status;
      })
    );
    expect(listed).toContain(429);
  });

  it("works when the app partitions its cookies", async () => {
    const { register } = await setup(
      {},
      {
        advanced: {
          defaultCookieAttributes: { partitioned: true, secure: true },
        },
      }
    );
    const { browser, instructions, startResponse } = await register();
    expect(startResponse.status).toBe(200);
    const issued = browser.setCookies.find(
      (cookie) => cookie.name === boundCookieName(instructions)
    );
    expect(issued?.attributes.join("; ")).not.toMatch(/partitioned/iu);
    await expect(sessionUser(browser)).resolves.toBeDefined();
  });

  it("lets requests already in flight through right after registration", async () => {
    const { signIn } = await setup();
    const { browser, response } = await signIn();
    await completeRegistration(browser, response, await createDeviceKey(), {
      keepGrace: true,
    });
    const stolen = sessionCookieOnly(browser);
    await expect(sessionUser(browser, stolen)).resolves.toBeDefined();
    pastRegistrationGrace();
    await expect(sessionUser(browser, stolen)).resolves.toBeUndefined();
  });

  it("tolerates a bound cookie that expired seconds ago, not minutes", async () => {
    const { register } = await setup();
    const { browser } = await register();
    vi.setSystemTime(Date.now() + 600_000 + 10_000);
    await expect(sessionUser(browser)).resolves.toBeDefined();
    vi.setSystemTime(Date.now() + 60_000);
    await expect(sessionUser(browser)).resolves.toBeUndefined();
  });

  it("does not offer registration when an endpoint re-issues an existing session", async () => {
    const { signIn } = await setup();
    const { browser } = await signIn();
    const updated = await browser.fetch("/update-user", {
      body: { name: "Renamed" },
    });
    expect(updated.status).toBe(200);
    expect(updated.headers.get(REGISTRATION)).toBeNull();
  });

  it("recognises a navigation forwarded by a Node fetch proxy", async () => {
    const { signIn } = await setup();
    // undici rewrites Sec-Fetch-Mode to "cors" but keeps Sec-Fetch-Dest.
    const { response } = await signIn({
      "sec-fetch-dest": "document",
      "sec-fetch-mode": "cors",
      "sec-fetch-site": "cross-site",
    });
    const offer = parseRegistrationHeader(response.headers.get(REGISTRATION));
    expect(offer.authorization).toMatch(/^t1\./u);
  });

  it("offers nothing to cross-site fetches (crossDomain() clients)", async () => {
    const { signIn } = await setup();
    const { response } = await signIn({
      "sec-fetch-dest": "empty",
      "sec-fetch-mode": "cors",
      "sec-fetch-site": "cross-site",
    });
    expect(response.headers.get(REGISTRATION)).toBeNull();
  });

  it("lets only one of two concurrent registrations win", async () => {
    const { signIn } = await setup();
    const { browser, response } = await signIn();
    const offer = parseRegistrationHeader(response.headers.get(REGISTRATION));
    const attempts = await Promise.all(
      [await createDeviceKey(), await createDeviceKey()].map(async (key) => {
        const attempt = await browser.fetch("/dbsc/start", {
          headers: {
            "Secure-Session-Response": await key.prove({
              jti: offer.challenge,
              mode: "registration",
            }),
          },
          method: "POST",
        });
        return attempt.status;
      })
    );
    expect(attempts.toSorted()).toStrictEqual([200, 400]);
  });
});

describe("challenge ordering", () => {
  it("accepts the proactive challenge even within the same millisecond", async () => {
    const { register } = await setup();
    const { browser, deviceKey, instructions } = await register();
    const sessionId = instructions.session_identifier;
    // Freeze the clock: every challenge below is minted at the same instant.
    vi.useFakeTimers({ now: Date.now(), toFake: ["Date"] });
    const first = await challengeFrom(refresh(browser, sessionId));
    const refreshed = await refresh(
      browser,
      sessionId,
      await deviceKey.prove({ jti: first, mode: "refresh" })
    );
    expect(refreshed.status).toBe(200);
    const next = parseChallengeHeader(
      refreshed.headers.get("Secure-Session-Challenge")
    );
    const again = await refresh(
      browser,
      sessionId,
      await deviceKey.prove({ jti: next.challenge, mode: "refresh" })
    );
    expect(again.status).toBe(200);
  });
});

describe("secret rotation", () => {
  it("keeps refreshing bindings made under a previous secret", async () => {
    const { register, instance } = await setup();
    const { browser, deviceKey, instructions } = await register();
    const context = await instance.auth.$context;
    const previous = context.secret;
    const next = "rotated-".repeat(6);
    context.secret = next;
    context.secretConfig = {
      currentVersion: 2,
      keys: new Map([
        [2, next],
        [1, previous],
      ]),
    };
    const sessionId = instructions.session_identifier;
    const challenge = await challengeFrom(refresh(browser, sessionId));
    const refreshed = await refresh(
      browser,
      sessionId,
      await deviceKey.prove({ jti: challenge, mode: "refresh" })
    );
    expect(refreshed.status).toBe(200);
  });

  it("fails closed when no accepted secret opens a binding", async () => {
    const { register, instance } = await setup();
    const { browser, instructions } = await register();
    const context = await instance.auth.$context;
    context.secret = "unrelated-".repeat(5);
    context.secretConfig = context.secret;
    await expect(
      refreshStatus(browser, instructions.session_identifier)
    ).resolves.toBe(401);
    const rows = await context.adapter.findMany({ model: "dbscSession" });
    expect(rows).toHaveLength(1);
  });
});

const crossSiteNavigation = (cookie: string) =>
  new Headers({
    cookie,
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "cross-site",
  });

describe("arrivals from other sites", () => {
  it("flags a cross-site navigation of a bound session without its cookie", async () => {
    const { register, signIn, instance } = await setup();
    const { browser } = await register();
    const { auth } = instance;
    await expect(
      dbscRefreshNeeded(auth, crossSiteNavigation(sessionCookieOnly(browser)))
    ).resolves.toBeTruthy();
    // With the bound cookie, same-origin, or unbound: nothing to do.
    await expect(
      dbscRefreshNeeded(auth, crossSiteNavigation(browser.cookieHeader()))
    ).resolves.toBeFalsy();
    const sameOrigin = crossSiteNavigation(sessionCookieOnly(browser));
    sameOrigin.set("sec-fetch-site", "same-origin");
    await expect(dbscRefreshNeeded(auth, sameOrigin)).resolves.toBeFalsy();
    const unbound = await signIn();
    await expect(
      dbscRefreshNeeded(
        auth,
        crossSiteNavigation(sessionCookieOnly(unbound.browser))
      )
    ).resolves.toBeFalsy();
  });

  it("answers the same question over HTTP for proxied deployments", async () => {
    const { register, events } = await setup();
    const { browser } = await register();
    const ask = async (cookies: string) => {
      const response = await browser.fetch("/dbsc/refresh-needed", {
        cookies,
        headers: {
          "sec-fetch-mode": "navigate",
          "sec-fetch-site": "cross-site",
        },
      });
      expect(response.headers.get("cache-control")).toContain("no-store");
      return response.json();
    };
    const before = events.length;
    await expect(ask(sessionCookieOnly(browser))).resolves.toStrictEqual({
      refreshNeeded: true,
    });
    await expect(ask(browser.cookieHeader())).resolves.toStrictEqual({
      refreshNeeded: false,
    });
    // Proxied with Node's fetch: Sec-Fetch-Mode arrives as "cors".
    const proxied = await browser.fetch("/dbsc/refresh-needed", {
      cookies: sessionCookieOnly(browser),
      headers: {
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site",
      },
    });
    await expect(proxied.json()).resolves.toStrictEqual({
      refreshNeeded: true,
    });
    // Asking is not an attempt to use the session: no proof-missing alert.
    expect(events.slice(before)).toStrictEqual([]);
  });

  it("answers with a page that reloads itself without script", async () => {
    const page = dbscRefreshPage();
    expect(page.headers.get("cache-control")).toBe("no-store");
    await expect(page.text()).resolves.toContain(
      '<meta http-equiv="refresh" content="0">'
    );
  });
});

describe("configuration", () => {
  it("must come after multiSession()", async () => {
    await expect(
      getTestInstance({ plugins: [dbsc(), multiSession()] })
    ).rejects.toThrow(/after multiSession\(\)/u);
  });

  it("must come after twoFactor()", async () => {
    await expect(
      getTestInstance({ plugins: [dbsc(), twoFactor()] })
    ).rejects.toThrow(/after twoFactor\(\)/u);
  });

  it("validates its options", () => {
    expect(() => dbsc({ algorithms: [] })).toThrow(/must not be empty/u);
    expect(() => dbsc({ cookieMaxAge: 10 })).toThrow(/cookieMaxAge/u);
    expect(() => dbsc({ cookieMaxAge: 299 })).toThrow(/cookieMaxAge/u);
    expect(() => dbsc({ challengeMaxAge: 650 })).toThrow(/challengeMaxAge/u);
    expect(() => dbsc({ scope: { origin: "https://example.com/" } })).toThrow(
      /bare origin/u
    );
    expect(() =>
      dbsc({ scope: { rules: [{ path: "static", type: "exclude" }] } })
    ).toThrow(/must start with/u);
    expect(() => dbsc({ allowedRefreshInitiators: ["a.*.com"] })).toThrow(
      /allowedRefreshInitiators/u
    );
    expect(() =>
      dbsc({
        allowedRefreshInitiators: ["*.example.com"],
        scope: { origin: "https://app.example.com" },
      })
    ).not.toThrow();
  });
});

/* -------------------------------------------------------------------------- */
/* Security audit regressions                                                 */
/* -------------------------------------------------------------------------- */

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;

/** Signs up another account in its own browser and binds its session. */
const registerAnotherAccount = async (
  handler: (request: Request) => Promise<Response>,
  label: string
) => {
  const browser = new Browser(handler);
  const signUp = await browser.fetch("/sign-up/email", {
    body: {
      email: [label, "example.com"].join("@"),
      name: label,
      password: [label, "account", "password"].join("-"),
    },
  });
  const { startResponse } = await completeRegistration(
    browser,
    signUp,
    await createDeviceKey()
  );
  expect(startResponse.status).toBe(200);
  return browser;
};

const findBindingRow = async (
  instance: Awaited<ReturnType<typeof setup>>["instance"],
  dbscSessionId: string
) => {
  const context = await instance.auth.$context;
  return context.adapter.findOne<{ expiresAt: Date; updatedAt: Date }>({
    model: "dbscSession",
    where: [{ field: "dbscSessionId", value: dbscSessionId }],
  });
};

/** A plugin whose before hook reads the session, like username() or anonymous(). */
const sessionReader = (seen: (string | null)[]): BetterAuthPlugin => ({
  hooks: {
    before: [
      {
        handler: createAuthMiddleware(async (ctx) => {
          const session = await getSessionFromCtx(ctx);
          seen.push(session?.user.id ?? null);
        }),
        matcher: () => true,
      },
    ],
  },
  id: "session-reader",
});

describe("cookie parsing matches Better Auth", () => {
  it("refuses a bound session's cookie sent as a quoted value", async () => {
    const { register } = await setup();
    const { browser } = await register();
    const value = browser.cookies.get(SESSION_COOKIE) ?? "";
    const quoted = `${SESSION_COOKIE}="${value}"`;

    await expect(sessionUser(browser, quoted)).resolves.toBeUndefined();
    const list = await browser.fetch("/list-sessions", { cookies: quoted });
    expect(list.status).toBe(401);
    // With the bound cookie a quoted value is still the owner's session.
    const bound = browser.cookieHeader((name) => name !== SESSION_COOKIE);
    await expect(
      sessionUser(browser, `${quoted}; ${bound}`)
    ).resolves.toBeDefined();
  });

  it("does not let a Better-Auth-Cookie value hide the Cookie header", async () => {
    const { register } = await setup();
    const { browser } = await register();
    const shadowed = {
      cookies: sessionCookieOnly(browser),
      headers: { "Better-Auth-Cookie": `${SESSION_COOKIE}=x` },
    };
    const { response } = await getSession(browser);
    expect(response.status).toBe(200);
    const stolen = await browser.fetch("/get-session", shadowed);
    await expect(stolen.json()).resolves.toBeNull();
    const list = await browser.fetch("/list-sessions", shadowed);
    expect(list.status).toBe(401);
  });
});

describe("bearer tokens on loosely matching databases", () => {
  it("refuses a case-swapped copy of a bound session's token", async () => {
    const { register, signIn, instance } = await setup(
      {},
      { plugins: [bearer()] }
    );
    const { browser } = await register();
    const token =
      decodeURIComponent(browser.cookies.get(SESSION_COOKIE) ?? "").split(
        "."
      )[0] ?? "";
    // What a case-insensitive collation (MySQL `_ci`, SQL Server) does.
    const context = await instance.auth.$context;
    const findSession = context.internalAdapter.findSession.bind(
      context.internalAdapter
    );
    const lookup = vi
      .spyOn(context.internalAdapter, "findSession")
      .mockImplementation(
        async (value) =>
          await findSession(
            value.toLowerCase() === token.toLowerCase() ? token : value
          )
      );
    const swapped = [...token]
      .map((char) =>
        char === char.toLowerCase() ? char.toUpperCase() : char.toLowerCase()
      )
      .join("");
    expect(swapped).not.toBe(token);

    const statuses = await Promise.all(
      [token, swapped].map(async (value) => {
        const response = await browser.fetch("/get-session", {
          cookies: "",
          headers: { Authorization: `Bearer ${value}` },
        });
        return response.status;
      })
    );
    expect(statuses).toStrictEqual([401, 401]);

    // Unbound sessions keep working as bearer tokens.
    const unbound = await signIn();
    const [unboundToken] = decodeURIComponent(
      unbound.browser.cookies.get(SESSION_COOKIE) ?? ""
    ).split(".");
    const allowed = await unbound.browser.fetch("/get-session", {
      cookies: "",
      headers: { Authorization: `Bearer ${unboundToken}` },
    });
    await expect(allowed.json()).resolves.toMatchObject({
      user: expect.any(Object),
    });
    lookup.mockRestore();
  });
});

describe("binding cleanup", () => {
  it("keeps the binding of a session extended after its last refresh", async () => {
    const { register, handler, instance } = await setup();
    const { browser, deviceKey, instructions } = await register();
    const sessionId = instructions.session_identifier;

    // Day 6: the device refreshes, then a page load extends the session.
    vi.setSystemTime(Date.now() + 6 * DAY_MS);
    const challenge = await challengeFrom(refresh(browser, sessionId));
    const refreshed = await refresh(
      browser,
      sessionId,
      await deviceKey.prove({ jti: challenge, mode: "refresh" })
    );
    expect(refreshed.status).toBe(200);
    await expect(sessionUser(browser)).resolves.toBeDefined();

    // Past the session's original expiry, still inside the extended one.
    vi.setSystemTime(Date.now() + DAY_MS + HOUR_MS);
    const stolen = sessionCookieOnly(browser);
    await expect(sessionUser(browser, stolen)).resolves.toBeUndefined();
    // Another account's registration runs the cleanup.
    await registerAnotherAccount(handler, "sweep-trigger");
    await expect(findBindingRow(instance, sessionId)).resolves.not.toBeNull();
    await expect(sessionUser(browser, stolen)).resolves.toBeUndefined();
  });

  it("keeps the stored expiry in step when Better Auth extends the session", async () => {
    const { register, instance } = await setup();
    const { browser, deviceKey, instructions } = await register();
    const sessionId = instructions.session_identifier;
    // Past updateAge: refresh, then a page load makes Better Auth extend.
    vi.setSystemTime(Date.now() + 2 * DAY_MS);
    const challenge = await challengeFrom(refresh(browser, sessionId));
    await refresh(
      browser,
      sessionId,
      await deviceKey.prove({ jti: challenge, mode: "refresh" })
    );
    const before = await findBindingRow(instance, sessionId);
    const { body } = await getSession(browser);
    const extended = (body as { session?: { expiresAt: string } } | null)
      ?.session?.expiresAt;
    const after = await findBindingRow(instance, sessionId);
    expect(new Date(after?.expiresAt ?? 0).getTime()).toBe(
      new Date(extended ?? 0).getTime()
    );
    expect(new Date(after?.expiresAt ?? 0).getTime()).toBeGreaterThan(
      new Date(before?.expiresAt ?? 0).getTime()
    );
  });

  it("keeps the stored expiry in step with sessions in secondary storage", async () => {
    const store = new Map<string, string>();
    const { register, instance } = await setup(
      {},
      {
        secondaryStorage: {
          delete: (key) => {
            store.delete(key);
          },
          get: (key) => store.get(key) ?? null,
          getAndDelete: (key) => {
            const value = store.get(key) ?? null;
            store.delete(key);
            return value;
          },
          increment: (key) => {
            const next = Number(store.get(key) ?? 0) + 1;
            store.set(key, String(next));
            return next;
          },
          set: (key, value) => {
            store.set(key, value);
          },
        },
      }
    );
    const { browser, deviceKey, instructions } = await register();
    const sessionId = instructions.session_identifier;
    vi.setSystemTime(Date.now() + 2 * DAY_MS);
    const challenge = await challengeFrom(refresh(browser, sessionId));
    await refresh(
      browser,
      sessionId,
      await deviceKey.prove({ jti: challenge, mode: "refresh" })
    );
    const { body } = await getSession(browser);
    const extended = (body as { session?: { expiresAt: string } } | null)
      ?.session?.expiresAt;
    const row = await findBindingRow(instance, sessionId);
    expect(extended).toBeDefined();
    expect(new Date(row?.expiresAt ?? 0).getTime()).toBe(
      new Date(extended ?? 0).getTime()
    );
  });

  it("still removes bindings whose session is long gone", async () => {
    const { register, handler, instance } = await setup();
    const { instructions } = await register();
    const sessionId = instructions.session_identifier;
    const context = await instance.auth.$context;
    const age = async (expiresAt: number, updatedAt: number) => {
      await context.adapter.update({
        model: "dbscSession",
        update: {
          expiresAt: new Date(expiresAt),
          updatedAt: new Date(updatedAt),
        },
        where: [{ field: "dbscSessionId", value: sessionId }],
      });
    };

    // A stale stored expiry alone does not prove the session dead.
    await age(Date.now() - DAY_MS, Date.now() - HOUR_MS);
    await registerAnotherAccount(handler, "sweep-first");
    await expect(findBindingRow(instance, sessionId)).resolves.not.toBeNull();

    // Untouched for longer than any session can last: swept.
    await age(Date.now() - DAY_MS, Date.now() - 8 * DAY_MS);
    await registerAnotherAccount(handler, "sweep-second");
    await expect(findBindingRow(instance, sessionId)).resolves.toBeNull();
  });
});

describe("with multiSession(), every cookie it reads", () => {
  it("is checked whatever its name, and on /sign-out", async () => {
    const { register, handler } = await setup(
      {},
      { plugins: [multiSession()] }
    );
    const { browser } = await register();
    const value = browser.cookies.get(SESSION_COOKIE) ?? "";

    const listed = await browser.fetch("/multi-session/list-device-sessions", {
      cookies: `x_multi-a=${value}`,
    });
    await expect(listed.json()).resolves.toStrictEqual([]);

    const thief = new Browser(handler);
    await thief.fetch("/sign-out", {
      body: {},
      cookies: `${SESSION_COOKIE}_multi-a=${value}`,
    });
    await expect(sessionUser(browser)).resolves.toBeDefined();
  });

  it("hands the endpoint the exact cookies it checked when it drops one", async () => {
    const { register, handler } = await setup(
      {},
      { plugins: [multiSession()] }
    );
    const { browser } = await register();
    const value = browser.cookies.get(SESSION_COOKIE) ?? "";
    const thief = new Browser(handler);
    // A doubly quoted copy reads as a foreign token; dropping the second
    // cookie must not rewrite it into the plain stolen value.
    const doublyQuoted = `${SESSION_COOKIE}=""${value}""`;
    await thief.fetch("/sign-out", {
      body: {},
      cookies: `${doublyQuoted}; x_multi-b=${value}`,
    });
    await expect(sessionUser(browser)).resolves.toBeDefined();

    const overLimit = Array.from(
      { length: 7 },
      (_, index) => `j${index}_multi-x=junk${index}.x`
    );
    const listed = await thief.fetch("/multi-session/list-device-sessions", {
      cookies: [`a_multi-a=""${value}""`, ...overLimit].join("; "),
    });
    await expect(listed.json()).resolves.toStrictEqual([]);
  });

  it("costs a bounded number of lookups however many cookies are sent", async () => {
    const { instance, handler } = await setup(
      {},
      { plugins: [multiSession()] }
    );
    const context = await instance.auth.$context;
    const findOne = vi.spyOn(context.adapter, "findOne");
    const bindingReads = () =>
      findOne.mock.calls.filter(([query]) => query.model === "dbscSession")
        .length;
    const browser = new Browser(handler);

    const forged = Array.from(
      { length: 50 },
      (_, index) => `${SESSION_COOKIE}_multi-${index}=t${index}.x`
    ).join("; ");
    await browser.fetch("/multi-session/list-device-sessions", {
      cookies: forged,
    });
    // multiSession() keeps at most 5 sessions: 6 checked, the rest dropped.
    expect(bindingReads()).toBe(6);

    findOne.mockClear();
    const repeated = Array.from(
      { length: 5 },
      (_, index) => `${SESSION_COOKIE}_multi-${index}=same.x`
    ).join("; ");
    await browser.fetch("/multi-session/list-device-sessions", {
      cookies: repeated,
    });
    expect(bindingReads()).toBe(1);
    findOne.mockRestore();
  });
});

describe("other plugins' hooks", () => {
  it("never see a refused session, even when they run after dbsc()", async () => {
    const seen: (string | null)[] = [];
    const { register } = await setup({}, {}, { after: [sessionReader(seen)] });
    const { browser } = await register();
    seen.length = 0;
    await expect(
      sessionUser(browser, sessionCookieOnly(browser))
    ).resolves.toBeUndefined();
    expect(seen).toStrictEqual([null]);
    await expect(sessionUser(browser)).resolves.toBeDefined();
    expect(seen.at(-1)).toStrictEqual(expect.any(String));
  });

  it("keeps username()'s /update-user hook from acting for a stolen cookie", async () => {
    const { register } = await setup({}, {}, { after: [username()] });
    const { browser } = await register();
    const stolen = await browser.fetch("/update-user", {
      body: { name: "renamed-by-thief", username: "thief_name" },
      cookies: sessionCookieOnly(browser),
    });
    expect(stolen.status).toBe(401);
    const genuine = await browser.fetch("/update-user", {
      body: { name: "Renamed", username: "owner_name" },
    });
    expect(genuine.status).toBe(200);
    await expect(sessionUser(browser)).resolves.toMatchObject({
      name: "Renamed",
    });
  });

  it("requires dbsc() before plugins that read the session in their hooks", async () => {
    await expect(
      getTestInstance({ plugins: [anonymous(), dbsc()] })
    ).rejects.toThrow(/before anonymous\(\)/u);
    await expect(
      getTestInstance({ plugins: [username(), dbsc()] })
    ).rejects.toThrow(/before username\(\)/u);
    await expect(
      getTestInstance({ plugins: [dbsc(), anonymous(), username()] })
    ).resolves.toBeDefined();
  });

  it("refuses a stolen cookie when crossDomain() rebuilds the request's cookies", async () => {
    // Like the real crossDomain(): rebuilds from the request as sent.
    const crossDomainFromRequest: BetterAuthPlugin = {
      hooks: {
        before: [
          {
            handler: createAuthMiddleware(async (ctx) => {
              const headers = new Headers(ctx.request?.headers);
              const carried = headers.get("better-auth-cookie") ?? "";
              for (const [name, value] of parseCookies(carried)) {
                setRequestCookie(headers, name, value);
              }
              await Promise.resolve();
              return { context: { headers } };
            }),
            matcher: (ctx) =>
              Boolean(ctx.request?.headers.has("better-auth-cookie")),
          },
        ],
      },
      id: "cross-domain",
    };
    const { register } = await setup({}, { plugins: [crossDomainFromRequest] });
    const { browser } = await register();
    const stolen = sessionCookieOnly(browser);
    const viaBoth = await browser.fetch("/get-session", {
      cookies: stolen,
      headers: { "Better-Auth-Cookie": "a=1" },
    });
    await expect(viaBoth.json()).resolves.toBeNull();
    const carriedOnly = await browser.fetch("/get-session", {
      cookies: "",
      headers: { "Better-Auth-Cookie": stolen },
    });
    await expect(carriedOnly.json()).resolves.toBeNull();
    const genuine = await browser.fetch("/get-session", {
      cookies: "",
      headers: { "Better-Auth-Cookie": browser.cookieHeader() },
    });
    await expect(genuine.json()).resolves.toMatchObject({
      user: expect.any(Object),
    });
  });

  it("requires dbsc() after crossDomain()", async () => {
    await expect(
      getTestInstance({ plugins: [dbsc(), { id: "cross-domain" }] })
    ).rejects.toThrow(/after crossDomain\(\)/u);
  });
});

const skippedTypes = (events: DbscEvent[]) =>
  events.filter((event) => event.type === "refresh-skipped");

describe("Secure-Session-Skipped reports", () => {
  it("reports a few distinct, well-formed ids per request", async () => {
    const { register, events } = await setup();
    const { browser, instructions } = await register();
    const id = instructions.session_identifier;
    events.length = 0;
    const flood = [
      ...Array.from(
        { length: 100 },
        () => `unreachable;session_identifier="${id}"`
      ),
      ...Array.from(
        { length: 20 },
        (_, index) => `server_error;session_identifier="forged-${index}"`
      ),
    ].join(", ");
    await browser.fetch("/get-session", {
      headers: { "Secure-Session-Skipped": flood },
    });
    expect(skippedTypes(events)).toStrictEqual([
      { dbscSessionId: id, reason: "unreachable", type: "refresh-skipped" },
    ]);

    events.length = 0;
    const distinct = Array.from(
      { length: 10 },
      (_, index) => `unreachable;session_identifier="${"A".repeat(21)}${index}"`
    ).join(", ");
    await browser.fetch("/get-session", {
      headers: { "Secure-Session-Skipped": distinct },
    });
    expect(skippedTypes(events)).toHaveLength(4);
  });

  it("ignores the header on the protocol endpoints the rate limiter skips", async () => {
    const { register, events } = await setup();
    const { browser, instructions } = await register();
    const id = instructions.session_identifier;
    events.length = 0;
    await Promise.all(
      ["/dbsc/refresh", "/dbsc/start"].map((path) =>
        browser.fetch(path, {
          cookies: "",
          headers: {
            "Secure-Session-Skipped": `unreachable;session_identifier="${id}"`,
          },
          method: "POST",
        })
      )
    );
    expect(skippedTypes(events)).toStrictEqual([]);
  });
});

describe("binding storage", () => {
  it("declares lastChallengeAt as bigint: epoch milliseconds overflow INTEGER", () => {
    const { fields } = createSchema().dbscSession;
    expect(fields.lastChallengeAt).toMatchObject({
      bigint: true,
      type: "number",
    });
    expect(Date.now()).toBeGreaterThan(2 ** 31);
  });

  it("logs an error when the binding table cannot store a row", async () => {
    const errors: string[] = [];
    const { signIn, instance } = await setup(
      {},
      {
        logger: {
          level: "error",
          log: (level, message) => {
            if (level === "error") {
              errors.push(message);
            }
          },
        },
      }
    );
    const context = await instance.auth.$context;
    const originalCreate = context.adapter.create.bind(context.adapter);
    // What Postgres does with a millisecond timestamp in an INTEGER column.
    const create = vi
      .spyOn(context.adapter, "create")
      .mockImplementation(async (query) => {
        if (query.model === "dbscSession") {
          throw new Error("value out of range for type integer");
        }
        return await originalCreate(query);
      });
    const { browser, response } = await signIn();
    const { startResponse } = await completeRegistration(
      browser,
      response,
      await createDeviceKey()
    );
    create.mockRestore();
    expect(startResponse.status).toBe(400);
    expect(errors.join("\n")).toMatch(/Could not store a binding/u);
  });

  it("never lets two interleaved registrations both bind a session", async () => {
    // A store without unique indexes. The first creator inserts and lists
    // alone, then the second inserts with an id that sorts first, which used
    // to let both keep their row.
    const bindingIds = ["zzzz-first", "aaaa-second"];
    const { signIn, instance } = await setup(
      {},
      {
        advanced: {
          database: {
            generateId: ({ model }) =>
              model === "dbscSession"
                ? (bindingIds.shift() ?? crypto.randomUUID())
                : crypto.randomUUID(),
          },
        },
        database: memoryAdapter({
          account: [],
          dbscSession: [],
          session: [],
          user: [],
          verification: [],
        }),
      }
    );
    const context = await instance.auth.$context;
    const { browser, response } = await signIn();
    const offer = parseRegistrationHeader(response.headers.get(REGISTRATION));

    const originalCreate = context.adapter.create.bind(context.adapter);
    const originalFindMany = context.adapter.findMany.bind(context.adapter);
    let creates = 0;
    let firstInserted = false;
    const firstListed = Promise.withResolvers<undefined>();
    const secondReady = Promise.withResolvers<undefined>();
    const create = vi
      .spyOn(context.adapter, "create")
      .mockImplementation(async (query) => {
        if (query.model !== "dbscSession") {
          return await originalCreate(query);
        }
        creates += 1;
        if (creates === 1) {
          await secondReady.promise;
          const row = await originalCreate(query);
          firstInserted = true;
          return row;
        }
        secondReady.resolve(undefined);
        await firstListed.promise;
        return await originalCreate(query);
      });
    const findMany = vi
      .spyOn(context.adapter, "findMany")
      .mockImplementation(async (query) => {
        const rows = await originalFindMany(query);
        if (query.model === "dbscSession" && firstInserted) {
          firstListed.resolve(undefined);
        }
        return rows;
      });

    const keys = [await createDeviceKey(), await createDeviceKey()];
    const timeout = Promise.withResolvers<never>();
    const guard = setTimeout(() => {
      timeout.reject(new Error("the interleaving never completed"));
    }, 5000);
    const attempts = Promise.all(
      keys.map(async (key) => {
        const attempt = await browser.fetch("/dbsc/start", {
          headers: {
            "Secure-Session-Response": await key.prove({
              jti: offer.challenge,
              mode: "registration",
            }),
          },
          method: "POST",
        });
        return attempt.status;
      })
    );
    const statuses = await Promise.race([attempts, timeout.promise]).finally(
      () => {
        clearTimeout(guard);
      }
    );
    create.mockRestore();
    findMany.mockRestore();

    const rows = await context.adapter.findMany({ model: "dbscSession" });
    expect(rows.length).toBeLessThanOrEqual(1);
    expect(statuses.filter((status) => status === 200)).toHaveLength(
      rows.length
    );
  });
});

/* -------------------------------------------------------------------------- */
/* Unbound marker                                                             */
/* -------------------------------------------------------------------------- */

const UNBOUND_MARKER = "better-auth.dbsc_unbound_";
const MINUTE_MS = 60_000;
/** Deferred offer (5 min 10 s) plus registration challenge (5 min). */
const REGISTRATION_WINDOW_MS = 10 * MINUTE_MS + 10_000;
/** Past the window and the wait before the first marker. */
const PAST_REGISTRATION_WINDOW_MS = REGISTRATION_WINDOW_MS + MINUTE_MS + 1000;
const ADAPTER_METHODS = [
  "count",
  "create",
  "findMany",
  "findOne",
  "update",
  "updateMany",
] as const;

const pastRegistrationWindow = () => {
  vi.setSystemTime(Date.now() + PAST_REGISTRATION_WINDOW_MS);
};

/** The marker cookie name of the session whose bound cookie is named here. */
const markerNameOf = (instructions: Instructions) =>
  boundCookieName(instructions).replace("better-auth.dbsc_", UNBOUND_MARKER);

const markerOf = (browser: Browser) =>
  [...browser.cookies].find(([name]) => name.startsWith(UNBOUND_MARKER));

const hasMarker = (browser: Browser) => markerOf(browser) !== undefined;

/** Counts the binding lookups made from here on. */
const countBindingReads = async (
  instance: Awaited<ReturnType<typeof setup>>["instance"]
) => {
  const context = await instance.auth.$context;
  const findOne = vi.spyOn(context.adapter, "findOne");
  return () =>
    findOne.mock.calls.filter(([query]) => query.model === DBSC_MODEL).length;
};

/** Makes the binding write return `delayMs` later. */
const slowBindingWrites = async (
  instance: Awaited<ReturnType<typeof setup>>["instance"],
  delayMs: number
) => {
  const context = await instance.auth.$context;
  const create = context.adapter.create.bind(context.adapter);
  return vi.spyOn(context.adapter, "create").mockImplementation((async (
    query: Parameters<typeof create>[0]
  ) => {
    const created = await create(query);
    if (query.model === DBSC_MODEL) {
      vi.setSystemTime(Date.now() + delayMs);
    }
    return created;
  }) as typeof create);
};

const countBindings = async (
  instance: Awaited<ReturnType<typeof setup>>["instance"]
) => {
  const context = await instance.auth.$context;
  return context.adapter.count({ model: DBSC_MODEL });
};

/** The session token in a signed session cookie value, unverified. */
const tokenIn = (value: string | undefined) =>
  decodeURIComponent(value ?? "").split(".")[0];

describe("unbound marker", () => {
  it("ends the lookups of a browser without DBSC once its session cannot register", async () => {
    const { signIn, instance } = await setup();
    const { browser } = await signIn();
    const bindingReads = await countBindingReads(instance);

    // While the session could still register, every request asks.
    await expect(sessionUser(browser)).resolves.toBeDefined();
    await expect(sessionUser(browser)).resolves.toBeDefined();
    expect(bindingReads()).toBe(2);
    expect(hasMarker(browser)).toBeFalsy();

    // Inside the wait that follows the window: still asking.
    vi.setSystemTime(Date.now() + REGISTRATION_WINDOW_MS + MINUTE_MS / 2);
    await expect(sessionUser(browser)).resolves.toBeDefined();
    expect(bindingReads()).toBe(3);
    expect(hasMarker(browser)).toBeFalsy();

    // Past it: one last lookup, which the marker then stands for.
    vi.setSystemTime(Date.now() + MINUTE_MS);
    await expect(sessionUser(browser)).resolves.toBeDefined();
    expect(bindingReads()).toBe(4);
    expect(hasMarker(browser)).toBeTruthy();
    await expect(sessionUser(browser)).resolves.toBeDefined();
    const list = await browser.fetch("/list-sessions");
    expect(list.status).toBe(200);
    expect(bindingReads()).toBe(4);

    // The marker lasts a day.
    vi.setSystemTime(Date.now() + 23 * 60 * MINUTE_MS);
    await expect(sessionUser(browser)).resolves.toBeDefined();
    expect(bindingReads()).toBe(4);
    vi.setSystemTime(Date.now() + 2 * 60 * MINUTE_MS);
    await expect(sessionUser(browser)).resolves.toBeDefined();
    await expect(sessionUser(browser)).resolves.toBeDefined();
    expect(bindingReads()).toBe(5);
  });

  it("is issued by endpoints behind sessionMiddleware and by server-side reads, without a second lookup", async () => {
    const { signIn, instance } = await setup();
    const { browser } = await signIn();
    const other = await signIn();
    pastRegistrationWindow();
    const bindingReads = await countBindingReads(instance);

    const list = await browser.fetch("/list-sessions");
    expect(list.status).toBe(200);
    expect(hasMarker(browser)).toBeTruthy();
    expect(bindingReads()).toBe(1);

    const { headers } = await instance.auth.api.getSession({
      headers: new Headers({ cookie: other.browser.cookieHeader() }),
      returnHeaders: true,
    });
    expect(headers.getSetCookie().join("\n")).toContain(UNBOUND_MARKER);
    expect(bindingReads()).toBe(2);
  });

  it("reads nothing for /get-session with the cookie cache on, bound or not", async () => {
    const { signIn, register, instance } = await setup(
      { cookieMaxAge: 1200 },
      { session: { cookieCache: { enabled: true, maxAge: 1200 } } }
    );
    const unbound = await signIn();
    const bound = await register();
    pastRegistrationWindow();
    await expect(sessionUser(unbound.browser)).resolves.toBeDefined();
    expect(hasMarker(unbound.browser)).toBeTruthy();

    const context = await instance.auth.$context;
    const spies = ADAPTER_METHODS.map((method) =>
      vi.spyOn(context.adapter, method)
    );
    await expect(sessionUser(unbound.browser)).resolves.toBeDefined();
    await expect(sessionUser(bound.browser)).resolves.toBeDefined();
    expect(spies.flatMap((spy) => spy.mock.calls)).toStrictEqual([]);
    // A bound cookie is not a lookup that found nothing: no marker for it.
    expect(hasMarker(bound.browser)).toBeFalsy();
  });

  it("does not exist while the session can still register, so a copy made before the registration stops working at once", async () => {
    const { signIn, handler } = await setup();
    const { browser, response } = await signIn();
    // The page's first requests race Chrome's registration.
    await expect(sessionUser(browser)).resolves.toBeDefined();
    const listed = await browser.fetch("/list-sessions");
    expect(listed.status).toBe(200);
    expect(hasMarker(browser)).toBeFalsy();
    const copied = browser.cookieHeader();

    await completeRegistration(browser, response, await createDeviceKey());
    const thief = new Browser(handler);
    await expect(sessionUser(thief, copied)).resolves.toBeUndefined();
    await expect(sessionUser(browser)).resolves.toBeDefined();
  });

  it("is never issued for a bound session, and only fits its own session", async () => {
    const { signIn, register, handler } = await setup();
    const { browser, instructions } = await register();
    const other = await signIn();
    pastRegistrationWindow();

    const stolen = sessionCookieOnly(browser);
    const thief = new Browser(handler);
    await thief.fetch("/get-session", { cookies: stolen });
    await thief.fetch("/list-sessions", { cookies: stolen });
    expect(hasMarker(thief)).toBeFalsy();
    expect(hasMarker(browser)).toBeFalsy();

    // Another session's marker, under its own name and under the name the
    // bound session's marker would have.
    await sessionUser(other.browser);
    const [otherName = "", otherValue = ""] = markerOf(other.browser) ?? [];
    expect(otherValue).not.toBe("");
    await expect(
      sessionUser(thief, `${stolen}; ${otherName}=${otherValue}`)
    ).resolves.toBeUndefined();
    await expect(
      sessionUser(
        thief,
        `${stolen}; ${markerNameOf(instructions)}=${otherValue}`
      )
    ).resolves.toBeUndefined();
  });

  it("does not stand in for the bound cookie, nor the bound cookie for it", async () => {
    const { signIn, register, instance } = await setup();
    const { browser, instructions } = await register();
    const boundValue = browser.cookies.get(boundCookieName(instructions));
    expect(boundValue).toBeDefined();
    await expect(
      sessionUser(
        browser,
        `${sessionCookieOnly(browser)}; ${markerNameOf(instructions)}=${boundValue}`
      )
    ).resolves.toBeUndefined();

    // A marker under the bound cookie's name proves nothing either: without
    // the real marker, the lookup happens again.
    const unbound = await signIn();
    pastRegistrationWindow();
    await sessionUser(unbound.browser);
    const [markerName = "", markerValue = ""] = markerOf(unbound.browser) ?? [];
    expect(markerValue).not.toBe("");
    const asBound = markerName.replace(UNBOUND_MARKER, "better-auth.dbsc_");
    const bindingReads = await countBindingReads(instance);
    await expect(
      sessionUser(
        unbound.browser,
        `${sessionCookieOnly(unbound.browser)}; ${asBound}=${markerValue}`
      )
    ).resolves.toBeDefined();
    expect(bindingReads()).toBe(1);
  });

  it("goes on sign-out", async () => {
    const { signIn } = await setup();
    const { browser } = await signIn();
    pastRegistrationWindow();
    await sessionUser(browser);
    expect(hasMarker(browser)).toBeTruthy();
    await browser.fetch("/sign-out", { body: {} });
    expect(hasMarker(browser)).toBeFalsy();
  });

  it("goes when every session is revoked, and is not handed out again", async () => {
    const { signIn } = await setup();
    const { browser } = await signIn();
    pastRegistrationWindow();
    await sessionUser(browser);
    expect(hasMarker(browser)).toBeTruthy();
    const setCookiesBefore = browser.setCookies.length;
    const response = await browser.fetch("/revoke-sessions", { body: {} });
    expect(response.status).toBe(200);
    expect(hasMarker(browser)).toBeFalsy();
    const markerCookies = browser.setCookies
      .slice(setCookiesBefore)
      .filter((cookie) => cookie.name.includes(UNBOUND_MARKER));
    expect(markerCookies).toHaveLength(1);
    expect(markerCookies[0]?.expired).toBeTruthy();
  });

  it("is not handed out by a response that ends the session", async () => {
    const { signIn } = await setup();
    const { browser } = await signIn();
    pastRegistrationWindow();
    // Without a marker, the request is looked up and found unbound, which
    // would earn it a marker, but the response ends its session.
    const setCookiesBefore = browser.setCookies.length;
    const response = await browser.fetch("/revoke-sessions", {
      body: {},
      cookies: sessionCookieOnly(browser),
    });
    expect(response.status).toBe(200);
    const markerCookies = browser.setCookies
      .slice(setCookiesBefore)
      .filter((cookie) => cookie.name.includes(UNBOUND_MARKER));
    expect(markerCookies.every((cookie) => cookie.expired)).toBeTruthy();
    expect(hasMarker(browser)).toBeFalsy();
  });

  it("is not handed out for a session the response replaces", async () => {
    const { signIn, instance } = await setup();
    const { browser } = await signIn();
    pastRegistrationWindow();
    const oldToken = await sessionToken(browser);
    const setCookiesBefore = browser.setCookies.length;
    // revokeOtherSessions deletes every session, this one included, and
    // signs the browser in to a new one.
    const response = await browser.fetch("/change-password", {
      body: {
        currentPassword: instance.testUser.password,
        newPassword: ["a", "new", "password"].join("-"),
        revokeOtherSessions: true,
      },
      cookies: sessionCookieOnly(browser),
    });
    expect(response.status).toBe(200);
    await expect(sessionToken(browser)).resolves.not.toBe(oldToken);
    const markersSet = browser.setCookies
      .slice(setCookiesBefore)
      .filter(
        (cookie) => cookie.name.includes(UNBOUND_MARKER) && !cookie.expired
      );
    expect(markersSet).toStrictEqual([]);
  });

  it("is still handed out when the response re-sets the same session", async () => {
    // A short updateAge makes /get-session refresh the session and set its
    // cookie again, with the same token.
    const { signIn } = await setup({}, { session: { updateAge: 60 } });
    const { browser } = await signIn();
    pastRegistrationWindow();
    const token = tokenIn(browser.cookies.get(SESSION_COOKIE));
    const setCookiesBefore = browser.setCookies.length;
    await sessionUser(browser);
    const sessionCookies = browser.setCookies
      .slice(setCookiesBefore)
      .filter((cookie) => cookie.name === SESSION_COOKIE);
    expect(sessionCookies.length).toBeGreaterThan(0);
    expect(sessionCookies.map((cookie) => tokenIn(cookie.value))).toStrictEqual(
      sessionCookies.map(() => token)
    );
    expect(hasMarker(browser)).toBeTruthy();
  });

  it("is not handed out on a lookup made while the session could still register", async () => {
    // A plugin after dbsc() that holds the request after dbsc()'s lookup.
    let holdMs = 0;
    const slowRequest: BetterAuthPlugin = {
      hooks: {
        before: [
          {
            handler: createAuthMiddleware(async () => {
              if (holdMs > 0) {
                vi.setSystemTime(Date.now() + holdMs);
                holdMs = 0;
              }
              await Promise.resolve();
            }),
            matcher: () => true,
          },
        ],
      },
      id: "slow-request",
    };
    const { signIn } = await setup({}, {}, { after: [slowRequest] });
    const { browser } = await signIn();
    // The lookup runs a second before markers are allowed; the response is
    // sent two minutes later.
    vi.setSystemTime(Date.now() + REGISTRATION_WINDOW_MS + MINUTE_MS - 1000);
    holdMs = 2 * MINUTE_MS;
    await expect(sessionUser(browser)).resolves.toBeDefined();
    expect(hasMarker(browser)).toBeFalsy();
    // The next lookup comes after the cutoff.
    await expect(sessionUser(browser)).resolves.toBeDefined();
    expect(hasMarker(browser)).toBeTruthy();
  });

  it("is not handed out on a cached lookup made while the session could still register", async () => {
    const { signIn, instance } = await setup();
    const { browser } = await signIn();
    const token = await sessionToken(browser);
    // The bearer check looks the binding up a second before markers are
    // allowed, then waits two minutes for the session; the cookie check
    // reuses that lookup.
    vi.setSystemTime(Date.now() + REGISTRATION_WINDOW_MS + MINUTE_MS - 1000);
    const context = await instance.auth.$context;
    const findSession = context.internalAdapter.findSession.bind(
      context.internalAdapter
    );
    let held = false;
    const slowSession = vi
      .spyOn(context.internalAdapter, "findSession")
      .mockImplementation((async (...args: Parameters<typeof findSession>) => {
        if (!held) {
          held = true;
          vi.setSystemTime(Date.now() + 2 * MINUTE_MS);
        }
        return await findSession(...args);
      }) as typeof findSession);
    const read = await browser.fetch("/get-session", {
      headers: { authorization: `Bearer ${token}` },
    });
    slowSession.mockRestore();
    expect(held).toBeTruthy();
    await expect(read.json()).resolves.toMatchObject({
      user: expect.any(Object),
    });
    expect(hasMarker(browser)).toBeFalsy();
    // A fresh lookup after the cutoff earns it.
    await expect(sessionUser(browser)).resolves.toBeDefined();
    expect(hasMarker(browser)).toBeTruthy();
  });

  it("a binding written after the registration deadline is rolled back", async () => {
    const { signIn, instance, events } = await setup();
    const { browser, response } = await signIn();
    const writes = await slowBindingWrites(
      instance,
      PAST_REGISTRATION_WINDOW_MS
    );
    const { startResponse } = await completeRegistration(
      browser,
      response,
      await createDeviceKey()
    );
    writes.mockRestore();
    expect(startResponse.status).toBe(400);
    await expect(countBindings(instance)).resolves.toBe(0);
    expect(
      events.some((event) => event.type === "session-registered")
    ).toBeFalsy();
    // The session stays, unbound, and can now get its marker.
    await expect(sessionUser(browser)).resolves.toBeDefined();
    expect(hasMarker(browser)).toBeTruthy();
  });

  it("a binding written just before the deadline stays", async () => {
    const { signIn, instance } = await setup();
    const { browser, response } = await signIn();
    // The commit deadline is the window plus half the margin.
    const writes = await slowBindingWrites(
      instance,
      REGISTRATION_WINDOW_MS + MINUTE_MS / 2 - 5000
    );
    const { startResponse } = await completeRegistration(
      browser,
      response,
      await createDeviceKey()
    );
    writes.mockRestore();
    expect(startResponse.status).toBe(200);
    await expect(countBindings(instance)).resolves.toBe(1);
  });

  it("a late binding that cannot be rolled back revokes its session", async () => {
    const { signIn, instance } = await setup();
    const { browser, response } = await signIn();
    const context = await instance.auth.$context;
    const deleteMany = context.adapter.deleteMany.bind(context.adapter);
    const failingRollback = vi
      .spyOn(context.adapter, "deleteMany")
      .mockImplementation(((query: Parameters<typeof deleteMany>[0]) => {
        if (
          query.model === DBSC_MODEL &&
          query.where.some((clause) => clause.field === "dbscSessionId")
        ) {
          return Promise.reject(new Error("database unavailable"));
        }
        return deleteMany(query);
      }) as typeof deleteMany);
    const writes = await slowBindingWrites(
      instance,
      PAST_REGISTRATION_WINDOW_MS
    );
    const { startResponse } = await completeRegistration(
      browser,
      response,
      await createDeviceKey()
    );
    writes.mockRestore();
    failingRollback.mockRestore();
    expect(startResponse.status).toBe(400);
    // Revoking the session also deleted its binding (session-delete hook).
    await expect(sessionUser(browser)).resolves.toBeUndefined();
    await expect(countBindings(instance)).resolves.toBe(0);
  });

  it("spares dbscRefreshNeeded the lookup", async () => {
    const { signIn, instance } = await setup();
    const { browser } = await signIn();
    pastRegistrationWindow();
    await sessionUser(browser);
    const bindingReads = await countBindingReads(instance);
    await expect(
      dbscRefreshNeeded(
        instance.auth,
        crossSiteNavigation(browser.cookieHeader())
      )
    ).resolves.toBeFalsy();
    expect(bindingReads()).toBe(0);
  });
});

/**
 * Registers with a challenge minted now, which no offer would give a session
 * this old: only the window check in `/dbsc/start` stands in the way.
 */
const startWithFreshChallenge = async (
  instance: Awaited<ReturnType<typeof setup>>["instance"],
  browser: Browser
) => {
  const { secret } = await instance.auth.$context;
  const signed = decodeURIComponent(browser.cookies.get(SESSION_COOKIE) ?? "");
  const token = signed.slice(0, signed.lastIndexOf("."));
  const deviceKey = await createDeviceKey();
  const proof = await deviceKey.prove({
    jti: createChallenge(deriveKeys(secret), "r", hashToken(token), Date.now())
      .value,
    mode: "registration",
  });
  return browser.fetch("/dbsc/start", {
    headers: { "Secure-Session-Response": proof },
    method: "POST",
  });
};

describe("registration window", () => {
  it("lets a registration challenge live 5 minutes, whatever challengeMaxAge is", async () => {
    const { signIn } = await setup({ challengeMaxAge: 3600 });
    const onTime = await signIn();
    vi.setSystemTime(Date.now() + 4 * MINUTE_MS);
    const registered = await completeRegistration(
      onTime.browser,
      onTime.response,
      await createDeviceKey()
    );
    expect(registered.startResponse.status).toBe(200);

    const late = await signIn();
    vi.setSystemTime(Date.now() + 5 * MINUTE_MS + 1000);
    const refused = await completeRegistration(
      late.browser,
      late.response,
      await createDeviceKey()
    );
    expect(refused.startResponse.status).toBe(400);
    expect(refused.instructions).toMatchObject({ code: "INVALID_CHALLENGE" });
  });

  it("never binds a session past the window, even with a fresh challenge", async () => {
    const { signIn, instance } = await setup();
    const inTime = await signIn();
    vi.setSystemTime(Date.now() + REGISTRATION_WINDOW_MS - 1000);
    const bound = await startWithFreshChallenge(instance, inTime.browser);
    expect(bound.status).toBe(200);

    const late = await signIn();
    vi.setSystemTime(Date.now() + REGISTRATION_WINDOW_MS + 1000);
    const refused = await startWithFreshChallenge(instance, late.browser);
    expect(refused.status).toBe(400);
    await expect(refused.json()).resolves.toMatchObject({
      code: "INVALID_CHALLENGE",
    });
    await expect(
      fetchJson(late.browser, "/dbsc/status")
    ).resolves.toMatchObject({ bound: false });
  });
});

describe("cookie cache lifetime", () => {
  it("warns when the cookie cache outlives the bound cookie", async () => {
    const warnings: string[] = [];
    const logger = {
      level: "warn" as const,
      log: (level: string, message: string) => {
        if (level === "warn") {
          warnings.push(message);
        }
      },
    };
    await getTestInstance({
      logger,
      plugins: [dbsc()],
      session: { cookieCache: { enabled: true, maxAge: 3600 } },
    });
    expect(warnings.join("\n")).toMatch(/cookieCache\.maxAge/u);
    warnings.length = 0;
    await getTestInstance({
      logger,
      plugins: [dbsc()],
      session: { cookieCache: { enabled: true, maxAge: 300 } },
    });
    expect(warnings.join("\n")).not.toMatch(/cookieCache\.maxAge/u);
  });
});
