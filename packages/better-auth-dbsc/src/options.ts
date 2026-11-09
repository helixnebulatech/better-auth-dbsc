import type { InferOptionSchema } from "better-auth/plugins";

import type { DbscAlgorithm } from "./crypto/jwk";
import type { SkippedReason } from "./protocol/headers";
import type { DbscSchema } from "./schema";

/** One rule of `scope.scope_specification` (ED §9.8). */
export interface DbscScopeRule {
  type: "include" | "exclude";
  /** Host pattern, e.g. `*.example.com`. Defaults to `*`. */
  domain?: string;
  /** Path prefix. Defaults to `/`. */
  path?: string;
}

export type DbscEvent =
  | {
      type: "session-registered";
      userId: string;
      sessionId: string;
      dbscSessionId: string;
    }
  | {
      type: "session-refreshed";
      userId: string;
      sessionId: string;
      dbscSessionId: string;
    }
  | {
      /** A proof whose signature failed against the stored key. */
      type: "proof-invalid";
      userId: string;
      sessionId: string;
      dbscSessionId: string;
    }
  | {
      /**
       * A bound session was used without a valid device proof: a stolen
       * cookie, or a browser whose refresh failed. The session cookie was
       * ignored for that request.
       */
      type: "proof-missing";
      userId: string | undefined;
      sessionId: string | undefined;
      path: string | undefined;
    }
  | { type: "refresh-skipped"; reason: SkippedReason; dbscSessionId: string };

export interface DbscOptions {
  /**
   * Signature algorithms offered to the browser, in order of preference.
   * RS256 covers TPMs without ECC support and needs Web Crypto.
   * @default ["ES256", "RS256"]
   */
  algorithms?: DbscAlgorithm[];
  /**
   * Lifetime of the short-lived bound cookie, in seconds. Chrome refreshes
   * it when less than 120 s are left, so values below 300 cause a refresh on
   * almost every request.
   * @default 600
   */
  cookieMaxAge?: number;
  /**
   * How long a challenge stays valid, in seconds. Must outlive the cookie:
   * the browser keeps the challenge from one refresh until the next.
   * @default cookieMaxAge + 300
   */
  challengeMaxAge?: number;
  /**
   * When a sign-in response cannot carry the registration offer (cross-site
   * SSO/OAuth callbacks, sign-ins made server-side with `auth.api`), offer it
   * once from the first same-site `/get-session` instead. Each session is
   * offered registration exactly once either way.
   * @default true
   */
  registerOnGetSession?: boolean;
  /** Session scope sent to the browser (ED §9.7). */
  scope?: {
    /** Scope origin. Defaults to the origin that serves the instructions. */
    origin?: string;
    /**
     * Cover the whole site instead of one origin. The origin host must then
     * be the registrable domain.
     * @default false
     */
    includeSite?: boolean;
    /** Include/exclude rules, most general first. */
    rules?: DbscScopeRule[];
  };
  /** Out-of-scope initiators allowed to trigger a refresh (ED §9.6). */
  allowedRefreshInitiators?: string[];
  /**
   * Called for security-relevant events. Errors are logged and swallowed.
   */
  onEvent?: (event: DbscEvent) => void | Promise<void>;
  /** Rename the table or its fields. */
  schema?: InferOptionSchema<DbscSchema>;
}

export interface ResolvedDbscOptions {
  algorithms: readonly DbscAlgorithm[];
  cookieMaxAgeMs: number;
  challengeMaxAgeMs: number;
  registerOnGetSession: boolean;
  scope: Required<Pick<NonNullable<DbscOptions["scope"]>, "includeSite">> &
    Omit<NonNullable<DbscOptions["scope"]>, "includeSite">;
  allowedRefreshInitiators: readonly string[] | undefined;
  onEvent: DbscOptions["onEvent"];
}

const DEFAULT_COOKIE_MAX_AGE_SECONDS = 600;
const CHALLENGE_EXTRA_SECONDS = 300;
/**
 * Chrome signs at most 6 proofs per 9 minutes per site and refreshes when
 * less than 120 s are left; shorter cookies exhaust that quota, and a
 * skipped refresh reads as signed out.
 */
const MIN_COOKIE_MAX_AGE_SECONDS = 300;
/** The browser keeps the challenge of one refresh until the next one. */
const MIN_CHALLENGE_EXTRA_SECONDS = 120;
/** `*`, `*.example.com` or `example.com` (Chrome's host patterns). */
const HOST_PATTERN = /^(?:\*|(?:\*\.)?(?:[a-z0-9-]+\.)*[a-z0-9-]+)$/iu;

const assertHostPattern = (pattern: string, label: string) => {
  if (!HOST_PATTERN.test(pattern)) {
    throw new Error(
      `[dbsc] ${label} "${pattern}" must be "*", "*.example.com" or "example.com"`
    );
  }
};

/** Chrome rejects (and on refresh deletes) sessions with malformed scopes. */
const validateScope = (
  scope: DbscOptions["scope"],
  initiators: readonly string[] | undefined
) => {
  if (scope?.origin !== undefined) {
    let parsed: URL;
    try {
      parsed = new URL(scope.origin);
    } catch {
      throw new Error(`[dbsc] scope.origin "${scope.origin}" is not a URL`);
    }
    if (parsed.origin !== scope.origin) {
      throw new Error(
        `[dbsc] scope.origin must be a bare origin such as "${parsed.origin}" (no path or trailing slash)`
      );
    }
  }
  for (const rule of scope?.rules ?? []) {
    if (rule.type !== "include" && rule.type !== "exclude") {
      throw new Error(
        '[dbsc] scope rules must have type "include" or "exclude"'
      );
    }
    if (rule.domain !== undefined) {
      assertHostPattern(rule.domain, "scope rule domain");
    }
    if (rule.path !== undefined && !rule.path.startsWith("/")) {
      throw new Error(
        `[dbsc] scope rule path "${rule.path}" must start with "/"`
      );
    }
  }
  for (const initiator of initiators ?? []) {
    assertHostPattern(initiator, "allowedRefreshInitiators entry");
  }
};
const MAX_COOKIE_MAX_AGE_SECONDS = 86_400;
const MS_PER_SECOND = 1000;

export const resolveOptions = (
  options: DbscOptions = {}
): ResolvedDbscOptions => {
  const algorithms = options.algorithms ?? ["ES256", "RS256"];
  if (algorithms.length === 0) {
    throw new Error("[dbsc] `algorithms` must not be empty");
  }
  for (const algorithm of algorithms) {
    if (algorithm !== "ES256" && algorithm !== "RS256") {
      throw new Error(`[dbsc] Unsupported algorithm "${String(algorithm)}"`);
    }
  }
  const cookieMaxAge = options.cookieMaxAge ?? DEFAULT_COOKIE_MAX_AGE_SECONDS;
  if (
    !Number.isInteger(cookieMaxAge) ||
    cookieMaxAge < MIN_COOKIE_MAX_AGE_SECONDS ||
    cookieMaxAge > MAX_COOKIE_MAX_AGE_SECONDS
  ) {
    throw new Error(
      `[dbsc] cookieMaxAge must be an integer between ${MIN_COOKIE_MAX_AGE_SECONDS} and ${MAX_COOKIE_MAX_AGE_SECONDS}`
    );
  }
  const challengeMaxAge =
    options.challengeMaxAge ?? cookieMaxAge + CHALLENGE_EXTRA_SECONDS;
  if (
    !Number.isInteger(challengeMaxAge) ||
    challengeMaxAge < cookieMaxAge + MIN_CHALLENGE_EXTRA_SECONDS
  ) {
    throw new Error(
      `[dbsc] challengeMaxAge must be an integer of at least cookieMaxAge + ${MIN_CHALLENGE_EXTRA_SECONDS}`
    );
  }
  validateScope(options.scope, options.allowedRefreshInitiators);
  return {
    algorithms: [...new Set(algorithms)],
    allowedRefreshInitiators: options.allowedRefreshInitiators,
    challengeMaxAgeMs: challengeMaxAge * MS_PER_SECOND,
    cookieMaxAgeMs: cookieMaxAge * MS_PER_SECOND,
    onEvent: options.onEvent,
    registerOnGetSession: options.registerOnGetSession ?? true,
    scope: {
      ...options.scope,
      includeSite: options.scope?.includeSite ?? false,
    },
  };
};
