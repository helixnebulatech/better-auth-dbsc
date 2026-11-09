import type { ResolvedDbscOptions } from "../options";

/** The subset of cookie attributes DBSC compares (ED §8.6). */
export interface BoundCookieAttributes {
  domain: string | undefined;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: "Strict" | "Lax" | "None";
}

export interface BoundCookie {
  name: string;
  attributes: BoundCookieAttributes;
}

const SAME_SITE_VALUES = {
  lax: "Lax",
  none: "None",
  strict: "Strict",
} as const;

export const normalizeSameSite = (
  value: unknown
): BoundCookieAttributes["sameSite"] => {
  if (typeof value === "string") {
    const normalized =
      SAME_SITE_VALUES[value.toLowerCase() as keyof typeof SAME_SITE_VALUES];
    if (normalized) {
      return normalized;
    }
  }
  return "Lax";
};

/**
 * `credentials[].attributes`. Chrome only accepts Domain, Path, Secure,
 * HttpOnly and SameSite here (Max-Age is rejected), and they must match the
 * Set-Cookie exactly or the browser treats the cookie as always missing.
 */
export const serializeCredentialAttributes = (
  attributes: BoundCookieAttributes
): string =>
  [
    attributes.domain ? `Domain=${attributes.domain}` : undefined,
    `Path=${attributes.path}`,
    attributes.secure ? "Secure" : undefined,
    attributes.httpOnly ? "HttpOnly" : undefined,
    `SameSite=${attributes.sameSite}`,
  ]
    .filter(Boolean)
    .join("; ");

export const serializeSetCookie = (
  cookie: BoundCookie,
  value: string,
  maxAgeSeconds: number
): string =>
  `${cookie.name}=${value}; Max-Age=${maxAgeSeconds}; ${serializeCredentialAttributes(cookie.attributes)}`;

/** Session instructions JSON (ED §9.6). */
export const buildSessionInstructions = (input: {
  sessionId: string;
  refreshUrl: string;
  cookie: BoundCookie;
  options: ResolvedDbscOptions;
}) => {
  const { scope, allowedRefreshInitiators } = input.options;
  return {
    credentials: [
      {
        attributes: serializeCredentialAttributes(input.cookie.attributes),
        name: input.cookie.name,
        type: "cookie" as const,
      },
    ],
    refresh_url: input.refreshUrl,
    scope: {
      include_site: scope.includeSite,
      ...(scope.origin ? { origin: scope.origin } : {}),
      ...(scope.rules?.length
        ? {
            scope_specification: scope.rules.map((rule) => ({
              domain: rule.domain ?? "*",
              path: rule.path ?? "/",
              type: rule.type,
            })),
          }
        : {}),
    },
    session_identifier: input.sessionId,
    ...(allowedRefreshInitiators?.length
      ? { allowed_refresh_initiators: [...allowedRefreshInitiators] }
      : {}),
  };
};
