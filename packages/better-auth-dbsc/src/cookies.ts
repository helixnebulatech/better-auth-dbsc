const DOUBLE_QUOTE = 34;

/**
 * Splits a `Cookie` request header into name → the pair's original text
 * (`name=value`, trimmed), first wins. Rebuild headers from this text, never
 * from parsed values: unquoting changes a value, so re-serializing it would
 * hand the endpoint a different cookie than the one that was checked.
 */
export const parseCookiePairs = (
  header: string | null | undefined
): Map<string, string> => {
  const pairs = new Map<string, string>();
  if (!header) {
    return pairs;
  }
  for (const pair of header.split(";")) {
    const separator = pair.indexOf("=");
    if (separator <= 0) {
      continue;
    }
    const name = pair.slice(0, separator).trim();
    if (name && !pairs.has(name)) {
      pairs.set(name, `${name}=${pair.slice(separator + 1).trim()}`);
    }
  }
  return pairs;
};

/**
 * Parses a `Cookie` request header into name → value (first wins), the way
 * better-call does for `getSignedCookie`: a value starting with a double
 * quote loses its first and last character. The value is not decoded.
 *
 * Any difference from Better Auth's own parsing would let a stolen cookie be
 * read one way here and another way by the endpoint, so keep them identical.
 */
export const parseCookieHeader = (
  header: string | null | undefined
): Map<string, string> => {
  const cookies = new Map<string, string>();
  for (const [name, pair] of parseCookiePairs(header)) {
    let value = pair.slice(name.length + 1);
    if (value.codePointAt(0) === DOUBLE_QUOTE) {
      value = value.slice(1, -1);
    }
    cookies.set(name, value);
  }
  return cookies;
};

/**
 * The session token inside a Better Auth signed cookie value
 * (`encodeURIComponent(token + "." + signature)`), unverified.
 */
export const readSignedCookieToken = (
  value: string | undefined
): string | null => {
  if (!value) {
    return null;
  }
  let decoded = value;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    // Keep the raw value.
  }
  const separator = decoded.lastIndexOf(".");
  return separator > 0 ? decoded.slice(0, separator) : null;
};

const BEARER_PREFIX = "bearer ";

/**
 * The raw session token from `Authorization: Bearer <token>[.signature]`,
 * as the bearer plugin would accept it.
 */
export const readBearerToken = (headers: Headers): string | null => {
  const header = headers.get("authorization");
  if (
    !header ||
    header.slice(0, BEARER_PREFIX.length).toLowerCase() !== BEARER_PREFIX
  ) {
    return null;
  }
  let value = header.slice(BEARER_PREFIX.length).trim();
  if (value.includes("%")) {
    try {
      value = decodeURIComponent(value);
    } catch {
      // Keep the raw value: the bearer plugin does the same.
    }
  }
  const [token] = value.split(".");
  return token || null;
};
