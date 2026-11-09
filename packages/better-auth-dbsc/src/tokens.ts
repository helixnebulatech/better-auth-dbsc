import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

import {
  base64urlDecode,
  base64urlEncode,
  constantTimeEqualStrings,
  utf8Decode,
  utf8Encode,
} from "./crypto/encoding";
import { hmacSha256 } from "./crypto/keys";
import type { DerivedKeys } from "./crypto/keys";

const NONCE_BYTES = 16;
const XCHACHA_NONCE_BYTES = 24;
const SESSION_ID_BYTES = 16;
const COOKIE_NAME_TAG_LENGTH = 12;
const RADIX = 36;
const TIMESTAMP_PATTERN = /^[0-9a-z]{1,11}$/u;
const TOKEN_ENCRYPTION_VERSION = "v1";

const randomId = (bytes: number) => base64urlEncode(randomBytes(bytes));

const mac = (key: Uint8Array, message: string) =>
  base64urlEncode(hmacSha256(key, message));

const parseTimestamp = (value: string): number | null => {
  if (!TIMESTAMP_PATTERN.test(value)) {
    return null;
  }
  const parsed = Number.parseInt(value, RADIX);
  return Number.isSafeInteger(parsed) ? parsed : null;
};

/** Opaque, sf-string-safe DBSC `session_identifier`. */
export const createDbscSessionId = (): string => randomId(SESSION_ID_BYTES);

/* -------------------------------------------------------------------------- */
/* Challenges                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * `r` challenges are bound to a session token hash (registration), `f`
 * challenges to a DBSC session id (refresh). A challenge minted for one
 * subject or purpose never verifies for another.
 */
export type ChallengePurpose = "r" | "f";

/**
 * Stateless challenge: `purpose.issuedAt.nonce.mac`, with the MAC also
 * covering the subject. Nothing is stored until a proof is accepted, so
 * offering registration to browsers without DBSC costs no writes.
 */
export const createChallenge = (
  keys: DerivedKeys,
  purpose: ChallengePurpose,
  subject: string,
  now: number
): { value: string; issuedAt: number } => {
  const prefix = `${purpose}.${now.toString(RADIX)}.${randomId(NONCE_BYTES)}`;
  return {
    issuedAt: now,
    value: `${prefix}.${mac(keys.challenge, `${prefix}|${subject}`)}`,
  };
};

/** Returns the challenge's issue time (ms) if it is authentic and fresh. */
export const verifyChallenge = (
  keys: DerivedKeys,
  value: string,
  input: {
    purpose: ChallengePurpose;
    subject: string;
    maxAgeMs: number;
    now: number;
  }
): number | null => {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return null;
  }
  const [purpose = "", issuedAtText = "", nonce = "", signature = ""] = parts;
  const prefix = `${purpose}.${issuedAtText}.${nonce}`;
  const expected = mac(keys.challenge, `${prefix}|${input.subject}`);
  if (
    !constantTimeEqualStrings(signature, expected) ||
    purpose !== input.purpose
  ) {
    return null;
  }
  const issuedAt = parseTimestamp(issuedAtText);
  if (issuedAt === null) {
    return null;
  }
  // A small allowance for clock skew between servers.
  const skewMs = 5000;
  if (issuedAt > input.now + skewMs || input.now - issuedAt > input.maxAgeMs) {
    return null;
  }
  return issuedAt;
};

/* -------------------------------------------------------------------------- */
/* Bound cookie                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Per-session cookie name suffix, so each Better Auth session (multi-session)
 * gets its own DBSC credential. Derived from the token hash, so it can be
 * computed from the session cookie without a database read, and keyless, so
 * it survives a secret rotation (the browser keeps the name it was given).
 */
export const cookieNameTag = (tokenHash: string): string =>
  base64urlEncode(sha256(utf8Encode(`dbsc-cookie-name|${tokenHash}`))).slice(
    0,
    COOKIE_NAME_TAG_LENGTH
  );

/**
 * `expiresAt.nonce.mac`, MAC over the token hash. Rotates on every refresh
 * (fresh nonce and expiry) and verifies offline: any unexpired value is
 * accepted, which gives in-flight requests the previous-value grace period.
 */
export const createBoundCookieValue = (
  keys: DerivedKeys,
  tokenHash: string,
  expiresAt: number
): string => {
  const prefix = `${expiresAt.toString(RADIX)}.${randomId(NONCE_BYTES)}`;
  return `${prefix}.${mac(keys.cookie, `${prefix}|${tokenHash}`)}`;
};

export const verifyBoundCookieValue = (
  keys: DerivedKeys,
  value: string,
  tokenHash: string,
  now: number
): boolean => {
  const parts = value.split(".");
  if (parts.length !== 3) {
    return false;
  }
  const [expiresAtText = "", nonce = "", signature = ""] = parts;
  const prefix = `${expiresAtText}.${nonce}`;
  if (
    !constantTimeEqualStrings(
      signature,
      mac(keys.cookie, `${prefix}|${tokenHash}`)
    )
  ) {
    return false;
  }
  const expiresAt = parseTimestamp(expiresAtText);
  return expiresAt !== null && expiresAt > now;
};

/* -------------------------------------------------------------------------- */
/* Session token at rest                                                      */
/* -------------------------------------------------------------------------- */

/**
 * The refresh endpoint must not depend on the Better Auth cookie: it is
 * SameSite=Lax and is not sent when a cross-site navigation triggers the
 * refresh. The binding keeps the token encrypted (XChaCha20-Poly1305, AAD =
 * DBSC session id) so refresh can check the session in any storage mode.
 */
export const encryptSessionToken = (
  keys: DerivedKeys,
  token: string,
  dbscSessionId: string
): string => {
  const nonce = randomBytes(XCHACHA_NONCE_BYTES);
  const sealed = xchacha20poly1305(
    keys.tokenEncryption,
    nonce,
    utf8Encode(dbscSessionId)
  ).encrypt(utf8Encode(token));
  return `${TOKEN_ENCRYPTION_VERSION}.${base64urlEncode(nonce)}.${base64urlEncode(sealed)}`;
};

export const decryptSessionToken = (
  keys: DerivedKeys,
  value: string,
  dbscSessionId: string
): string | null => {
  const [version, nonceText, sealedText, extra] = value.split(".");
  if (
    version !== TOKEN_ENCRYPTION_VERSION ||
    !nonceText ||
    !sealedText ||
    extra
  ) {
    return null;
  }
  try {
    const nonce = base64urlDecode(nonceText);
    if (nonce.length !== XCHACHA_NONCE_BYTES) {
      return null;
    }
    return utf8Decode(
      xchacha20poly1305(
        keys.tokenEncryption,
        nonce,
        utf8Encode(dbscSessionId)
      ).decrypt(base64urlDecode(sealedText))
    );
  } catch {
    return null;
  }
};

/* -------------------------------------------------------------------------- */
/* Registration tickets                                                       */
/* -------------------------------------------------------------------------- */

const TICKET_VERSION = "t1";
const TICKET_AAD = "better-auth-dbsc/registration-ticket";

/**
 * The `authorization` value of a registration offered in a cross-site
 * response (an SSO/OAuth callback). The browser's registration POST then
 * carries no SameSite=Lax session cookie, so the ticket says which session
 * is registering: the session token sealed with XChaCha20-Poly1305 together
 * with its expiry. It reaches the server only inside the JWT signed by the
 * new device key.
 */
export const sealRegistrationTicket = (
  keys: DerivedKeys,
  token: string,
  expiresAt: number
): string => {
  const nonce = randomBytes(XCHACHA_NONCE_BYTES);
  const expiry = expiresAt.toString(RADIX);
  const sealed = xchacha20poly1305(
    keys.ticket,
    nonce,
    utf8Encode(`${TICKET_AAD}|${expiry}`)
  ).encrypt(utf8Encode(token));
  return `${TICKET_VERSION}.${expiry}.${base64urlEncode(nonce)}.${base64urlEncode(sealed)}`;
};

/** The session token inside an authentic, unexpired ticket, or null. */
export const openRegistrationTicket = (
  keys: DerivedKeys,
  ticket: string,
  now: number
): string | null => {
  const [version, expiry = "", nonceText, sealedText, extra] =
    ticket.split(".");
  if (version !== TICKET_VERSION || !nonceText || !sealedText || extra) {
    return null;
  }
  const expiresAt = parseTimestamp(expiry);
  if (expiresAt === null || expiresAt <= now) {
    return null;
  }
  try {
    const nonce = base64urlDecode(nonceText);
    if (nonce.length !== XCHACHA_NONCE_BYTES) {
      return null;
    }
    return utf8Decode(
      xchacha20poly1305(
        keys.ticket,
        nonce,
        utf8Encode(`${TICKET_AAD}|${expiry}`)
      ).decrypt(base64urlDecode(sealedText))
    );
  } catch {
    return null;
  }
};
