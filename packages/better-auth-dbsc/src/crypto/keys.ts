import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { base64urlEncode, utf8Encode } from "./encoding";

const KEY_LENGTH = 32;
const HKDF_SALT = utf8Encode("better-auth-dbsc");

/**
 * Independent keys derived from the Better Auth secret, one per purpose, so a
 * value minted for one job (a challenge) can never verify as another (a
 * cookie).
 */
export interface DerivedKeys {
  /** HMAC key for the short-lived bound cookie. */
  readonly cookie: Uint8Array;
  /** HMAC key for registration and refresh challenges. */
  readonly challenge: Uint8Array;
  /** XChaCha20-Poly1305 key for the session token stored with a binding. */
  readonly tokenEncryption: Uint8Array;
  /** XChaCha20-Poly1305 key for registration tickets (`authorization`). */
  readonly ticket: Uint8Array;
}

const derive = (secret: Uint8Array, purpose: string): Uint8Array =>
  hkdf(sha256, secret, HKDF_SALT, utf8Encode(`v1/${purpose}`), KEY_LENGTH);

const cache = new Map<string, DerivedKeys>();
const MAX_CACHED_SECRETS = 8;

export const deriveKeys = (secret: string): DerivedKeys => {
  const cached = cache.get(secret);
  if (cached) {
    return cached;
  }
  const ikm = utf8Encode(secret);
  const keys: DerivedKeys = {
    challenge: derive(ikm, "challenge"),
    cookie: derive(ikm, "cookie"),
    ticket: derive(ikm, "registration-ticket"),
    tokenEncryption: derive(ikm, "token-encryption"),
  };
  if (cache.size >= MAX_CACHED_SECRETS) {
    cache.clear();
  }
  cache.set(secret, keys);
  return keys;
};

export const hmacSha256 = (key: Uint8Array, message: string): Uint8Array =>
  hmac(sha256, key, utf8Encode(message));

/** base64url(SHA-256(value)): how session tokens are referenced at rest. */
export const hashToken = (token: string): string =>
  base64urlEncode(sha256(utf8Encode(token)));

/**
 * Keys for the current secret (to sign and seal) and for every secret Better
 * Auth still accepts (to verify and open), so rotating `secrets` does not
 * break bindings made before the rotation.
 */
export interface Keyring {
  readonly current: DerivedKeys;
  readonly all: readonly DerivedKeys[];
}

export const buildKeyring = (
  current: string,
  accepted: Iterable<string>
): Keyring => {
  const secrets = [...new Set([current, ...accepted])].filter(Boolean);
  return { all: secrets.map(deriveKeys), current: deriveKeys(current) };
};
