import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { base64urlDecode, base64urlEncode, utf8Encode } from "./encoding";

export type DbscAlgorithm = "ES256" | "RS256";

export const SUPPORTED_ALGORITHMS: readonly DbscAlgorithm[] = [
  "ES256",
  "RS256",
];

/** Minimal public JWK: exactly the RFC 7638 required members. */
export type PublicJwk =
  | {
      readonly kty: "EC";
      readonly crv: "P-256";
      readonly x: string;
      readonly y: string;
    }
  | { readonly kty: "RSA"; readonly n: string; readonly e: string };

const P256_COORDINATE_BYTES = 32;
const P256_SIGNATURE_BYTES = 64;
const UNCOMPRESSED_POINT_PREFIX = 0x04;
const MIN_RSA_MODULUS_BYTES = 256;
const MAX_RSA_MODULUS_BYTES = 512;
const MAX_RSA_EXPONENT_BYTES = 8;

/** Members that would make the JWK a private key. */
const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

export class InvalidKeyError extends Error {
  override name = "InvalidKeyError";
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const decodeMember = (jwk: Record<string, unknown>, member: string) => {
  const value = jwk[member];
  if (typeof value !== "string" || value.length === 0) {
    throw new InvalidKeyError(`JWK member "${member}" is missing`);
  }
  try {
    return base64urlDecode(value);
  } catch {
    throw new InvalidKeyError(`JWK member "${member}" is not base64url`);
  }
};

const ecPoint = (jwk: { x: string; y: string }): Uint8Array => {
  const x = base64urlDecode(jwk.x);
  const y = base64urlDecode(jwk.y);
  const point = new Uint8Array(1 + P256_COORDINATE_BYTES * 2);
  point[0] = UNCOMPRESSED_POINT_PREFIX;
  point.set(x, 1);
  point.set(y, 1 + P256_COORDINATE_BYTES);
  return point;
};

/**
 * Validates an untrusted JWK for `alg` and returns its minimal public form.
 * Rejects private keys, wrong key types, off-curve points and weak RSA.
 */
export const parsePublicJwk = (
  value: unknown,
  algorithm: DbscAlgorithm
): PublicJwk => {
  if (!isRecord(value)) {
    throw new InvalidKeyError("JWK must be an object");
  }
  for (const member of PRIVATE_MEMBERS) {
    if (member in value) {
      throw new InvalidKeyError("JWK must not contain private key members");
    }
  }
  if (value.alg !== undefined && value.alg !== algorithm) {
    throw new InvalidKeyError("JWK alg does not match the JWT alg");
  }
  if (value.use !== undefined && value.use !== "sig") {
    throw new InvalidKeyError('JWK use must be "sig"');
  }

  if (algorithm === "ES256") {
    if (value.kty !== "EC" || value.crv !== "P-256") {
      throw new InvalidKeyError("ES256 requires an EC P-256 key");
    }
    const x = decodeMember(value, "x");
    const y = decodeMember(value, "y");
    if (
      x.length !== P256_COORDINATE_BYTES ||
      y.length !== P256_COORDINATE_BYTES
    ) {
      throw new InvalidKeyError("P-256 coordinates must be 32 bytes");
    }
    const jwk = {
      crv: "P-256",
      kty: "EC",
      x: base64urlEncode(x),
      y: base64urlEncode(y),
    } as const;
    try {
      // Throws if the point is not on the curve or is the identity.
      p256.Point.fromBytes(ecPoint(jwk)).assertValidity();
    } catch {
      throw new InvalidKeyError("Point is not on P-256");
    }
    return jwk;
  }

  if (value.kty !== "RSA") {
    throw new InvalidKeyError("RS256 requires an RSA key");
  }
  const modulus = decodeMember(value, "n");
  const exponent = decodeMember(value, "e");
  if (modulus[0] === 0) {
    throw new InvalidKeyError("RSA modulus has a leading zero byte");
  }
  if (
    modulus.length < MIN_RSA_MODULUS_BYTES ||
    modulus.length > MAX_RSA_MODULUS_BYTES
  ) {
    throw new InvalidKeyError("RSA modulus must be 2048 to 4096 bits");
  }
  if (exponent.length > MAX_RSA_EXPONENT_BYTES || exponent[0] === 0) {
    throw new InvalidKeyError("Invalid RSA exponent");
  }
  return {
    e: base64urlEncode(exponent),
    kty: "RSA",
    n: base64urlEncode(modulus),
  };
};

/** RFC 7638 JWK thumbprint (SHA-256, base64url). */
export const jwkThumbprint = (jwk: PublicJwk): string => {
  // Required members only, in lexicographic order, no whitespace.
  const canonical =
    jwk.kty === "EC"
      ? `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`
      : `{"e":"${jwk.e}","kty":"RSA","n":"${jwk.n}"}`;
  return base64urlEncode(sha256(utf8Encode(canonical)));
};

const getSubtle = (): SubtleCrypto => {
  const subtle = globalThis.crypto?.subtle;
  if (typeof subtle !== "object" || subtle === null) {
    throw new Error(
      "RS256 verification needs Web Crypto (crypto.subtle) in this runtime"
    );
  }
  return subtle;
};

/** Throws at startup when an offered algorithm cannot be verified here. */
export const assertAlgorithmsSupported = (
  algorithms: readonly DbscAlgorithm[]
): void => {
  if (algorithms.includes("RS256")) {
    getSubtle();
  }
};

/** An ArrayBuffer-backed copy that later mutation of the input cannot reach. */
const snapshot = (bytes: Uint8Array): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(bytes);

/**
 * Verifies a JWS signature. `signingInput` is the ASCII `header.payload`.
 * Returns false (never throws) for a malformed or wrong signature.
 */
export const verifySignature = async (
  algorithm: DbscAlgorithm,
  jwk: PublicJwk,
  signingInput: Uint8Array,
  signature: Uint8Array
): Promise<boolean> => {
  if (algorithm === "ES256") {
    if (jwk.kty !== "EC" || signature.length !== P256_SIGNATURE_BYTES) {
      return false;
    }
    try {
      // JWS ES256 is raw r||s over SHA-256. Hardware keys and Web Crypto do not
      // normalise s, so high-S signatures must be accepted.
      return p256.verify(signature, signingInput, ecPoint(jwk), {
        format: "compact",
        lowS: false,
        prehash: true,
      });
    } catch {
      return false;
    }
  }

  if (jwk.kty !== "RSA") {
    return false;
  }
  // A missing Web Crypto is a deployment error, not a bad signature.
  const subtle = getSubtle();
  // Copy before awaiting, as noble's Web Crypto wrappers do.
  const signatureBytes = snapshot(signature);
  const message = snapshot(signingInput);
  try {
    const key = await subtle.importKey(
      "jwk",
      { alg: "RS256", e: jwk.e, ext: true, kty: "RSA", n: jwk.n },
      { hash: "SHA-256", name: "RSASSA-PKCS1-v1_5" },
      false,
      ["verify"]
    );
    return await subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      signatureBytes,
      message
    );
  } catch {
    return false;
  }
};
