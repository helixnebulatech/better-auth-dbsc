import { base64urlDecode, utf8Decode, utf8Encode } from "../crypto/encoding";
import { parsePublicJwk } from "../crypto/jwk";
import type { DbscAlgorithm, PublicJwk } from "../crypto/jwk";

/** Generous for a 4096-bit RSA JWK plus signature; real proofs are < 2 KB. */
export const MAX_PROOF_LENGTH = 8192;
const DBSC_JWT_TYPE = "dbsc+jwt";

export class InvalidProofError extends Error {
  override name = "InvalidProofError";
}

export interface DbscProof {
  readonly algorithm: DbscAlgorithm;
  /** Present on registration proofs only. */
  readonly jwk: PublicJwk | undefined;
  /** The challenge the browser signed. */
  readonly jti: string;
  readonly authorization: string | undefined;
  readonly signingInput: Uint8Array;
  readonly signature: Uint8Array;
}

const parseJsonSegment = (
  segment: string,
  label: string
): Record<string, unknown> => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(base64urlDecode(segment)));
  } catch {
    throw new InvalidProofError(`Proof ${label} is not base64url JSON`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new InvalidProofError(`Proof ${label} must be a JSON object`);
  }
  return parsed as Record<string, unknown>;
};

/**
 * Parses a DBSC proof JWT (`Secure-Session-Response`) without verifying it.
 *
 * - `registration`: the JOSE header must carry the public key as `jwk`.
 * - `refresh`: `jwk` must be absent; the caller verifies with the stored key.
 *
 * The current spec defines only `jti` and `authorization`; other claims
 * (such as `aud`, sent behind a Chrome flag) are ignored.
 */
export const parseProof = (
  token: string,
  mode: "registration" | "refresh",
  allowedAlgorithms: readonly DbscAlgorithm[]
): DbscProof => {
  if (token.length === 0 || token.length > MAX_PROOF_LENGTH) {
    throw new InvalidProofError("Proof is empty or too long");
  }
  const segments = token.split(".");
  if (segments.length !== 3) {
    throw new InvalidProofError("Proof must be a compact JWS");
  }
  const [headerSegment = "", payloadSegment = "", signatureSegment = ""] =
    segments;

  const header = parseJsonSegment(headerSegment, "header");
  if (header.typ !== DBSC_JWT_TYPE) {
    throw new InvalidProofError(`Proof typ must be "${DBSC_JWT_TYPE}"`);
  }
  const algorithm = allowedAlgorithms.find((alg) => alg === header.alg);
  if (!algorithm) {
    throw new InvalidProofError("Proof alg is not allowed");
  }
  if (header.crit !== undefined) {
    throw new InvalidProofError("Proof crit header is not supported");
  }

  let jwk: PublicJwk | undefined;
  if (mode === "registration") {
    try {
      jwk = parsePublicJwk(header.jwk, algorithm);
    } catch (error) {
      throw new InvalidProofError(
        `Invalid proof jwk: ${error instanceof Error ? error.message : "unknown"}`
      );
    }
  } else if (header.jwk !== undefined) {
    throw new InvalidProofError("Refresh proofs must not carry a jwk");
  }

  const payload = parseJsonSegment(payloadSegment, "payload");
  if (typeof payload.jti !== "string" || payload.jti.length === 0) {
    throw new InvalidProofError("Proof jti is missing");
  }
  if (
    payload.authorization !== undefined &&
    typeof payload.authorization !== "string"
  ) {
    throw new InvalidProofError("Proof authorization must be a string");
  }

  let signature: Uint8Array;
  try {
    signature = base64urlDecode(signatureSegment);
  } catch {
    throw new InvalidProofError("Proof signature is not base64url");
  }

  return {
    algorithm,
    authorization: payload.authorization,
    jti: payload.jti,
    jwk,
    signature,
    signingInput: utf8Encode(`${headerSegment}.${payloadSegment}`),
  };
};
