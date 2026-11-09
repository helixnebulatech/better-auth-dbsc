/**
 * A browser-side DBSC key made with Web Crypto: an implementation independent
 * of the noble code under test, like a real TPM-backed key would be.
 */
import { base64urlEncode, utf8Encode } from "../crypto/encoding";
import type { DbscAlgorithm } from "../crypto/jwk";

const PARAMS = {
  ES256: {
    generate: { name: "ECDSA", namedCurve: "P-256" } satisfies EcKeyGenParams,
    sign: { hash: "SHA-256", name: "ECDSA" } satisfies EcdsaParams,
  },
  RS256: {
    generate: {
      hash: "SHA-256",
      modulusLength: 2048,
      name: "RSASSA-PKCS1-v1_5",
      publicExponent: new Uint8Array([1, 0, 1]),
    } satisfies RsaHashedKeyGenParams,
    sign: { name: "RSASSA-PKCS1-v1_5" } satisfies Algorithm,
  },
} as const;

const encodeJson = (value: unknown) =>
  base64urlEncode(utf8Encode(JSON.stringify(value)));

export interface DeviceKey {
  algorithm: DbscAlgorithm;
  publicJwk: JsonWebKey;
  /** Signs a proof JWT the way Chrome does. */
  prove: (input: {
    jti: string;
    mode: "registration" | "refresh";
    header?: Record<string, unknown>;
    payload?: Record<string, unknown>;
  }) => Promise<string>;
}

export const createDeviceKey = async (
  algorithm: DbscAlgorithm = "ES256"
): Promise<DeviceKey> => {
  const params = PARAMS[algorithm];
  const pair = (await crypto.subtle.generateKey(params.generate, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const publicJwk: JsonWebKey =
    algorithm === "ES256"
      ? { crv: exported.crv, kty: exported.kty, x: exported.x, y: exported.y }
      : { e: exported.e, kty: exported.kty, n: exported.n };

  return {
    algorithm,
    async prove({ jti, mode, header, payload }) {
      const headerSegment = encodeJson({
        alg: algorithm,
        typ: "dbsc+jwt",
        ...(mode === "registration" ? { jwk: publicJwk } : {}),
        ...header,
      });
      const payloadSegment = encodeJson({ jti, ...payload });
      const signingInput = utf8Encode(`${headerSegment}.${payloadSegment}`);
      const signature = new Uint8Array(
        await crypto.subtle.sign(params.sign, pair.privateKey, signingInput)
      );
      return `${headerSegment}.${payloadSegment}.${base64urlEncode(signature)}`;
    },
    publicJwk,
  };
};
