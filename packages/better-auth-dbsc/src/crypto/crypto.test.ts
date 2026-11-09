import { p256 } from "@noble/curves/nist.js";
import { describe, expect, it } from "vitest";

import { createDeviceKey } from "../__fixtures__/device-key";
import {
  base64urlDecode,
  base64urlEncode,
  constantTimeEqual,
  utf8Encode,
} from "./encoding";
import {
  assertAlgorithmsSupported,
  InvalidKeyError,
  jwkThumbprint,
  parsePublicJwk,
  verifySignature,
} from "./jwk";

const splitJws = (jws: string) => {
  const [header = "", payload = "", signature = ""] = jws.split(".");
  return {
    header: JSON.parse(new TextDecoder().decode(base64urlDecode(header))) as {
      jwk: Record<string, unknown>;
    },
    signature: base64urlDecode(signature),
    signingInput: utf8Encode(`${header}.${payload}`),
  };
};

describe("base64url", () => {
  it("round-trips every length and matches RFC 4648 vectors", () => {
    const vectors: [string, string][] = [
      ["", ""],
      ["f", "Zg"],
      ["fo", "Zm8"],
      ["foo", "Zm9v"],
      ["foob", "Zm9vYg"],
      ["fooba", "Zm9vYmE"],
      ["foobar", "Zm9vYmFy"],
    ];
    for (const [plain, encoded] of vectors) {
      expect(base64urlEncode(utf8Encode(plain))).toBe(encoded);
      expect(new TextDecoder().decode(base64urlDecode(encoded))).toBe(plain);
    }
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe]);
    expect(base64urlEncode(bytes)).toBe("-__-");
  });

  it("rejects padding, standard base64 and non-canonical encodings", () => {
    expect(() => base64urlDecode("Zg==")).toThrow(/Unknown letter/u);
    expect(() => base64urlDecode("+/8")).toThrow(/Unknown letter/u);
    expect(() => base64urlDecode("Z")).toThrow(/padding/u);
    // "Zh" decodes to "f" with non-zero trailing bits.
    expect(() => base64urlDecode("Zh")).toThrow(/padding/u);
  });

  it("compares in constant time", () => {
    expect(
      constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))
    ).toBeTruthy();
    expect(
      constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))
    ).toBeFalsy();
    expect(
      constantTimeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))
    ).toBeFalsy();
  });
});

describe("ES256", () => {
  it("verifies Web Crypto signatures and rejects tampering", async () => {
    const key = await createDeviceKey("ES256");
    const { header, signature, signingInput } = splitJws(
      await key.prove({ jti: "c", mode: "registration" })
    );
    const jwk = parsePublicJwk(header.jwk, "ES256");
    await expect(
      verifySignature("ES256", jwk, signingInput, signature)
    ).resolves.toBeTruthy();

    const tampered = Uint8Array.from(signingInput, (byte, index) =>
      index === 0 ? (byte + 1) % 256 : byte
    );
    await expect(
      verifySignature("ES256", jwk, tampered, signature)
    ).resolves.toBeFalsy();
    await expect(
      verifySignature("ES256", jwk, signingInput, signature.slice(1))
    ).resolves.toBeFalsy();

    const otherKey = await createDeviceKey("ES256");
    const other = parsePublicJwk(otherKey.publicJwk, "ES256");
    await expect(
      verifySignature("ES256", other, signingInput, signature)
    ).resolves.toBeFalsy();
  });

  it("accepts high-S signatures, which hardware keys do not normalise", async () => {
    const secretKey = p256.utils.randomSecretKey();
    const publicKey = p256.getPublicKey(secretKey, false);
    const jwk = parsePublicJwk(
      {
        crv: "P-256",
        kty: "EC",
        x: base64urlEncode(publicKey.slice(1, 33)),
        y: base64urlEncode(publicKey.slice(33)),
      },
      "ES256"
    );
    const message = utf8Encode("header.payload");
    const low = p256.Signature.fromBytes(
      p256.sign(message, secretKey, { lowS: true })
    );
    const high = new p256.Signature(low.r, p256.Point.CURVE().n - low.s);
    await expect(
      verifySignature("ES256", jwk, message, high.toBytes("compact"))
    ).resolves.toBeTruthy();
  });

  it("rejects private keys, wrong curves and points off the curve", async () => {
    const { publicJwk } = await createDeviceKey("ES256");
    expect(() => parsePublicJwk({ ...publicJwk, d: "AAAA" }, "ES256")).toThrow(
      InvalidKeyError
    );
    expect(() =>
      parsePublicJwk({ ...publicJwk, crv: "P-384" }, "ES256")
    ).toThrow(InvalidKeyError);
    expect(() => parsePublicJwk(publicJwk, "RS256")).toThrow(InvalidKeyError);
    const badY = base64urlEncode(new Uint8Array(32).fill(7));
    expect(() => parsePublicJwk({ ...publicJwk, y: badY }, "ES256")).toThrow(
      InvalidKeyError
    );
  });
});

describe("RS256", () => {
  it("verifies Web Crypto signatures", async () => {
    const key = await createDeviceKey("RS256");
    const { header, signature, signingInput } = splitJws(
      await key.prove({ jti: "c", mode: "registration" })
    );
    const jwk = parsePublicJwk(header.jwk, "RS256");
    await expect(
      verifySignature("RS256", jwk, signingInput, signature)
    ).resolves.toBeTruthy();
    await expect(
      verifySignature("RS256", jwk, utf8Encode("other"), signature)
    ).resolves.toBeFalsy();
  });

  it("rejects keys under 2048 bits", async () => {
    const pair = (await crypto.subtle.generateKey(
      {
        hash: "SHA-256",
        modulusLength: 1024,
        name: "RSASSA-PKCS1-v1_5",
        publicExponent: new Uint8Array([1, 0, 1]),
      },
      true,
      ["sign", "verify"]
    )) as CryptoKeyPair;
    const weak = await crypto.subtle.exportKey("jwk", pair.publicKey);
    expect(() =>
      parsePublicJwk({ e: weak.e, kty: "RSA", n: weak.n }, "RS256")
    ).toThrow(InvalidKeyError);
  });
});

describe(jwkThumbprint, () => {
  it("matches the RFC 7638 §3.1 example", () => {
    const n =
      "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";
    expect(jwkThumbprint({ e: "AQAB", kty: "RSA", n })).toBe(
      "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
    );
  });
});

describe(assertAlgorithmsSupported, () => {
  it("accepts the algorithms this runtime can verify", () => {
    expect(() => assertAlgorithmsSupported(["ES256", "RS256"])).not.toThrow();
  });
});
