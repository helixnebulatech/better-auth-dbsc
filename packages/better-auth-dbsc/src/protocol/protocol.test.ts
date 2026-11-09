import { describe, expect, it } from "vitest";

import { createDeviceKey } from "../__fixtures__/device-key";
import { base64urlEncode, utf8Encode } from "../crypto/encoding";
import { resolveOptions } from "../options";
import {
  parseSkippedHeader,
  readStringHeader,
  serializeChallengeHeader,
  serializeRegistrationHeader,
  serializeSfString,
} from "./headers";
import { buildSessionInstructions, serializeSetCookie } from "./instructions";
import { InvalidProofError, parseProof } from "./jwt";

const encode = (value: unknown) =>
  base64urlEncode(utf8Encode(JSON.stringify(value)));

describe("structured headers", () => {
  it("serializes the registration and challenge headers like the spec examples", () => {
    expect(
      serializeRegistrationHeader({
        algorithms: ["ES256", "RS256"],
        challenge: "cv",
        path: "/api/auth/dbsc/start",
      })
    ).toBe('(ES256 RS256);path="/api/auth/dbsc/start";challenge="cv"');
    expect(
      serializeRegistrationHeader({
        algorithms: ["ES256"],
        authorization: "ac",
        challenge: "cv",
        path: "reg",
      })
    ).toBe('(ES256);path="reg";challenge="cv";authorization="ac"');
    expect(serializeChallengeHeader("new challenge", "my session")).toBe(
      '"new challenge";id="my session"'
    );
    expect(serializeSfString('a"b\\c')).toBe('"a\\"b\\\\c"');
    expect(() => serializeSfString("é")).toThrow(/printable ASCII/u);
  });

  it("reads quoted (spec) and bare (Chrome) string headers", () => {
    const headers = new Headers({
      a: '"abc"',
      b: "abc",
      c: '"a\\"b";x=1',
      d: '"unterminated',
      e: '"bad\\escape"',
    });
    expect(readStringHeader(headers, "a")).toBe("abc");
    expect(readStringHeader(headers, "b")).toBe("abc");
    expect(readStringHeader(headers, "c")).toBe('a"b');
    expect(readStringHeader(headers, "d")).toBeNull();
    expect(readStringHeader(headers, "e")).toBeNull();
    expect(readStringHeader(headers, "missing")).toBeNull();
  });

  it("parses Secure-Session-Skipped", () => {
    expect(
      parseSkippedHeader(
        'unreachable;session_identifier="a", quota_exceeded;session_identifier="b", bogus;session_identifier="c"'
      )
    ).toStrictEqual([
      { reason: "unreachable", sessionId: "a" },
      { reason: "quota_exceeded", sessionId: "b" },
    ]);
  });
});

describe(parseProof, () => {
  it("accepts registration proofs with a jwk and refresh proofs without", async () => {
    const key = await createDeviceKey();
    const registration = parseProof(
      await key.prove({ jti: "c1", mode: "registration" }),
      "registration",
      ["ES256"]
    );
    expect(registration.jti).toBe("c1");
    expect(registration.jwk).toMatchObject({ crv: "P-256", kty: "EC" });

    const refresh = parseProof(
      await key.prove({ jti: "c2", mode: "refresh" }),
      "refresh",
      ["ES256"]
    );
    expect(refresh.jwk).toBeUndefined();
  });

  it("ignores claims the current spec does not define (aud behind a Chrome flag)", async () => {
    const key = await createDeviceKey();
    const proof = parseProof(
      await key.prove({
        jti: "c",
        mode: "refresh",
        payload: { aud: "https://x" },
      }),
      "refresh",
      ["ES256"]
    );
    expect(proof.jti).toBe("c");
  });

  it("rejects wrong typ, alg, jwk placement and malformed tokens", async () => {
    const key = await createDeviceKey();
    const cases: [string, "registration" | "refresh"][] = [
      [
        await key.prove({ header: { typ: "JWT" }, jti: "c", mode: "refresh" }),
        "refresh",
      ],
      [
        await key.prove({ header: { alg: "none" }, jti: "c", mode: "refresh" }),
        "refresh",
      ],
      [
        await key.prove({
          header: { alg: "HS256" },
          jti: "c",
          mode: "refresh",
        }),
        "refresh",
      ],
      [await key.prove({ jti: "c", mode: "registration" }), "refresh"],
      [await key.prove({ jti: "c", mode: "refresh" }), "registration"],
      [
        await key.prove({ header: { crit: ["x"] }, jti: "c", mode: "refresh" }),
        "refresh",
      ],
      [
        `${encode({ alg: "ES256", typ: "dbsc+jwt" })}.${encode({})}.AA`,
        "refresh",
      ],
      ["a.b", "refresh"],
      ["x".repeat(9000), "refresh"],
    ];
    for (const [token, mode] of cases) {
      expect(() => parseProof(token, mode, ["ES256"])).toThrow(
        InvalidProofError
      );
    }
  });

  it("only accepts the algorithms it was given", async () => {
    const key = await createDeviceKey("RS256");
    const token = await key.prove({ jti: "c", mode: "refresh" });
    expect(() => parseProof(token, "refresh", ["ES256"])).toThrow(
      InvalidProofError
    );
    expect(parseProof(token, "refresh", ["RS256"]).algorithm).toBe("RS256");
  });
});

describe("session instructions", () => {
  const cookie = {
    attributes: {
      domain: undefined,
      httpOnly: true,
      path: "/",
      sameSite: "Lax" as const,
      secure: true,
    },
    name: "__Secure-better-auth.dbsc_abc",
  };

  it("lists only attributes Chrome accepts and matches the Set-Cookie", () => {
    const instructions = buildSessionInstructions({
      cookie,
      options: resolveOptions(),
      refreshUrl: "/api/auth/dbsc/refresh",
      sessionId: "sid",
    });
    expect(instructions).toStrictEqual({
      credentials: [
        {
          attributes: "Path=/; Secure; HttpOnly; SameSite=Lax",
          name: "__Secure-better-auth.dbsc_abc",
          type: "cookie",
        },
      ],
      refresh_url: "/api/auth/dbsc/refresh",
      scope: { include_site: false },
      session_identifier: "sid",
    });
    expect(serializeSetCookie(cookie, "v", 600)).toBe(
      "__Secure-better-auth.dbsc_abc=v; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax"
    );
  });

  it("passes scope rules and refresh initiators through", () => {
    const instructions = buildSessionInstructions({
      cookie,
      options: resolveOptions({
        allowedRefreshInitiators: ["*.example.com"],
        scope: {
          includeSite: true,
          origin: "https://example.com",
          rules: [{ path: "/static", type: "exclude" }],
        },
      }),
      refreshUrl: "/r",
      sessionId: "sid",
    });
    expect(instructions.scope).toStrictEqual({
      include_site: true,
      origin: "https://example.com",
      scope_specification: [{ domain: "*", path: "/static", type: "exclude" }],
    });
    expect(instructions.allowed_refresh_initiators).toStrictEqual([
      "*.example.com",
    ]);
  });
});
