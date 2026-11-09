import { describe, expect, it } from "vitest";

import { deriveKeys } from "./crypto/keys";
import {
  cookieNameTag,
  createBoundCookieValue,
  createChallenge,
  decryptSessionToken,
  encryptSessionToken,
  openRegistrationTicket,
  sealRegistrationTicket,
  verifyBoundCookieValue,
  verifyChallenge,
} from "./tokens";

const keys = deriveKeys("k1-".repeat(12));
const otherKeys = deriveKeys("k2-".repeat(12));
const NOW = 1_800_000_000_000;
const MINUTE = 60_000;

describe("challenges", () => {
  it("verify only for their purpose, subject and lifetime", () => {
    const { value, issuedAt } = createChallenge(keys, "f", "sid", NOW);
    const input = {
      maxAgeMs: 15 * MINUTE,
      now: NOW + MINUTE,
      purpose: "f" as const,
      subject: "sid",
    };
    expect(verifyChallenge(keys, value, input)).toBe(issuedAt);
    expect(
      verifyChallenge(keys, value, { ...input, subject: "other" })
    ).toBeNull();
    expect(verifyChallenge(keys, value, { ...input, purpose: "r" })).toBeNull();
    expect(
      verifyChallenge(keys, value, { ...input, now: NOW + 16 * MINUTE })
    ).toBeNull();
    expect(
      verifyChallenge(keys, value, { ...input, now: NOW - MINUTE })
    ).toBeNull();
    expect(verifyChallenge(otherKeys, value, input)).toBeNull();
    expect(verifyChallenge(keys, `${value}x`, input)).toBeNull();
    expect(
      verifyChallenge(keys, value.replace(/^f/u, "r"), {
        ...input,
        purpose: "r",
      })
    ).toBeNull();
  });

  it("are unique and safe inside an sf-string", () => {
    const a = createChallenge(keys, "r", "hash", NOW).value;
    const b = createChallenge(keys, "r", "hash", NOW).value;
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_.-]+$/u);
  });
});

describe("bound cookie", () => {
  it("verifies for its token until it expires", () => {
    const value = createBoundCookieValue(keys, "hash", NOW + 10 * MINUTE);
    expect(verifyBoundCookieValue(keys, value, "hash", NOW)).toBeTruthy();
    expect(verifyBoundCookieValue(keys, value, "other-hash", NOW)).toBeFalsy();
    expect(
      verifyBoundCookieValue(keys, value, "hash", NOW + 10 * MINUTE)
    ).toBeFalsy();
    expect(verifyBoundCookieValue(otherKeys, value, "hash", NOW)).toBeFalsy();
    const [, nonce, mac] = value.split(".");
    const extended = `${(NOW + 99 * MINUTE).toString(36)}.${nonce}.${mac}`;
    expect(verifyBoundCookieValue(keys, extended, "hash", NOW)).toBeFalsy();
  });

  it("rotates on every issue", () => {
    expect(createBoundCookieValue(keys, "hash", NOW)).not.toBe(
      createBoundCookieValue(keys, "hash", NOW)
    );
  });

  it("gets a stable per-session name", () => {
    expect(cookieNameTag("hash")).toBe(cookieNameTag("hash"));
    expect(cookieNameTag("hash")).not.toBe(cookieNameTag("other"));
    expect(cookieNameTag("hash")).toMatch(/^[A-Za-z0-9_-]{12}$/u);
  });
});

describe("session token at rest", () => {
  it("decrypts only with the same key and DBSC session id", () => {
    const sealed = encryptSessionToken(keys, "token-123", "sid");
    expect(sealed).not.toContain("token-123");
    expect(decryptSessionToken(keys, sealed, "sid")).toBe("token-123");
    expect(decryptSessionToken(keys, sealed, "other-sid")).toBeNull();
    expect(decryptSessionToken(otherKeys, sealed, "sid")).toBeNull();
    expect(decryptSessionToken(keys, sealed.slice(0, -2), "sid")).toBeNull();
    expect(decryptSessionToken(keys, "v0.a.b", "sid")).toBeNull();
  });
});

describe("registration tickets", () => {
  it("open only with the same key, unexpired and untouched", () => {
    const ticket = sealRegistrationTicket(keys, "token-123", NOW + 5 * MINUTE);
    expect(ticket).not.toContain("token-123");
    expect(ticket).toMatch(/^t1\.[0-9a-z]+\.[\w-]+\.[\w-]+$/u);
    expect(openRegistrationTicket(keys, ticket, NOW)).toBe("token-123");
    expect(openRegistrationTicket(keys, ticket, NOW + 5 * MINUTE)).toBeNull();
    expect(openRegistrationTicket(otherKeys, ticket, NOW)).toBeNull();
    // Change one character in the middle of the ciphertext, always to a
    // different one (replacing the tail with a fixed string was a no-op when
    // the ticket already ended with it).
    const at = ticket.length - 8;
    const flipped = ticket[at] === "A" ? "B" : "A";
    expect(
      openRegistrationTicket(
        keys,
        `${ticket.slice(0, at)}${flipped}${ticket.slice(at + 1)}`,
        NOW
      )
    ).toBeNull();
  });

  it("cannot have its expiry extended", () => {
    const ticket = sealRegistrationTicket(keys, "token-123", NOW + MINUTE);
    const [version, , nonce, sealed] = ticket.split(".");
    const extended = [
      version,
      (NOW + 99 * MINUTE).toString(36),
      nonce,
      sealed,
    ].join(".");
    expect(openRegistrationTicket(keys, extended, NOW + 2 * MINUTE)).toBeNull();
  });

  it("does not open as a stored session token, nor the other way round", () => {
    const stored = encryptSessionToken(keys, "token-123", "sid");
    expect(openRegistrationTicket(keys, stored, NOW)).toBeNull();
    const ticket = sealRegistrationTicket(keys, "token-123", NOW + MINUTE);
    expect(decryptSessionToken(keys, ticket, "sid")).toBeNull();
  });
});
