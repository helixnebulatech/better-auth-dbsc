import { base64urlnopad } from "@scure/base";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export const utf8Encode = (value: string): Uint8Array<ArrayBuffer> =>
  textEncoder.encode(value);

/** Throws on invalid UTF-8 instead of inserting replacement characters. */
export const utf8Decode = (bytes: Uint8Array): string =>
  textDecoder.decode(bytes);

/** Base64url without padding (RFC 4648 §5), as used by JOSE. */
export const base64urlEncode = (bytes: Uint8Array): string =>
  base64urlnopad.encode(bytes);

/**
 * Strict base64url decoder: rejects padding, foreign characters, impossible
 * lengths and non-zero trailing bits, so one value has one encoding.
 */
export const base64urlDecode = (value: string): Uint8Array =>
  base64urlnopad.decode(value);

/** Compares two byte arrays in time that depends only on their lengths. */
export const constantTimeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) {
    // oxlint-disable-next-line eslint/no-bitwise -- constant-time comparison
    diff |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return diff === 0;
};

export const constantTimeEqualStrings = (a: string, b: string): boolean =>
  constantTimeEqual(utf8Encode(a), utf8Encode(b));
