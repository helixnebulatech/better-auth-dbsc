import type { DbscAlgorithm } from "../crypto/jwk";

/** Response header that starts a registration (ED §9.1). */
export const REGISTRATION_HEADER = "Secure-Session-Registration";
/** Response header carrying the next challenge (ED §9.2). */
export const CHALLENGE_HEADER = "Secure-Session-Challenge";
/** Request header with the signed proof JWT (ED §9.3). */
export const RESPONSE_HEADER = "Secure-Session-Response";
/** Request header naming the session being refreshed (ED §9.4). */
export const SESSION_ID_HEADER = "Sec-Secure-Session-Id";
/** Request header listing refreshes the browser skipped (ED §9.5). */
export const SKIPPED_HEADER = "Secure-Session-Skipped";

/** sf-string: printable ASCII (0x20-0x7E), RFC 9651 §3.3.3. */
const PRINTABLE_ASCII = /^[ -~]*$/u;

export const serializeSfString = (value: string): string => {
  if (!PRINTABLE_ASCII.test(value)) {
    throw new TypeError("sf-string values must be printable ASCII");
  }
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
};

/**
 * Parses a leading sf-string and ignores any parameters after it. Returns
 * null when the input does not start with a valid sf-string.
 */
const parseLeadingSfString = (input: string): string | null => {
  if (!input.startsWith('"')) {
    return null;
  }
  let output = "";
  for (let index = 1; index < input.length; index += 1) {
    const char = input[index] ?? "";
    if (char === "\\") {
      const next = input[index + 1];
      if (next !== '"' && next !== "\\") {
        return null;
      }
      output += next;
      index += 1;
    } else if (char === '"') {
      const rest = input.slice(index + 1).trimStart();
      return rest === "" || rest.startsWith(";") ? output : null;
    } else if (PRINTABLE_ASCII.test(char)) {
      output += char;
    } else {
      return null;
    }
  }
  return null;
};

/**
 * Reads `Sec-Secure-Session-Id` / `Secure-Session-Response`. The spec says
 * sf-string, Chrome sends the bare value, so both forms are accepted.
 */
export const readStringHeader = (
  headers: Headers,
  name: string
): string | null => {
  const raw = headers.get(name)?.trim();
  if (!raw) {
    return null;
  }
  if (raw.startsWith('"')) {
    return parseLeadingSfString(raw);
  }
  return PRINTABLE_ASCII.test(raw) && !raw.includes('"') ? raw : null;
};

export const serializeRegistrationHeader = (input: {
  algorithms: readonly DbscAlgorithm[];
  path: string;
  challenge: string;
  /** Copied by the browser into the registration JWT (ED §9.1). */
  authorization?: string | undefined;
}): string =>
  `(${input.algorithms.join(" ")});path=${serializeSfString(input.path)};challenge=${serializeSfString(input.challenge)}${
    input.authorization
      ? `;authorization=${serializeSfString(input.authorization)}`
      : ""
  }`;

export const serializeChallengeHeader = (
  challenge: string,
  sessionId: string
): string =>
  `${serializeSfString(challenge)};id=${serializeSfString(sessionId)}`;

export type SkippedReason = "unreachable" | "server_error" | "quota_exceeded";

const SKIPPED_ITEM =
  /^\s*(?<reason>unreachable|server_error|quota_exceeded)\s*(?:;(?<params>.*))?$/u;
const SESSION_IDENTIFIER_PARAM =
  /(?:^|;)\s*session_identifier\s*=\s*(?<value>"(?:[^"\\]|\\.)*")/u;

/**
 * Parses `Secure-Session-Skipped` (a list of tokens with a
 * `session_identifier` parameter). Unknown members are dropped.
 */
export const parseSkippedHeader = (
  value: string | null
): { reason: SkippedReason; sessionId: string }[] => {
  if (!value) {
    return [];
  }
  const results: { reason: SkippedReason; sessionId: string }[] = [];
  for (const member of value.split(",")) {
    const match = SKIPPED_ITEM.exec(member);
    if (!match) {
      continue;
    }
    const quoted = SESSION_IDENTIFIER_PARAM.exec(match.groups?.params ?? "")
      ?.groups?.value;
    const sessionId = quoted ? parseLeadingSfString(quoted) : null;
    if (sessionId !== null) {
      results.push({
        reason: match.groups?.reason as SkippedReason,
        sessionId,
      });
    }
  }
  return results;
};
