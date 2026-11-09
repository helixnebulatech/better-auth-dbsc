import { defineErrorCodes } from "@better-auth/core/utils/error-codes";

export const DBSC_ERROR_CODES = defineErrorCodes({
  ALREADY_BOUND: "This session is already bound to a device",
  DEVICE_PROOF_REQUIRED:
    "This session is bound to a device and the request has no device proof",
  INVALID_CHALLENGE: "The device proof does not answer a valid challenge",
  INVALID_PROOF: "The device proof is invalid",
  KEY_ALREADY_USED: "This device key is already bound to another session",
  MISSING_PROOF: "The Secure-Session-Response header is missing",
  MISSING_SESSION_ID: "The Sec-Secure-Session-Id header is missing",
  SESSION_NOT_FOUND: "The device-bound session does not exist or has ended",
  UNAUTHORIZED: "A signed-in session is required",
});
