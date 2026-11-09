import type { BetterAuthPluginDBSchema } from "@better-auth/core/db";

export const DBSC_MODEL = "dbscSession";

/**
 * One row per device-bound Better Auth session. Kept apart from `session` so
 * session writes can never clobber the binding, and so keys never reach
 * session payloads.
 *
 * `sessionId` has no foreign key on purpose: with `secondaryStorage` the
 * session row may not exist in the database. Rows are removed by the
 * session-delete hook and ignored once the session is gone.
 */
export const createSchema = () =>
  ({
    [DBSC_MODEL]: {
      fields: {
        algorithm: { required: true, type: "string" },
        createdAt: { required: true, type: "date" },
        /** `session_identifier` sent to the browser. */
        dbscSessionId: {
          index: true,
          required: true,
          type: "string",
          unique: true,
        },
        /**
         * Better Auth session expiry, kept in step by a session-update hook.
         * Cleanup also checks `updatedAt`, so it never relies on this alone.
         */
        expiresAt: { index: true, required: true, type: "date" },
        /** RFC 7638 thumbprint; a key may bind only one session. */
        keyThumbprint: {
          index: true,
          required: true,
          type: "string",
          unique: true,
        },
        /**
         * Issue time (ms) of the newest accepted challenge: replay guard.
         * Epoch milliseconds do not fit a 32-bit INTEGER, hence `bigint`.
         */
        lastChallengeAt: { bigint: true, required: true, type: "number" },
        /** Minimal public JWK as JSON. */
        publicKey: { required: true, type: "string" },
        refreshCount: { required: true, type: "number" },
        sessionId: { index: true, required: true, type: "string" },
        /** Session token, XChaCha20-Poly1305 encrypted. */
        sessionTokenEncrypted: { required: true, type: "string" },
        /** base64url(SHA-256(session token)). */
        tokenHash: {
          index: true,
          required: true,
          type: "string",
          unique: true,
        },
        updatedAt: { required: true, type: "date" },
        userId: {
          index: true,
          references: { field: "id", model: "user", onDelete: "cascade" },
          required: true,
          type: "string",
        },
      },
    },
  }) satisfies BetterAuthPluginDBSchema;

export type DbscSchema = ReturnType<typeof createSchema>;

export interface DbscSessionRecord {
  id: string;
  algorithm: string;
  createdAt: Date;
  dbscSessionId: string;
  expiresAt: Date;
  keyThumbprint: string;
  lastChallengeAt: number;
  publicKey: string;
  refreshCount: number;
  sessionId: string;
  sessionTokenEncrypted: string;
  tokenHash: string;
  updatedAt: Date;
  userId: string;
}
