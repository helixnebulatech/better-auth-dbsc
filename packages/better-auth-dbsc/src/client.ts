import type { BetterAuthClientPlugin } from "@better-auth/core";

import { DBSC_ERROR_CODES } from "./error-codes";
import type { dbsc } from "./plugin";

/**
 * Client counterpart of `dbsc()`. The protocol itself needs no JavaScript
 * (the browser drives it from response headers); this adds a typed
 * `authClient.dbsc.status()` and the plugin's error codes.
 */
export const dbscClient = () =>
  ({
    $ERROR_CODES: DBSC_ERROR_CODES,
    $InferServerPlugin: {} as ReturnType<typeof dbsc>,
    id: "dbsc",
    pathMethods: { "/dbsc/status": "GET" },
  }) satisfies BetterAuthClientPlugin;

export { DBSC_ERROR_CODES } from "./error-codes";
