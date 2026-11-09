// Real-browser check: Chromium with DBSC (software keys) against a Better
// Auth server that uses the built plugin. Run `bun run build` first, then
// `bun run test:e2e`.
//
// Chrome only processes DBSC headers on connections with valid TLS
// (net/url_request/url_request_http_job.cc), so plain http://localhost does
// not work: the server uses a throwaway self-signed certificate that Chrome
// is told to trust by its SPKI hash.
import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as sleep } from "node:timers/promises";

import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { toNodeHandler } from "better-auth/node";
import { chromium } from "playwright";

import { dbsc } from "../dist/index.js";

const PORT = 4319;
const ORIGIN = `https://localhost:${PORT}`;
const DEBUG = Boolean(process.env.DBSC_E2E_DEBUG);

// The "For developers" variant of
// chrome://flags/#enable-standard-device-bound-session-credentials, plus
// software keys (no TPM on Linux or CI).
const developerParams = [
  ["Require", "Origin", "Trial", "Tokens"].join(""),
  "false",
  ["Refresh", "Quota"].join(""),
  "false",
  ["Check", "Subdomain", "Registration"].join(""),
  "false",
].join("/");
const FEATURES = [
  `DeviceBoundSessions:${developerParams}`,
  [
    "Enable",
    "BoundSession",
    "Credentials",
    "SoftwareKeys",
    "ForManualTesting",
  ].join(""),
  ["Use", "Unexportable", "KeyService", "InBrowserProcess"].join(""),
  ["Persist", "DeviceBound", "Sessions"].join(""),
];

/* -------------------------------------------------------------------------- */
/* TLS                                                                        */
/* -------------------------------------------------------------------------- */

const certDir = mkdtempSync(path.join(tmpdir(), "dbsc-e2e-"));
const keyPath = path.join(certDir, "key.pem");
const certPath = path.join(certDir, "cert.pem");
execFileSync(
  "openssl",
  [
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=localhost",
    "-addext",
    "subjectAltName=DNS:localhost",
    "-keyout",
    keyPath,
    "-out",
    certPath,
  ],
  { stdio: "ignore" }
);
const certPem = readFileSync(certPath);
const spkiHash = createHash("sha256")
  .update(
    new X509Certificate(certPem).publicKey.export({
      format: "der",
      type: "spki",
    })
  )
  .digest("base64");

/* -------------------------------------------------------------------------- */
/* Server                                                                     */
/* -------------------------------------------------------------------------- */

const events = [];
/** Status of every `/dbsc/refresh` call Chrome makes, in order. */
const refreshStatuses = [];
const options = {
  baseURL: ORIGIN,
  database: new DatabaseSync(":memory:"),
  emailAndPassword: { enabled: true },
  logger: { level: "error" },
  plugins: [dbsc({ onEvent: (event) => events.push(event) })],
  secret: "e2e-".repeat(10),
};
const auth = betterAuth(options);
const migrations = await getMigrations(options);
await migrations.runMigrations();

const authHandler = toNodeHandler(auth);
const server = createServer(
  { cert: certPem, key: readFileSync(keyPath) },
  (request, response) => {
    if (request.url?.startsWith("/api/auth")) {
      if (request.url.startsWith("/api/auth/dbsc/refresh")) {
        response.on("finish", () => refreshStatuses.push(response.statusCode));
      }
      if (DEBUG) {
        response.on("finish", () =>
          console.log(
            `[server] ${request.method} ${request.url} -> ${response.statusCode}`
          )
        );
      }
      return authHandler(request, response);
    }
    response.setHeader("content-type", "text/html");
    response.end("<!doctype html><title>dbsc e2e</title><p>ok</p>");
  }
);
server.listen(PORT);
await once(server, "listening");

/* -------------------------------------------------------------------------- */
/* Browser                                                                    */
/* -------------------------------------------------------------------------- */

const waitFor = async (predicate, label, timeoutMs = 15_000) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) {
      return;
    }
    // Polling on purpose: the server records events as Chrome calls it.
    // oxlint-disable-next-line eslint/no-await-in-loop
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${label}`);
};

const check = (condition, message) => {
  if (!condition) {
    throw new Error(`FAILED: ${message}`);
  }
  console.log(`ok - ${message}`);
};

const browser = await chromium.launch({
  args: [
    `--enable-features=${FEATURES.join(",")}`,
    `--ignore-certificate-errors-spki-list=${spkiHash}`,
  ],
  // The full browser: chrome-headless-shell has no DBSC service.
  channel: "chromium",
  chromiumSandbox: true,
  headless: !process.env.DBSC_E2E_HEADED,
});

const fetchInPage = (page, authPath, body) =>
  page.evaluate(
    async ([url, payload]) => {
      const response = await fetch(url, {
        body: payload ? JSON.stringify(payload) : undefined,
        headers: payload ? { "content-type": "application/json" } : {},
        method: payload ? "POST" : "GET",
      });
      return { body: await response.json(), status: response.status };
    },
    [`/api/auth${authPath}`, body]
  );

let exitCode = 0;
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  if (DEBUG) {
    const cdp = await context.newCDPSession(page);
    cdp.on("Network.deviceBoundSessionEventOccurred", (event) =>
      console.log("[chrome]", JSON.stringify(event))
    );
    await cdp.send("Network.enable");
    await cdp.send("Network.enableDeviceBoundSessions", { enable: true });
  }
  await page.goto(ORIGIN);

  const signUp = await fetchInPage(page, "/sign-up/email", {
    email: ["e2e", "example.com"].join("@"),
    name: "E2E",
    password: ["correct", "horse", "battery", "staple"].join("-"),
  });
  check(signUp.status === 200, "sign-up succeeds");

  await waitFor(
    () => events.some((event) => event.type === "session-registered"),
    "registration"
  );
  check(true, "Chrome registered a device-bound session");

  const cookies = await context.cookies();
  const bound = cookies.find((cookie) =>
    cookie.name.includes("better-auth.dbsc_")
  );
  check(Boolean(bound), `bound cookie set (${bound?.name})`);

  const session = await fetchInPage(page, "/get-session");
  check(Boolean(session.body?.user), "session works with the bound cookie");

  // Drop the bound cookie: Chrome must hold the next request and refresh.
  await context.clearCookies({ name: bound.name });
  const refreshed = await fetchInPage(page, "/get-session");
  check(Boolean(refreshed.body?.user), "request succeeds after a refresh");
  check(
    events.some((event) => event.type === "session-refreshed"),
    "Chrome refreshed with a signed challenge"
  );
  // Chrome cached the challenge sent with the registration (it logs a
  // "NoSessionMatch" challenge event first; see the README).
  check(
    refreshStatuses.join(",") === "200",
    `first refresh signed without a 403 (${refreshStatuses.join(",")})`
  );
  const cookiesAfterRefresh = await context.cookies();
  const rotated = cookiesAfterRefresh.find(
    (cookie) => cookie.name === bound.name
  );
  check(
    Boolean(rotated) && rotated.value !== bound.value,
    "bound cookie rotated"
  );

  // Another browser profile with only the stolen session cookie.
  const stolenCookie = cookies.find((cookie) =>
    cookie.name.endsWith("better-auth.session_token")
  );
  // The plugin lets the session cookie alone through for 10 s after the
  // registration (requests already in flight); wait that out.
  await sleep(11_000);
  const thief = await browser.newContext();
  await thief.addCookies([stolenCookie]);
  const thiefPage = await thief.newPage();
  await thiefPage.goto(ORIGIN);
  const stolen = await fetchInPage(thiefPage, "/get-session");
  check(stolen.body === null, "stolen session cookie is refused elsewhere");
} catch (error) {
  console.error(error);
  console.error("events:", JSON.stringify(events, null, 2));
  exitCode = 1;
} finally {
  await browser.close();
  server.close();
  rmSync(certDir, { force: true, recursive: true });
}
process.exit(exitCode);
