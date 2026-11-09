// Real-browser check of a cross-site sign-in (the SSO/OAuth callback case):
// a page on another site (127.0.0.1) links to a magic-link URL on
// localhost, so Chrome navigates cross-site to a GET that creates the
// session and redirects, like an OAuth callback. The registration POST then
// carries no SameSite=Lax session cookie; the plugin's `authorization`
// ticket must carry the session instead. Run `bun run build` first.
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
import { magicLink } from "better-auth/plugins";
import { chromium } from "playwright";

import { dbsc, dbscRefreshNeeded, dbscRefreshPage } from "../dist/index.js";

const APP_PORT = 4319;
const IDP_PORT = 4320;
const APP = `https://localhost:${APP_PORT}`;
// A different site from localhost: the "identity provider".
const IDP = `https://${["127", "0", "0", "1"].join(".")}:${IDP_PORT}`;

const developerParams = [
  ["Require", "Origin", "Trial", "Tokens"].join(""),
  "false",
  ["Refresh", "Quota"].join(""),
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
];

const certDir = mkdtempSync(path.join(tmpdir(), "dbsc-sso-"));
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
    `subjectAltName=DNS:localhost,IP:${new URL(IDP).hostname}`,
    "-keyout",
    keyPath,
    "-out",
    certPath,
  ],
  { stdio: "ignore" }
);
const tls = { cert: readFileSync(certPath), key: readFileSync(keyPath) };
const spkiHash = createHash("sha256")
  .update(
    new X509Certificate(tls.cert).publicKey.export({
      format: "der",
      type: "spki",
    })
  )
  .digest("base64");

let magicUrl = "";
const events = [];
const options = {
  baseURL: APP,
  database: new DatabaseSync(":memory:"),
  emailAndPassword: { enabled: true },
  logger: { level: "error" },
  plugins: [
    magicLink({
      sendMagicLink: ({ url }) => {
        magicUrl = url;
      },
    }),
    dbsc({ onEvent: (event) => events.push(event) }),
  ],
  secret: "sso-".repeat(10),
};
const auth = betterAuth(options);
const migrations = await getMigrations(options);
await migrations.runMigrations();

const email = ["sso", "example.com"].join("@");
await auth.api.signUpEmail({
  body: { email, name: "SSO", password: ["sso", "user", "password"].join("-") },
});
await auth.api.signInMagicLink({
  body: { callbackURL: "/", email },
  headers: new Headers(),
});

const authHandler = toNodeHandler(auth);
let interstitials = 0;
const toHeaders = (request) => {
  const headers = new Headers();
  for (const [name, value] of Object.entries(request.headers)) {
    if (typeof value === "string") {
      headers.set(name, value);
    }
  }
  return headers;
};

// An SSR page: "/raw" renders straight away, "/me" first asks the plugin
// whether a cross-site arrival needs a refresh.
const renderPage = async (request, response, useHelper) => {
  const headers = toHeaders(request);
  if (useHelper && (await dbscRefreshNeeded(auth, headers))) {
    interstitials += 1;
    const page = dbscRefreshPage();
    response.writeHead(page.status, Object.fromEntries(page.headers));
    response.end(await page.text());
    return;
  }
  const session = await auth.api.getSession({ headers });
  response.setHeader("content-type", "text/html");
  response.end(
    `<!doctype html><title>page</title><p id="who">${session ? "signed-in" : "anonymous"}</p>`
  );
};

const app = createServer(tls, (request, response) => {
  if (request.url?.startsWith("/api/auth")) {
    return authHandler(request, response);
  }
  if (request.url === "/me" || request.url === "/raw") {
    return renderPage(request, response, request.url === "/me");
  }
  response.setHeader("content-type", "text/html");
  response.end("<!doctype html><title>app</title><p>app</p>");
});
const idp = createServer(tls, (_request, response) => {
  response.setHeader("content-type", "text/html");
  response.end(
    `<!doctype html><title>idp</title><a id="go" href="${magicUrl}">continue</a> <a id="raw" href="${APP}/raw">raw</a> <a id="me" href="${APP}/me">me</a>`
  );
});
app.listen(APP_PORT);
idp.listen(IDP_PORT);
await Promise.all([once(app, "listening"), once(idp, "listening")]);

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
  channel: "chromium",
  chromiumSandbox: true,
  headless: !process.env.DBSC_E2E_HEADED,
});

const fetchSession = (target) =>
  target.evaluate(async () => {
    const response = await fetch("/api/auth/get-session");
    return response.json();
  });

let exitCode = 0;
const chrome = [];
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  cdp.on("Network.deviceBoundSessionEventOccurred", (event) => {
    const detail =
      event.creationEventDetails?.fetchResult ??
      event.refreshEventDetails?.refreshResult ??
      event.challengeEventDetails?.challengeResult;
    chrome.push(
      `${Object.keys(event).find((key) => key.endsWith("Details"))}:${detail}`
    );
  });
  await cdp.send("Network.enable");
  await cdp.send("Network.enableDeviceBoundSessions", { enable: true });

  await page.goto(`${IDP}/`);
  await Promise.all([page.waitForURL(`${APP}/`), page.click("#go")]);
  check(
    page.url() === `${APP}/`,
    "cross-site magic-link sign-in landed on the app"
  );

  for (
    let i = 0;
    i < 100 && !events.some((event) => event.type === "session-registered");
    i += 1
  ) {
    // Polling on purpose: the server records events as Chrome calls it.
    // oxlint-disable-next-line eslint/no-await-in-loop
    await sleep(100);
  }
  check(
    events.some((event) => event.type === "session-registered"),
    `Chrome registered from the cross-site sign-in (${chrome.join(", ")})`
  );
  const cookies = await context.cookies();
  const bound = cookies.find((cookie) =>
    cookie.name.includes("better-auth.dbsc_")
  );
  check(
    Boolean(bound),
    `bound cookie stored (${bound?.name}, SameSite=${bound?.sameSite})`
  );

  const session = await fetchSession(page);
  check(Boolean(session?.user), "session works");

  await context.clearCookies({ name: bound.name });
  const refreshed = await fetchSession(page);
  check(Boolean(refreshed?.user), "session survives a refresh");
  check(
    events.some((event) => event.type === "session-refreshed"),
    "refreshed with the device key"
  );

  // The plugin lets the session cookie alone through for 10 s after the
  // registration (requests already in flight); wait that out.
  await sleep(11_000);
  const thief = await browser.newContext();
  await thief.addCookies(
    cookies.filter((cookie) => cookie.name.endsWith("session_token"))
  );
  const thiefPage = await thief.newPage();
  await thiefPage.goto(`${APP}/`);
  check(
    (await fetchSession(thiefPage)) === null,
    "stolen session cookie is refused"
  );

  // A link from another site after the bound cookie expired: Chrome does not
  // refresh for a cross-site initiator, so the page renders signed out...
  const linkFromOtherSite = async (id) => {
    await context.clearCookies({ name: bound.name });
    await page.goto(`${IDP}/`);
    await Promise.all([page.waitForURL(`${APP}/${id}`), page.click(`#${id}`)]);
    await page.waitForSelector("#who");
    return page.textContent("#who");
  };
  check(
    (await linkFromOtherSite("raw")) === "anonymous",
    "without the helper a cross-site arrival renders signed out"
  );
  // ...unless the app answers with the refresh page, whose same-origin reload
  // lets Chrome refresh first.
  const refreshesBefore = events.filter(
    (event) => event.type === "session-refreshed"
  ).length;
  check(
    (await linkFromOtherSite("me")) === "signed-in",
    "with dbscRefreshNeeded/dbscRefreshPage it renders signed in"
  );
  check(
    interstitials === 1,
    `exactly one refresh page served (${interstitials})`
  );
  check(
    events.filter((event) => event.type === "session-refreshed").length >
      refreshesBefore,
    "the reload triggered a device-bound refresh"
  );
} catch (error) {
  console.error(error);
  console.error("chrome:", chrome.join(" | "));
  console.error("events:", events.map((event) => event.type).join(", "));
  exitCode = 1;
} finally {
  await browser.close();
  app.close();
  idp.close();
  rmSync(certDir, { force: true, recursive: true });
}
process.exit(exitCode);
