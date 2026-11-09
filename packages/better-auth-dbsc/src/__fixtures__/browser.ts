/**
 * A tiny cookie-jar "browser" that talks to `auth.handler`, enough to drive
 * the DBSC flow the way Chrome does (headers in, headers out).
 */
export const BASE_URL = "http://localhost:3000";

const REGISTRATION_PATTERN =
  /^\((?<algorithms>[^)]*)\);path="(?<path>[^"]*)";challenge="(?<challenge>[^"]*)"(?:;authorization="(?<authorization>[^"]*)")?$/u;
const CHALLENGE_PATTERN = /^"(?<challenge>[^"]*)";id="(?<id>[^"]*)"$/u;

const parseSetCookie = (header: string) => {
  const [pair = "", ...attributes] = header.split(";");
  const separator = pair.indexOf("=");
  const maxAge = attributes
    .map((attribute) => attribute.trim())
    .find((attribute) => attribute.toLowerCase().startsWith("max-age="));
  return {
    attributes: attributes.map((attribute) => attribute.trim()),
    expired: maxAge !== undefined && Number(maxAge.split("=")[1]) <= 0,
    name: pair.slice(0, separator).trim(),
    value: pair.slice(separator + 1).trim(),
  };
};

export class Browser {
  readonly cookies = new Map<string, string>();
  /** Set-Cookie headers seen, newest last. */
  readonly setCookies: ReturnType<typeof parseSetCookie>[] = [];

  private readonly handler: (request: Request) => Promise<Response>;

  constructor(handler: (request: Request) => Promise<Response>) {
    this.handler = handler;
  }

  cookieHeader(filter: (name: string) => boolean = () => true): string {
    return [...this.cookies]
      .filter(([name]) => filter(name))
      .map(([name, value]) => `${name}=${value}`)
      .join("; ");
  }

  async fetch(
    path: string,
    init: {
      method?: string;
      headers?: Record<string, string>;
      body?: unknown;
      cookies?: string;
    } = {}
  ): Promise<Response> {
    // Like Chrome: Sec-Fetch-Site on every request and Origin on POSTs.
    // Tests override them; an empty value removes the header.
    const method = init.method ?? (init.body === undefined ? "GET" : "POST");
    // Lower-case the overrides: Headers would join "Sec-Fetch-Site" and
    // "sec-fetch-site" into one comma-separated value.
    const overrides = Object.fromEntries(
      Object.entries(init.headers ?? {}).map(([name, value]) => [
        name.toLowerCase(),
        value,
      ])
    );
    const headers = new Headers({
      "sec-fetch-site": "same-origin",
      ...(method === "GET" ? {} : { origin: BASE_URL }),
      ...overrides,
    });
    // Collect first: deleting while iterating Headers skips entries.
    const emptied = [...headers]
      .filter(([, value]) => value === "")
      .map(([name]) => name);
    for (const name of emptied) {
      headers.delete(name);
    }
    const cookie = init.cookies ?? this.cookieHeader();
    if (cookie) {
      headers.set("cookie", cookie);
    }
    let body: string | undefined;
    if (init.body !== undefined) {
      headers.set("content-type", "application/json");
      body = JSON.stringify(init.body);
    }
    const response = await this.handler(
      new Request(`${BASE_URL}/api/auth${path}`, {
        body,
        headers,
        method: init.method ?? (body ? "POST" : "GET"),
      })
    );
    for (const header of response.headers.getSetCookie()) {
      const parsed = parseSetCookie(header);
      this.setCookies.push(parsed);
      if (parsed.expired) {
        this.cookies.delete(parsed.name);
      } else {
        this.cookies.set(parsed.name, parsed.value);
      }
    }
    return response;
  }
}

export const parseRegistrationHeader = (value: string | null) => {
  const match = REGISTRATION_PATTERN.exec(value ?? "");
  if (!match) {
    throw new Error(`Unexpected registration header: ${value}`);
  }
  return {
    algorithms: (match.groups?.algorithms ?? "").split(" "),
    authorization: match.groups?.authorization,
    challenge: match.groups?.challenge ?? "",
    path: match.groups?.path ?? "",
  };
};

export const parseChallengeHeader = (value: string | null) => {
  const match = CHALLENGE_PATTERN.exec(value ?? "");
  if (!match) {
    throw new Error(`Unexpected challenge header: ${value}`);
  }
  return {
    challenge: match.groups?.challenge ?? "",
    sessionId: match.groups?.id ?? "",
  };
};
