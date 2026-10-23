/**
 * @spec authority-server#mission-join rule 8 (#818 slice 3; RFC 7662)
 *
 * The estate route's introspection adapter (`TokenIntrospector`) against a
 * local introspection endpoint whose answer each test sets: the facts it reads
 * from an active response, the authenticated call it makes, every fail-closed
 * refusal (no answer, an inactive or unusable answer), and the cache bounds
 * (a positive result for at most `cacheMaxSeconds` and never past `exp`; a
 * negative one never). FGA-independent.
 */

import { createServer, type IncomingMessage, type Server } from "node:http";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { IntrospectionTokenTypeUnsupportedError, IntrospectionUnavailableError, TokenInactiveError, TokenIntrospector } from "../src/index.js";

const ESTATE = "https://estate.test";
const AUD = "http://localhost:4403/mcp";

/** What the endpoint answers next, and what it saw. */
let answer: { status: number; body: string; delayMs?: number; location?: string };
/** Runs while a call is in flight, before the endpoint answers. */
let onRequest: (() => void) | undefined;
const seen: { authorization?: string; body: string }[] = [];
let server: Server;
let endpoint: string;

const read = (req: IncomingMessage): Promise<string> =>
  new Promise((resolve) => {
    let s = "";
    req.on("data", (c) => {
      s += c;
    });
    req.on("end", () => resolve(s));
  });

const nowS = () => Math.floor(Date.now() / 1000);
const active = (over: Record<string, unknown> = {}) =>
  JSON.stringify({
    active: true,
    iss: ESTATE,
    sub: "u-1001",
    client_id: "estate-opaque-bot",
    aud: AUD,
    scope: "invoices.read",
    exp: nowS() + 300,
    iat: nowS(),
    cnf: { jkt: "jkt-1" },
    token_type: "DPoP",
    ...over,
  });

function introspector(over: { cacheMaxSeconds?: number; now?: () => Date; timeoutMs?: number } = {}) {
  return new TokenIntrospector(
    {
      endpoint,
      clientId: "gateway-introspector",
      clientSecret: "s3cret",
      timeoutMs: over.timeoutMs ?? 500,
      cacheMaxSeconds: over.cacheMaxSeconds ?? 60,
      ...(over.now ? { now: over.now } : {}),
    },
    ESTATE,
  );
}

/** A clock the test moves. */
function clock() {
  let offset = 0;
  return { now: () => new Date(Date.now() + offset), advance: (s: number) => { offset += s * 1000; } };
}

beforeAll(async () => {
  server = createServer(async (req, res) => {
    const body = await read(req);
    seen.push({ ...(req.headers.authorization ? { authorization: req.headers.authorization } : {}), body });
    onRequest?.();
    // Where a redirect points: the estate's unsupported-type answer, so a
    // client that followed redirects would read it.
    if (req.url === "/elsewhere") {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "unsupported_token_type" }));
      return;
    }
    const { status, body: out, delayMs, location } = answer;
    if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
    res.writeHead(status, { "content-type": "application/json", ...(location ? { location } : {}) });
    res.end(out);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const addr = server.address();
  endpoint = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}/introspect`;
});
afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});
beforeEach(() => {
  onRequest = undefined;
  seen.length = 0;
  answer = { status: 200, body: active() };
});

describe("token introspection: an active answer (RFC 7662, #818 slice 3)", () => {
  it("reads sub, client_id, scope, aud, exp and cnf.jkt, from an authenticated call naming the token", async () => {
    const token = await introspector().introspect("opaque-token-1");
    expect(token).toMatchObject({ sub: "u-1001", clientId: "estate-opaque-bot", scope: "invoices.read", aud: [AUD], cnfJkt: "jkt-1" });
    expect(seen[0]?.authorization).toBe(`Basic ${Buffer.from("gateway-introspector:s3cret").toString("base64")}`);
    expect(new URLSearchParams(seen[0]?.body)).toEqual(new URLSearchParams({ token: "opaque-token-1", token_type_hint: "access_token" }));
  });
});

describe("token introspection: fail-closed refusals (RFC 7662, #818 slice 3)", () => {
  it("refuses an inactive token, and does not cache the refusal", async () => {
    // Every other member present, so `active` alone decides.
    answer = { status: 200, body: active({ active: false }) };
    const i = introspector();
    await expect(i.introspect("revoked")).rejects.toBeInstanceOf(TokenInactiveError);
    await expect(i.introspect("revoked")).rejects.toBeInstanceOf(TokenInactiveError);
    expect(seen).toHaveLength(2);
  });

  it("fails closed as unavailable when the estate does not answer within the timeout", async () => {
    answer = { status: 200, body: active(), delayMs: 400 };
    const started = Date.now();
    await expect(introspector({ timeoutMs: 100 }).introspect("slow")).rejects.toBeInstanceOf(IntrospectionUnavailableError);
    expect(Date.now() - started).toBeLessThan(380);
  });

  it("fails closed as unavailable on an error status or a body that is not a JSON object", async () => {
    answer = { status: 500, body: "{}" };
    await expect(introspector().introspect("t")).rejects.toBeInstanceOf(IntrospectionUnavailableError);
    answer = { status: 200, body: "not json" };
    await expect(introspector().introspect("t")).rejects.toBeInstanceOf(IntrospectionUnavailableError);
    answer = { status: 200, body: "[true]" };
    await expect(introspector().introspect("t")).rejects.toBeInstanceOf(IntrospectionUnavailableError);
  });

  it("refuses an answer naming another issuer", async () => {
    answer = { status: 200, body: active({ iss: "https://mas.test" }) };
    await expect(introspector().introspect("t")).rejects.toThrow(/another issuer/);
  });

  it("refuses a token that is not sender-constrained (no cnf.jkt)", async () => {
    answer = { status: 200, body: active({ cnf: undefined }) };
    await expect(introspector().introspect("t")).rejects.toThrow(/cnf\.jkt/);
  });

  it("refuses a non-DPoP token type, a passed exp, and a missing sub, client_id or aud", async () => {
    for (const over of [{ token_type: "refresh_token" }, { exp: nowS() - 1 }, { sub: undefined }, { client_id: "" }, { aud: undefined }]) {
      answer = { status: 200, body: active(over) };
      await expect(introspector().introspect("t"), JSON.stringify(over)).rejects.toBeInstanceOf(TokenInactiveError);
    }
  });
});

describe("token introspection: the estate's unsupported-token-type answer (#1454 review)", () => {
  const unsupported = JSON.stringify({ error: "unsupported_token_type", error_description: "structured tokens cannot be introspected" });

  it("names an unsupported token type only for an HTTP 400 whose error is exactly unsupported_token_type", async () => {
    answer = { status: 400, body: unsupported };
    await expect(introspector().introspect("jwt")).rejects.toBeInstanceOf(IntrospectionTokenTypeUnsupportedError);
  });

  it("is unavailable, not an unsupported token type, for any other status carrying that error, another 400 error, or a redirect to that answer", async () => {
    const cases: Array<[string, typeof answer]> = [
      ["401", { status: 401, body: unsupported }],
      ["403", { status: 403, body: unsupported }],
      ["429", { status: 429, body: unsupported }],
      ["500", { status: 500, body: unsupported }],
      ["503", { status: 503, body: unsupported }],
      ["a 400 with another error", { status: 400, body: JSON.stringify({ error: "invalid_request" }) }],
      ["a 302 to the 400 answer", { status: 302, body: "{}", location: endpoint.replace("/introspect", "/elsewhere") }],
    ];
    for (const [label, next] of cases) {
      answer = next;
      const refused = await introspector().introspect("jwt").catch((e: unknown) => e);
      expect(refused, label).toBeInstanceOf(IntrospectionUnavailableError);
      expect(refused, label).not.toBeInstanceOf(IntrospectionTokenTypeUnsupportedError);
    }
  });
});

describe("token introspection: the cache bounds (RFC 7662, #818 slice 3)", () => {
  it("caches a positive answer for at most cacheMaxSeconds", async () => {
    const c = clock();
    const i = introspector({ cacheMaxSeconds: 60, now: c.now });
    await i.introspect("cached");
    await i.introspect("cached");
    expect(seen).toHaveLength(1);
    c.advance(61);
    answer = { status: 200, body: JSON.stringify({ active: false }) };
    await expect(i.introspect("cached")).rejects.toBeInstanceOf(TokenInactiveError);
    expect(seen).toHaveLength(2);
  });

  it("never keeps a positive answer past the token's exp, though cacheMaxSeconds is longer", async () => {
    const c = clock();
    answer = { status: 200, body: active({ exp: nowS() + 5 }) };
    const i = introspector({ cacheMaxSeconds: 60, now: c.now });
    await i.introspect("short-lived");
    c.advance(6);
    answer = { status: 200, body: JSON.stringify({ active: false }) };
    await expect(i.introspect("short-lived")).rejects.toBeInstanceOf(TokenInactiveError);
    expect(seen).toHaveLength(2);
  });
});

describe("token introspection: expiry is checked after the answer arrives (#1400 review)", () => {
  it("refuses a token that expires while its introspection is in flight, and keeps no cache entry for it", async () => {
    const c = clock();
    answer = { status: 200, body: active({ exp: nowS() + 5 }) };
    onRequest = () => c.advance(10);
    const i = introspector({ cacheMaxSeconds: 60, now: c.now });
    await expect(i.introspect("expiring-in-flight")).rejects.toThrow(/expired/);
    onRequest = undefined;
    await expect(i.introspect("expiring-in-flight")).rejects.toThrow(/expired/);
    expect(seen).toHaveLength(2);
  });
});
