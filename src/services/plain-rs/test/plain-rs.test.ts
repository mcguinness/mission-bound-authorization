/**
 * RFC 9068 / RFC 9449 / RFC 6750 behavior of the plain Resource Server, driven
 * by a local signing key (no Authorization Server): scope-only authorization,
 * the `insufficient_scope` challenge, DPoP binding, introspection mode and its
 * failure contract, and the access token's time boundaries under an injected
 * clock.
 */
import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type PlainRsHandler, type PlainRsOptions, plainResourceServer, startPlainResourceServer } from "../src/index.js";

const PORT = 14711;
const INTROSPECT_PORT = 14712;
const BASE = `http://localhost:${PORT}`;
const ISSUER = "https://as.test";
const AUDIENCE = "https://rs.test/api";

let asKey: CryptoKey;
let jwks: { keys: JWK[] };
let dpopKeys: CryptoKeyPair;
let dpopJwk: JWK;
let jkt: string;
let rs: Server;
let rsIntrospecting: Server;
let introspection: Server;
let active = true;
/** The DPoP key's thumbprint (a well-formed 43-character jkt). */
const jkt43 = () => jkt;

async function accessToken(claims: Record<string, unknown> = {}, typ = "at+jwt"): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: ISSUER,
    sub: "alice",
    aud: AUDIENCE,
    iat: now,
    exp: now + 300,
    jti: crypto.randomUUID(),
    client_id: "client-1",
    scope: "reports.read",
    cnf: { jkt },
    ...claims,
  })
    .setProtectedHeader({ alg: "ES256", kid: "k1", typ })
    .sign(asKey);
}

async function proof(htm: string, url: string, token: string, jti = crypto.randomUUID()): Promise<string> {
  return new SignJWT({ htm, htu: url, ath: createHash("sha256").update(token).digest("base64url") })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopJwk })
    .setIssuedAt()
    .setJti(jti)
    .sign(dpopKeys.privateKey);
}

async function call(method: string, token: string, opts: { base?: string; scheme?: string; dpop?: string | null } = {}) {
  const url = `${opts.base ?? BASE}/api/reports`;
  const dpop = opts.dpop === undefined ? await proof(method, url, token) : opts.dpop;
  return fetch(url, {
    method,
    headers: {
      authorization: `${opts.scheme ?? "DPoP"} ${token}`,
      ...(dpop ? { dpop } : {}),
      ...(method === "POST" ? { "content-type": "application/json" } : {}),
    },
    ...(method === "POST" ? { body: JSON.stringify({ title: "q3" }) } : {}),
  });
}

beforeAll(async () => {
  const k = await generateKeyPair("ES256", { extractable: true });
  asKey = k.privateKey;
  jwks = { keys: [{ ...(await exportJWK(k.publicKey)), kid: "k1", alg: "ES256" }] };
  dpopKeys = await generateKeyPair("ES256", { extractable: true });
  dpopJwk = await exportJWK(dpopKeys.publicKey);
  jkt = await calculateJwkThumbprint(dpopJwk);
  rs = await startPlainResourceServer({ issuer: ISSUER, audience: AUDIENCE, jwks, baseUrl: BASE }, PORT);
  introspection = createServer((req, res) => {
    const ok = req.headers.authorization === `Basic ${Buffer.from("rs-1:s3cret").toString("base64")}`;
    res.writeHead(ok ? 200 : 401, { "content-type": "application/json" });
    res.end(JSON.stringify(ok ? { active, scope: "reports.write" } : { error: "invalid_client" }));
  });
  await new Promise<void>((r) => introspection.listen(INTROSPECT_PORT, () => r()));
  rsIntrospecting = await startPlainResourceServer(
    {
      issuer: ISSUER,
      audience: AUDIENCE,
      jwks,
      baseUrl: `http://localhost:${PORT + 10}`,
      introspection: { endpoint: `http://localhost:${INTROSPECT_PORT}/introspect`, clientId: "rs-1", clientSecret: "s3cret" },
    },
    PORT + 10,
  );
});

afterAll(() => {
  rs?.close();
  rsIntrospecting?.close();
  introspection?.close();
});

describe("plain-rs scope-only authorization", () => {
  it("allows an operation the token's scope covers and refuses one it does not with 403 insufficient_scope", async () => {
    const token = await accessToken();
    const ok = await call("GET", token);
    expect(ok.status).toBe(200);
    const denied = await call("POST", token);
    expect(denied.status).toBe(403);
    expect(((await denied.json()) as { error: string }).error).toBe("insufficient_scope");
    expect(denied.headers.get("www-authenticate")).toMatch(/^DPoP error="insufficient_scope".*scope="reports\.write"/);
  });

  it("a token with no scope claim authorizes nothing", async () => {
    const res = await call("GET", await accessToken({ scope: undefined }));
    expect(res.status).toBe(403);
  });
});

describe("plain-rs RFC 9068 / RFC 9449 validation", () => {
  it("refuses a wrong typ, a wrong audience or issuer, and an expired token", async () => {
    expect((await call("GET", await accessToken({}, "JWT"))).status).toBe(401);
    expect((await call("GET", await accessToken({ aud: "https://elsewhere.test" }))).status).toBe(401);
    expect((await call("GET", await accessToken({ iss: "https://evil.test" }))).status).toBe(401);
    expect((await call("GET", await accessToken({ exp: Math.floor(Date.now() / 1000) - 10 }))).status).toBe(401);
  });

  it("refuses a DPoP-bound token under Bearer, a missing or replayed proof, and a proof from another key", async () => {
    const token = await accessToken();
    expect((await call("GET", token, { scheme: "Bearer", dpop: null })).status).toBe(401);
    expect((await call("GET", token, { dpop: null })).status).toBe(401);
    const once = await proof("GET", `${BASE}/api/reports`, token);
    expect((await call("GET", token, { dpop: once })).status).toBe(200);
    expect((await call("GET", token, { dpop: once })).status).toBe(401);
    const stranger = await calculateJwkThumbprint(await exportJWK((await generateKeyPair("ES256")).publicKey));
    const other = await accessToken({ cnf: { jkt: stranger } });
    const res = await call("GET", other);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toMatch(/invalid_dpop_proof/);
  });
});

describe("plain-rs confirmation methods (RFC 7800, RFC 8705, RFC 9449)", () => {
  const refusedAs = async (res: Response) => {
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: string; error_description: string }).error_description).toBe(
      "unsupported or malformed confirmation method",
    );
    expect(res.headers.get("www-authenticate")).toMatch(/error="invalid_token"/);
  };

  it("refuses a certificate-bound (x5t#S256) token rather than accepting it as bearer", async () => {
    const token = await accessToken({ cnf: { "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" } });
    await refusedAs(await call("GET", token, { scheme: "Bearer", dpop: null }));
    await refusedAs(await call("GET", token));
  });

  it("refuses a malformed jkt: wrong length, padded, non-base64url, or not a string", async () => {
    for (const jkt of [jkt43().slice(0, 42), `${jkt43()}=`, `${jkt43().slice(0, 42)}+`, 42, null, { v: "x" }]) {
      const token = await accessToken({ cnf: { jkt } });
      await refusedAs(await call("GET", token));
      await refusedAs(await call("GET", token, { scheme: "Bearer", dpop: null }));
    }
  });

  it("refuses a cnf carrying jkt plus another member, and a cnf that is not an object", async () => {
    await refusedAs(await call("GET", await accessToken({ cnf: { jkt: jkt43(), "x5t#S256": jkt43() } })));
    await refusedAs(await call("GET", await accessToken({ cnf: { jkt: jkt43(), kid: "k" } })));
    for (const cnf of ["jkt", [jkt43()], null, {}]) {
      await refusedAs(await call("GET", await accessToken({ cnf }), { scheme: "Bearer", dpop: null }));
    }
  });

  it("a well-formed jkt-only cnf keeps DPoP handling, and a token with no cnf stays a bearer token", async () => {
    expect((await call("GET", await accessToken())).status).toBe(200);
    expect((await call("GET", await accessToken({ cnf: undefined }), { scheme: "Bearer", dpop: null })).status).toBe(
      200,
    );
  });
});

describe("plain-rs introspection mode", () => {
  it("honors only `active`: an inactive token is refused even when its JWT is valid, and an introspected scope grants nothing", async () => {
    const base = `http://localhost:${PORT + 10}`;
    active = true;
    const token = await accessToken();
    expect((await call("GET", token, { base })).status).toBe(200);
    // The introspection response names reports.write; authorization still reads the JWT scope.
    expect((await call("POST", token, { base })).status).toBe(403);
    active = false;
    const res = await call("GET", token, { base });
    expect(res.status).toBe(401);
    expect(((await res.json()) as { error: string }).error).toBe("invalid_token");
    active = true;
  });
});

/** Serve a handler on `port`, returning the server and the handler (for `performed`). */
async function serve(port: number, opts: PlainRsOptions): Promise<{ server: Server; handler: PlainRsHandler }> {
  const handler = plainResourceServer(opts);
  const server = createServer((req, res) => {
    void handler(req, res);
  });
  await new Promise<void>((r) => server.listen(port, () => r()));
  return { server, handler };
}

/** A Bearer access token (no `cnf`) carrying `reports.write`, times relative to `t`. */
async function bearer(t: number, claims: Record<string, unknown> = {}): Promise<string> {
  return accessToken({ cnf: undefined, scope: "reports.read reports.write", iat: t - 10, exp: t + 300, ...claims });
}

/** POST /api/reports with a Bearer token (no DPoP proof). */
function postBearer(base: string, token: string) {
  return fetch(`${base}/api/reports`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ title: "q4" }),
  });
}

describe("plain-rs introspection failure contract (#873)", () => {
  const STUB_PORT = 14713;
  const RS_PORT = 14714;
  const DEAD_RS_PORT = 14715;
  const DEAD_PORT = 14716;
  const TIMEOUT_MS = 150;
  const base = `http://localhost:${RS_PORT}`;
  /** What the stub answers: a status, a raw body, and an optional delay. */
  let reply: { status: number; body: string; delayMs?: number } = { status: 200, body: '{"active":true}' };
  let calls = 0;
  let stub: Server;
  let rsServer: Server;
  let handler: PlainRsHandler;
  let dead: { server: Server; handler: PlainRsHandler };
  const settings = (endpoint: string) => ({
    endpoint,
    clientId: "rs-1",
    clientSecret: "s3cret",
    timeoutMs: TIMEOUT_MS,
  });

  beforeAll(async () => {
    stub = createServer((_req, res) => {
      calls += 1;
      const { status, body, delayMs } = reply;
      const answer = () => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(body);
      };
      if (delayMs) setTimeout(answer, delayMs).unref();
      else answer();
    });
    await new Promise<void>((r) => stub.listen(STUB_PORT, () => r()));
    ({ server: rsServer, handler } = await serve(RS_PORT, {
      issuer: ISSUER,
      audience: AUDIENCE,
      jwks,
      baseUrl: base,
      introspection: settings(`http://localhost:${STUB_PORT}/introspect`),
    }));
    dead = await serve(DEAD_RS_PORT, {
      issuer: ISSUER,
      audience: AUDIENCE,
      jwks,
      baseUrl: `http://localhost:${DEAD_RS_PORT}`,
      introspection: settings(`http://localhost:${DEAD_PORT}/introspect`),
    });
  });

  afterAll(() => {
    stub?.closeAllConnections?.();
    stub?.close();
    rsServer?.close();
    dead?.server.close();
  });

  /** POST under the stub's `r` reply; asserts the status/error and that no operation ran. */
  async function refusedWith(r: typeof reply, status: number, error: string) {
    reply = r;
    const before = handler.performed;
    const res = await postBearer(base, await bearer(Math.floor(Date.now() / 1000)));
    expect(res.status).toBe(status);
    expect(((await res.json()) as { error: string }).error).toBe(error);
    expect(handler.performed).toBe(before);
  }

  it("a 500 from the introspection endpoint refuses 503 temporarily_unavailable before the operation", async () => {
    await refusedWith({ status: 500, body: '{"active":true}' }, 503, "temporarily_unavailable");
  });

  it("an unreachable introspection endpoint (connection refused) refuses 503 temporarily_unavailable before the operation", async () => {
    const before = dead.handler.performed;
    const res = await postBearer(`http://localhost:${DEAD_RS_PORT}`, await bearer(Math.floor(Date.now() / 1000)));
    expect(res.status).toBe(503);
    expect(((await res.json()) as { error: string }).error).toBe("temporarily_unavailable");
    expect(dead.handler.performed).toBe(before);
  });

  it("a body that is not JSON refuses 503 temporarily_unavailable before the operation", async () => {
    await refusedWith({ status: 200, body: "{active: true" }, 503, "temporarily_unavailable");
  });

  it("a JSON null body refuses 503 temporarily_unavailable, never 500", async () => {
    await refusedWith({ status: 200, body: "null" }, 503, "temporarily_unavailable");
  });

  it("a JSON array, number or string body refuses 503 temporarily_unavailable", async () => {
    for (const body of ['[{"active":true}]', "1", '"active"']) {
      await refusedWith({ status: 200, body }, 503, "temporarily_unavailable");
    }
  });

  it("an object with no active member refuses 401 invalid_token before the operation", async () => {
    await refusedWith({ status: 200, body: "{}" }, 401, "invalid_token");
  });

  it('an object whose active is the string "true" refuses 401 invalid_token before the operation', async () => {
    await refusedWith({ status: 200, body: '{"active":"true"}' }, 401, "invalid_token");
  });

  it("a response slower than the introspection timeout refuses 503 temporarily_unavailable within about the timeout", async () => {
    const started = Date.now();
    await refusedWith({ status: 200, body: '{"active":true}', delayMs: 3000 }, 503, "temporarily_unavailable");
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThanOrEqual(TIMEOUT_MS - 20);
    expect(elapsed).toBeLessThan(1500);
  });

  it("active true admits the operation", async () => {
    reply = { status: 200, body: '{"active":true}' };
    const before = handler.performed;
    const res = await postBearer(base, await bearer(Math.floor(Date.now() / 1000)));
    expect(res.status).toBe(201);
    expect(handler.performed).toBe(before + 1);
  });

  it("introspects every request: two requests make two calls, and a positive first result does not admit the second once the endpoint says active false", async () => {
    const token = await bearer(Math.floor(Date.now() / 1000));
    reply = { status: 200, body: '{"active":true}' };
    const startCalls = calls;
    const before = handler.performed;
    expect((await postBearer(base, token)).status).toBe(201);
    reply = { status: 200, body: '{"active":false}' };
    const second = await postBearer(base, token);
    expect(second.status).toBe(401);
    expect(calls - startCalls).toBe(2);
    expect(handler.performed).toBe(before + 1);
  });
});

describe("plain-rs access-token time boundaries (injected clock)", () => {
  // An injected clock an hour ahead of the system clock, so a boundary the
  // server decides on its own clock differs from one decided on the system's.
  const T = Math.floor(Date.now() / 1000) + 3600;
  const opts = (port: number, extra: Partial<PlainRsOptions> = {}): PlainRsOptions => ({
    issuer: ISSUER,
    audience: AUDIENCE,
    jwks,
    baseUrl: `http://localhost:${port}`,
    now: () => T,
    ...extra,
  });
  let strict: { server: Server; handler: PlainRsHandler };
  let tolerant: { server: Server; handler: PlainRsHandler };
  beforeAll(async () => {
    strict = await serve(14717, opts(14717));
    tolerant = await serve(14718, opts(14718, { clockToleranceSeconds: 5 }));
  });
  afterAll(() => {
    strict?.server.close();
    tolerant?.server.close();
  });

  it("with clock tolerance 0, a token whose exp is 1 s before now is refused and one whose exp is 1 s after now is accepted", async () => {
    const before = strict.handler.performed;
    const late = await postBearer("http://localhost:14717", await bearer(T, { exp: T - 1 }));
    expect(late.status).toBe(401);
    expect(((await late.json()) as { error: string }).error).toBe("invalid_token");
    expect(strict.handler.performed).toBe(before);
    expect((await postBearer("http://localhost:14717", await bearer(T, { exp: T + 1 }))).status).toBe(201);
  });

  it("with clock tolerance 5 s, a token 3 s past exp is accepted and one 6 s past exp is refused", async () => {
    expect((await postBearer("http://localhost:14718", await bearer(T, { exp: T - 3 }))).status).toBe(201);
    const before = tolerant.handler.performed;
    const late = await postBearer("http://localhost:14718", await bearer(T, { exp: T - 6 }));
    expect(late.status).toBe(401);
    expect(tolerant.handler.performed).toBe(before);
  });

  it("a DPoP proof whose iat is exactly 60 s either side of now is accepted, and 61 s is refused", async () => {
    const url = "http://localhost:14717/api/reports";
    const at = (iat: number, token: string) =>
      new SignJWT({ htm: "POST", htu: url, ath: createHash("sha256").update(token).digest("base64url") })
        .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopJwk })
        .setIssuedAt(iat)
        .setJti(crypto.randomUUID())
        .sign(dpopKeys.privateKey);
    const send = async (iat: number) => {
      const token = await accessToken({ scope: "reports.write", iat: T - 10, exp: T + 300 });
      return fetch(url, {
        method: "POST",
        headers: { authorization: `DPoP ${token}`, dpop: await at(iat, token), "content-type": "application/json" },
        body: "{}",
      });
    };
    expect((await send(T - 60)).status).toBe(201);
    expect((await send(T + 60)).status).toBe(201);
    const before = strict.handler.performed;
    for (const iat of [T - 61, T + 61]) {
      const res = await send(iat);
      expect(res.status).toBe(401);
      expect(((await res.json()) as { error: string }).error).toBe("invalid_dpop_proof");
    }
    expect(strict.handler.performed).toBe(before);
  });
});
