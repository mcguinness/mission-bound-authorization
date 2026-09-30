/**
 * RFC 9068 / RFC 9449 / RFC 6750 behavior of the plain Resource Server, driven
 * by a local signing key (no Authorization Server): scope-only authorization,
 * the `insufficient_scope` challenge, DPoP binding, and introspection mode.
 */
import { createHash } from "node:crypto";
import { createServer, type Server } from "node:http";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startPlainResourceServer } from "../src/index.js";

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
    const other = await accessToken({ cnf: { jkt: "not-this-key" } });
    const res = await call("GET", other);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toMatch(/invalid_dpop_proof/);
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
