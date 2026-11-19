/**
 * @spec mission#scope-projection-per-audience, mission#rs-requirements (#2072):
 * the mixed Resource Server alone, with locally signed tokens. The same
 * server under AS-issued tokens is exercised in
 * services/authorization-server/test/scope-projection.test.ts.
 */
import type { Server } from "node:http";
import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type MixedRsHandler, startMixedResourceServer, WRITE_ACTION } from "../src/index.js";

const PORT = 14680;
const BASE = `http://localhost:${PORT}`;
const ISSUER = "https://as.mixed.test";
const AUDIENCE = "https://rs.mixed.test/api";
const URL_ = `${BASE}/api/reports`;
const CAP = { amount: "100.00", currency: "USD" };
const READ_ENTRY = { type: "mission_resource_access", resource: AUDIENCE, actions: ["reports:report.read"] };
const CAPPED = { type: "mission_resource_access", resource: AUDIENCE, actions: [WRITE_ACTION], constraints: { max_amount: CAP } };

type Keys = { privateKey: CryptoKey; jwk: JWK };
let server: Server;
let handler: MixedRsHandler;
let signing: CryptoKey;
let holder: Keys;

async function accessToken(claims: Record<string, unknown>, aud = AUDIENCE): Promise<string> {
  return new SignJWT({
    client_id: "agent",
    mission: { id: "msn_1", issuer: ISSUER },
    cnf: { jkt: await import("jose").then((j) => j.calculateJwkThumbprint(holder.jwk)) },
    ...claims,
  })
    .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: "k1" })
    .setIssuer(ISSUER)
    .setAudience(aud)
    .setSubject("alice")
    .setIssuedAt()
    .setExpirationTime("5m")
    .setJti(crypto.randomUUID())
    .sign(signing);
}

async function call(method: "GET" | "POST", token: string, cost?: string, keys = holder): Promise<Response> {
  const ath = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token))).toString("base64url");
  const proof = await new SignJWT({ htm: method, htu: URL_, ath })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: keys.jwk })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
  return fetch(URL_, {
    method,
    headers: {
      authorization: `DPoP ${token}`,
      dpop: proof,
      ...(method === "POST" ? { "content-type": "application/json" } : {}),
    },
    ...(method === "POST" ? { body: JSON.stringify({ title: "Q3 audit", cost: { amount: cost, currency: "USD" } }) } : {}),
  });
}

beforeAll(async () => {
  const rsa = await generateKeyPair("RS256", { extractable: true });
  signing = rsa.privateKey;
  const pub = { ...(await exportJWK(rsa.publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  const ec = await generateKeyPair("ES256", { extractable: true });
  holder = { privateKey: ec.privateKey, jwk: await exportJWK(ec.publicKey) };
  ({ server, handler } = await startMixedResourceServer(
    { issuer: ISSUER, audience: AUDIENCE, jwks: { keys: [pub] }, baseUrl: BASE },
    PORT,
  ));
});

afterAll(() => {
  server?.close();
});

describe("the mixed Resource Server (@spec mission#scope-projection-per-audience, mission#rs-requirements, #2072)", () => {
  it("reads on the projected scope alone, and refuses a read without it naming the scope", async () => {
    expect((await call("GET", await accessToken({ scope: "reports.read" }))).status).toBe(200);
    const res = await call("GET", await accessToken({ authorization_details: [READ_ENTRY] }));
    expect(res.status).toBe(403);
    expect(res.headers.get("www-authenticate")).toMatch(/error="insufficient_scope".*scope="reports\.read"/);
  });

  it("performs a write the capped entry covers, and refuses an over-limit write despite the read scope, with no effect", async () => {
    const token = await accessToken({ scope: "reports.read", authorization_details: [READ_ENTRY, CAPPED] });
    const before = handler.reports.length;
    const ok = await call("POST", token, "60.00");
    expect(ok.status).toBe(201);
    expect(handler.reports.length).toBe(before + 1);
    expect(handler.reports.at(-1)).toMatchObject({ cost: { amount: "60.00", currency: "USD" }, mission_id: "msn_1" });
    const over = await call("POST", token, "150.00");
    expect(over.status).toBe(403);
    expect(over.headers.get("www-authenticate")).toMatch(/mission_denial="insufficient_authority"/);
    expect(over.headers.get("www-authenticate")).not.toMatch(/scope=/);
    expect(handler.reports.length).toBe(before + 1);
  });

  it("never grants a write on a scope value: a token carrying a write scope and no covering entry is refused, with no effect", async () => {
    const before = handler.reports.length;
    const res = await call("POST", await accessToken({ scope: "reports.read reports.write", authorization_details: [READ_ENTRY] }), "10.00");
    expect(res.status).toBe(403);
    expect(handler.reports.length).toBe(before);
  });

  it("an entry it cannot fully enforce provides no authority, and leaves another covering entry to authorize alone", async () => {
    const unenforced = { ...CAPPED, constraints: { max_amount: CAP, vendors: ["acme"] } };
    const alone = await call("POST", await accessToken({ authorization_details: [unenforced] }), "10.00");
    expect(alone.status).toBe(403);
    expect(alone.headers.get("www-authenticate")).toMatch(/mission_denial="constraint_unrecognized"/);
    expect((await call("POST", await accessToken({ authorization_details: [unenforced, CAPPED] }), "10.00")).status).toBe(201);
  });

  it("refuses a write without this issuer's mission claim, a token for another audience, and a proof from another key", async () => {
    expect((await call("POST", await accessToken({ authorization_details: [CAPPED], mission: undefined }), "10.00")).status).toBe(401);
    expect((await call("GET", await accessToken({ scope: "reports.read" }, "https://other.test/api"))).status).toBe(401);
    const ec = await generateKeyPair("ES256", { extractable: true });
    const other = { privateKey: ec.privateKey, jwk: await exportJWK(ec.publicKey) };
    expect((await call("GET", await accessToken({ scope: "reports.read" }), undefined, other)).status).toBe(401);
  });
});
