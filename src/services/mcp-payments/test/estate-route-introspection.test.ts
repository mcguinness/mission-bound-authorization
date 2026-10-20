/**
 * @spec authority-server#mission-join rule 8, authority-server#limitations (#818 slice 3; RFC 7662)
 *
 * The estate route with introspection configured: an opaque access token's
 * facts come from the estate's introspection response, qualified by the
 * route's own (estate) issuer, under the same audience rule as a JWT and with
 * the request's DPoP proof bound to the introspected `cnf.jkt`. A compact JWS
 * still takes the JWT path. FGA-independent: no PEP is reached.
 */

import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  CANONICAL_RESOURCE,
  type DpopKeys,
  dpopProofFor,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
} from "../src/index.js";

const ESTATE = "https://estate.test";
const HTU = CANONICAL_RESOURCE;
const HTM = "POST";
const OPAQUE = "XgZGsaFKSB3N-qXOtBNFCOav9ILZQe5-rD2iM5_6EID";

let holder: DpopKeys;
let holderJkt: string;
let signKey: CryptoKey;
let jwk: Record<string, unknown>;
let answer: Record<string, unknown>;
const seen: string[] = [];
let stub: Server;
let endpoint: string;

const read = (req: IncomingMessage): Promise<string> =>
  new Promise((resolve) => {
    let s = "";
    req.on("data", (c) => {
      s += c;
    });
    req.on("end", () => resolve(s));
  });

function server(over: { ordinaryOnly?: boolean; introspection?: boolean; now?: () => Date } = {}): McpPaymentsServer {
  return new McpPaymentsServer({
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
    pep: undefined as never, // token validation alone never reaches the PEP
    payments: new PaymentsStore(),
    loadView: () => undefined,
    jwks: { keys: [jwk as never] },
    keyRoles: { accessToken: ["estate-key"], attenuationRoot: [], transactionToken: [] },
    issuer: ESTATE,
    ordinaryOnly: over.ordinaryOnly ?? true,
    ...((over.introspection ?? true)
      ? {
          introspection: {
            endpoint,
            clientId: "gw",
            clientSecret: "s",
            timeoutMs: 500,
            cacheMaxSeconds: 0,
            ...(over.now ? { now: over.now } : {}),
          },
        }
      : {}),
  });
}

async function present(s: McpPaymentsServer, token: string, keys: DpopKeys = holder) {
  return s.validateGatewayCredential(token, { proof: await dpopProofFor(keys, HTU, HTM, token), htu: HTU, htm: HTM }, true);
}

beforeAll(async () => {
  holder = await generateKeyPair("ES256", { extractable: true });
  holderJkt = await calculateJwkThumbprint(await exportJWK(holder.publicKey));
  const kp = await generateKeyPair("ES256", { extractable: true });
  signKey = kp.privateKey;
  jwk = { ...(await exportJWK(kp.publicKey)), kid: "estate-key", alg: "ES256" };
  stub = createServer(async (req, res) => {
    seen.push(await read(req));
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(answer));
  });
  await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", () => resolve()));
  const addr = stub.address();
  endpoint = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}/introspect`;
});
afterAll(async () => {
  stub.closeAllConnections();
  await new Promise<void>((resolve) => stub.close(() => resolve()));
});
beforeEach(() => {
  seen.length = 0;
  const now = Math.floor(Date.now() / 1000);
  answer = {
    active: true,
    iss: ESTATE,
    sub: "u-1001",
    client_id: "estate-opaque-bot",
    aud: CANONICAL_RESOURCE,
    scope: "invoices.read",
    exp: now + 300,
    iat: now,
    cnf: { jkt: holderJkt },
    token_type: "DPoP",
  };
});

describe("estate route with introspection: an opaque token (#818 slice 3)", () => {
  it("admits an opaque token as ordinary facts from its introspection, qualified by the estate issuer", async () => {
    const admitted = present(server(), OPAQUE);
    await expect(admitted).resolves.toMatchObject({ sub: "u-1001", clientId: "estate-opaque-bot", scope: "invoices.read", iss: ESTATE });
    const facts = await admitted;
    expect(facts.mission).toBeUndefined();
    expect(facts.credential?.issuer).toBe(ESTATE);
    expect(facts.cnfJkt).toBe(holderJkt);
    expect(seen).toHaveLength(1);
  });

  it("refuses an opaque token presented with a DPoP proof by a key other than the introspected cnf.jkt", async () => {
    const other = await generateKeyPair("ES256", { extractable: true });
    await expect(present(server(), OPAQUE, other)).rejects.toThrow();
    expect(seen).toHaveLength(1);
  });

  it("refuses an opaque token introspected for another resource, under the same audience rule as a JWT", async () => {
    answer = { ...answer, aud: "https://ledger.estate.invalid/api" };
    await expect(present(server(), OPAQUE)).rejects.toThrow(/audience/);
  });

  it("still takes the JWT path for a compact JWS, calling no introspection", async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = await new SignJWT({ client_id: "estate-bot", scope: "invoices.read", cnf: { jkt: holderJkt }, jti: randomUUID() })
      .setProtectedHeader({ alg: "ES256", kid: "estate-key", typ: "at+jwt" })
      .setIssuer(ESTATE)
      .setAudience(CANONICAL_RESOURCE)
      .setSubject("u-1001")
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(signKey);
    await expect(present(server(), jwt)).resolves.toMatchObject({ clientId: "estate-bot" });
    expect(seen).toHaveLength(0);
  });

  it("refuses to configure introspection on a route whose issuer is a Mission Issuer", () => {
    expect(() => server({ ordinaryOnly: false })).toThrow(/ordinaryOnly/);
  });
});

describe("estate route with introspection: expiry is re-checked at admission (#1400 review)", () => {
  it("refuses a token whose exp passes after the adapter accepted it, before admission completes", async () => {
    // Time passes across the awaits: this clock moves one second forward at
    // each reading. The adapter reads it twice (the cache lookup, then once
    // the answer is in) and accepts a token whose exp is two seconds after the
    // first reading; admission's own re-check is the third reading, at exp.
    const startMs = Math.floor(Date.now() / 1000) * 1000;
    let readings = 0;
    const stepping = () => new Date(startMs + 1000 * readings++);
    answer = { ...answer, exp: startMs / 1000 + 2 };
    await expect(present(server({ now: stepping }), OPAQUE)).rejects.toThrow(/expired while being admitted/);
    expect(readings).toBe(3);
  });
});
