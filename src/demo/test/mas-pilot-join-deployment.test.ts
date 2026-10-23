/**
 * @spec authority-server#join-assertion-request, authority-server#enterprise-prerequisites (#1454 review)
 *
 * The pilot MAS's acting-token establishment (`pilotJoinAssertions`) against
 * a stub estate whose introspection answer each test sets, so every branch is
 * driven exactly: the MAS introspects every acting token first; the estate's
 * `unsupported_token_type` error alone sends a JWT to local validation under
 * the estate's published keys; an inactive answer is refused with no local
 * check; an estate that cannot be asked is `unavailable`, with no local
 * fallback; and an opaque token is introspection only. Defined for the
 * owner's confirmation. No OpenFGA.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { ActorRecords } from "@mission/mcp-payments";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadMasPilotConfig, type MasPilotConfig } from "../src/mas-pilot/config.js";
import { pilotJoinAssertions } from "../src/mas-pilot/mas-join-assertions.js";
import { relocateEstate } from "./mas-pilot-support.js";

type Answer = { status: number; body: unknown; delayMs?: number };

let server: Server;
let base: string;
let signer: CryptoKey;
let introspection: (token: string) => Answer;
const asked: string[] = [];

beforeAll(async () => {
  const key = await generateKeyPair("ES256", { extractable: true });
  signer = key.privateKey;
  const jwk = { ...(await exportJWK(key.publicKey)), kid: "stub-estate-1", alg: "ES256", use: "sig" };
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const send = (status: number, body: unknown) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(typeof body === "string" ? body : JSON.stringify(body));
      };
      if (req.url === "/.well-known/openid-configuration") {
        return send(200, { issuer: base, jwks_uri: `${base}/jwks`, introspection_endpoint: `${base}/introspect` });
      }
      if (req.url === "/jwks") return send(200, { keys: [jwk] });
      const token = new URLSearchParams(Buffer.concat(chunks).toString("utf8")).get("token") ?? "";
      asked.push(token);
      const answer = introspection(token);
      setTimeout(() => send(answer.status, answer.body), answer.delayMs ?? 0);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => {
  server.closeAllConnections();
  server.close();
});

/** The pilot's configuration with the estate at the stub, the path declared, and a short introspection deadline. */
function deploymentAtStub() {
  const port = Number(new URL(base).port);
  const moved: MasPilotConfig = relocateEstate(loadMasPilotConfig(), port);
  const config: MasPilotConfig = {
    ...moved,
    introspection: { ...moved.introspection, timeout_ms: 300, cache_max_seconds: 0 },
    join_assertion: { introspection_client_id: "mas-join-introspector", required: false, required_classes: [] },
  };
  return pilotJoinAssertions(config, { introspectionSecret: "stub-secret", actorRecords: new ActorRecords() });
}

/** A JWT access token the stub estate issued, which validates locally under its published key. */
function estateJwt(sub = "u-1001"): Promise<string> {
  return new SignJWT({ client_id: "estate-ap-bot-7f3", aud: CANONICAL_RESOURCE, cnf: { jkt: "jkt-stub" }, scope: "invoices.read" })
    .setProtectedHeader({ alg: "ES256", kid: "stub-estate-1", typ: "at+jwt" })
    .setIssuer(base)
    .setSubject(sub)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(signer);
}

const activeAnswer = (sub: string): Answer => ({
  status: 200,
  body: {
    active: true,
    iss: base,
    sub,
    client_id: "estate-ap-bot-7f3",
    aud: CANONICAL_RESOURCE,
    exp: Math.floor(Date.now() / 1000) + 300,
    cnf: { jkt: "jkt-introspected" },
    token_type: "DPoP",
  },
});
const unsupported: Answer = { status: 400, body: { error: "unsupported_token_type", error_description: "structured tokens cannot be introspected" } };

describe("the pilot MAS introspects every acting token first (@spec authority-server#join-assertion-request, #1454 review)", () => {
  it("introspects a JWT the estate can introspect, and takes the token from the answer, not from its own claims", async () => {
    introspection = () => activeAnswer("u-from-introspection");
    asked.length = 0;
    const jwt = await estateJwt("u-from-claims");
    const result = await deploymentAtStub().establishActingToken({ accessToken: jwt });
    expect(asked).toEqual([jwt]);
    expect(result).toMatchObject({ ok: true, token: { subject: "u-from-introspection", cnf: { jkt: "jkt-introspected" } } });
  });

  it("validates a JWT locally under the estate's published keys only on unsupported_token_type, and refuses one that fails that validation", async () => {
    introspection = () => unsupported;
    const result = await deploymentAtStub().establishActingToken({ accessToken: await estateJwt() });
    expect(result).toMatchObject({ ok: true, token: { issuer: base, subject: "u-1001", clientId: "estate-ap-bot-7f3", cnf: { jkt: "jkt-stub" } } });
    const forged = await new SignJWT({ client_id: "estate-ap-bot-7f3", aud: CANONICAL_RESOURCE, cnf: { jkt: "jkt-stub" } })
      .setProtectedHeader({ alg: "ES256", kid: "stub-estate-1", typ: "at+jwt" })
      .setIssuer(base)
      .setSubject("u-1001")
      .setExpirationTime("5m")
      .sign((await generateKeyPair("ES256")).privateKey);
    expect(await deploymentAtStub().establishActingToken({ accessToken: forged })).toEqual({ ok: false, reason: "inactive" });
  });

  it("refuses a JWT the estate reports inactive, though it would validate locally", async () => {
    introspection = () => ({ status: 200, body: { active: false } });
    expect(await deploymentAtStub().establishActingToken({ accessToken: await estateJwt() })).toEqual({ ok: false, reason: "inactive" });
  });

  it("is unavailable, with no local fallback, when introspection of a locally valid JWT cannot be answered: a server error, another error code, a malformed answer, a timeout", async () => {
    const cases: Array<[string, Answer]> = [
      ["a server error", { status: 503, body: { error: "temporarily_unavailable" } }],
      ["another error code", { status: 400, body: { error: "invalid_request" } }],
      ["an error member that is not exactly unsupported_token_type", { status: 400, body: { error: "Unsupported_Token_Type" } }],
      ["a malformed answer", { status: 200, body: "[]" }],
      ["a timeout", { status: 200, body: { active: true }, delayMs: 1000 }],
    ];
    for (const [label, answer] of cases) {
      introspection = () => answer;
      expect(await deploymentAtStub().establishActingToken({ accessToken: await estateJwt() }), label).toEqual({ ok: false, reason: "unavailable" });
    }
  });

  it("establishes an opaque token by introspection only: active is used, unsupported_token_type and inactive refuse, an estate that cannot answer is unavailable", async () => {
    const opaque = `opaque-${crypto.randomUUID()}`;
    introspection = () => activeAnswer("u-1001");
    expect(await deploymentAtStub().establishActingToken({ accessToken: opaque })).toMatchObject({ ok: true, token: { subject: "u-1001" } });
    introspection = () => unsupported;
    expect(await deploymentAtStub().establishActingToken({ accessToken: opaque })).toEqual({ ok: false, reason: "inactive" });
    introspection = () => ({ status: 200, body: { active: false } });
    expect(await deploymentAtStub().establishActingToken({ accessToken: opaque })).toEqual({ ok: false, reason: "inactive" });
    introspection = () => ({ status: 503, body: {} });
    expect(await deploymentAtStub().establishActingToken({ accessToken: opaque })).toEqual({ ok: false, reason: "unavailable" });
  });
});
