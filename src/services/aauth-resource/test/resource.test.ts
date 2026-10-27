import { request as httpRequest } from "node:http";
import { createIssuerStub, decodeClaims } from "@mission/aauth-testkit";
import { BASE_COMPONENTS, generateSigningKey, signRequest } from "@mission/aauth-wire";
import { afterEach, describe, expect, it } from "vitest";
import { buildResourceTokenClaims, parseResourceConfig } from "../src/index.js";
import {
  anotherPs,
  M,
  PS,
  RESOURCE,
  requirementOf,
  sendMessage,
  signedMessage,
  verifiedResourceToken,
  type World,
  world,
} from "./helpers.js";

let w: World;
afterEach(() => w.net.close());

const DOCS = `${RESOURCE}/api/documents`;
const nothingRan = () => {
  expect(w.resource.effects).toEqual([]);
};

describe("metadata and keys (@spec aauth#section-11.2.4)", () => {
  it("publishes its metadata at its identifier, with its JWKS on the same origin", async () => {
    w = await world();
    const meta = await w.net.fetchJson(`${RESOURCE}/.well-known/aauth-resource.json`);
    expect(meta).toEqual({
      status: 200,
      body: {
        issuer: RESOURCE,
        jwks_uri: `${RESOURCE}/.well-known/jwks.json`,
        name: "AAuth document service",
        access_mode: "auth-token",
        authorization_endpoint: `${RESOURCE}/authorize`,
        scope_descriptions: {
          "documents.read": "Read your documents",
          "documents.write": "Create documents for you",
        },
        signature_window: 60,
      },
    });
    const jwks = await w.net.fetchJson(`${RESOURCE}/.well-known/jwks.json`);
    expect((jwks.body as { keys: unknown[] }).keys).toEqual([
      expect.objectContaining({
        kty: "OKP",
        crv: "Ed25519",
        alg: "Ed25519",
        kid: "resource-key-1",
      }),
    ]);
  });
});

describe("challenges (@spec aauth#section-6.4, aauth#section-6.5)", () => {
  it("answers an unsigned request with requirement=person-token, issuing and running nothing", async () => {
    w = await world();
    const res = await w.net.request({ method: "GET", url: DOCS });
    expect(res.status).toBe(401);
    expect(res.headers["aauth-requirement"]).toBe("requirement=person-token");
    expect(w.resource.issuedResourceTokens).toEqual([]);
    nothingRan();
  });

  it("answers an agent token with requirement=person-token, issuing no resource token", async () => {
    w = await world();
    const res = await w.agent.send(DOCS);
    expect(res.status).toBe(401);
    expect(requirementOf(res)).toEqual({ requirement: "person-token", resourceToken: undefined });
    expect(w.resource.issuedResourceTokens).toEqual([]);
    nothingRan();
  });

  it("answers a person token with requirement=auth-token and a resource token naming it, never running the operation (@spec aauth#section-13.11)", async () => {
    w = await world();
    const pt = await w.ps.personToken(w.agent, { mission_s256: M, tenant: "acme" });
    const res = await w.agent.send(DOCS, { token: pt });
    expect(res.status).toBe(401);
    const challenge = requirementOf(res);
    expect(challenge?.requirement).toBe("auth-token");
    const rt = await verifiedResourceToken(w, challenge?.resourceToken as string);
    const presented = decodeClaims(pt);
    expect(rt.header.typ).toBe("aa-resource+jwt");
    expect(rt.payload).toMatchObject({
      iss: RESOURCE,
      dwk: "aauth-resource.json",
      aud: PS,
      ps: PS,
      sub: presented.sub,
      presented_jti: presented.jti,
      agent_jkt: w.agent.thumbprint,
      scope: "documents.read",
    });
    expect((rt.payload.exp as number) - (rt.payload.iat as number)).toBe(300);
    expect(w.resource.issuedResourceTokens).toHaveLength(1);
    nothingRan();
  });

  it("copies mission_s256 unchanged from the person token (@spec aauth#section-6.7.1)", async () => {
    w = await world();
    const pt = await w.ps.personToken(w.agent, { mission_s256: M });
    const res = await w.agent.send(DOCS, { token: pt });
    const rt = await verifiedResourceToken(w, requirementOf(res)?.resourceToken as string);
    expect(rt.payload.mission_s256).toBe(M);
  });

  it("copies tenant from the person token", async () => {
    w = await world();
    const pt = await w.ps.personToken(w.agent, { tenant: "acme" });
    const res = await w.agent.send(DOCS, { token: pt });
    const rt = await verifiedResourceToken(w, requirementOf(res)?.resourceToken as string);
    expect(rt.payload.tenant).toBe("acme");
  });

  it("names no mission for a missionless person token", async () => {
    w = await world();
    const pt = await w.ps.personToken(w.agent);
    const res = await w.agent.send(DOCS, { token: pt });
    const rt = await verifiedResourceToken(w, requirementOf(res)?.resourceToken as string);
    expect("mission_s256" in rt.payload).toBe(false);
    expect("tenant" in rt.payload).toBe(false);
  });

  it("answers a token that fails verification with Signature-Error, not a requirement", async () => {
    w = await world();
    const pt = await w.ps.personToken(w.agent, { aud: "https://other.test" });
    const res = await w.agent.send(DOCS, { token: pt });
    expect(res.status).toBe(401);
    expect(res.headers["signature-error"]).toBe("error=invalid_jwt");
    expect(res.headers["aauth-requirement"]).toBeUndefined();
    expect(w.resource.issuedResourceTokens).toEqual([]);
    nothingRan();
  });
});

describe("execution (@spec aauth#section-9.4.3, aauth#section-13.7)", () => {
  it("runs an operation on an auth token whose scope covers it, and logs the run", async () => {
    w = await world();
    const at = await w.ps.authToken(w.agent, { mission_s256: M, tenant: "acme" });
    const res = await w.agent.send(DOCS, { method: "POST", body: { title: "plan" }, token: at });
    expect(res.status).toBe(201);
    expect(res.json()).toMatchObject({ title: "plan" });
    const list = await w.agent.send(DOCS, { token: at });
    expect(list.json()).toEqual({ items: [res.json()] });
    expect(w.resource.effects).toEqual([
      expect.objectContaining({
        seq: 1,
        operation: "POST /api/documents",
        person: 1,
        iss: PS,
        sub: "person-1",
        tenant: "acme",
        mission_s256: M,
        authJti: decodeClaims(at).jti,
        scope: "documents.write",
      }),
      expect.objectContaining({ seq: 2, operation: "GET /api/documents", person: 1 }),
    ]);
  });

  it("refuses an auth token an access server issued, since this resource has none", async () => {
    w = await world();
    const as = createIssuerStub({ issuer: "https://as.test", dwk: "aauth-access.json" });
    await w.net.serve(as.issuer, as.handler);
    const iat = w.seconds();
    const at = await as.mint("aa-auth+jwt", {
      iss: as.issuer,
      dwk: "aauth-access.json",
      aud: RESOURCE,
      ps: PS,
      sub: "person-1",
      scope: "documents.read",
      cnf: { jwk: w.agent.key.publicJwk },
      jti: "as-at-1",
      iat,
      exp: iat + 600,
    });
    const res = await w.agent.send(DOCS, { token: at });
    expect(res.status).toBe(401);
    expect(res.headers["signature-error"]).toBe("error=invalid_jwt");
    expect(w.resource.persons).toEqual([]);
    nothingRan();
  });

  it("refuses an expired auth token, one for another resource and one bound to another key", async () => {
    w = await world();
    const iat = w.seconds() - 3600;
    const expired = await w.ps.authToken(w.agent, { iat, exp: iat + 1800 });
    const elsewhere = await w.ps.authToken(w.agent, { aud: "https://other.test" });
    const otherKey = generateSigningKey("Ed25519").publicJwk;
    const foreignKey = await w.ps.authToken(w.agent, { cnf: { jwk: otherKey } });
    const codes = [];
    for (const token of [expired, elsewhere, foreignKey]) {
      const res = await w.agent.send(DOCS, { token });
      codes.push([res.status, res.headers["signature-error"]]);
    }
    expect(codes).toEqual([
      [401, "error=expired_jwt"],
      [401, "error=invalid_jwt"],
      [401, "error=invalid_signature"],
    ]);
    nothingRan();
  });

  it("keys a person by (iss, sub): one sub under two PSs is two people (@spec aauth#section-7.1.4)", async () => {
    w = await world();
    const ps2 = await anotherPs(w, "https://ps2.test");
    await w.agent.send(DOCS, { token: await w.ps.authToken(w.agent) });
    await w.agent.send(DOCS, { token: await ps2.authToken(w.agent) });
    await w.agent.send(DOCS, { token: await w.ps.authToken(w.agent) });
    expect(w.resource.persons).toEqual([
      { id: 1, iss: PS, sub: "person-1" },
      { id: 2, iss: "https://ps2.test", sub: "person-1" },
    ]);
    expect(w.resource.effects.map((e) => e.person)).toEqual([1, 2, 1]);
  });

  it("refuses input it cannot run, with no effect", async () => {
    w = await world();
    const at = await w.ps.authToken(w.agent);
    const res = await w.agent.send(DOCS, { method: "POST", body: { title: "" }, token: at });
    expect(res.status).toBe(400);
    expect(res.json()).toMatchObject({ error: "invalid_request" });
    nothingRan();
  });
});

describe("step-up on a presented auth token (V5; @spec aauth#section-6.5)", () => {
  it("challenges an auth token whose scope falls short with a resource token naming it", async () => {
    w = await world();
    const at = await w.ps.authToken(w.agent, {
      scope: "documents.read",
      mission_s256: M,
      tenant: "acme",
    });
    const res = await w.agent.send(DOCS, { method: "POST", body: { title: "plan" }, token: at });
    expect(res.status).toBe(401);
    const challenge = requirementOf(res);
    expect(challenge?.requirement).toBe("auth-token");
    const rt = await verifiedResourceToken(w, challenge?.resourceToken as string);
    const presented = decodeClaims(at);
    expect(rt.payload).toMatchObject({
      aud: PS,
      ps: PS,
      sub: presented.sub,
      presented_jti: presented.jti,
      mission_s256: M,
      tenant: "acme",
      scope: "documents.read documents.write",
    });
    nothingRan();
  });
});

describe("request binding (@spec aauth#section-11.3.4)", () => {
  it("requires Content-Digest and Content-Type on a request with a body", async () => {
    w = await world();
    const at = await w.ps.authToken(w.agent);
    const message = signedMessage(w, {
      method: "POST",
      path: "/api/documents",
      token: at,
      body: JSON.stringify({ title: "plan" }),
      components: BASE_COMPONENTS,
    });
    const res = await sendMessage(w, message);
    expect(res.status).toBe(401);
    expect(res.headers["signature-error"]).toBe(
      'error=invalid_input, required_input=("@method" "@authority" "@path" "signature-key" "content-digest" "content-type")',
    );
    nothingRan();
  });

  it("refuses a replayed request", async () => {
    w = await world();
    const at = await w.ps.authToken(w.agent);
    const message = signedMessage(w, {
      method: "POST",
      path: "/api/documents",
      token: at,
      body: JSON.stringify({ title: "plan" }),
    });
    expect((await sendMessage(w, message)).status).toBe(201);
    const replay = await sendMessage(w, message);
    expect(replay.status).toBe(401);
    expect(replay.headers["signature-error"]).toBe("error=invalid_signature");
    expect(w.resource.effects).toHaveLength(1);
  });

  it("refuses a body that is not the one signed", async () => {
    w = await world();
    const at = await w.ps.authToken(w.agent);
    const message = signedMessage(w, {
      method: "POST",
      path: "/api/documents",
      token: at,
      body: JSON.stringify({ title: "plan" }),
    });
    const res = await sendMessage(w, { ...message, body: JSON.stringify({ title: "pwn" }) });
    expect(res.status).toBe(401);
    expect(res.headers["signature-error"]).toBe("error=invalid_signature");
    nothingRan();
  });

  it("refuses a request whose Host is not this resource's", async () => {
    w = await world();
    const at = await w.ps.authToken(w.agent);
    const message = signedMessage(w, { path: "/api/documents", token: at });
    const port = w.net.portOf(RESOURCE) as number;
    const status = await new Promise<number>((resolve, reject) => {
      const req = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/api/documents",
          headers: { ...message.headers, host: "other.test" },
          agent: false,
        },
        (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        },
      );
      req.on("error", reject);
      req.end();
    });
    expect(status).toBe(421);
    nothingRan();
  });

  it("does not verify a request signed for another authority", async () => {
    w = await world();
    const at = await w.ps.authToken(w.agent);
    // Signed over https://other.test/api/documents, sent here.
    const added = signRequest(
      { method: "GET", url: "https://other.test/api/documents", headers: {} },
      {
        alg: w.agent.key.alg,
        privateKey: w.agent.key.privateKey,
        signatureKey: { scheme: "jwt", jwt: at },
        created: w.seconds(),
      },
    );
    const res = await w.net.request({ method: "GET", url: DOCS, headers: added });
    expect(res.status).toBe(401);
    expect(res.headers["signature-error"]).toBe("error=invalid_signature");
    nothingRan();
  });
});

describe("authorization endpoint (@spec aauth#section-6.6)", () => {
  const AUTHORIZE = `${RESOURCE}/authorize`;

  it("answers a person token and a defined scope with a resource token", async () => {
    w = await world();
    const pt = await w.ps.personToken(w.agent, { mission_s256: M });
    const res = await w.agent.send(AUTHORIZE, {
      method: "POST",
      body: { scope: "documents.read documents.write" },
      token: pt,
    });
    expect(res.status).toBe(200);
    const rt = await verifiedResourceToken(
      w,
      (res.json() as { resource_token: string }).resource_token,
    );
    expect(rt.payload).toMatchObject({
      presented_jti: decodeClaims(pt).jti,
      mission_s256: M,
      scope: "documents.read documents.write",
    });
    nothingRan();
  });

  it("challenges a request without a person token for one, an auth token included", async () => {
    w = await world();
    const statuses = [];
    for (const token of [w.agent.agentToken, await w.ps.authToken(w.agent)]) {
      const res = await w.agent.send(AUTHORIZE, {
        method: "POST",
        body: { scope: "documents.read" },
        token,
      });
      statuses.push([res.status, res.headers["aauth-requirement"]]);
    }
    expect(statuses).toEqual([
      [401, "requirement=person-token"],
      [401, "requirement=person-token"],
    ]);
    expect(w.resource.issuedResourceTokens).toEqual([]);
  });

  it.each([
    [{}, "invalid_request"],
    [{ scope: "" }, "invalid_request"],
    [{ scope: "documents.read  documents.write" }, "invalid_request"],
    [{ scope: "documents.delete" }, "invalid_scope"],
    [{ scope: "documents.read", account: "acct-1" }, "invalid_account"],
  ])("refuses %j with %s", async (body, error) => {
    w = await world();
    const pt = await w.ps.personToken(w.agent);
    const res = await w.agent.send(AUTHORIZE, { method: "POST", body, token: pt });
    expect(res.status).toBe(400);
    expect(res.headers["content-type"]).toBe("application/problem+json");
    expect(res.json()).toMatchObject({ error });
    expect(w.resource.issuedResourceTokens).toEqual([]);
  });
});

describe("resource token claims (@spec aauth#section-6.7.1)", () => {
  it("refuses to build a resource token from an agent token", () => {
    expect(() =>
      buildResourceTokenClaims({
        issuer: RESOURCE,
        presented: { typ: "aa-agent+jwt", alg: "Ed25519", header: {}, payload: {} },
        agentJkt: "x",
        scope: "s",
        now: 0,
        lifetimeSeconds: 300,
      }),
    ).toThrow(/person token or auth token/);
  });
});

describe("configuration", () => {
  const valid = () => ({
    issuer: "https://resource.test",
    name: "n",
    signing_key: { kid: "k", alg: "Ed25519" },
    resource_token_lifetime_seconds: 300,
    signature_window_seconds: 60,
    scope_descriptions: { "a.read": "A" },
    operations: [{ method: "GET", path: "/a", scope: "a.read" }],
  });

  it.each([
    ["an unknown member", { extra: 1 }],
    ["a non-identifier issuer", { issuer: "https://resource.test:8443" }],
    ["a resource token lifetime over 300 seconds", { resource_token_lifetime_seconds: 301 }],
    [
      "an operation scope it does not define",
      { operations: [{ method: "GET", path: "/a", scope: "b" }] },
    ],
    [
      "an operation at a reserved path",
      { operations: [{ method: "POST", path: "/authorize", scope: "a.read" }] },
    ],
    ["a symmetric key algorithm", { signing_key: { kid: "k", alg: "HS256" } }],
  ])("refuses %s", (_what, change) => {
    expect(() => parseResourceConfig({ ...valid(), ...change })).toThrow(/aauth-resource config/);
  });

  it("accepts the shipped configuration's shape", () => {
    expect(parseResourceConfig(valid()).operations).toEqual([
      { method: "GET", path: "/a", scope: "a.read" },
    ]);
  });
});
