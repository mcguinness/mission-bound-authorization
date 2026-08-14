/**
 * @spec mission#introspection, mission#composite-active,
 * mission#caller-authorization-and-minimization (issue #526)
 *
 * The authenticated introspection state machine, wire-level:
 *  - the caller is an AUTHENTICATED introspection principal whose authorized
 *    audiences and disclosure privileges come from server-side registration,
 *    never from a caller-supplied value (the shared x-service-token boolean is
 *    retired for this endpoint);
 *  - the presented credential is resolved STRICTLY (signature, expected
 *    issuer, at+jwt token class, time validity, individual revocation via the
 *    stored-token record, Mission-reference resolution) before Mission state
 *    is consulted;
 *  - the response matrix: caller auth failure -> 401; a token the resolver
 *    cannot bind (malformed, unknown, individually expired/revoked,
 *    unresolvable, or not visible to this caller) -> bare `active: false`
 *    with NO Mission or token detail; valid + visible + Mission active ->
 *    `active: true` plus the audience-minimized projection; valid + visible +
 *    Mission non-active -> `active: false` plus ONLY the `mission` projection
 *    including `mission.state`;
 *  - the projection matrix: audience-filtered `authorization_details`
 *    (EFFECTIVE, contained authority), `derivations_remaining` when
 *    `controls.max_derivations` is in force, `containment_version` when
 *    containment applies, and issuer-only members (`proposal_hash`, the
 *    Status List reference) disclosed only under an explicit per-principal
 *    privilege: issuer-only is authority to assert, not authorization to
 *    disclose. Complete disclosed key sets are pinned so `sub`, `aud`,
 *    `client_id`, `jti`, and `cnf` are not a cross-audience privacy oracle;
 *  - Mission-bound refresh tokens are introspectable under the SAME composite
 *    rule.
 */
import type { Server } from "node:http";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildAuthorizationServer, type AuthorityEntry, type BuiltAs } from "../src/index.js";

const PORT = 14540;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const PAYMENTS = DERIVATION_POLICY.ceiling[0].resource;
const SAAS = DERIVATION_POLICY.ceiling[1].resource;

// Registered introspection principals (config/introspection.json): rs-payments
// is authorized for the payments audience and holds the provenance +
// status_list disclosure privileges; rs-saas is authorized for the saas
// audience and holds none.
const RS_PAYMENTS = ["rs-payments", "dev-introspection-rs-payments"] as const;
const RS_SAAS = ["rs-saas", "dev-introspection-rs-saas"] as const;

let as: BuiltAs;
let asServer: Server;
let agentKey: CryptoKey;

interface FlowResult {
  at: string;
  rt: string | undefined;
  missionId: string;
  jti: string;
  payload: Record<string, unknown>;
}

async function clientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(agentKey);
}

const PKCE_VERIFIER = "introspection-verifier-0123456789-0123456789-012";
async function pkceChallenge(): Promise<string> {
  return Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER)),
  ).toString("base64url");
}

/** One full PAR -> approval -> code-redemption flow; returns the issued pair. */
async function runFlow(input: {
  intent: Record<string, unknown>;
  proposal?: AuthorityEntry[];
  resource: string;
}): Promise<FlowResult> {
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "payments",
      resource: input.resource,
      code_challenge: await pkceChallenge(),
      code_challenge_method: "S256",
      mission_intent: JSON.stringify({ intent: input.intent }),
      ...(input.proposal ? { authorization_details: JSON.stringify(input.proposal) } : {}),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  expect(par.status).toBe(201);
  const { request_uri } = (await par.json()) as { request_uri: string };

  const cookies = new Map<string, string>();
  const cookieHeader = () => [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  const storeCookies = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };

  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
    redirect: "manual",
  });
  storeCookies(res);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/json", cookie: cookieHeader() },
    body: JSON.stringify({ decision: "approve", approver: "bob", subject: "alice" }),
  });
  storeCookies(res);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader() } });
    storeCookies(res);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;

  const dpopKeys = await generateKeyPair("ES256", { extractable: true });
  const dpopPub = await exportJWK(dpopKeys.publicKey);
  const htu = `${ISSUER}/token`;
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await new SignJWT({ htu, htm: "POST", ...extra })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopPub })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(dpopKeys.privateKey),
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: PKCE_VERIFIER,
        resource: input.resource,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let tok = await send();
  const nonce = tok.headers.get("dpop-nonce");
  if (tok.status === 400 && nonce) tok = await send({ nonce });
  expect(tok.status).toBe(200);
  const body = (await tok.json()) as { access_token: string; refresh_token?: string };
  const payload = JSON.parse(
    Buffer.from(body.access_token.split(".")[1] as string, "base64url").toString(),
  ) as Record<string, unknown>;
  return {
    at: body.access_token,
    rt: body.refresh_token,
    missionId: (payload.mission as { id: string }).id,
    jti: payload.jti as string,
    payload,
  };
}

/** RFC 7662 introspection call: form-encoded body, HTTP Basic principal. */
async function introspect(
  token: string | undefined,
  opts: {
    principal?: readonly [string, string];
    hint?: string;
    rawAuth?: string;
    extraHeaders?: Record<string, string>;
  } = {},
): Promise<{ status: number; headers: Headers; body: Record<string, unknown> }> {
  const headers: Record<string, string> = {
    "content-type": "application/x-www-form-urlencoded",
    ...(opts.extraHeaders ?? {}),
  };
  if (opts.rawAuth) headers.authorization = opts.rawAuth;
  else if (opts.principal) {
    headers.authorization = `Basic ${Buffer.from(`${opts.principal[0]}:${opts.principal[1]}`).toString("base64")}`;
  }
  const res = await fetch(`${ISSUER}/introspect`, {
    method: "POST",
    headers,
    body: new URLSearchParams({
      ...(token !== undefined ? { token } : {}),
      ...(opts.hint ? { token_type_hint: opts.hint } : {}),
    }).toString(),
  });
  return { status: res.status, headers: res.headers, body: (await res.json()) as Record<string, unknown> };
}

/** Sign an adversarial at+jwt with the AS's REAL token key (test-only seam). */
async function craftToken(
  payload: Record<string, unknown>,
  opts: { typ?: string; expiresIn?: number } = {},
): Promise<string> {
  const jwk = (as as unknown as { tokenSigningJwk?: Record<string, unknown> }).tokenSigningJwk;
  const key = (await importJWK(jwk as never, "RS256")) as CryptoKey;
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ iss: ISSUER, sub: "alice", aud: PAYMENTS, client_id: "ap-agent", ...payload })
    .setProtectedHeader({ alg: "RS256", kid: "as-token", typ: opts.typ ?? "at+jwt" })
    .setIssuedAt(now)
    .setExpirationTime(now + (opts.expiresIn ?? 300))
    .sign(key);
}

const tokenAdapter = () =>
  (as.provider.AccessToken as unknown as {
    adapter: { find(id: string): Promise<unknown>; destroy(id: string): Promise<void> };
  }).adapter;
const refreshAdapter = () =>
  (as.provider.RefreshToken as unknown as {
    adapter: { destroy(id: string): Promise<void> };
  }).adapter;

let flow1: FlowResult; // payments; controls.max_derivations 5; proposal (proposal_hash on record)
let flow2: FlowResult; // multi-audience: payments + saas
let flow3: FlowResult; // saas-only (rs-saas positive rows)
let flow4: FlowResult; // payments; refresh-token rows

const PAYMENTS_PROPOSAL: AuthorityEntry[] = [
  {
    type: "mission_resource_access",
    resource: PAYMENTS,
    actions: ["payments:invoice.read", "payments:remittance.send"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
  },
];
const SAAS_PROPOSAL: AuthorityEntry[] = [
  { type: "mission_resource_access", resource: SAAS, actions: ["ledger:vendor.read"] },
];

beforeAll(async () => {
  as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
  asServer = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  flow1 = await runFlow({
    intent: {
      goal: "Pay Acme invoices for Q3",
      resources: [PAYMENTS],
      expires_at: "2027-01-01T00:00:00Z",
      controls: { max_derivations: 5 },
    },
    proposal: PAYMENTS_PROPOSAL,
    resource: PAYMENTS,
  });
  flow2 = await runFlow({
    intent: {
      goal: "Reconcile payments against the ledger",
      resources: [PAYMENTS, SAAS],
      expires_at: "2027-01-01T00:00:00Z",
    },
    proposal: [...PAYMENTS_PROPOSAL, ...SAAS_PROPOSAL],
    resource: PAYMENTS,
  });
  flow3 = await runFlow({
    intent: {
      goal: "Read ledger vendors",
      resources: [SAAS],
      expires_at: "2027-01-01T00:00:00Z",
    },
    proposal: SAAS_PROPOSAL,
    resource: SAAS,
  });
  flow4 = await runFlow({
    intent: {
      goal: "Pay Acme invoices for Q4",
      resources: [PAYMENTS],
      expires_at: "2027-01-01T00:00:00Z",
    },
    proposal: PAYMENTS_PROPOSAL,
    resource: PAYMENTS,
  });
}, 60000);

afterAll(() => {
  asServer?.close();
});

describe("caller authentication (@spec mission#caller-authorization-and-minimization)", () => {
  it("refuses an unauthenticated call with 401 + WWW-Authenticate", async () => {
    const res = await introspect(flow1.at);
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("Basic");
  });

  it("refuses a wrong secret with 401", async () => {
    const res = await introspect(flow1.at, { principal: ["rs-payments", "wrong-secret"] });
    expect(res.status).toBe(401);
  });

  it("refuses an unregistered principal with 401", async () => {
    const res = await introspect(flow1.at, { principal: ["rs-unknown", "whatever"] });
    expect(res.status).toBe(401);
  });

  it("the retired shared x-service-token header does not authenticate", async () => {
    const res = await introspect(flow1.at, {
      extraHeaders: { "x-service-token": "dev-service-token" },
    });
    expect(res.status).toBe(401);
  });

  it("a missing token parameter is invalid_request", async () => {
    const res = await introspect(undefined, { principal: RS_PAYMENTS });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
  });
});

describe("strict token resolution: bare active:false, no Mission or token detail", () => {
  it("malformed token", async () => {
    const res = await introspect("not-a-jwt", { principal: RS_PAYMENTS });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ active: false });
  });

  it("wrong issuer", async () => {
    const crafted = await craftToken({ jti: flow1.jti, mission: { id: flow1.missionId }, iss: "https://evil.example" });
    expect((await introspect(crafted, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
  });

  it("wrong token class (typ is not at+jwt)", async () => {
    const crafted = await craftToken({ jti: flow1.jti, mission: { id: flow1.missionId } }, { typ: "JWT" });
    expect((await introspect(crafted, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
  });

  it("individually expired token", async () => {
    const crafted = await craftToken(
      { jti: flow1.jti, mission: { id: flow1.missionId } },
      { expiresIn: -60 },
    );
    expect((await introspect(crafted, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
  });

  it("unknown Mission reference is never returned active", async () => {
    const crafted = await craftToken({ jti: flow1.jti, mission: { id: "m-unknown" } });
    expect((await introspect(crafted, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
  });

  it("token carrying no Mission reference is unresolvable", async () => {
    const crafted = await craftToken({ jti: flow1.jti });
    expect((await introspect(crafted, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
  });

  it("wrong-audience caller: the ENTIRE response is minimized", async () => {
    const res = await introspect(flow1.at, { principal: RS_SAAS });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ active: false });
  });
});

describe("active composite + projection matrix (@spec mission#composite-active)", () => {
  it("active Mission + valid token: complete pinned key set, audience-minimized", async () => {
    const res = await introspect(flow1.at, { principal: RS_PAYMENTS });
    expect(res.status).toBe(200);
    expect(res.body.active).toBe(true);
    // The COMPLETE disclosed top-level key set (no privacy oracle beyond it).
    expect(Object.keys(res.body).sort()).toEqual([
      "active",
      "aud",
      "client_id",
      "cnf",
      "exp",
      "iat",
      "iss",
      "jti",
      "mission",
      "scope",
      "sub",
      "token_type",
    ]);
    expect(res.body.iss).toBe(ISSUER);
    expect(res.body.client_id).toBe("ap-agent");
    expect(res.body.aud).toBe(PAYMENTS);
    expect(res.body.jti).toBe(flow1.jti);
    expect(res.body.token_type).toBe("DPoP");
    expect((res.body.cnf as { jkt?: string }).jkt).toBeDefined();

    const mission = res.body.mission as Record<string, unknown>;
    // Core members + derivations_remaining (max_derivations in force) +
    // proposal_hash (provenance privilege) + audience-filtered effective set.
    expect(Object.keys(mission).sort()).toEqual([
      "approval_basis",
      "authority_hash",
      "authorization_details",
      "derivations_remaining",
      "expires_at",
      "id",
      "issuer",
      "proposal_hash",
      "state",
      "version",
    ]);
    expect(mission.id).toBe(flow1.missionId);
    expect(mission.state).toBe("active");
    // One committed issuance (this token) against max_derivations 5.
    expect(mission.derivations_remaining).toBe(4);
    const record = as.kernel.get(flow1.missionId);
    expect(mission.proposal_hash).toBe(record?.proposal_hash);
    const details = mission.authorization_details as AuthorityEntry[];
    expect(details.length).toBeGreaterThan(0);
    for (const entry of details) expect(entry.resource).toBe(PAYMENTS);
  });

  it("multi-audience Mission: authorization_details filter to the caller's audience", async () => {
    const record = as.kernel.get(flow2.missionId);
    expect(record).toBeDefined();
    const effective = as.kernel.effectiveAuthoritySet(record as never);
    expect(effective.some((e) => e.resource === SAAS)).toBe(true);

    const res = await introspect(flow2.at, { principal: RS_PAYMENTS });
    expect(res.body.active).toBe(true);
    const details = (res.body.mission as { authorization_details: AuthorityEntry[] })
      .authorization_details;
    expect(details.length).toBeGreaterThan(0);
    for (const entry of details) expect(entry.resource).toBe(PAYMENTS);
  });

  it("issuer-only members are disclosure-gated: a privilege-less principal never sees them", async () => {
    // flow3's record carries a proposal_hash and participates in the Status
    // List, but rs-saas holds neither the provenance nor the status_list
    // privilege: neither member may appear.
    as.kernel.participateInStatusList(flow3.missionId);
    const record = as.kernel.get(flow3.missionId);
    expect(record?.proposal_hash).toBeDefined();

    const res = await introspect(flow3.at, { principal: RS_SAAS });
    expect(res.body.active).toBe(true);
    const mission = res.body.mission as Record<string, unknown>;
    expect(Object.keys(mission).sort()).toEqual([
      "approval_basis",
      "authority_hash",
      "authorization_details",
      "expires_at",
      "id",
      "issuer",
      "state",
      "version",
    ]);
    for (const entry of mission.authorization_details as AuthorityEntry[]) {
      expect(entry.resource).toBe(SAAS);
    }
    // Cross-check: the payments principal is not an audience of this token.
    expect((await introspect(flow3.at, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
  });

  it("containment projection: containment_version + EFFECTIVE (contained) authority", async () => {
    as.kernel.contain(flow1.missionId, {
      event: {
        type: "credential-compromise",
        source: "test-sensor",
        observed_at: new Date().toISOString(),
        event_id: "introspection-containment-1",
      },
      remove: [{ resource: PAYMENTS, actions: ["payments:remittance.send"] }],
    });
    const res = await introspect(flow1.at, { principal: RS_PAYMENTS });
    expect(res.body.active).toBe(true);
    const mission = res.body.mission as Record<string, unknown>;
    expect(mission.containment_version).toBe(1);
    const actions = (mission.authorization_details as AuthorityEntry[]).flatMap((e) => e.actions);
    expect(actions).not.toContain("payments:remittance.send");
    expect(actions).toContain("payments:invoice.read");
  });

  it("status_list is disclosed to a privileged principal once the Mission participates", async () => {
    as.kernel.participateInStatusList(flow1.missionId);
    const res = await introspect(flow1.at, { principal: RS_PAYMENTS });
    const mission = res.body.mission as { status_list?: { idx: number; uri: string } };
    expect(mission.status_list).toBeDefined();
    expect(typeof mission.status_list?.idx).toBe("number");
  });
});

describe("composite non-active: active:false WITH mission.state (@spec mission#composite-active)", () => {
  it("revoked Mission + valid token: only { active, mission }, state revoked", async () => {
    as.kernel.transition(flow1.missionId, "revoke");
    const res = await introspect(flow1.at, { principal: RS_PAYMENTS });
    expect(res.status).toBe(200);
    expect(Object.keys(res.body).sort()).toEqual(["active", "mission"]);
    expect(res.body.active).toBe(false);
    const mission = res.body.mission as Record<string, unknown>;
    expect(mission.state).toBe("revoked");
    expect(mission.id).toBe(flow1.missionId);
    // Still audience-minimized in the non-active branch.
    for (const entry of mission.authorization_details as AuthorityEntry[]) {
      expect(entry.resource).toBe(PAYMENTS);
    }
    // The Mission-bound refresh token reports the SAME composite.
    const rt = await introspect(flow1.rt, { principal: RS_PAYMENTS, hint: "refresh_token" });
    expect(Object.keys(rt.body).sort()).toEqual(["active", "mission"]);
    expect((rt.body.mission as { state: string }).state).toBe("revoked");
  });

  it("Mission-expired composite: active:false with state expired", async () => {
    as.kernel.db
      .prepare("UPDATE missions SET expires_at = ? WHERE id = ?")
      .run("2020-01-01T00:00:00.000Z", flow2.missionId);
    const res = await introspect(flow2.at, { principal: RS_PAYMENTS });
    expect(Object.keys(res.body).sort()).toEqual(["active", "mission"]);
    expect(res.body.active).toBe(false);
    expect((res.body.mission as { state: string }).state).toBe("expired");
  });
});

describe("Mission-bound refresh tokens (@spec mission#introspection)", () => {
  it("a valid refresh token on an active Mission introspects under the composite rule", async () => {
    expect(flow4.rt).toBeDefined();
    const res = await introspect(flow4.rt, { principal: RS_PAYMENTS, hint: "refresh_token" });
    expect(res.status).toBe(200);
    expect(res.body.active).toBe(true);
    // A confidential client's refresh token is not DPoP-bound, so no cnf.
    expect(Object.keys(res.body).sort()).toEqual([
      "active",
      "client_id",
      "exp",
      "iat",
      "iss",
      "jti",
      "mission",
      "sub",
    ]);
    expect(res.body.client_id).toBe("ap-agent");
    const mission = res.body.mission as Record<string, unknown>;
    expect(mission.id).toBe(flow4.missionId);
    expect(mission.state).toBe("active");
    for (const entry of mission.authorization_details as AuthorityEntry[]) {
      expect(entry.resource).toBe(PAYMENTS);
    }
  });

  it("an individually revoked refresh token is bare active:false; the access token is unaffected", async () => {
    await refreshAdapter().destroy(flow4.rt as string);
    expect(
      (await introspect(flow4.rt, { principal: RS_PAYMENTS, hint: "refresh_token" })).body,
    ).toEqual({ active: false });
    const at = await introspect(flow4.at, { principal: RS_PAYMENTS });
    expect(at.body.active).toBe(true);
  });

  it("grant-scoped revocation of an ACTIVE Mission's token is bare active:false", async () => {
    // A stateless at+jwt has no per-token record; with the Mission still
    // active, RFC 7009-style grant destruction is the token-level revocation
    // signal, and a revoked token discloses NOTHING.
    const record = as.kernel.get(flow4.missionId);
    expect(record?.grant_id).toBeDefined();
    await (as.provider.Grant as unknown as {
      adapter: { destroy(id: string): Promise<void> };
    }).adapter.destroy(record?.grant_id as string);
    expect((await introspect(flow4.at, { principal: RS_PAYMENTS })).body).toEqual({
      active: false,
    });
  });

  it("Mission revocation reports the composite even though it destroys the grant", async () => {
    // Mission-level revocation destroys the grant as a side effect; the core
    // REQUIRES active:false WITH mission.state so a Resource Server can
    // distinguish a dead Mission from a bad token. The non-active branch
    // therefore precedes the grant arm.
    as.kernel.transition(flow4.missionId, "revoke");
    const res = await introspect(flow4.at, { principal: RS_PAYMENTS });
    expect(Object.keys(res.body).sort()).toEqual(["active", "mission"]);
    expect((res.body.mission as { state: string }).state).toBe("revoked");
  });
});
