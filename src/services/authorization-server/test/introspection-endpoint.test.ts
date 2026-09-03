/**
 * @spec mission#introspection, mission#composite-active,
 * mission#caller-authorization-and-minimization (issue #526, hardened by #541)
 *
 * The authenticated introspection state machine, wire-level:
 *  - the caller is an AUTHENTICATED introspection principal whose authorized
 *    audiences and disclosure privileges come from server-side registration,
 *    never from a caller-supplied value (the shared x-service-token boolean is
 *    retired for this endpoint);
 *  - the presented credential is resolved STRICTLY (signature, expected
 *    issuer, at+jwt token class, time validity, the FULL RFC 9068 + Mission
 *    claim set, individual revocation via the grant/family that ACTUALLY
 *    minted the credential, Mission-reference resolution) before Mission
 *    state is consulted;
 *  - the response matrix: caller auth failure -> 401; a token the resolver
 *    cannot bind (malformed, unknown, individually expired/revoked,
 *    unresolvable, or not visible to this caller) -> bare `active: false`
 *    with NO Mission or token detail; valid + visible + Mission active ->
 *    `active: true` plus the audience-minimized top-level
 *    `authorization_details` (RFC 9396 §9.2) and the `mission` projection;
 *    valid + visible + Mission non-active -> `active: false` plus ONLY the
 *    `mission` projection including `mission.state`, NEVER top-level
 *    authorization detail;
 *  - the projection matrix (@spec mission#541 P1-1): the top-level
 *    `authorization_details` is the INTERSECTION of the presented
 *    credential's OWN authority and the Mission's CURRENT effective
 *    (containment-applied) authority, audience-minimized — never the
 *    Mission's full effective set, so a narrowed/attenuated credential can
 *    never introspect as though it held authority it was never issued. The
 *    `mission` object carries the core claim/status projection only
 *    (`derivations_remaining` when in force, `containment_version` when
 *    containment applies, issuer-only members gated by explicit per-principal
 *    disclosure privilege) — NO `authorization_details`;
 *  - individual revocation (@spec mission#541 P1-2) is scoped to the
 *    grant/family that ACTUALLY minted the presented credential, never the
 *    Mission's own approval grant: an async-delegation family's tokens go
 *    inactive when THAT family is destroyed/invalidated, independent of the
 *    Mission (and any sibling family) staying active;
 *  - Mission-bound refresh tokens introspect under the SAME composite rule.
 */
import type { Server } from "node:http";
import { DERIVATION_POLICY, TOPOLOGY } from "@mission/demo-data";
import { exportJWK, generateKeyPair, importJWK, SignJWT, type CryptoKey, type JWK } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ACCESS_TOKEN_TOKEN_TYPE,
  TOKEN_EXCHANGE_GRANT_TYPE,
} from "../src/adapters/continuation-grant.js";
import { resourcesForAudiences } from "../src/adapters/provider.js";
import { buildAuthorizationServer, type AuthorityEntry, type BuiltAs } from "../src/index.js";

const PORT = 14540;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
// @spec mission#authorization-derivation (#743) — the payments resource is
// now governed by two ceiling entries (a money-carrying group and a
// read-only group), so `ceiling[1].resource` no longer names the saas/ledger
// resource; both constants are selected by name rather than array index.
const PAYMENTS = DERIVATION_POLICY.ceiling[0].resource;
const SAAS = TOPOLOGY.resources.saas;

// Registered introspection principals (config/introspection.json): rs-payments
// is authorized for the payments audience and holds the provenance +
// status_list + budget disclosure privileges; rs-payments-basic is authorized
// for the same audience and holds none; rs-saas is authorized for the saas
// audience and holds none.
const RS_PAYMENTS = ["rs-payments", "dev-introspection-rs-payments"] as const;
const RS_PAYMENTS_BASIC = ["rs-payments-basic", "dev-introspection-rs-payments-basic"] as const;
const RS_SAAS = ["rs-saas", "dev-introspection-rs-saas"] as const;

let as: BuiltAs;
let asServer: Server;
let agentKey: CryptoKey;
// @spec mission#introspection (issue #541 P1-4) — the TEST's own retained
// copy of the AT signing key it injected via testTokenSigningJwk; BuiltAs
// never exposes it (the pre-#541 tokenSigningJwk export is retired).
let testSigningKey: CryptoKey;

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

/**
 * Sign an adversarial at+jwt with the TEST's OWN injected signing key (@spec
 * mission#introspection issue #541 P1-4 — never the production key, which
 * BuiltAs no longer exposes). Defaults to a FULLY VALID RFC 9068 + Mission
 * claim set (so a test that overrides only ONE field is a true one-field
 * mutation of an otherwise-active token, never a vacuous pass at some other
 * gate); `opts.omitExp`/`omitIat` drop the builder-set claim entirely (a
 * `payload.exp` override alone cannot removed a builder-set claim).
 */
async function craftToken(
  payload: Record<string, unknown>,
  opts: { typ?: string; expiresIn?: number; omitExp?: boolean; omitIat?: boolean } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  let builder = new SignJWT({
    iss: ISSUER,
    sub: "alice",
    aud: PAYMENTS,
    client_id: "ap-agent",
    authorization_details: PAYMENTS_PROPOSAL,
    ...payload,
  }).setProtectedHeader({ alg: "RS256", kid: "as-token", typ: opts.typ ?? "at+jwt" });
  if (!opts.omitIat) builder = builder.setIssuedAt(now);
  if (!opts.omitExp) builder = builder.setExpirationTime(now + (opts.expiresIn ?? 300));
  return builder.sign(testSigningKey);
}

const tokenAdapter = () =>
  (as.provider.AccessToken as unknown as {
    adapter: { find(id: string): Promise<unknown>; destroy(id: string): Promise<void> };
  }).adapter;
const refreshAdapter = () =>
  (as.provider.RefreshToken as unknown as {
    adapter: { destroy(id: string): Promise<void> };
  }).adapter;

let flow1: FlowResult; // payments; requested_derivation_limit 5; proposal (proposal_hash on record)
let flow2: FlowResult; // multi-audience: payments + saas
let flow3: FlowResult; // saas-only (rs-saas positive rows)
let flow4: FlowResult; // payments; refresh-token rows
let flow5: FlowResult; // payments; DEDICATED to P1-1/P1-2 (never mutated by other describes)

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
  // @spec mission#introspection (issue #541 P1-4) — generate the AT signing
  // key HERE and inject it, so the test (not BuiltAs) holds the private half.
  const testSigningKeys = await generateKeyPair("RS256", { extractable: true });
  testSigningKey = testSigningKeys.privateKey;
  const testTokenSigningJwk = (await exportJWK(testSigningKeys.privateKey)) as JWK;

  as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true, testTokenSigningJwk });
  asServer = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  flow1 = await runFlow({
    intent: {
      goal: "Pay Acme invoices for Q3",
      target_resources: [PAYMENTS],
      expires_at: "2027-01-01T00:00:00Z",
      requested_derivation_limit: 5,
    },
    proposal: PAYMENTS_PROPOSAL,
    resource: PAYMENTS,
  });
  flow2 = await runFlow({
    intent: {
      goal: "Reconcile payments against the ledger",
      target_resources: [PAYMENTS, SAAS],
      expires_at: "2027-01-01T00:00:00Z",
    },
    proposal: [...PAYMENTS_PROPOSAL, ...SAAS_PROPOSAL],
    resource: PAYMENTS,
  });
  flow3 = await runFlow({
    intent: {
      goal: "Read ledger vendors",
      target_resources: [SAAS],
      expires_at: "2027-01-01T00:00:00Z",
    },
    proposal: SAAS_PROPOSAL,
    resource: SAAS,
  });
  flow4 = await runFlow({
    intent: {
      goal: "Pay Acme invoices for Q4",
      target_resources: [PAYMENTS],
      expires_at: "2027-01-01T00:00:00Z",
    },
    proposal: PAYMENTS_PROPOSAL,
    resource: PAYMENTS,
  });
  flow5 = await runFlow({
    intent: {
      goal: "Pay Acme invoices for Q1 (dedicated to P1-1/P1-2 fixtures)",
      target_resources: [PAYMENTS],
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

  // @spec RFC 6749 Appendix B (cleanup, issue #541) — the Basic scheme token
  // is case-insensitive; a lowercase "basic" is not the wrong scheme.
  it("authenticates a case-insensitive Basic scheme token", async () => {
    const raw = `basic ${Buffer.from("rs-payments:dev-introspection-rs-payments").toString("base64")}`;
    const res = await introspect(flow1.at, { rawAuth: raw });
    expect(res.status).toBe(200);
    expect(res.body.active).toBe(true);
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
    // A FULLY WELL-FORMED mission claim (id/issuer/authority_hash all
    // present) pointing at a Mission id this AS has never approved: this
    // exercises Mission-lookup failure specifically, not the claim-shape
    // gate (@spec mission#541 P1-3, which a shape-incomplete claim would
    // trip FIRST, pinning nothing about Mission resolution).
    const crafted = await craftToken({
      jti: flow1.jti,
      mission: { id: "m-unknown", issuer: ISSUER, authority_hash: "sha256:deadbeef" },
    });
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

describe("RFC 9068 + Mission claim-set enforcement (@spec mission#introspection — issue #541 P1-3)", () => {
  // A crafted baseline reusing flow1's REAL jti/missionId (so the P1-2
  // issuance-index/grant-liveness check resolves against flow1's live
  // approval grant) with an otherwise FULLY VALID claim set. Each negative
  // test corrupts/removes exactly ONE field from this baseline.
  const baselineFields = () => ({
    jti: flow1.jti,
    mission: { id: flow1.missionId, issuer: ISSUER, authority_hash: "sha256:whatever-the-shape-check-does-not-verify-equality" },
  });

  it("baseline sanity: a fully-formed crafted token introspects active", async () => {
    const res = await introspect(await craftToken(baselineFields()), { principal: RS_PAYMENTS });
    expect(res.body.active).toBe(true);
  });

  it("@spec mission#the-mission-claim (#702): a baseline {id, issuer} mission claim, with no authority_hash at all, still introspects active", async () => {
    const crafted = await craftToken({
      jti: flow1.jti,
      mission: { id: flow1.missionId, issuer: ISSUER },
    });
    const res = await introspect(crafted, { principal: RS_PAYMENTS });
    expect(res.body.active).toBe(true);
  });

  it("a present-but-empty-string authority_hash on the mission claim -> bare active:false (typed-when-present, not merely truthy-checked)", async () => {
    const crafted = await craftToken({
      jti: flow1.jti,
      mission: { id: flow1.missionId, issuer: ISSUER, authority_hash: "" },
    });
    expect((await introspect(crafted, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
  });

  it("@spec mission#the-mission-claim (#702): a real mission.id with a MISMATCHED mission.issuer is never silently repaired to the record's issuer -> bare active:false", async () => {
    const crafted = await craftToken({
      jti: flow1.jti,
      mission: { id: flow1.missionId, issuer: "https://evil.example" },
    });
    expect((await introspect(crafted, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
  });

  it("missing exp -> bare active:false", async () => {
    const crafted = await craftToken(baselineFields(), { omitExp: true });
    expect((await introspect(crafted, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
  });

  it("missing jti -> bare active:false", async () => {
    const { jti: _jti, ...rest } = baselineFields();
    const crafted = await craftToken(rest);
    expect((await introspect(crafted, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
  });

  it("malformed authorization_details (array of bare strings) -> bare active:false", async () => {
    const crafted = await craftToken({
      ...baselineFields(),
      authorization_details: ["payments:invoice.read", "payments:remittance.send"],
    });
    expect((await introspect(crafted, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
  });

  it("missing authorization_details entirely -> bare active:false (every AT this AS mints carries it)", async () => {
    const crafted = await craftToken({ ...baselineFields(), authorization_details: undefined });
    expect((await introspect(crafted, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
  });
});

describe("audience-to-resource mapping (cleanup, issue #541): an OAuth aud need not be byte-equal to a RAR resource", () => {
  it("an unmapped audience defaults to identity", () => {
    expect(resourcesForAudiences(["https://rs.example/aud"], undefined)).toEqual(
      new Set(["https://rs.example/aud"]),
    );
  });

  it("a mapped audience contributes its FULL mapped resource set, not itself", () => {
    const mapping = { "https://rs.example/aud": ["urn:svc:payments-api", "urn:svc:payments-api-v2"] };
    expect(resourcesForAudiences(["https://rs.example/aud"], mapping)).toEqual(
      new Set(["urn:svc:payments-api", "urn:svc:payments-api-v2"]),
    );
  });

  it("mixes mapped and unmapped audiences independently, unioning the result", () => {
    const mapping = { a1: ["r1", "r2"] };
    expect(resourcesForAudiences(["a1", "a2"], mapping)).toEqual(new Set(["r1", "r2", "a2"]));
  });
});

describe("credential-authority projection: never the Mission's full authority (@spec mission#introspection — issue #541 P1-1)", () => {
  it("a narrowed credential discloses ONLY the authority IT carries, even though the Mission permits more", async () => {
    const record = as.kernel.get(flow5.missionId);
    // @spec mission#authorization-derivation (#743) — the payments ceiling is
    // now two entries (money-bearing / read-only), so PAYMENTS_PROPOSAL's
    // single mixed entry derives two authority_set entries; checked across
    // the whole set, not `authority_set[0]` alone.
    const recordActions = (record?.authority_set ?? []).flatMap((e) => e.actions);
    expect(recordActions).toEqual(
      expect.arrayContaining(["payments:invoice.read", "payments:remittance.send"]),
    );
    const narrowClaim: AuthorityEntry[] = [
      { type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:invoice.read"] },
    ];
    const crafted = await craftToken({
      jti: flow5.jti,
      mission: { id: flow5.missionId, issuer: ISSUER, authority_hash: record?.authority_hash },
      authorization_details: narrowClaim,
    });
    const res = await introspect(crafted, { principal: RS_PAYMENTS });
    expect(res.body.active).toBe(true);
    const details = res.body.authorization_details as AuthorityEntry[];
    expect(details).toHaveLength(1);
    const allActions = details.flatMap((d) => d.actions);
    expect(allActions).toContain("payments:invoice.read");
    expect(allActions).not.toContain("payments:remittance.send");
    // The `mission` object no longer carries authorization_details at all
    // (it moved to the top level, @spec mission#541 P1-1).
    expect("authorization_details" in (res.body.mission as object)).toBe(false);
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
      "authorization_details",
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
    // Core members ({id, issuer} baseline #702) + derivations_remaining
    // (requested_derivation_limit in force) + proposal_hash, authority_hash,
    // approval_basis (all provenance privilege). NO authorization_details: it
    // now lives at the top level only (@spec mission#541 P1-1). NO
    // expires_at: introspection never carries it (@spec mission#introspection).
    expect(Object.keys(mission).sort()).toEqual([
      "approval_basis",
      "authority_hash",
      "derivations_remaining",
      "id",
      "issuer",
      "proposal_hash",
      "state",
      "version",
    ]);
    expect(mission.id).toBe(flow1.missionId);
    expect(mission.state).toBe("active");
    // One committed issuance (this token) against requested_derivation_limit 5.
    expect(mission.derivations_remaining).toBe(4);
    const record = as.kernel.get(flow1.missionId);
    expect(mission.proposal_hash).toBe(record?.proposal_hash);
    const details = res.body.authorization_details as AuthorityEntry[];
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
    const details = res.body.authorization_details as AuthorityEntry[];
    expect(details.length).toBeGreaterThan(0);
    for (const entry of details) expect(entry.resource).toBe(PAYMENTS);
  });

  it("budget disclosure is privilege-gated: an authorized RS without the budget privilege never sees derivations_remaining", async () => {
    // flow1 carries requested_derivation_limit, but rs-payments-basic holds no
    // disclosure privileges: the enforcement projection arrives without
    // derivations_remaining (and without proposal_hash).
    const res = await introspect(flow1.at, { principal: RS_PAYMENTS_BASIC });
    expect(res.body.active).toBe(true);
    const mission = res.body.mission as Record<string, unknown>;
    // (#702) `authority_hash`/`approval_basis` share the same "provenance"
    // disclosure privilege as `proposal_hash`; a privilege-less principal
    // sees none of them.
    expect(Object.keys(mission).sort()).toEqual(["id", "issuer", "state", "version"]);
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
    expect(Object.keys(mission).sort()).toEqual(["id", "issuer", "state", "version"]);
    for (const entry of res.body.authorization_details as AuthorityEntry[]) {
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
    const actions = (res.body.authorization_details as AuthorityEntry[]).flatMap((e) => e.actions);
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

describe("individual revocation is grant/family-scoped, never Mission-scoped (@spec mission#introspection — issue #541 P1-2)", () => {
  it("destroying ONLY an async-delegation family leaves ITS tokens active:false while the Mission-grant token stays active", async () => {
    const actingDpop = await generateKeyPair("ES256", { extractable: true });
    const actingPub = await exportJWK(actingDpop.publicKey);
    const dpopProof = async (extra: Record<string, unknown> = {}): Promise<string> =>
      new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
        .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: actingPub })
        .setIssuedAt()
        .setJti(crypto.randomUUID())
        .sign(actingDpop.privateKey);

    const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
      fetch(`${ISSUER}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(extra) },
        body: new URLSearchParams({
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          request_refresh_token: "true",
          subject_token: flow5.at,
          subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
          resource: PAYMENTS,
          creation_request_id: crypto.randomUUID(),
          client_assertion: await clientAssertion(),
          client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        }).toString(),
      });
    let res = await send();
    const nonce = res.headers.get("dpop-nonce");
    if (res.status === 400 && nonce) res = await send({ nonce });
    const exchangeBody = (await res.json()) as { access_token: string };
    expect(res.status, JSON.stringify(exchangeBody)).toBe(200);
    const familyAt = exchangeBody.access_token;

    // Sanity: the fresh family access token introspects active BEFORE the
    // family is touched, and the Mission's approval-grant token is (still)
    // unaffected by this family's mere existence.
    expect((await introspect(familyAt, { principal: RS_PAYMENTS })).body.active).toBe(true);
    expect((await introspect(flow5.at, { principal: RS_PAYMENTS })).body.active).toBe(true);

    // Recover the family's grantId from the delegation-family store the
    // Mission was rooted in (a real production accessor, not a test hack).
    const familyGrantId = as.delegationFamilyStore
      .familiesForMission(flow5.missionId)
      .find((gid) => as.delegationFamilyStore.resolve(gid) !== undefined);
    expect(familyGrantId).toBeDefined();

    // Destroy ONLY the family: the Mission itself is untouched and stays
    // active (unlike Mission-level revocation, which destroys every grant
    // rooted in it as a side effect).
    as.delegationFamilyStore.invalidate(familyGrantId as string);
    expect(as.kernel.get(flow5.missionId)?.state).toBe("active");

    // The family's own access token is now bare inactive...
    expect((await introspect(familyAt, { principal: RS_PAYMENTS })).body).toEqual({ active: false });
    // ...but the Mission-grant access token is isolated from that family's
    // destruction (isolation in BOTH directions).
    expect((await introspect(flow5.at, { principal: RS_PAYMENTS })).body.active).toBe(true);
  });
});

describe("composite non-active: active:false WITH mission.state (@spec mission#composite-active)", () => {
  it("revoked Mission + valid token: only { active, mission }, state revoked, NO top-level or mission authorization_details", async () => {
    as.kernel.transition(flow1.missionId, "revoke");
    const res = await introspect(flow1.at, { principal: RS_PAYMENTS });
    expect(res.status).toBe(200);
    // @spec mission#541 (advisor-confirmed guard) — the non-active branch
    // NEVER gains a top-level authorization_details member.
    expect(Object.keys(res.body).sort()).toEqual(["active", "mission"]);
    expect(res.body.active).toBe(false);
    const mission = res.body.mission as Record<string, unknown>;
    expect(mission.state).toBe("revoked");
    expect(mission.id).toBe(flow1.missionId);
    expect("authorization_details" in mission).toBe(false);
    // The Mission-bound refresh token reports the SAME composite.
    const rt = await introspect(flow1.rt, { principal: RS_PAYMENTS, hint: "refresh_token" });
    expect(Object.keys(rt.body).sort()).toEqual(["active", "mission"]);
    expect((rt.body.mission as { state: string }).state).toBe("revoked");
  });

  it("the inactive response is member-scoped too: a privilege-less principal sees no budget or provenance metadata", async () => {
    // Self-contained setup (order-independent): a fresh Mission with a
    // derivation cap and an authority proposal, revoked here, introspected
    // by the privilege-less principal: the non-active composite carries the
    // enforcement projection alone.
    const flowX = await runFlow({
      intent: {
        goal: "Pay Acme invoices for Q3 (inactive-disclosure fixture)",
        target_resources: [PAYMENTS],
        expires_at: "2027-01-01T00:00:00Z",
        requested_derivation_limit: 5,
      },
      proposal: PAYMENTS_PROPOSAL,
      resource: PAYMENTS,
    });
    as.kernel.transition(flowX.missionId, "revoke");
    const res = await introspect(flowX.at, { principal: RS_PAYMENTS_BASIC });
    expect(res.body.active).toBe(false);
    const mission = res.body.mission as Record<string, unknown>;
    expect("derivations_remaining" in mission).toBe(false);
    expect("proposal_hash" in mission).toBe(false);
    expect("authority_hash" in mission).toBe(false);
    expect("approval_basis" in mission).toBe(false);
    expect(mission.state).toBe("revoked");
    expect(Object.keys(mission).sort()).toEqual(["id", "issuer", "state", "version"]);
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
      "authorization_details",
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
    for (const entry of res.body.authorization_details as AuthorityEntry[]) {
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
