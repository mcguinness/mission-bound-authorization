/**
 * @spec mission#scope-projection, resource-access#scope-projection — the
 * token endpoint's scope projection, end to end, against a Resource Server
 * that carries no Mission code (@mission/plain-rs) and authorizes on `scope`
 * alone.
 *
 * The mapping is the shipped config/scope-projection.json (the plain RS
 * audience is `scope_only`; payments consumes `authorization_details`),
 * injected as a mutable copy so a case can swap the plain RS entry (or bump
 * its version) between issuances. Every Mission is derived by the real
 * kernel under the shipped ceiling, whose plain RS entry is constraints-free,
 * so constraint cases add their constraint through the authority proposal.
 */
import type { Server } from "node:http";
import { ResourceContractDeclarations, type ResourceContractRef, resourceContractDigest } from "@mission/core";
import { startPlainResourceServer } from "@mission/plain-rs";
import {
  DERIVATION_POLICY,
  DEV_SERVICE_TOKEN,
  demoReconciliationTemplate,
  INTROSPECTION_PRINCIPALS,
  RUNTIME_SCOPE_CONFIG,
  SCOPE_PROJECTION,
  TOPOLOGY,
} from "@mission/demo-data";
import {
  type CryptoKey,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  SignJWT,
} from "jose";
// oidc-provider 9.10.0's internal instance cache, the one its JWT format
// reads the configured customizer from (no published types).
import instance from "oidc-provider/lib/helpers/weak_cache.js";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { MISSION_DISPATCH_GRANT_TYPE } from "../src/adapters/provider.js";
import { ApprovalSessionStore, type AuthorityEntry, type BuiltAs, buildAuthorizationServer } from "../src/index.js";
import { DEFERRED_GRANT_TYPE } from "../src/kernel/deferred.js";
import { browserApprovalHeaders, floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";
import { delegationHandleParams } from "./delegation-handle.helper.js";

const PORT = 14620;
const RS_PORT = 14621;
const RS_INTROSPECT_PORT = 14622;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const PLAIN = TOPOLOGY.resources.plainRs;
const PAYMENTS = DERIVATION_POLICY.ceiling[0].resource;
const READ = "reports:report.read";
const WRITE = "reports:report.write";
const PKCE_VERIFIER = "scope-projection-verifier-0123456789-0123456789";

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey; jwk: JWK };
type Json = Record<string, unknown>;

/** The live mapping the AS reads at every issuance. */
const MAPPING = structuredClone(SCOPE_PROJECTION);
const SHIPPED_PLAIN = structuredClone(SCOPE_PROJECTION.audiences[PLAIN]);

/**
 * @spec resource-access#scope-projection (a requested scope value standing for
 * an entry with a contract): a contract the plain RS declares, v1 superseded
 * within retention and v2 current, required for no action, beside the shipped
 * declarations, so a mapping value can name one and no other case changes.
 */
const PLAIN_CONTRACT = "https://plain.test/contracts/reports";
const plainContractDoc = (version: string) => ({
  id: PLAIN_CONTRACT,
  version,
  operation_profile: `reports-${version}`,
  operations: { read: { action: READ }, write: { action: WRITE } },
});
const plainContractRef = (version: string): ResourceContractRef => ({
  id: PLAIN_CONTRACT,
  version,
  digest: resourceContractDigest(plainContractDoc(version)),
});
const CONTRACTS = new ResourceContractDeclarations([
  ...((RUNTIME_SCOPE_CONFIG as { extensions?: { resource_contracts?: unknown[] } }).extensions?.resource_contracts ?? []),
  {
    resource: PLAIN,
    resource_match: "exact",
    id: PLAIN_CONTRACT,
    requires_reference: [],
    versions: [
      {
        version: "v1",
        state: "superseded",
        retained_until: "2099-01-01T00:00:00Z",
        digest: plainContractRef("v1").digest,
        document: plainContractDoc("v1"),
      },
      { version: "v2", state: "current", digest: plainContractRef("v2").digest, document: plainContractDoc("v2") },
    ],
  },
]);

let as: BuiltAs;
let asServer: Server;
let rs: Server;
let rsIntrospecting: Server;
let agentKey: CryptoKey;
let governedKey: CryptoKey;
/** The TEST's own copy of the AT signing key it injected, to craft adversarial subject tokens. */
let signingKey: CryptoKey;

const entry = (actions: string[], extra: Json = {}): AuthorityEntry =>
  ({ type: "mission_resource_access", resource: PLAIN, actions, ...extra }) as AuthorityEntry;
const rights = (actions: string[], match = "exact") => ({
  type: "mission_resource_access",
  resource: PLAIN,
  match,
  actions,
});
/** Replace the plain RS audience's mapping entry (undefined removes it) for one case. */
async function withPlain(value: unknown, run: () => Promise<void>): Promise<void> {
  const audiences = MAPPING.audiences as Record<string, unknown>;
  if (value === undefined) delete audiences[PLAIN];
  else audiences[PLAIN] = value;
  try {
    await run();
  } finally {
    audiences[PLAIN] = structuredClone(SHIPPED_PLAIN);
  }
}

async function newKeys(): Promise<Keys> {
  const k = await generateKeyPair("ES256", { extractable: true });
  return { ...k, jwk: await exportJWK(k.publicKey) };
}

async function dpopProof(keys: Keys, htm: string, htu: string, extra: Json = {}): Promise<string> {
  return new SignJWT({ htm, htu, ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: keys.jwk })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

async function clientAssertion(client = "ap-agent"): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${client}-auth` })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(client === "governed-agent" ? governedKey : agentKey);
}

/**
 * POST /token with a DPoP proof, retrying once on a DPoP nonce. Authenticates
 * as ap-agent unless `client` names another registered client, or "none"
 * (no client authentication at all).
 */
async function token(
  params: Record<string, string>,
  keys: Keys,
  client: "ap-agent" | "governed-agent" | "none" = "ap-agent",
): Promise<{ status: number; body: Json }> {
  const htu = `${ISSUER}/token`;
  const send = async (extra: Json = {}) =>
    fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await dpopProof(keys, "POST", htu, extra),
      },
      body: new URLSearchParams({
        ...params,
        ...(client === "none"
          ? { client_id: "ap-agent" }
          : {
              client_assertion: await clientAssertion(client),
              client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            }),
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Json };
}

/**
 * The acting client's delegation handle for `base` (#1157, D358), the async
 * transport's subject_token: requested under the base token's own key, which
 * the handle and the family it opens keep.
 */
async function handle(base: string, keys: Keys): Promise<string> {
  const res = await token(delegationHandleParams(base, "ap-agent"), keys);
  if (res.status !== 200) throw new Error(`delegation handle refused: ${res.status} ${JSON.stringify(res.body)}`);
  return res.body.access_token as string;
}

/** The trusted browser login, for the approvals an ID Token can describe (#826). */
const SESSIONS = new ApprovalSessionStore();

/**
 * PAR -> approval for a Mission over `proposal`, optionally naming `scope`:
 * the PAR response, then the authorization response's code or error.
 */
async function authorize(
  proposal: AuthorityEntry[] | undefined,
  opts: { resource?: string; scope?: string; targetResources?: string[] } = {},
): Promise<{ par: { status: number; body: Json }; code?: string; error?: string; description?: string }> {
  const resource = opts.resource ?? PLAIN;
  const targetResources = opts.targetResources ?? [resource];
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER)),
  ).toString("base64url");
  const parRes = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource,
      ...(opts.scope !== undefined ? { scope: opts.scope } : {}),
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: { goal: "Publish the quarterly reports", target_resources: targetResources, expires_at: "2027-01-01T00:00:00Z" },
      }),
      ...(proposal ? { authorization_details: JSON.stringify(proposal) } : {}),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const par = { status: parRes.status, body: (await parRes.json()) as Json };
  if (par.status !== 201) return { par };
  const { request_uri } = par.body as { request_uri: string };
  const cookies = new Map<string, string>();
  const cookie = () => [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
    redirect: "manual",
  });
  keep(res);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    // An `openid` request needs an End-User authenticated in this user agent
    // and approving for themself (#826): a trusted browser self-approval.
    // Every other request is Bob's browser approval for alice, which the
    // approval-authentication floor accepts for high-risk authority (D425).
    headers: {
      ...(opts.scope?.split(" ").includes("openid")
        ? browserApprovalHeaders(SESSIONS, uid, { sub: "alice" }, cookie())
        : floorApprovalHeaders(SESSIONS, uid, cookie())),
      "content-type": "application/json",
    },
    body: JSON.stringify({ decision: "approve" }),
  });
  keep(res);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") as string;
  }
  const q = new URL(location).searchParams;
  return {
    par,
    ...(q.get("code") ? { code: q.get("code") as string } : {}),
    ...(q.get("error") ? { error: q.get("error") as string } : {}),
    ...(q.get("error_description") ? { description: q.get("error_description") as string } : {}),
  };
}

/** PAR -> approval: returns the authorization code for a Mission over `proposal`. */
async function approve(proposal: AuthorityEntry[], resource = PLAIN, scope?: string): Promise<string> {
  const r = await authorize(proposal, { resource, ...(scope !== undefined ? { scope } : {}) });
  expect(r.par.status, JSON.stringify(r.par.body)).toBe(201);
  expect(r.code, JSON.stringify(r)).toBeTruthy();
  return r.code as string;
}

function redeem(code: string, keys: Keys, resource = PLAIN) {
  return token(
    { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: PKCE_VERIFIER, resource },
    keys,
  );
}

function refresh(refreshToken: string, keys: Keys, scope?: string, client?: "ap-agent" | "governed-agent" | "none") {
  return token(
    { grant_type: "refresh_token", refresh_token: refreshToken, ...(scope !== undefined ? { scope } : {}) },
    keys,
    client,
  );
}

/** A full issuance to the plain RS: the token response plus the DPoP key it is bound to. */
async function issue(proposal: AuthorityEntry[], scope?: string): Promise<{ status: number; body: Json; keys: Keys }> {
  const keys = await newKeys();
  const code = await approve(proposal, PLAIN, scope);
  return { ...(await redeem(code, keys)), keys };
}

/** Call the plain RS with a DPoP-bound access token. */
async function callRs(port: number, method: "GET" | "POST", accessToken: string, keys: Keys): Promise<Response> {
  const url = `http://localhost:${port}/api/reports`;
  const ath = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessToken))).toString(
    "base64url",
  );
  return fetch(url, {
    method,
    headers: {
      authorization: `DPoP ${accessToken}`,
      dpop: await dpopProof(keys, method, url, { ath }),
      ...(method === "POST" ? { "content-type": "application/json" } : {}),
    },
    ...(method === "POST" ? { body: JSON.stringify({ title: "Q3" }) } : {}),
  });
}

beforeAll(async () => {
  const signing = await generateKeyPair("RS256", { extractable: true });
  signingKey = signing.privateKey;
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
    scopeProjection: MAPPING,
    resourceContracts: CONTRACTS,
    testTokenSigningJwk: (await exportJWK(signing.privateKey)) as JWK,
  });
  asServer = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  governedKey = (await importJWK(as.governedClientJwk as never, "ES256")) as CryptoKey;
  const base = { issuer: ISSUER, audience: PLAIN, jwksUri: `${ISSUER}/jwks` };
  rs = await startPlainResourceServer({ ...base, baseUrl: `http://localhost:${RS_PORT}` }, RS_PORT);
  const principal = INTROSPECTION_PRINCIPALS.find((p) => p.principal_id === "rs-plain");
  if (!principal) throw new Error("config/introspection.json names no rs-plain principal");
  rsIntrospecting = await startPlainResourceServer(
    {
      ...base,
      baseUrl: `http://localhost:${RS_INTROSPECT_PORT}`,
      introspection: {
        endpoint: `${ISSUER}/introspect`,
        clientId: principal.principal_id,
        clientSecret: principal.secret,
      },
    },
    RS_INTROSPECT_PORT,
  );
});

afterAll(() => {
  asServer?.close();
  rs?.close();
  rsIntrospecting?.close();
});

describe("scope projection at the token endpoint (@spec mission#scope-projection)", () => {
  it("a safe projection carries exactly the projected scope, and the plain RS allows the in-scope operation and refuses the other with 403 insufficient_scope", async () => {
    const { status, body, keys } = await issue([entry([READ])]);
    expect(status, JSON.stringify(body)).toBe(200);
    expect(body.scope).toBe("reports.read");
    const at = body.access_token as string;
    expect(decodeJwt(at).scope).toBe("reports.read");
    expect((await callRs(RS_PORT, "GET", at, keys)).status).toBe(200);
    const denied = await callRs(RS_PORT, "POST", at, keys);
    expect(denied.status).toBe(403);
    expect(((await denied.json()) as Json).error).toBe("insufficient_scope");
    expect(denied.headers.get("www-authenticate")).toMatch(/error="insufficient_scope".*scope="reports\.write"/);
  });

  it("refuses invalid_target when an entry constraint is not independently enforced by the target, and projects once the mapping declares a control at least as tight", async () => {
    const constrained = [entry([READ], { constraints: { vendors: ["acme"] } })];
    const refused = await issue(constrained);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("invalid_target");
    expect(refused.body.error_description).toMatch(/no safe scope projection/);

    await withPlain(
      {
        version: SHIPPED_PLAIN?.version,
        mission_aware: false,
        mode: "scope_only",
        scopes: { "reports.read": { rights: rights([READ]), mandatory_controls: { vendors: ["acme"] } } },
      },
      async () => {
        const ok = await issue(constrained);
        expect(ok.status, JSON.stringify(ok.body)).toBe(200);
        expect(ok.body.scope).toBe("reports.read");
      },
    );
  });

  it("refuses invalid_target for an audience the mapping does not know", async () => {
    const keys = await newKeys();
    const code = await approve([entry([READ])]);
    await withPlain(undefined, async () => {
      const res = await redeem(code, keys);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_target");
      expect(res.body.error_description).toMatch(/no scope-projection mapping/);
    });
  });

  it("refuses a scope only the union of two entries covers", async () => {
    await withPlain(
      {
        version: "union-1",
        mission_aware: false,
        mode: "scope_only",
        scopes: { "reports.rw": { rights: rights([READ, WRITE]), mandatory_controls: {} } },
      },
      async () => {
        const res = await issue([entry([READ]), entry([WRITE])]);
        expect(res.status, JSON.stringify(res.body)).toBe(400);
        expect(res.body.error).toBe("invalid_target");
        expect(res.body.error_description).toMatch(/no safe scope projection/);
      },
    );
  });

  it("refuses a scope that aggregates an action the entry does not carry", async () => {
    await withPlain(
      {
        version: "aggregate-1",
        mission_aware: false,
        mode: "scope_only",
        scopes: { "reports.all": { rights: rights([READ, WRITE]), mandatory_controls: {} } },
      },
      async () => {
        const res = await issue([entry([READ])]);
        expect(res.status, JSON.stringify(res.body)).toBe(400);
        expect(res.body.error).toBe("invalid_target");
        expect(res.body.error_description).toMatch(/no safe scope projection/);
      },
    );
  });

  it("refuses a prefix scope for an exact entry", async () => {
    await withPlain(
      {
        version: "prefix-1",
        mission_aware: false,
        mode: "scope_only",
        scopes: { "reports.read": { rights: rights([READ], "prefix"), mandatory_controls: {} } },
      },
      async () => {
        const res = await issue([entry([READ])]);
        expect(res.status, JSON.stringify(res.body)).toBe(400);
        expect(res.body.error).toBe("invalid_target");
        expect(res.body.error_description).toMatch(/no safe scope projection/);
      },
    );
  });

  it("omits scope on a Mission-bound token to an authorization_details audience", async () => {
    const keys = await newKeys();
    const code = await approve(
      [
        {
          type: "mission_resource_access",
          resource: PAYMENTS,
          actions: ["payments:invoice.read"],
          constraints: { vendors: ["acme"] },
        },
      ],
      PAYMENTS,
    );
    const res = await redeem(code, keys, PAYMENTS);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scope).toBeUndefined();
    const claims = decodeJwt(res.body.access_token as string);
    expect(claims.aud).toBe(PAYMENTS);
    expect(claims.mission).toBeDefined();
    expect(claims.scope).toBeUndefined();
    expect(claims.authorization_details).toEqual(res.body.authorization_details);
  });
});

/**
 * @spec resource-access#resource-access-type (#1266): "the authorization
 * server SHOULD emit for a given `resource` only `constraints` keys that the
 * resource server serving it is known to understand and enforce". The
 * mapping's `mission_constraints_supported` is that knowledge; a key it
 * cannot vouch for refuses the issuance, never dropped from the entry.
 */
describe("the token endpoint emits for an audience only constraints keys it is known to enforce (@spec resource-access#resource-access-type)", () => {
  const SAAS = TOPOLOGY.resources.saas;
  const SHIPPED_PAYMENTS = structuredClone(SCOPE_PROJECTION.audiences[PAYMENTS]);
  /** Replace the payments audience's mapping entry for one case. */
  async function withPayments(value: unknown, run: () => Promise<void>): Promise<void> {
    const audiences = MAPPING.audiences as Record<string, unknown>;
    audiences[PAYMENTS] = value;
    try {
      await run();
    } finally {
      audiences[PAYMENTS] = structuredClone(SHIPPED_PAYMENTS);
    }
  }
  const paymentsRead = (constraints: Json): AuthorityEntry =>
    ({ type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:invoice.read"], constraints }) as AuthorityEntry;
  const TENANTED = { vendors: ["acme"], tenant: "payments-demo" };
  const withoutTenant = () => ({
    version: "2026-10-20.test",
    mission_aware: true,
    mode: "authorization_details",
    mission_constraints_supported: ["max_amount", "vendors"],
  });

  it("emits an entry whose every key the audience's mission_constraints_supported names, unchanged", async () => {
    const keys = await newKeys();
    const code = await approve([paymentsRead(TENANTED)], PAYMENTS);
    const res = await redeem(code, keys, PAYMENTS);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const details = decodeJwt(res.body.access_token as string).authorization_details as Json[];
    expect(details.map((e) => e.constraints)).toEqual([TENANTED]);
  });

  it("refuses invalid_target, issuing no token, when an entry for the audience carries a key the audience is not known to enforce", async () => {
    const keys = await newKeys();
    const code = await approve([paymentsRead(TENANTED)], PAYMENTS);
    await withPayments(withoutTenant(), async () => {
      const refused = await redeem(code, keys, PAYMENTS);
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_target");
      expect(refused.body.error_description).toMatch(/not known to enforce the constraints key tenant/);
      expect(refused.body.access_token).toBeUndefined();
    });
  });

  it("a refresh re-checks against the current mapping: an audience whose key list no longer names a carried key refuses, and an audience with no list is known to enforce no key (boundary)", async () => {
    const keys = await newKeys();
    const first = await redeem(await approve([paymentsRead(TENANTED)], PAYMENTS), keys, PAYMENTS);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    const rt = first.body.refresh_token as string;
    await withPayments(withoutTenant(), async () => {
      const refused = await refresh(rt, keys);
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_target");
    });
    const { mission_constraints_supported: _keys, ...noList } = withoutTenant();
    await withPayments(noList, async () => {
      const refused = await refresh(rt, keys);
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_target");
      expect(refused.body.error_description).toMatch(/not known to enforce the constraints key vendors/);
    });
    const after = await refresh(rt, keys);
    expect(after.status, JSON.stringify(after.body)).toBe(200);
  });

  it("checks an entry against the audience it is issued for: an entry for another resource rides in this token, and a token issued for that resource refuses it (boundary)", async () => {
    // SaaS is known to enforce only vendors; payments enforces tenant.
    const saasRead = {
      type: "mission_resource_access",
      resource: SAAS,
      actions: ["ledger:vendor.read"],
      constraints: { vendors: ["acme"], tenant: "ledger-demo" },
    } as AuthorityEntry;
    const proposal = [paymentsRead(TENANTED), saasRead];
    const targetResources = [PAYMENTS, SAAS];

    const forPayments = await authorize(proposal, { resource: PAYMENTS, targetResources });
    expect(forPayments.code, JSON.stringify(forPayments)).toBeTruthy();
    const keys = await newKeys();
    const payments = await redeem(forPayments.code as string, keys, PAYMENTS);
    expect(payments.status, JSON.stringify(payments.body)).toBe(200);
    const carried = decodeJwt(payments.body.access_token as string).authorization_details as Json[];
    expect(carried.find((e) => e.resource === SAAS)?.constraints).toEqual(saasRead.constraints);

    const forSaas = await authorize(proposal, { resource: SAAS, targetResources });
    expect(forSaas.code, JSON.stringify(forSaas)).toBeTruthy();
    const saas = await redeem(forSaas.code as string, await newKeys(), SAAS);
    expect(saas.status).toBe(400);
    expect(saas.body.error).toBe("invalid_target");
    expect(saas.body.error_description).toMatch(/not known to enforce the constraints key tenant/);
    expect(saas.body.access_token).toBeUndefined();
  });
});

describe("scope projection on derived tokens (@spec mission#scope-projection)", () => {
  it("refresh re-projects against the current mapping: a version bump alone still projects, a mapping that no longer proves the value refuses invalid_target, and an audience removed from the mapping fails closed", async () => {
    const first = await issue([entry([READ, WRITE])]);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    expect(first.body.scope).toBe("reports.read reports.write");
    const rt = first.body.refresh_token as string;

    const again = await refresh(rt, first.keys);
    expect(again.status, JSON.stringify(again.body)).toBe(200);
    expect(again.body.scope).toBe("reports.read reports.write");
    expect(decodeJwt(again.body.access_token as string).scope).toBe("reports.read reports.write");

    // A changed mapping is not by itself stale: the bumped version re-projects.
    await withPlain({ ...structuredClone(SHIPPED_PLAIN), version: "2026-10-01.1" }, async () => {
      const bumped = await refresh(rt, first.keys);
      expect(bumped.status, JSON.stringify(bumped.body)).toBe(200);
      expect(bumped.body.scope).toBe("reports.read reports.write");
    });

    // A mapping that no longer proves any value: the subset condition refuses.
    await withPlain(
      {
        version: "2026-10-02.1",
        mission_aware: false,
        mode: "scope_only",
        scopes: { "reports.admin": { rights: rights([READ, WRITE, "reports:report.delete"]), mandatory_controls: {} } },
      },
      async () => {
        const res = await refresh(rt, first.keys);
        expect(res.status).toBe(400);
        expect(res.body.error).toBe("invalid_target");
        expect(res.body.error_description).toMatch(/no safe scope projection/);
      },
    );

    // No mapping the AS can establish as current for the target: fails closed.
    await withPlain(undefined, async () => {
      const res = await refresh(rt, first.keys);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_target");
      expect(res.body.error_description).toMatch(/no scope-projection mapping/);
    });

    // Neither refusal cost the refresh token.
    const after = await refresh(rt, first.keys);
    expect(after.status, JSON.stringify(after.body)).toBe(200);
  });

  it("Token Exchange projects the family token's scope from its confined subset, keeps it on the family refresh, and refuses an unenforced constraint before creating a family", async () => {
    const base = await issue([entry([READ, WRITE])]);
    expect(base.status, JSON.stringify(base.body)).toBe(200);
    const acting = base.keys;
    const subject = await handle(base.body.access_token as string, acting);
    const exchange = (authorizationDetails: AuthorityEntry[]) =>
      token(
        {
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          request_refresh_token: "true",
          subject_token: subject,
          subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
          resource: PLAIN,
          creation_request_id: crypto.randomUUID(),
          authorization_details: JSON.stringify(authorizationDetails),
        },
        acting,
      );

    const family = await exchange([entry([READ])]);
    expect(family.status, JSON.stringify(family.body)).toBe(200);
    expect(family.body.scope).toBe("reports.read");
    const at = family.body.access_token as string;
    expect(decodeJwt(at).scope).toBe("reports.read");
    expect((await callRs(RS_PORT, "GET", at, acting)).status).toBe(200);
    expect((await callRs(RS_PORT, "POST", at, acting)).status).toBe(403);

    const refreshed = await refresh(family.body.refresh_token as string, acting);
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    expect(refreshed.body.scope).toBe("reports.read");
    expect(decodeJwt(refreshed.body.access_token as string).scope).toBe("reports.read");

    const missionId = (decodeJwt(base.body.access_token as string).mission as { id: string }).id;
    const count = as.kernel.get(missionId)?.derivation_count;
    const refused = await exchange([entry([READ], { constraints: { vendors: ["acme"] } })]);
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_target");
    expect(refused.body.error_description).toMatch(/no safe scope projection/);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(count);
  });
});

describe("scope projection on the dispatch and expansion-successor mints (@spec mission#scope-projection)", () => {
  /** A fresh copy of the demo read-only reconciliation template, through the admin plane. */
  async function newTemplate(): Promise<string> {
    const res = await fetch(`${ISSUER}/templates`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({ ...demoReconciliationTemplate(ISSUER), approval_event_id: `scope-tmpl-${crypto.randomUUID()}` }),
    });
    const body = (await res.json()) as Json;
    expect(res.status, JSON.stringify(body)).toBe(201);
    return body.template_id as string;
  }
  const submission = (goal: string) =>
    JSON.stringify({ intent: { goal, target_resources: [PLAIN], expires_at: "2027-01-01T00:00:00Z" } });

  it("a template dispatch to the scope-only target carries only the scope the instance's template-bounded entry proves, which the plain RS enforces, and refuses invalid_target while the target's mapping is unknown", async () => {
    const templateId = await newTemplate();
    const keys = await newKeys();
    const dispatchEventId = crypto.randomUUID();
    const dispatch = () =>
      token(
        {
          grant_type: MISSION_DISPATCH_GRANT_TYPE,
          template_id: templateId,
          mission_intent: submission("Read the quarterly reports"),
          dispatch_event_id: dispatchEventId,
        },
        keys,
      );

    await withPlain(undefined, async () => {
      const refused = await dispatch();
      expect(refused.status, JSON.stringify(refused.body)).toBe(400);
      expect(refused.body.error).toBe("invalid_target");
      expect(refused.body.error_description).toMatch(/no scope-projection mapping/);
      expect(refused.body.access_token).toBeUndefined();
    });

    // The template's ceiling keeps only the read action, while the policy
    // ceiling and the target's mapping also name the write action: the
    // token's scope is the projection of the derived entry alone.
    const res = await dispatch();
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.authorization_details).toEqual([{ type: "mission_resource_access", resource: PLAIN, actions: [READ] }]);
    expect(res.body.scope).toBe("reports.read");
    const at = res.body.access_token as string;
    const claims = decodeJwt(at);
    expect(claims.aud).toBe(PLAIN);
    expect((claims.mission as { id?: string }).id).toBe(res.body.mission_id);
    expect(claims.scope).toBe("reports.read");
    expect(claims.authorization_details).toEqual(res.body.authorization_details);
    expect((await callRs(RS_PORT, "GET", at, keys)).status).toBe(200);
    expect((await callRs(RS_PORT, "POST", at, keys)).status).toBe(403);
  });

  it("an expansion successor's first token carries the scope projected from the successor's own derived entry, which drops a requested action beyond the ceiling, and the plain RS enforces the widened scope", async () => {
    const DELETE = "reports:report.delete";
    const predecessor = await issue([entry([READ])]);
    expect(predecessor.status, JSON.stringify(predecessor.body)).toBe(200);
    expect(predecessor.body.scope).toBe("reports.read");
    const keys = predecessor.keys;
    const before = predecessor.body.access_token as string;
    expect((await callRs(RS_PORT, "POST", before, keys)).status).toBe(403);

    // The mapping also names a value for an action the policy ceiling never
    // grants at this target: only the derived entry can keep it out of `scope`.
    await withPlain(
      {
        ...structuredClone(SHIPPED_PLAIN),
        scopes: {
          ...structuredClone(SHIPPED_PLAIN?.scopes),
          "reports.delete": { rights: rights([DELETE]), mandatory_controls: {} },
        },
      },
      async () => {
        const opened = await token(
          {
            grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
            subject_token: before,
            subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
            requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
            login_hint: "alice",
            mission_intent: submission("Publish and retire the quarterly reports"),
            authorization_details: JSON.stringify([entry([READ, WRITE, DELETE])]),
            creation_request_id: crypto.randomUUID(),
            completion_mode: "deferred",
          },
          keys,
        );
        expect(opened.status, JSON.stringify(opened.body)).toBe(400);
        expect(opened.body.error).toBe("authorization_pending");
        as.expansionDeferrals.approve(opened.body.deferral_code as string, {
          approver: { iss: ISSUER, sub: "bob" },
          approvalEventId: `scope-exp-${crypto.randomUUID()}`,
          approvedUntil: "2027-01-01T00:00:00Z",
        });
        const polled = await token(
          {
            grant_type: DEFERRED_GRANT_TYPE,
            deferral_code: opened.body.deferral_code as string,
          },
          keys,
        );
        expect(polled.status, JSON.stringify(polled.body)).toBe(200);
        const successor = as.kernel.get(polled.body.mission_id as string);
        expect(successor?.predecessor).toBeDefined();
        expect(polled.body.authorization_details).toEqual([
          { type: "mission_resource_access", resource: PLAIN, actions: [READ, WRITE] },
        ]);
        expect(polled.body.scope).toBe("reports.read reports.write");
        const at = polled.body.access_token as string;
        const claims = decodeJwt(at);
        expect(claims.aud).toBe(PLAIN);
        expect((claims.mission as { id?: string }).id).toBe(successor?.id);
        expect(claims.scope).toBe("reports.read reports.write");
        expect(claims.authorization_details).toEqual(polled.body.authorization_details);
        expect((await callRs(RS_PORT, "POST", at, keys)).status).toBe(201);
      },
    );
  });
});

describe("the JWT customizer backstop, invoked directly (@spec mission#scope-projection, mission#rs-enforcement)", () => {
  // No mint reaches either refusal today: every Mission-bound token passes
  // through the save-time projection, and no oidc-provider mint carries
  // `act`. These cases call the customizer this AS configured, read the way
  // oidc-provider 9.10.0 reads it (lib/models/formats/jwt.js), with a token
  // the projection decided at a real issuance. The endpoint witness of the
  // `act` branch waits on a same-Mission delegation mint (#869).
  type JwtCustomizer = (ctx: unknown, token: object, jwt: { payload: Json }) => Promise<void>;
  const customizer = (): JwtCustomizer =>
    (instance as (p: object) => { configuration: { formats: { customizers: { jwt: JwtCustomizer } } } })(as.provider)
      .configuration.formats.customizers.jwt;

  /** A real issuance to the plain RS, and the AccessToken instance its save() projected. */
  async function projectedToken(): Promise<{ token: { jti?: string; grantId?: string; scope?: string }; claims: Json }> {
    const issued: Array<{ jti?: string; grantId?: string; scope?: string }> = [];
    const listener = (t: { jti?: string; grantId?: string; scope?: string }) => issued.push(t);
    as.provider.on("access_token.issued", listener);
    let claims: Json;
    try {
      const res = await issue([entry([READ])]);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      claims = decodeJwt(res.body.access_token as string) as Json;
    } finally {
      as.provider.off("access_token.issued", listener);
    }
    const t = issued.find((x) => x.jti === claims.jti);
    expect(t?.scope).toBe("reports.read");
    return { token: t as { jti?: string; grantId?: string; scope?: string }, claims };
  }
  /** The payload oidc-provider assembles for a Mission-bound token, before the customizer. */
  const payload = (claims: Json, extra: Json = {}): Json => ({
    sub: "the-approver",
    aud: PLAIN,
    mission: claims.mission,
    authorization_details: claims.authorization_details,
    scope: "reports.read reports.write",
    ...extra,
  });

  it("refuses invalid_target a Mission-bound payload whose token the scope projection did not decide, and applies the decided scope for a projected token", async () => {
    const { token: projected, claims } = await projectedToken();

    const undecided = { grantId: projected.grantId, scope: "reports.read reports.write" };
    await expect(customizer()(undefined, undecided, { payload: payload(claims) })).rejects.toMatchObject({
      error: "invalid_target",
      error_description: expect.stringMatching(/without a scope projection/),
    });
    // A token carrying no `mission` claim is not Mission-bound: untouched.
    const ordinary = { payload: { aud: PLAIN, scope: "reports.write" } as Json };
    await customizer()(undefined, undecided, ordinary);
    expect(ordinary.payload.scope).toBe("reports.write");

    const decided = { payload: payload(claims) };
    await customizer()(undefined, projected, decided);
    expect(decided.payload.scope).toBe("reports.read");
    expect(decided.payload.sub).toBe(claims.sub);
  });

  it("refuses invalid_target an act-bearing Mission-bound payload to an audience not classified Mission-aware or not mapped, and passes it to a Mission-aware audience", async () => {
    const { token: projected, claims } = await projectedToken();
    const act = { sub: "subagent-invoice-extractor" };

    await expect(
      customizer()(undefined, projected, { payload: payload(claims, { act }) }),
    ).rejects.toMatchObject({
      error: "invalid_target",
      error_description: expect.stringMatching(/not classified mission_aware/),
    });
    await expect(
      customizer()(undefined, projected, { payload: payload(claims, { act, aud: "https://unmapped.example/api" }) }),
    ).rejects.toMatchObject({
      error: "invalid_target",
      error_description: expect.stringMatching(/no scope-projection mapping/),
    });

    // The same payload without `act` passes to the same audience.
    await customizer()(undefined, projected, { payload: payload(claims) });
    // And with `act` to an audience the mapping classifies Mission-aware.
    expect(MAPPING.audiences[PAYMENTS]?.mission_aware).toBe(true);
    const aware = { payload: payload(claims, { act, aud: PAYMENTS }) };
    await customizer()(undefined, projected, aware);
    expect(aware.payload.act).toEqual(act);
  });
});

describe("unsupported actor context on the async-delegation exchange (@spec continuation#transport-async)", () => {
  /** An async-delegation Token Exchange from `base`, optionally presenting an actor_token. */
  const delegate = (base: string, resource: string, acting: Keys, extra: Record<string, string> = {}) =>
    token(
      {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        request_refresh_token: "true",
        subject_token: base,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        resource,
        creation_request_id: crypto.randomUUID(),
        ...extra,
      },
      acting,
    );
  const actorAssertion = (acting: Keys) =>
    new SignJWT({ cnf: { jkt: "delegate" } })
      .setProtectedHeader({ alg: "ES256", typ: "JWT" })
      .setIssuer("https://delegates.example")
      .setSubject("subagent-invoice-extractor")
      .setIssuedAt()
      .setExpirationTime("2m")
      .sign(acting.privateKey);

  it("refuses invalid_request any exchange presenting an actor_token, to a scope-only or a Mission-aware target, spending no derivation; the same exchange with no actor succeeds with the projected scope", async () => {
    const base = await issue([entry([READ])]);
    expect(base.status, JSON.stringify(base.body)).toBe(200);
    const baseToken = base.body.access_token as string;
    const missionId = (decodeJwt(baseToken).mission as { id: string }).id;
    const acting = base.keys;
    const subject = await handle(baseToken, acting);
    const count = as.kernel.get(missionId)?.derivation_count;
    const actor = {
      actor_token: await actorAssertion(acting),
      actor_token_type: "urn:ietf:params:oauth:token-type:jwt",
    };

    for (const target of [PLAIN, PAYMENTS]) {
      const refused = await delegate(subject, target, acting, actor);
      expect(refused.status, JSON.stringify(refused.body)).toBe(400);
      expect(refused.body.error).toBe("invalid_request");
      expect(refused.body.error_description).toBe("actor_token is not supported on this exchange");
    }
    expect(as.kernel.get(missionId)?.derivation_count).toBe(count);

    const self = await delegate(subject, PLAIN, acting);
    expect(self.status, JSON.stringify(self.body)).toBe(200);
    expect(self.body.scope).toBe("reports.read");
    const claims = decodeJwt(self.body.access_token as string);
    expect(claims.scope).toBe("reports.read");
    expect(claims.act).toBeUndefined();
    expect((await callRs(RS_PORT, "GET", self.body.access_token as string, acting)).status).toBe(200);
  });

  it("refuses invalid_request a subject_token that already carries act, rather than stripping it", async () => {
    const base = await issue([entry([READ])]);
    expect(base.status, JSON.stringify(base.body)).toBe(200);
    const claims = decodeJwt(base.body.access_token as string);
    const missionId = (claims.mission as { id: string }).id;
    const count = as.kernel.get(missionId)?.derivation_count;
    const withAct = await new SignJWT({ ...claims, act: { iss: ISSUER, sub: "subagent-invoice-extractor" } })
      .setProtectedHeader({ alg: "RS256", kid: "as-token", typ: "at+jwt" })
      .sign(signingKey);
    const refused = await delegate(withAct, PLAIN, await newKeys());
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_request");
    expect(refused.body.error_description).toMatch(/actor context \(act\) is not supported/);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(count);
    // The delegation-handle request refuses it too, rather than minting a
    // handle that silently drops the actor context (#1157).
    const handleRefused = await token(delegationHandleParams(withAct, "ap-agent"), base.keys);
    expect(handleRefused.status, JSON.stringify(handleRefused.body)).toBe(400);
    expect(handleRefused.body.error).toBe("invalid_request");
    expect(handleRefused.body.error_description).toMatch(/actor context \(act\) is not supported/);
  });
});

describe("requested scope and the token response (@spec mission#scope-projection)", () => {
  it("a requested scope narrows the projection to exactly the requested values, and the response reports them", async () => {
    const { status, body, keys } = await issue([entry([READ, WRITE])], "reports.read");
    expect(status, JSON.stringify(body)).toBe(200);
    expect(body.scope).toBe("reports.read");
    expect(decodeJwt(body.access_token as string).scope).toBe("reports.read");
    expect((await callRs(RS_PORT, "GET", body.access_token as string, keys)).status).toBe(200);
    expect((await callRs(RS_PORT, "POST", body.access_token as string, keys)).status).toBe(403);
  });

  it("a mapped value granting a proper subset of the entry's actions is a safe projection (@spec resource-access#scope-projection)", async () => {
    // reports.read stands for reports:report.read alone; the entry carries read and write.
    const { status, body } = await issue([entry([READ, WRITE])]);
    expect(status, JSON.stringify(body)).toBe(200);
    expect(body.scope).toBe("reports.read reports.write");
    await withPlain(
      {
        version: "subset-1",
        mission_aware: false,
        mode: "scope_only",
        scopes: { "reports.read": { rights: rights([READ]), mandatory_controls: {} } },
      },
      async () => {
        const narrowed = await issue([entry([READ, WRITE])]);
        expect(narrowed.status, JSON.stringify(narrowed.body)).toBe(200);
        expect(narrowed.body.scope).toBe("reports.read");
      },
    );
  });

  it("OIDC values combine with authorization_details: openid yields an id_token, and the response scope reports the granted OIDC and projected values", async () => {
    const plain = await issue([entry([READ])], "openid");
    expect(plain.status, JSON.stringify(plain.body)).toBe(200);
    expect(plain.body.id_token).toBeTruthy();
    expect(plain.body.scope).toBe("openid reports.read");
    expect(decodeJwt(plain.body.access_token as string).scope).toBe("reports.read");

    const keys = await newKeys();
    const code = await approve(
      [{ type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } }],
      PAYMENTS,
      "openid",
    );
    const payments = await redeem(code, keys, PAYMENTS);
    expect(payments.status, JSON.stringify(payments.body)).toBe(200);
    expect(payments.body.id_token).toBeTruthy();
    expect(payments.body.scope).toBe("openid");
    expect(decodeJwt(payments.body.access_token as string).scope).toBeUndefined();
  });

  it("a Mission created from the Intent alone (no authorization_details, no scope) completes and projects", async () => {
    const r = await authorize(undefined);
    expect(r.par.status, JSON.stringify(r.par.body)).toBe(201);
    expect(r.code, JSON.stringify(r)).toBeTruthy();
    const res = await redeem(r.code as string, await newKeys());
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scope).toBe("reports.read reports.write");

    // The payments ceiling derives entries carrying constraints and delegation policy.
    const p = await authorize(undefined, { resource: PAYMENTS });
    expect(p.par.status, JSON.stringify(p.par.body)).toBe(201);
    expect(p.code, JSON.stringify(p)).toBeTruthy();
    const paid = await redeem(p.code as string, await newKeys(), PAYMENTS);
    expect(paid.status, JSON.stringify(paid.body)).toBe(200);
    expect(paid.body.scope).toBeUndefined();
    const carried = decodeJwt(paid.body.access_token as string).authorization_details as AuthorityEntry[];
    expect(carried.some((e) => e.delegation !== undefined)).toBe(true);
  });
});

// @spec mission#derivation-modes, mission#scope-projection,
// resource-access#scope-projection: with no proposal, the requested `scope`
// values of a `scope`-only target key the configured mapping. Each stands for
// the entry its mapping value names, narrowed to the ceiling; the Mission
// approves those entries alone, never the target's whole ceiling, and the
// token carries their projection.
describe("configured-mapping mode keyed on a requested scope (@spec mission#derivation-modes, resource-access#scope-projection)", () => {
  /** The Mission one authorization created, read from the store. */
  async function authorizeOne(scope: string | undefined) {
    const before = new Set(as.kernel.allMissions().map((m) => m.id));
    const r = await authorize(undefined, scope === undefined ? {} : { scope });
    const created = as.kernel.allMissions().filter((m) => !before.has(m.id));
    return { r, created };
  }

  it("an Intent-only request naming reports.read approves only the entry that value stands for, commits no proposal, and its token carries that value", async () => {
    const { r, created } = await authorizeOne("reports.read");
    expect(r.par.status, JSON.stringify(r.par.body)).toBe(201);
    expect(r.code, JSON.stringify(r)).toBeTruthy();
    expect(created).toHaveLength(1);
    const mission = created[0] as (typeof created)[number];
    expect(mission.authority_set).toEqual([{ type: "mission_resource_access", resource: PLAIN, actions: [READ] }]);
    expect(mission.proposal_hash).toBeUndefined();
    expect(mission.proposed_authority).toBeUndefined();
    const keys = await newKeys();
    const res = await redeem(r.code as string, keys);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scope).toBe("reports.read");
    expect((await callRs(RS_PORT, "GET", res.body.access_token as string, keys)).status).toBe(200);
    expect((await callRs(RS_PORT, "POST", res.body.access_token as string, keys)).status).toBe(403);
  });

  it("each requested value stands for its own entry, and without a requested scope the same Intent approves the target's whole ceiling (control)", async () => {
    const both = await authorizeOne("reports.read reports.write");
    expect(both.r.code, JSON.stringify(both.r)).toBeTruthy();
    expect(both.created[0]?.authority_set).toEqual([
      { type: "mission_resource_access", resource: PLAIN, actions: [READ] },
      { type: "mission_resource_access", resource: PLAIN, actions: [WRITE] },
    ]);

    const none = await authorizeOne(undefined);
    expect(none.r.code, JSON.stringify(none.r)).toBeTruthy();
    const actions = (none.created[0]?.authority_set ?? []).flatMap((e) => e.actions);
    expect(actions).toEqual(expect.arrayContaining([READ, WRITE]));
  });

  it("a requested value whose mapped rights the ceiling does not cover derives nothing: access_denied, and no Mission", async () => {
    await withPlain(
      {
        version: "scope-key-1",
        mission_aware: false,
        mode: "scope_only",
        scopes: {
          "reports.read": { rights: rights([READ]), mandatory_controls: {} },
          "reports.admin": { rights: rights(["reports:report.admin"]), mandatory_controls: {} },
        },
      },
      async () => {
        const { r, created } = await authorizeOne("reports.admin");
        expect(r.par.status, JSON.stringify(r.par.body)).toBe(201);
        expect(r.code).toBeUndefined();
        expect(r.error, JSON.stringify(r)).toBe("access_denied");
        expect(created).toHaveLength(0);
      },
    );
  });

  /** The plain RS mapping with reports.read naming `contract`. */
  const withContract = (contract: ResourceContractRef) => ({
    version: `scope-key-contract-${contract.version}`,
    mission_aware: false,
    mode: "scope_only",
    scopes: {
      "reports.read": { rights: rights([READ]), mandatory_controls: {}, resource_contract: contract },
    },
  });

  it("a value whose mapping names the current contract stands for an entry carrying that reference; the approval keeps it and the token projects (@spec resource-access#scope-projection)", async () => {
    await withPlain(withContract(plainContractRef("v2")), async () => {
      const { r, created } = await authorizeOne("reports.read");
      expect(r.code, JSON.stringify(r)).toBeTruthy();
      expect(created).toHaveLength(1);
      expect(created[0]?.authority_set).toEqual([
        { type: "mission_resource_access", resource: PLAIN, actions: [READ], resource_contract: plainContractRef("v2") },
      ]);
      const keys = await newKeys();
      const res = await redeem(r.code as string, keys);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.scope).toBe("reports.read");
      expect((await callRs(RS_PORT, "GET", res.body.access_token as string, keys)).status).toBe(200);
    });
  });

  it("a value whose mapping names a contract version that is not current is refused at the approval: invalid_authorization_details, and no Mission (@spec resource-access#resource-contract)", async () => {
    await withPlain(withContract(plainContractRef("v1")), async () => {
      const { r, created } = await authorizeOne("reports.read");
      expect(r.par.status, JSON.stringify(r.par.body)).toBe(201);
      expect(r.code).toBeUndefined();
      expect(r.error, JSON.stringify(r)).toBe("invalid_authorization_details");
      expect(created).toHaveLength(0);
    });
  });
});

describe("the Intent-only completion workaround is never a client proposal (@spec mission#authority-proposal)", () => {
  /** PAR -> /auth -> interaction uid and cookies, stopping before any decision. */
  async function open(extra: Record<string, string>) {
    const challenge = Buffer.from(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER)),
    ).toString("base64url");
    const par = await fetch(`${ISSUER}/request`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: "ap-agent",
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        resource: PLAIN,
        code_challenge: challenge,
        code_challenge_method: "S256",
        login_hint: "alice",
        mission_intent: JSON.stringify({
          intent: { goal: "Publish the quarterly reports", target_resources: [PLAIN], expires_at: "2027-01-01T00:00:00Z" },
        }),
        ...extra,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
    expect(par.status).toBe(201);
    const { request_uri } = (await par.json()) as { request_uri: string };
    const cookies = new Map<string, string>();
    const cookie = () => [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    const keep = (res: Response) => {
      for (const line of res.headers.getSetCookie()) {
        const [pair] = line.split(";");
        const eq = (pair as string).indexOf("=");
        cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
      }
    };
    const res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
      redirect: "manual",
    });
    keep(res);
    const uid = (res.headers.get("location") as string).split("/interaction/")[1] as string;
    const render = async () => {
      const page = await fetch(`${ISSUER}/interaction/${uid}`, { headers: { cookie: cookie() } });
      return { status: page.status, html: await page.text() };
    };
    const decide = async () => {
      const r = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
        method: "POST",
        redirect: "manual",
        headers: { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookie() },
        body: JSON.stringify({ decision: "approve" }),
      });
      keep(r);
      return r;
    };
    const finish = async (first: Response) => {
      let location = first.headers.get("location") as string;
      while (location?.startsWith(ISSUER)) {
        const r = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
        keep(r);
        location = r.headers.get("location") as string;
      }
      return new URL(location).searchParams.get("code");
    };
    return { render, decide, finish };
  }
  const missionOf = async (code: string) => {
    const res = await redeem(code, await newKeys());
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const id = (decodeJwt(res.body.access_token as string).mission as { id: string }).id;
    return as.kernel.get(id);
  };

  it("an Intent-only Mission commits no proposal_hash, and re-rendering or re-deciding the same interaction still reads no proposal", async () => {
    const approvals = vi.spyOn(as.kernel, "approve");
    const flow = await open({});
    const first = await flow.decide();
    expect(first.status).toBe(303);
    // The interaction survives until the redirect is followed: re-render and re-decide are reachable.
    const again = await flow.render();
    expect(again.status).toBe(200);
    expect(again.html).not.toContain("Proposed authority (submitted, untrusted)");
    const second = await flow.decide();
    expect(second.status).toBe(303);
    const code = await flow.finish(second);
    expect(code).toBeTruthy();
    const record = await missionOf(code as string);
    expect(record?.proposal_hash).toBeUndefined();
    expect((record as { proposed_authority?: unknown } | undefined)?.proposed_authority).toBeUndefined();
    // The first decision handed approve() (which computes the anchors) no
    // proposal. The repeated decision recovers that committed record and binds
    // the same grant without approving again (#916), so it reads none either.
    expect(approvals.mock.calls.length).toBe(1);
    for (const [input] of approvals.mock.calls) expect(input.proposedAuthority).toBeUndefined();
    expect(as.kernel.missionBoundGrants.resolve(record?.grant_id as string)?.missionId).toBe(record?.id);
    approvals.mockRestore();
  });

  it("a client-sent marker key is dropped: a pushed proposal is still the client's proposal, and an Intent-only request stays Intent-only", async () => {
    const withProposal = await open({
      authorization_details: JSON.stringify([entry([READ])]),
      __mission_derived_authorization_details: "true",
    });
    const record = await missionOf((await withProposal.finish(await withProposal.decide())) as string);
    expect(record?.proposal_hash).toBeTruthy();

    const intentOnly = await open({ __mission_derived_authorization_details: "true" });
    const bare = await missionOf((await intentOnly.finish(await intentOnly.decide())) as string);
    expect(bare?.proposal_hash).toBeUndefined();
  });
});

describe("ungrantable requested scope (@spec mission#scope-projection, mission#error-mapping)", () => {
  it("refuses invalid_scope at PAR a resource scope for an authorization_details target, and a value the scope-only target's mapping does not name", async () => {
    const payments = await authorize(
      [{ type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } }],
      { resource: PAYMENTS, scope: "payments" },
    );
    expect(payments.par.status).toBe(400);
    expect(payments.par.body.error).toBe("invalid_scope");
    expect(payments.par.body.error_description).toMatch(/consumes authorization_details/);

    const unnamed = await authorize([entry([READ])], { scope: "reports.admin" });
    expect(unnamed.par.status).toBe(400);
    expect(unnamed.par.body.error).toBe("invalid_scope");
    expect(unnamed.par.body.error_description).toMatch(/does not name it/);
  });

  it("refuses invalid_scope at the authorization decision a mapped value no carried entry makes safe, before any Mission exists", async () => {
    const before = as.kernel.allMissions().length;
    const r = await authorize([entry([READ])], { scope: "reports.write" });
    expect(r.par.status).toBe(201);
    expect(r.code).toBeUndefined();
    expect(r.error).toBe("invalid_scope");
    expect(r.description).toMatch(/reports\.write cannot be granted/);
    expect(as.kernel.allMissions().length).toBe(before);
  });

  it("refuses invalid_scope at the token endpoint when an authorized requested value is no longer safe, and invalid_target when the target's mapping is unknown even though scope was requested", async () => {
    const keys = await newKeys();
    const code = await approve([entry([READ, WRITE])], PLAIN, "reports.write");
    // The trusted mapping changes between authorization and redemption so that
    // reports.write aggregates an action the entry does not carry.
    await withPlain(
      {
        version: "narrow-2",
        mission_aware: false,
        mode: "scope_only",
        scopes: {
          "reports.read": { rights: rights([READ]), mandatory_controls: {} },
          "reports.write": { rights: rights([WRITE, "reports:report.delete"]), mandatory_controls: {} },
        },
      },
      async () => {
        const res = await redeem(code, keys);
        expect(res.status, JSON.stringify(res.body)).toBe(400);
        expect(res.body.error).toBe("invalid_scope");
        expect(res.body.error_description).toMatch(/reports\.write cannot be granted/);
      },
    );

    const code2 = await approve([entry([READ])], PLAIN, "reports.read");
    await withPlain(undefined, async () => {
      const res = await redeem(code2, await newKeys());
      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(res.body.error).toBe("invalid_target");
      expect(res.body.error_description).toMatch(/no scope-projection mapping/);
    });
  });

  it("refuses invalid_scope a Token Exchange naming a value no carried entry makes safe, or an OIDC value where no id_token is issued, and grants a safe requested value", async () => {
    const base = await issue([entry([READ])]);
    expect(base.status, JSON.stringify(base.body)).toBe(200);
    const acting = base.keys;
    const subject = await handle(base.body.access_token as string, acting);
    const exchange = (scope: string) =>
      token(
        {
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          request_refresh_token: "true",
          subject_token: subject,
          subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
          resource: PLAIN,
          creation_request_id: crypto.randomUUID(),
          scope,
        },
        acting,
      );
    const missionId = (decodeJwt(base.body.access_token as string).mission as { id: string }).id;
    const count = as.kernel.get(missionId)?.derivation_count;
    const unsafe = await exchange("reports.write");
    expect(unsafe.status, JSON.stringify(unsafe.body)).toBe(400);
    expect(unsafe.body.error).toBe("invalid_scope");
    const oidc = await exchange("openid");
    expect(oidc.status, JSON.stringify(oidc.body)).toBe(400);
    expect(oidc.body.error).toBe("invalid_scope");
    // Refused before the family, its reservation, or its derivation count exist.
    expect(as.kernel.get(missionId)?.derivation_count).toBe(count);
    const ok = await exchange("reports.read");
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    expect(ok.body.scope).toBe("reports.read");
  });
});

describe("async-delegation idempotency covers the requested scope (@spec continuation#transport-async, mission#scope-projection)", () => {
  const exchange = (base: string, acting: Keys, creationRequestId: string, scope: string) =>
    token(
      {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        request_refresh_token: "true",
        subject_token: base,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        resource: PLAIN,
        creation_request_id: creationRequestId,
        scope,
      },
      acting,
    );

  it("the same creation_request_id with a different scope is a different request: refused invalid_request, with no second derivation", async () => {
    const base = await issue([entry([READ, WRITE])]);
    expect(base.status, JSON.stringify(base.body)).toBe(200);
    const baseToken = base.body.access_token as string;
    const missionId = (decodeJwt(baseToken).mission as { id: string }).id;
    const acting = base.keys;
    const subject = await handle(baseToken, acting);
    const id = crypto.randomUUID();
    const first = await exchange(subject, acting, id, "reports.read reports.write");
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    const count = as.kernel.get(missionId)?.derivation_count;

    const reused = await exchange(subject, acting, id, "reports.read");
    expect(reused.status, JSON.stringify(reused.body)).toBe(400);
    expect(reused.body.error).toBe("invalid_request");
    expect(reused.body.error_description).toContain("different creation request");
    expect(reused.body.access_token).toBeUndefined();
    expect(as.kernel.get(missionId)?.derivation_count).toBe(count);
  });

  it("the same creation_request_id with the same scope values in another order replays the stored response", async () => {
    const base = await issue([entry([READ, WRITE])]);
    expect(base.status, JSON.stringify(base.body)).toBe(200);
    const baseToken = base.body.access_token as string;
    const missionId = (decodeJwt(baseToken).mission as { id: string }).id;
    const acting = base.keys;
    const subject = await handle(baseToken, acting);
    const id = crypto.randomUUID();
    const first = await exchange(subject, acting, id, "reports.write reports.read");
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    const count = as.kernel.get(missionId)?.derivation_count;

    const retry = await exchange(subject, acting, id, "reports.read  reports.write");
    expect(retry.status, JSON.stringify(retry.body)).toBe(200);
    expect(retry.body.refresh_token).toBe(first.body.refresh_token);
    expect(retry.body.access_token).toBe(first.body.access_token);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(count);
  });
});

describe("refresh preserved on a projection refusal (@spec mission#scope-projection)", () => {
  /** A rotating (async-delegation family) refresh token for a plain RS Mission over READ and WRITE. */
  async function family(): Promise<{ rt: string; acting: Keys }> {
    const base = await issue([entry([READ, WRITE])]);
    expect(base.status, JSON.stringify(base.body)).toBe(200);
    const acting = base.keys;
    const subject = await handle(base.body.access_token as string, acting);
    const fam = await token(
      {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        request_refresh_token: "true",
        subject_token: subject,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        resource: PLAIN,
        creation_request_id: crypto.randomUUID(),
      },
      acting,
    );
    expect(fam.status, JSON.stringify(fam.body)).toBe(200);
    expect(fam.body.scope).toBe("reports.read reports.write");
    return { rt: fam.body.refresh_token as string, acting };
  }
  const dropped = {
    version: "dropped-1",
    mission_aware: false,
    mode: "scope_only",
    scopes: { "reports.admin": { rights: rights([READ, WRITE, "reports:report.delete"]), mandatory_controls: {} } },
  };

  it("a refused rotating refresh leaves the same refresh token valid: once the trusted mapping is repaired it succeeds once, and its reuse gets the ordinary replay treatment", async () => {
    const { rt, acting } = await family();
    await withPlain(dropped, async () => {
      const refused = await refresh(rt, acting);
      expect(refused.status).toBe(400);
      expect(refused.body.error).toBe("invalid_target");
      const narrowed = await refresh(rt, acting, "reports.write");
      expect(narrowed.status).toBe(400);
      expect(narrowed.body.error).toBe("invalid_scope");
    });
    const repaired = await refresh(rt, acting);
    expect(repaired.status, JSON.stringify(repaired.body)).toBe(200);
    expect(repaired.body.scope).toBe("reports.read reports.write");
    expect(repaired.body.refresh_token).not.toBe(rt);
    const replay = await refresh(rt, acting);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");
    expect(replay.body.error_description).toMatch(/grant request is invalid|already used/);
    // Reuse detection revoked the family: its rotated successor is gone too.
    const successor = await refresh(repaired.body.refresh_token as string, acting);
    expect(successor.body.error).toBe("invalid_grant");
  });

  it("a refresh narrowing authorization_details projects the narrowed set: a scope only the dropped entry grants refuses invalid_scope before rotation, and the same token then refreshes (#1303)", async () => {
    const { rt, acting } = await family();
    const onlyRead = JSON.stringify([entry([READ])]);
    const refused = await token(
      { grant_type: "refresh_token", refresh_token: rt, scope: "reports.write", authorization_details: onlyRead },
      acting,
    );
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_scope");
    const still = await refresh(rt, acting);
    expect(still.status, JSON.stringify(still.body)).toBe(200);
    expect(still.body.scope).toBe("reports.read reports.write");
    const narrowed = await token(
      { grant_type: "refresh_token", refresh_token: still.body.refresh_token as string, authorization_details: onlyRead },
      acting,
    );
    expect(narrowed.status, JSON.stringify(narrowed.body)).toBe(200);
    expect(narrowed.body.scope).toBe("reports.read");
    expect(decodeJwt(narrowed.body.access_token as string).scope).toBe("reports.read");
  });

  it("a refresh naming a narrower scope is granted exactly it; a value never granted refuses invalid_scope without consuming the token (#871)", async () => {
    const first = await issue([entry([READ, WRITE])]);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    const rt = first.body.refresh_token as string;
    const narrower = await refresh(rt, first.keys, "reports.read");
    expect(narrower.status, JSON.stringify(narrower.body)).toBe(200);
    expect(narrower.body.scope).toBe("reports.read");
    expect(decodeJwt(narrower.body.access_token as string).scope).toBe("reports.read");

    const onlyRead = await issue([entry([READ, WRITE])], "reports.read");
    const wider = await refresh(onlyRead.body.refresh_token as string, onlyRead.keys, "reports.write");
    expect(wider.status).toBe(400);
    expect(wider.body.error).toBe("invalid_scope");
    const still = await refresh(onlyRead.body.refresh_token as string, onlyRead.keys);
    expect(still.status, JSON.stringify(still.body)).toBe(200);
    expect(still.body.scope).toBe("reports.read");
  });

  it("a refresh naming only OIDC values explicitly asks for no resource value: refused invalid_scope at a scope-only target without consuming the token, which then inherits its full granted scope", async () => {
    const first = await issue([entry([READ, WRITE])], "openid");
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    expect(first.body.scope).toBe("openid reports.read reports.write");
    const rt = first.body.refresh_token as string;
    const oidcOnly = await refresh(rt, first.keys, "openid");
    expect(oidcOnly.status, JSON.stringify(oidcOnly.body)).toBe(400);
    expect(oidcOnly.body.error).toBe("invalid_scope");
    const inherited = await refresh(rt, first.keys);
    expect(inherited.status, JSON.stringify(inherited.body)).toBe(200);
    expect(inherited.body.scope).toBe("openid reports.read reports.write");
  });

  it("a refresh naming only OIDC values at an authorization_details target is granted exactly them, with no scope on the token", async () => {
    const keys = await newKeys();
    const code = await approve(
      [{ type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } }],
      PAYMENTS,
      "openid",
    );
    const first = await redeem(code, keys, PAYMENTS);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    const res = await refresh(first.body.refresh_token as string, keys, "openid");
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scope).toBe("openid");
    expect(decodeJwt(res.body.access_token as string).scope).toBeUndefined();
  });

  const authorizationDetailsMode = { version: "mode-1", mission_aware: false, mode: "authorization_details" };

  it("a refresh omitting scope whose inherited grant the current mapping no longer grants, leaving no scope value to report, is refused invalid_scope before rotation; the restored mapping lets the same token succeed", async () => {
    const first = await issue([entry([READ])]);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    expect(first.body.scope).toBe("reports.read");
    const rt = first.body.refresh_token as string;
    await withPlain(authorizationDetailsMode, async () => {
      const res = await refresh(rt, first.keys);
      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(res.body.error).toBe("invalid_scope");
      expect(res.body.error_description).toMatch(/inherited scope reports\.read can no longer be granted/);
    });
    const restored = await refresh(rt, first.keys);
    expect(restored.status, JSON.stringify(restored.body)).toBe(200);
    expect(restored.body.scope).toBe("reports.read");

    // A rotating (family) refresh token: the refusal lands before rotation,
    // so the same token succeeds exactly once after the mapping is restored.
    const fam = await family();
    await withPlain(authorizationDetailsMode, async () => {
      const res = await refresh(fam.rt, fam.acting);
      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(res.body.error).toBe("invalid_scope");
    });
    const once = await refresh(fam.rt, fam.acting);
    expect(once.status, JSON.stringify(once.body)).toBe(200);
    expect(once.body.scope).toBe("reports.read reports.write");
    expect((await refresh(fam.rt, fam.acting)).body.error).toBe("invalid_grant");
  });

  it("a refresh omitting scope narrows an inherited grant the response can still report: a mode change keeps the OIDC values, an unsafe value drops out, and nothing widens", async () => {
    const withOidc = await issue([entry([READ])], "openid");
    expect(withOidc.body.scope).toBe("openid reports.read");
    await withPlain(authorizationDetailsMode, async () => {
      const res = await refresh(withOidc.body.refresh_token as string, withOidc.keys);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.scope).toBe("openid");
      expect(decodeJwt(res.body.access_token as string).scope).toBeUndefined();
    });

    const both = await issue([entry([READ, WRITE])]);
    expect(both.body.scope).toBe("reports.read reports.write");
    await withPlain(
      {
        version: "unsafe-1",
        mission_aware: false,
        mode: "scope_only",
        scopes: {
          "reports.read": { rights: rights([READ]), mandatory_controls: {} },
          "reports.write": { rights: rights([WRITE, "reports:report.delete"]), mandatory_controls: {} },
          "reports.list": { rights: rights([READ]), mandatory_controls: {} },
        },
      },
      async () => {
        const res = await refresh(both.body.refresh_token as string, both.keys);
        expect(res.status, JSON.stringify(res.body)).toBe(200);
        expect(res.body.scope).toBe("reports.read");
        expect(decodeJwt(res.body.access_token as string).scope).toBe("reports.read");
      },
    );
  });

  it("an unauthenticated or wrong-client refresh of a projection-failing token gets the ordinary client error, never a projection error", async () => {
    const { rt, acting } = await family();
    await withPlain(dropped, async () => {
      const anonymous = await refresh(rt, acting, undefined, "none");
      expect(anonymous.status).toBe(401);
      expect(anonymous.body.error).toBe("invalid_client");
      const wrong = await refresh(rt, acting, undefined, "governed-agent");
      expect(wrong.status).toBe(400);
      expect(wrong.body.error).toBe("invalid_grant");
    });
    const ok = await refresh(rt, acting);
    expect(ok.status, JSON.stringify(ok.body)).toBe(200);
  });
});

describe("revocation with a scope-only Resource Server (@spec mission#scope-projection)", () => {
  it("after the Mission is revoked, refresh refuses invalid_grant, introspection returns active false, and the plain RS in introspection mode denies the next call", async () => {
    const { status, body, keys } = await issue([entry([READ])]);
    expect(status, JSON.stringify(body)).toBe(200);
    const at = body.access_token as string;
    expect((await callRs(RS_INTROSPECT_PORT, "GET", at, keys)).status).toBe(200);

    const missionId = (decodeJwt(at).mission as { id: string }).id;
    as.kernel.transition(missionId, "revoke");

    const refused = await refresh(body.refresh_token as string, keys);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("invalid_grant");

    const principal = INTROSPECTION_PRINCIPALS.find((p) => p.principal_id === "rs-plain");
    const introspected = await fetch(`${ISSUER}/introspect`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(`${principal?.principal_id}:${principal?.secret}`).toString("base64")}`,
      },
      body: new URLSearchParams({ token: at }).toString(),
    });
    expect(introspected.status).toBe(200);
    expect(((await introspected.json()) as Json).active).toBe(false);

    const denied = await callRs(RS_INTROSPECT_PORT, "GET", at, keys);
    expect(denied.status).toBe(401);
    expect(((await denied.json()) as Json).error).toBe("invalid_token");
    // The JWT-only plain RS cannot see revocation: the token still validates there until it expires.
    expect((await callRs(RS_PORT, "GET", at, keys)).status).toBe(200);
  });
});
