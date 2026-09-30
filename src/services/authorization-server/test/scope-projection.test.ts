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
import { startPlainResourceServer } from "@mission/plain-rs";
import {
  DERIVATION_POLICY,
  INTROSPECTION_PRINCIPALS,
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
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import { type AuthorityEntry, type BuiltAs, buildAuthorizationServer } from "../src/index.js";
import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

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

let as: BuiltAs;
let asServer: Server;
let rs: Server;
let rsIntrospecting: Server;
let agentKey: CryptoKey;

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

/** POST /token as ap-agent with a DPoP proof, retrying once on a DPoP nonce. */
async function token(params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Json }> {
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
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Json };
}

/** PAR -> approval: returns the authorization code for a Mission over `proposal`. */
async function approve(proposal: AuthorityEntry[], resource = PLAIN): Promise<string> {
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
      scope: "payments",
      resource,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: { goal: "Publish the quarterly reports", target_resources: [resource], expires_at: "2027-01-01T00:00:00Z" },
      }),
      authorization_details: JSON.stringify(proposal),
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
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
    redirect: "manual",
  });
  keep(res);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookie() },
    body: JSON.stringify({ decision: "approve" }),
  });
  keep(res);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code");
  expect(code).toBeTruthy();
  return code as string;
}

function redeem(code: string, keys: Keys, resource = PLAIN) {
  return token(
    { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: PKCE_VERIFIER, resource },
    keys,
  );
}

function refresh(refreshToken: string, keys: Keys) {
  return token({ grant_type: "refresh_token", refresh_token: refreshToken }, keys);
}

/** A full issuance to the plain RS: the token response plus the DPoP key it is bound to. */
async function issue(proposal: AuthorityEntry[]): Promise<{ status: number; body: Json; keys: Keys }> {
  const keys = await newKeys();
  const code = await approve(proposal);
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
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    scopeProjection: MAPPING,
  });
  asServer = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
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

describe("scope projection on derived tokens (@spec mission#scope-projection)", () => {
  it("refresh re-projects the same scope, and refuses invalid_target when the mapping no longer proves it or its version changed since the grant was issued", async () => {
    const first = await issue([entry([READ, WRITE])]);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    expect(first.body.scope).toBe("reports.read reports.write");
    const rt1 = first.body.refresh_token as string;

    const again = await refresh(rt1, first.keys);
    expect(again.status, JSON.stringify(again.body)).toBe(200);
    expect(again.body.scope).toBe("reports.read reports.write");
    expect(decodeJwt(again.body.access_token as string).scope).toBe("reports.read reports.write");
    const rt2 = (again.body.refresh_token as string | undefined) ?? rt1;

    // Same version, a mapping that no longer proves any value: the subset condition refuses.
    await withPlain(
      {
        version: SHIPPED_PLAIN?.version,
        mission_aware: false,
        mode: "scope_only",
        scopes: { "reports.admin": { rights: rights([READ, WRITE, "reports:report.delete"]), mandatory_controls: {} } },
      },
      async () => {
        const res = await refresh(rt2, first.keys);
        expect(res.status).toBe(400);
        expect(res.body.error).toBe("invalid_target");
        expect(res.body.error_description).toMatch(/no safe scope projection/);
      },
    );

    // A fresh grant under the shipped mapping, then a version bump: stale on refresh.
    const second = await issue([entry([READ])]);
    expect(second.status, JSON.stringify(second.body)).toBe(200);
    await withPlain({ ...structuredClone(SHIPPED_PLAIN), version: "2026-10-01.1" }, async () => {
      const res = await refresh(second.body.refresh_token as string, second.keys);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_target");
      expect(res.body.error_description).toMatch(/stale/);
    });
  });

  it("Token Exchange projects the family token's scope from its confined subset, keeps it on the family refresh, and refuses an unenforced constraint before creating a family", async () => {
    const base = await issue([entry([READ, WRITE])]);
    expect(base.status, JSON.stringify(base.body)).toBe(200);
    const acting = await newKeys();
    const exchange = (authorizationDetails: AuthorityEntry[]) =>
      token(
        {
          grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
          request_refresh_token: "true",
          subject_token: base.body.access_token as string,
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

describe("delegated routing to a Mission-unaware Resource Server (@spec mission#rs-enforcement)", () => {
  /** An async-delegation Token Exchange from `base`, optionally presenting an actor_token. */
  const delegate = (base: string, resource: string, acting: Keys, actorToken?: string) =>
    token(
      {
        grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
        request_refresh_token: "true",
        subject_token: base,
        subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
        resource,
        creation_request_id: crypto.randomUUID(),
        ...(actorToken
          ? { actor_token: actorToken, actor_token_type: "urn:ietf:params:oauth:token-type:jwt" }
          : {}),
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

  it("refuses invalid_target, spending no derivation, a Token Exchange presenting an actor to the plain RS, while the same exchange with no actor succeeds with the projected scope", async () => {
    const base = await issue([entry([READ])]);
    expect(base.status, JSON.stringify(base.body)).toBe(200);
    const baseToken = base.body.access_token as string;
    const missionId = (decodeJwt(baseToken).mission as { id: string }).id;
    const count = as.kernel.get(missionId)?.derivation_count;
    const acting = await newKeys();

    const refused = await delegate(baseToken, PLAIN, acting, await actorAssertion(acting));
    expect(refused.status, JSON.stringify(refused.body)).toBe(400);
    expect(refused.body.error).toBe("invalid_target");
    expect(refused.body.error_description).toMatch(/routed only to a Mission-aware Resource Server/);
    expect(as.kernel.get(missionId)?.derivation_count).toBe(count);

    const self = await delegate(baseToken, PLAIN, acting);
    expect(self.status, JSON.stringify(self.body)).toBe(200);
    expect(self.body.scope).toBe("reports.read");
    const claims = decodeJwt(self.body.access_token as string);
    expect(claims.scope).toBe("reports.read");
    expect(claims.act).toBeUndefined();
    expect((await callRs(RS_PORT, "GET", self.body.access_token as string, acting)).status).toBe(200);
  });

  it("allows the Token Exchange presenting an actor to a Mission-aware audience", async () => {
    const keys = await newKeys();
    const code = await approve(
      [{ type: "mission_resource_access", resource: PAYMENTS, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } }],
      PAYMENTS,
    );
    const base = await redeem(code, keys, PAYMENTS);
    expect(base.status, JSON.stringify(base.body)).toBe(200);
    const acting = await newKeys();
    const res = await delegate(base.body.access_token as string, PAYMENTS, acting, await actorAssertion(acting));
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.scope).toBeUndefined();
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
