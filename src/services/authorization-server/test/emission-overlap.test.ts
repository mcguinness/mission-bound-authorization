/**
 * @spec resource-access#resource-access-type, resource-access#resource-matching
 * (#1266, #1276)
 *
 * "The authorization server SHOULD emit for a given `resource` only
 * `constraints` keys that the resource server serving it is known to
 * understand and enforce." A token's audience serves every entry whose
 * resource tree overlaps it: one naming the audience, an `exact` or `prefix`
 * entry for a finer resource within it, and a `prefix` entry whose base
 * contains it. Each such entry is checked against the audience's own
 * `mission_constraints_supported`, at the token endpoint, and a key the
 * audience is not known to enforce refuses the issuance.
 *
 * The shipped ceilings are `exact`, so this deployment's ceiling is
 * programmatic: one `prefix` entry over the whole payments origin, which
 * admits each proposal below.
 */

import type { Server } from "node:http";
import { APPROVAL_FLOOR, AUTHORITY_SOURCES, SCOPE_PROJECTION } from "@mission/demo-data";
import { type CryptoKey, decodeJwt, exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ApprovalSessionStore, type AuthorityEntry, type BuiltAs, buildAuthorizationServer } from "../src/index.js";
import { floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

const PORT = 14812;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const PKCE_VERIFIER = "emission-overlap-verifier-0123456789-0123456789";
const ORIGIN = "http://localhost:4403/";
/** The payments audience the shipped mapping names. */
const PAYMENTS = "http://localhost:4403/mcp";
const READ = "payments:invoice.read";

const CEILING: AuthorityEntry[] = [{ type: "mission_resource_access", resource: ORIGIN, resource_match: "prefix", actions: [READ] }];
/** Every resource a case below approves, which the approval floor must classify. */
const INVOICE = `${PAYMENTS}/invoices/inv-1`;
const INVOICES = `${PAYMENTS}/invoices`;
const SIBLING = "http://localhost:4403/mcp-other";
const APPROVED_RESOURCES = [INVOICE, INVOICES, ORIGIN, SIBLING];

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey; jwk: JWK };
type Json = Record<string, unknown>;

/** The live mapping the AS reads at every issuance; a case sets the payments audience's key list. */
const MAPPING = structuredClone(SCOPE_PROJECTION);
const SESSIONS = new ApprovalSessionStore();
let as: BuiltAs;
let asServer: Server;
let agentKey: CryptoKey;

async function withPaymentsKeys(keys: string[], run: () => Promise<void>): Promise<void> {
  const audiences = MAPPING.audiences as Record<string, unknown>;
  const shipped = audiences[PAYMENTS];
  audiences[PAYMENTS] = {
    version: "emission-overlap-1",
    mission_aware: true,
    mode: "authorization_details",
    mission_constraints_supported: keys,
  };
  try {
    await run();
  } finally {
    audiences[PAYMENTS] = shipped;
  }
}

async function newKeys(): Promise<Keys> {
  const k = await generateKeyPair("ES256", { extractable: true });
  return { ...k, jwk: await exportJWK(k.publicKey) };
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

/** PAR, then Bob's browser approval for alice: the authorization code for a Mission over `proposal`. */
async function approve(proposal: AuthorityEntry[]): Promise<string> {
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
      resource: PAYMENTS,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({
        intent: {
          goal: "Read invoices",
          target_resources: [...new Set(proposal.map((e) => e.resource))],
          expires_at: "2099-01-01T00:00:00Z",
        },
      }),
      authorization_details: JSON.stringify(proposal),
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const par = (await parRes.json()) as Json;
  expect(parRes.status, JSON.stringify(par)).toBe(201);
  const cookies = new Map<string, string>();
  const cookie = () => [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  let res = await fetch(
    `${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: par.request_uri as string })}`,
    { redirect: "manual" },
  );
  keep(res);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...floorApprovalHeaders(SESSIONS, uid, cookie()), "content-type": "application/json" },
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
  expect(code, location).toBeTruthy();
  return code as string;
}

/** Redeem `code` for a token whose audience is the payments resource. */
async function redeem(code: string): Promise<{ status: number; body: Json }> {
  const keys = await newKeys();
  const htu = `${ISSUER}/token`;
  const send = async (extra: Json = {}) =>
    fetch(htu, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await new SignJWT({ htm: "POST", htu, ...extra })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: keys.jwk })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(keys.privateKey),
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: PKCE_VERIFIER,
        resource: PAYMENTS,
        client_assertion: await clientAssertion(),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Json };
}

const at = (resource: string, constraints: Json, resource_match?: "prefix"): AuthorityEntry =>
  ({
    type: "mission_resource_access",
    resource,
    ...(resource_match ? { resource_match } : {}),
    actions: [READ],
    constraints,
  }) as AuthorityEntry;
const TENANT = { tenant: "payments-demo" };

/** Approve `entry` and redeem it for the payments audience under `keys`; return the response. */
async function issueUnder(keys: string[], entry: AuthorityEntry): Promise<{ status: number; body: Json }> {
  const code = await approve([entry]);
  let out: { status: number; body: Json } | undefined;
  await withPaymentsKeys(keys, async () => {
    out = await redeem(code);
  });
  return out as { status: number; body: Json };
}

function expectRefused(res: { status: number; body: Json }, key: string): void {
  expect(res.status, JSON.stringify(res.body)).toBe(400);
  expect(res.body.error).toBe("invalid_target");
  expect(res.body.error_description).toMatch(new RegExp(`${PAYMENTS} is not known to enforce the constraints key ${key}`));
  expect(res.body.access_token).toBeUndefined();
}

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: SESSIONS,
    scopeProjection: MAPPING,
    derivationPolicy: { policy_version: "emission-overlap-1266", ceiling: CEILING },
    // The shipped floor classifies the shipped resources only; these reads
    // are classified the same way the payments invoice read is.
    approvalFloor: {
      ...APPROVAL_FLOOR,
      classification: [
        ...APPROVAL_FLOOR.classification,
        ...APPROVED_RESOURCES.map((resource) => ({
          type: "mission_resource_access" as const,
          resource,
          actions: { [READ]: "consequential_read" as const },
        })),
      ],
    },
    authoritySources: {
      ...AUTHORITY_SOURCES,
      entries: AUTHORITY_SOURCES.entries.map((e) => (e.id === "acme-people" ? { ...e, ceiling: CEILING as never } : e)),
    },
  });
  asServer = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  asServer?.close();
});

describe("the token endpoint checks every entry an audience serves against that audience's own keys (@spec resource-access#resource-access-type, #1266)", () => {
  it("refuses invalid_target an invoice-level exact entry under the audience carrying a key the audience does not list, and emits it once the list names the key", async () => {
    const invoice = at(INVOICE, TENANT);
    expectRefused(await issueUnder([], invoice), "tenant");
    expectRefused(await issueUnder(["vendors"], invoice), "tenant");
    const issued = await issueUnder(["tenant"], invoice);
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    const details = decodeJwt(issued.body.access_token as string).authorization_details as Json[];
    // The trusted payments catalog also resolves the invoice-level entry's
    // catalog-sourced action, as for the service's own entry (#1440).
    const { capability_sources: sources, ...emitted } = details[0] as Json;
    expect([emitted]).toEqual([invoice]);
    expect((sources as Json[]).map((b) => b.action)).toEqual([READ]);
  });

  it("checks a prefix entry within the audience against the audience's list", async () => {
    const invoices = at(INVOICES, TENANT, "prefix");
    expectRefused(await issueUnder(["vendors"], invoices), "tenant");
    expect((await issueUnder(["tenant"], invoices)).status).toBe(200);
  });

  it("checks a prefix entry whose base contains the audience against the audience's list", async () => {
    const origin = at(ORIGIN, TENANT, "prefix");
    expectRefused(await issueUnder(["vendors"], origin), "tenant");
    expect((await issueUnder(["tenant"], origin)).status).toBe(200);
  });

  it("does not pair the audience with a sibling outside its segment boundary (boundary)", async () => {
    // `/mcp-other` shares the audience's characters but not its path segment.
    const sibling = at(SIBLING, TENANT);
    const issued = await issueUnder([], sibling);
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    expect(decodeJwt(issued.body.access_token as string).authorization_details).toEqual([sibling]);
  });
});
