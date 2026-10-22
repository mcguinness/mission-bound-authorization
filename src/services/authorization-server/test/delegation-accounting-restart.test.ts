/**
 * @spec mission#delegation-constraints, mission#designation (#869, D470),
 * #250 step 2 (the restart inventory): the delegation accounting is the token
 * issuance index's rows (kind, Mission, depth, actor chain, designee and
 * designator key), and that index is in memory, built per boot, also when the
 * kernel is file-backed. A restart on the same kernel file and key ring keeps
 * the Mission, its derivation count and the signing keys, so every token
 * minted before the restart still verifies after it; the accounting does not
 * survive, and the AS refuses rather than infers it:
 *
 *  - a designation minted before the restart is not redeemable
 *    (`invalid_request`);
 *  - neither an origin token nor a delegated token minted before it can be
 *    designated (`invalid_target`, depth not established);
 *  - nothing is counted for a refusal, and nothing counted before the restart
 *    is returned;
 *  - introspection answers a resource server bare inactive for each of them.
 *    The designation check itself loses its record: while the Mission is
 *    active the missing issuance record answers, and once it is not, audience
 *    separation alone keeps the designation's Mission data from a caller.
 *
 * The residual: a caller that accepts the designated client's identifier,
 * which audience separation forbids, is told a non-active Mission's state for
 * a designation minted before the restart. Before the restart the designation
 * check answers that same request bare inactive.
 *
 * oidc-provider's memory adapter is process-global, so this in-process
 * rebuild still holds the provider Grant the tokens were minted under; a
 * process restart loses it too. Every refusal here precedes the grant check,
 * so it is the accounting's, not the grant's.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import { decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import {
  ALL_PROVIDER_CAPABILITIES,
  ApprovalSessionStore,
  buildAuthorizationServer,
  type BuiltAs,
  initSigningKeyRing,
} from "../src/index.js";
import { floorApprovalHeaders, TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

const PORT = 14876;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const SUBAGENT = "subagent-invoice-extractor";
const SECOND = "test-second-delegate";
const RS_PAYMENTS = ["rs-payments", "dev-introspection-rs-payments"] as const;
const ROLES = {
  asToken: TOPOLOGY.keys.asToken,
  asStatus: TOPOLOGY.keys.asStatus,
  asTxn: TOPOLOGY.keys.asTxn,
  asContinuation: TOPOLOGY.keys.asContinuation,
};

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
type Body = Record<string, unknown>;
type Client = "ap-agent" | typeof SUBAGENT | typeof SECOND;

/** One running AS on PORT, with the client keys its boot generated. */
interface Running {
  as: BuiltAs;
  server: Server;
  keys: Map<Client, CryptoKey>;
}

const sessions = new ApprovalSessionStore();
/** A resource server that starts accepting the designated client's identifier after the restart (the residual). */
const RS_LATE = ["rs-late", "dev-introspection-rs-late"] as const;
const rsLate = { principal_id: RS_LATE[0], secret: RS_LATE[1], audiences: [RESOURCE] as string[], disclose: [] as string[] };
const dpop = new Map<Client, Keys>();
let secondKeys: Keys;

async function boot(ring: string, kernelFile: string): Promise<Running> {
  const as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    approvalSessions: sessions,
    signingKeys: { ring },
    kernelStore: { file: kernelFile },
    capabilities: new Set([...ALL_PROVIDER_CAPABILITIES, "delegation"]),
    // A second ai_agent delegate, so the delegated token has a next delegate to name.
    testClients: [
      {
        client_id: SECOND,
        grant_types: [TOKEN_EXCHANGE_GRANT_TYPE],
        response_types: [],
        redirect_uris: [],
        token_endpoint_auth_method: "private_key_jwt",
        token_endpoint_auth_signing_alg: "ES256",
        jwks: { keys: [{ ...(await exportJWK(secondKeys.publicKey)), kid: `${SECOND}-auth`, alg: "ES256" }] },
        authorization_details_types: ["mission_resource_access"],
      },
    ],
    actorProfiles: { [SECOND]: "ai_agent" },
    designableClients: [SUBAGENT, SECOND],
    testIntrospectionPrincipals: [rsLate],
  } as never);
  const server = as.provider.listen(PORT);
  await new Promise<void>((r) => server.once("listening", () => r()));
  const keys = new Map<Client, CryptoKey>([
    ["ap-agent", (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey],
    [SUBAGENT, (await importJWK(as.childClientJwk as never, "ES256")) as CryptoKey],
    [SECOND, secondKeys.privateKey],
  ]);
  return { as, server, keys };
}

async function shutdown(running: Running): Promise<void> {
  await new Promise<void>((r) => running.server.close(() => r()));
  running.as.suspensionScheduler?.stop();
  running.as.kernel.close();
}

const assertion = (running: Running, client: Client) =>
  new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${client}-auth` })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(running.keys.get(client) as CryptoKey);

async function token(running: Running, client: Client, params: Record<string, string>): Promise<{ status: number; body: Body }> {
  const keys = dpop.get(client) as Keys;
  const send = async (extra: Record<string, unknown> = {}) =>
    fetch(`${ISSUER}/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
          .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
          .setIssuedAt()
          .setJti(crypto.randomUUID())
          .sign(keys.privateKey),
      },
      body: new URLSearchParams({
        ...params,
        client_assertion: await assertion(running, client),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return { status: res.status, body: (await res.json()) as Body };
}

function storeCookies(res: Response, jar: Map<string, string>): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}
const cookieHeader = (jar: Map<string, string>) => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");

/** PAR, approval and code exchange as ap-agent: an active Mission and its access token. */
async function baseMission(running: Running): Promise<{ missionId: string; accessToken: string }> {
  const jar = new Map<string, string>();
  const verifier = "delegation-restart-verifier-0123456789-0123456789-0123";
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: { goal: "Read Acme invoices", target_resources: [RESOURCE], expires_at: "2099-01-01T00:00:00Z" } }),
      authorization_details: JSON.stringify([
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:invoice.read"],
          constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
          delegation: { max_depth: 2, allowed_delegates: [{ sub_profile: "ai_agent" }] },
        },
      ]),
      client_assertion: await assertion(running, "ap-agent"),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const pushed = (await par.json()) as { request_uri?: string };
  expect(par.status, JSON.stringify(pushed)).toBe(201);
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri: pushed.request_uri as string })}`, {
    redirect: "manual",
  });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...floorApprovalHeaders(sessions, uid, cookieHeader(jar)), "content-type": "application/json" },
    body: JSON.stringify({ decision: "approve" }),
  });
  storeCookies(res, jar);
  location = res.headers.get("location") as string;
  while (location?.startsWith(ISSUER)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    storeCookies(res, jar);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;
  const tok = await token(running, "ap-agent", {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
    resource: RESOURCE,
  });
  expect(tok.status, JSON.stringify(tok.body)).toBe(200);
  const accessToken = tok.body.access_token as string;
  return { missionId: (decodeJwt(accessToken) as { mission: { id: string } }).mission.id, accessToken };
}

/** A designation: `client` names `designee` for the presented token. */
const designate = (running: Running, subjectToken: string, designee: string, client: Client) =>
  token(running, client, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    audience: designee,
  });

/** A delegated exchange: the sub-agent redeems the designation for the payments resource. */
const redeem = (running: Running, designation: string) =>
  token(running, SUBAGENT, {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: designation,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    resource: RESOURCE,
  });

async function introspect(tokenValue: string, principal: readonly [string, string] = RS_PAYMENTS): Promise<Body> {
  const res = await fetch(`${ISSUER}/introspect`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(`${principal[0]}:${principal[1]}`).toString("base64")}`,
    },
    body: new URLSearchParams({ token: tokenValue }).toString(),
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Body;
}

const derivations = (running: Running, missionId: string) =>
  (running.as.kernel.get(missionId) as { derivation_count?: number }).derivation_count ?? 0;
const jtiOf = (jwt: string) => (decodeJwt(jwt) as { jti: string }).jti;

/** Introspect `tokenValue` as a resource server that also accepts the designated client's identifier. */
async function introspectAsLate(tokenValue: string): Promise<Body> {
  rsLate.audiences.push(SUBAGENT);
  try {
    return await introspect(tokenValue, RS_LATE);
  } finally {
    rsLate.audiences.pop();
  }
}

/**
 * Each request the tests below send after the restart was first sent before
 * it, in the same run, and answered differently there (or, for an invariant,
 * the same): the restart is the only difference.
 */
describe("delegation accounting across a restart on the same kernel file and key ring (@spec mission#delegation-constraints, #869, #250)", () => {
  let dir: string;
  let second: Running;
  /** Minted before the restart under an active Mission: its origin token, a designation, and the delegated token it was redeemed for. */
  let active: { missionId: string; origin: string; designation: string; delegated: string; grantId: string; counted: number };
  /** Minted before the restart under a Mission revoked before it: its origin token and a designation. */
  let revoked: { missionId: string; origin: string; designation: string };

  beforeAll(async () => {
    secondKeys = await generateKeyPair("ES256", { extractable: true });
    for (const c of ["ap-agent", SUBAGENT, SECOND] as Client[]) dpop.set(c, await generateKeyPair("ES256", { extractable: true }));
    dir = mkdtempSync(join(tmpdir(), "delegation-restart-"));
    const ring = join(dir, "keys", "ring.json");
    const kernelFile = join(dir, "kernel.db");
    await initSigningKeyRing(ring, ISSUER, ROLES);

    const first = await boot(ring, kernelFile);
    try {
      // The active Mission. Before the restart the origin token designates,
      // the designation redeems, the delegated token designates the next
      // delegate and introspects active, and the designation is bare inactive.
      const base = await baseMission(first);
      const designation = await designate(first, base.accessToken, SUBAGENT, "ap-agent");
      expect(designation.status, JSON.stringify(designation.body)).toBe(200);
      const delegated = await redeem(first, designation.body.access_token as string);
      expect(delegated.status, JSON.stringify(delegated.body)).toBe(200);
      const next = await designate(first, delegated.body.access_token as string, SECOND, SUBAGENT);
      expect(next.status, JSON.stringify(next.body)).toBe(200);
      expect(await introspect(delegated.body.access_token as string)).toMatchObject({ active: true });
      expect(await introspect(designation.body.access_token as string)).toEqual({ active: false });
      active = {
        missionId: base.missionId,
        origin: base.accessToken,
        designation: designation.body.access_token as string,
        delegated: delegated.body.access_token as string,
        grantId: first.as.kernel.get(base.missionId)?.grant_id as string,
        counted: derivations(first, base.missionId),
      };

      // The revoked Mission. Before the restart its designation is bare
      // inactive even to a caller that accepts the designated client's
      // identifier: the designation check answers before the Mission is read.
      const other = await baseMission(first);
      const otherDesignation = await designate(first, other.accessToken, SUBAGENT, "ap-agent");
      expect(otherDesignation.status, JSON.stringify(otherDesignation.body)).toBe(200);
      first.as.kernel.transition(other.missionId, "revoke");
      expect(await introspectAsLate(otherDesignation.body.access_token as string)).toEqual({ active: false });
      revoked = { missionId: other.missionId, origin: other.accessToken, designation: otherDesignation.body.access_token as string };

      for (const t of [active.origin, active.designation, active.delegated, revoked.designation]) {
        expect(first.as.tokenIssuanceStore.resolve(ISSUER, jtiOf(t))).toBeDefined();
      }
    } finally {
      await shutdown(first);
    }
    second = await boot(ring, kernelFile);
  }, 60_000);

  afterAll(async () => {
    if (second) await shutdown(second);
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  it("keeps the Mission, its derivation count and the signing keys, and loses the accounting: no token minted before the restart has a record after it", async () => {
    expect(second.as.kernel.get(active.missionId)?.state).toBe("active");
    expect(derivations(second, active.missionId)).toBe(active.counted);
    // The provider Grant is still held in this process (see the header).
    expect(await second.as.provider.Grant.find(active.grantId)).toBeDefined();
    for (const t of [active.origin, active.designation, active.delegated, revoked.designation]) {
      expect(second.as.tokenIssuanceStore.resolve(ISSUER, jtiOf(t))).toBeUndefined();
    }
  });

  it("refuses to redeem a designation minted before the restart invalid_request, issuing nothing and counting nothing", async () => {
    const res = await redeem(second, active.designation);
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toBe("subject_token is not a designation naming the requesting client");
    expect(res.body.access_token).toBeUndefined();
    expect(derivations(second, active.missionId)).toBe(active.counted);
  });

  it("refuses to designate the origin token or the delegated token minted before the restart invalid_target: depth is not established, nothing issued or counted", async () => {
    const origin = await designate(second, active.origin, SUBAGENT, "ap-agent");
    const delegated = await designate(second, active.delegated, SECOND, SUBAGENT);
    for (const res of [origin, delegated]) {
      expect(res.status, JSON.stringify(res.body)).toBe(400);
      expect(res.body.error).toBe("invalid_target");
      expect(res.body.error_description).toBe("the presented token's delegation depth cannot be established");
      expect(res.body.access_token).toBeUndefined();
    }
    expect(derivations(second, active.missionId)).toBe(active.counted);
  });

  it("introspects the delegated token and the designation minted before the restart bare inactive while the Mission is active", async () => {
    expect(await introspect(active.delegated)).toEqual({ active: false });
    expect(await introspect(active.designation)).toEqual({ active: false });
  });

  it("keeps a designation minted before the restart bare inactive, with no Mission data, once its Mission is not active, to a resource server it is not an audience of: audience separation", async () => {
    expect(await introspect(revoked.designation)).toEqual({ active: false });
    // A token the same resource server is an audience of reports the revoked Mission.
    expect((await introspect(revoked.origin)).mission).toMatchObject({ id: revoked.missionId, state: "terminated" });
  });

  it("the residual: a caller that accepts the designated client's identifier is told the revoked Mission's state for a designation minted before the restart, since its designation record is gone and only audience separation stood", async () => {
    const body = await introspectAsLate(revoked.designation);
    expect(body.active).toBe(false);
    expect(body.mission).toMatchObject({ id: revoked.missionId, state: "terminated", termination: { reason: "revoked" } });
  });
});
