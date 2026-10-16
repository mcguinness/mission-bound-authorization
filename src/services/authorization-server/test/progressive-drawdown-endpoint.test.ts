/**
 * @spec draft-mcguinness-oauth-mission-progressive (#progressive-authorization,
 * #in-ceiling-expansion, #ceiling-review, #audit-linkage),
 * expansion#creation-request-id, mission#standing-consent-bases
 *
 * Progressive authorization on the real OAuth surface (#1017). The Approver
 * consents an authority ceiling and a drawdown policy on the approval surface
 * (the decision body); the Mission records them under `ceiling_hash`. With the
 * deployment's `progressive` option set, an expansion token exchange of that
 * Mission is:
 *  - refused `out_of_ceiling` when the successor exceeds the ceiling;
 *  - completed in the token-exchange response under the `ceiling_drawdown`
 *    basis when the drawdown policy authorizes it: the `(client,
 *    creation_request_id)` reservation, the successor's activation and the
 *    predecessor's supersession commit together before the response, and the
 *    successor's `approval_event_id` is allocated once per reservation;
 *  - otherwise sent to the ordinary fresh-approval (deferred) path.
 * A second assembly without the option shows the capability is default off.
 */

import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

import { type Server } from "node:http";
import { CANONICAL_RESOURCE, DERIVATION_POLICY } from "@mission/demo-data";
import { authorityHash, computeAnchor, type JsonValue } from "@mission/core";
import { type CryptoKey, decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ACCESS_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import type { RegisteredActivationPolicy } from "../src/kernel/activation-policy.js";
import type { ProgressiveDrawdownOptions } from "../src/kernel/progressive.js";
import type { AuthorityEntry, LifecycleCommit, MissionRecord } from "../src/kernel/types.js";
import { buildAuthorizationServer, type BuiltAs, createChildMission } from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";

const PORT = 14839;
const ISSUER = `http://localhost:${PORT}`;
const OFF_PORT = 14840;
const OFF_ISSUER = `http://localhost:${OFF_PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = CANONICAL_RESOURCE;
const FAR_EXP = "2027-01-01T00:00:00Z";
const SECOND_CLIENT = "agent-A1";

type DpopKeys = { privateKey: CryptoKey; publicKey: CryptoKey };
/** An authenticating client: its id, its private_key_jwt key and kid, and its DPoP key. */
type Client = { id: string; kid: string; key: CryptoKey; dpop: DpopKeys };

let as: BuiltAs;
let asOff: BuiltAs;
let servers: Server[] = [];
let ap: Client;
let apOff: Client;
let second: Client;
let verifierSeq = 0;
const commits: LifecycleCommit[] = [];

/** The deployment's drawdown policies: a JSON snapshot stating the per-drawdown bound and the review cadence. */
const drawdownPolicy = (cadenceS = 2_592_000, maxAdded = 1): RegisteredActivationPolicy => ({
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ max_added_actions: maxAdded, ceiling_review_cadence_s: cadenceS }),
});
const POLICIES: Record<string, RegisteredActivationPolicy> = {
  "drawdown-std": drawdownPolicy(),
  // Edited in place by the changed-policy case.
  "drawdown-edit": drawdownPolicy(),
  // A one-second review cadence.
  "drawdown-short": drawdownPolicy(1),
  // Two widened actions per drawdown.
  "drawdown-wide": drawdownPolicy(2_592_000, 2),
};

/** The Mission Deployment Profile's published bounds and action-class mapping. */
const PROGRESSIVE: ProgressiveDrawdownOptions = {
  chainRateBound: { maxDrawdowns: 2, windowSeconds: 3600 },
  actionClasses: {
    "payments:invoice.list": "consequential_read",
    "payments:invoice.read": "consequential_read",
    "payments:vendor.read": "consequential_read",
    "payments:payment.schedule": "consequential_write",
    "payments:payment.schedule.cancel": "consequential_write",
    "payments:payment.execute": "irreversible_action",
    // payments:remittance.send is deliberately unclassified.
  },
  externalCommunicationActions: ["payments:vendor.read"],
};

/** The payments ceiling exactly as the derivation policy states it: every derived entry fits it. */
const FULL_CEILING = DERIVATION_POLICY.ceiling.filter((e) => e.resource === RESOURCE) as unknown as AuthorityEntry[];
/** Only the read entry of that ceiling. */
const READ_CEILING = FULL_CEILING.slice(0, 1);

const READ_ACTIONS = new Set(["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"]);

/** The proposal: read actions under the vendor constraint, amount-bearing ones also under max_amount. */
const authority = (actions: string[]) => {
  const reads = actions.filter((a) => READ_ACTIONS.has(a));
  const writes = actions.filter((a) => !READ_ACTIONS.has(a));
  return [
    ...(reads.length
      ? [{ type: "mission_resource_access", resource: RESOURCE, actions: reads, constraints: { vendors: ["acme"] } }]
      : []),
    ...(writes.length
      ? [
          {
            type: "mission_resource_access",
            resource: RESOURCE,
            actions: writes,
            constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
          },
        ]
      : []),
  ];
};

const intentJson = (goal: string, extra: Record<string, unknown> = {}): string =>
  JSON.stringify({ intent: { goal, target_resources: [RESOURCE], expires_at: FAR_EXP, ...extra } });

async function clientAssertion(client: Client, issuer: string): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: client.kid })
    .setIssuer(client.id)
    .setSubject(client.id)
    .setAudience(issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(client.key);
}

async function dpopProof(client: Client, htu: string, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(client.dpop.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(client.dpop.privateKey);
}

/** POST /token as `client` (private_key_jwt + DPoP), with the dpop-nonce retry. */
async function tokenRequest(
  params: Record<string, string>,
  client: Client = ap,
  issuer: string = ISSUER,
): Promise<Response> {
  const htu = `${issuer}/token`;
  const send = async (extra: Record<string, unknown> = {}): Promise<Response> =>
    fetch(htu, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProof(client, htu, extra) },
      body: new URLSearchParams({
        ...params,
        client_assertion: await clientAssertion(client, issuer),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      }).toString(),
    });
  let res = await send();
  const nonce = res.headers.get("dpop-nonce");
  if (res.status === 400 && nonce) res = await send({ nonce });
  return res;
}

function cookieHeader(jar: Map<string, string>): string {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
function storeCookies(res: Response, jar: Map<string, string>): void {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
}

/** What the Approver consents on the approval surface beside the Mission. */
type CeilingDecision = { authority_ceiling: AuthorityEntry[]; drawdown_policy?: { id: string; version: string } };

/**
 * PAR, approval (the decision carries the consented ceiling), code, token: an
 * ACTIVE Mission and its DPoP-bound access token.
 */
async function issueMission(
  actions: string[],
  ceiling: CeilingDecision | undefined,
  opts: { client?: Client; issuer?: string; intentExtra?: Record<string, unknown> } = {},
): Promise<{ missionId: string; accessToken: string }> {
  const client = opts.client ?? ap;
  const issuer = opts.issuer ?? ISSUER;
  const jar = new Map<string, string>();
  const verifier = `progressive-verifier-0123456789-0123456789-${verifierSeq++}`;
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  const par = await fetch(`${issuer}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: client.id,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: intentJson("Pay Acme invoices", opts.intentExtra),
      authorization_details: JSON.stringify(authority(actions)),
      client_assertion: await clientAssertion(client, issuer),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  const parBody = (await par.json()) as { request_uri: string };
  expect(par.status, JSON.stringify(parBody)).toBe(201);
  let res = await fetch(`${issuer}/auth?${new URLSearchParams({ client_id: client.id, request_uri: parBody.request_uri })}`, {
    redirect: "manual",
  });
  storeCookies(res, jar);
  let location = res.headers.get("location") as string;
  const uid = location.split("/interaction/")[1] as string;
  res = await fetch(`${issuer}/interaction/${uid}/decide`, {
    method: "POST",
    redirect: "manual",
    headers: { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookieHeader(jar) },
    body: JSON.stringify({ decision: "approve", ...(ceiling ?? {}) }),
  });
  storeCookies(res, jar);
  location = res.headers.get("location") as string;
  while (location?.startsWith(issuer)) {
    res = await fetch(location, { redirect: "manual", headers: { cookie: cookieHeader(jar) } });
    storeCookies(res, jar);
    location = res.headers.get("location") as string;
  }
  const code = new URL(location).searchParams.get("code") as string;
  const tok = await tokenRequest(
    {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
      resource: RESOURCE,
    },
    client,
    issuer,
  );
  const body = (await tok.json()) as { access_token: string };
  expect(tok.status, JSON.stringify(body)).toBe(200);
  const claims = decodeJwt(body.access_token) as { mission: { id: string } };
  return { missionId: claims.mission.id, accessToken: body.access_token };
}

const ceilingOf = (policyId = "drawdown-std", authorityCeiling = FULL_CEILING): CeilingDecision => ({
  authority_ceiling: authorityCeiling,
  drawdown_policy: { id: policyId, version: "1" },
});

function expansionParams(
  subjectToken: string,
  creationRequestId: string,
  actions: string[],
  goal = "Widen the invoice work",
  intentExtra: Record<string, unknown> = {},
): Record<string, string> {
  return {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    requested_token_type: ACCESS_TOKEN_TOKEN_TYPE,
    creation_request_id: creationRequestId,
    mission_intent: intentJson(goal, intentExtra),
    authorization_details: JSON.stringify(authority(actions)),
  };
}

type Completed = { access_token: string; mission_id: string; error?: string };

/** Expand and expect a synchronous drawdown: the 200 body. */
async function drawdown(
  subjectToken: string,
  creationRequestId: string,
  actions: string[],
  client: Client = ap,
): Promise<Completed> {
  const res = await tokenRequest(expansionParams(subjectToken, creationRequestId, actions), client);
  const body = (await res.json()) as Completed;
  expect(res.status, JSON.stringify(body)).toBe(200);
  return body;
}

/** Expand and expect the fresh-approval path: no policy-adjudicated successor, the predecessor untouched. */
async function expectFreshApproval(predecessorId: string, subjectToken: string, actions: string[]): Promise<void> {
  const before = as.kernel.allMissions().length;
  const res = await tokenRequest(expansionParams(subjectToken, crypto.randomUUID(), actions));
  const body = (await res.json()) as { error?: string; deferral_code?: string };
  expect(res.status, JSON.stringify(body)).toBe(400);
  expect(body.error).toBe("authorization_pending");
  expect(typeof body.deferral_code).toBe("string");
  expect(as.kernel.allMissions().length).toBe(before);
  expect(as.kernel.get(predecessorId)?.state).toBe("active");
}

/** The activating commits (creation events) published for a Mission. */
const activatingCommits = (missionId: string): LifecycleCommit[] =>
  commits.filter((c) => c.id === missionId && c.version === 1 && c.prior_state === undefined && c.state === "active");

const successorsOf = (predecessorId: string): MissionRecord[] =>
  as.kernel.allMissions().filter((m) => m.predecessor === predecessorId);

const READ = ["payments:invoice.read"];
const READ_LIST = ["payments:invoice.read", "payments:invoice.list"];

/** A client authenticating with the private JWK an assembly handed back. */
async function shippedClient(id: string, kid: string, jwk: Record<string, unknown>): Promise<Client> {
  const key = (await importJWK(jwk as never, "ES256")) as CryptoKey;
  return { id, kid, key, dpop: await generateKeyPair("ES256", { extractable: true }) };
}

beforeAll(async () => {
  const secondPair = await generateKeyPair("ES256", { extractable: true });
  second = {
    id: SECOND_CLIENT,
    kid: `${SECOND_CLIENT}-auth`,
    key: secondPair.privateKey,
    dpop: await generateKeyPair("ES256", { extractable: true }),
  };
  const secondJwk = { ...(await exportJWK(secondPair.publicKey)), kid: second.kid, alg: "ES256", use: "sig" };
  const testClients = [
    {
      client_id: SECOND_CLIENT,
      client_name: "A second Mission client of the acme-people source",
      grant_types: ["authorization_code", "refresh_token", TOKEN_EXCHANGE_GRANT_TYPE],
      response_types: ["code"],
      redirect_uris: [REDIRECT_URI],
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      jwks: { keys: [secondJwk] },
      authorization_details_types: ["mission_resource_access"],
    },
  ];
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    activationPolicies: POLICIES,
    actorProfiles: aiAgents("subagent-extractor"),
    onLifecycleCommit: (c) => commits.push(c),
    testClients,
    progressive: PROGRESSIVE,
  });
  asOff = await buildAuthorizationServer({
    issuer: OFF_ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    activationPolicies: POLICIES,
  });
  servers = [as.provider.listen(PORT), asOff.provider.listen(OFF_PORT)];
  ap = await shippedClient("ap-agent", "ap-agent-auth", as.agentClientJwk);
  apOff = await shippedClient("ap-agent", "ap-agent-auth", asOff.agentClientJwk);
});

afterAll(() => {
  for (const s of servers) s.close();
});

describe("ceiling consent (@spec progressive#progressive-authorization)", () => {
  it("records the consented authority_ceiling and drawdown_policy under ceiling_hash, outside authority_hash and the token", async () => {
    const m = await issueMission(READ, ceilingOf());
    const record = as.kernel.get(m.missionId) as MissionRecord;
    const ref = record.drawdown_policy;
    expect(ref?.id).toBe("drawdown-std");
    expect(ref?.version).toBe("1");
    expect(record.authority_ceiling).toEqual(FULL_CEILING);
    // ceiling_hash: typ mission-authority-ceiling over exactly the two members.
    expect(record.ceiling_hash).toBe(
      computeAnchor("mission-authority-ceiling", ISSUER, {
        authority_ceiling: FULL_CEILING,
        drawdown_policy: ref,
      } as unknown as JsonValue),
    );
    // authority_hash commits only the consented Authority Set.
    expect(record.authority_hash).toBe(authorityHash(ISSUER, record.authority_set as never));
    expect(record.ceiling_consented_at).toBe(record.created_at);
    // The ceiling is record provenance, never token content.
    expect(JSON.stringify(decodeJwt(m.accessToken))).not.toContain("authority_ceiling");
  });

  it("omits drawdown_policy from ceiling_hash when the Approver consents a ceiling without one", async () => {
    const m = await issueMission(READ, { authority_ceiling: FULL_CEILING });
    const record = as.kernel.get(m.missionId) as MissionRecord;
    expect(record.drawdown_policy).toBeUndefined();
    expect(record.ceiling_hash).toBe(
      computeAnchor("mission-authority-ceiling", ISSUER, { authority_ceiling: FULL_CEILING } as unknown as JsonValue),
    );
  });
});

describe("policy-adjudicated drawdown (@spec progressive#in-ceiling-expansion)", () => {
  it("completes in the token-exchange response: the successor is active under ceiling_drawdown, the predecessor superseded and the reservation committed", async () => {
    const pred = await issueMission(READ, ceilingOf());
    const predecessor = as.kernel.get(pred.missionId) as MissionRecord;
    const crid = crypto.randomUUID();
    const body = await drawdown(pred.accessToken, crid, READ_LIST);
    const successor = as.kernel.get(body.mission_id) as MissionRecord;
    expect((decodeJwt(body.access_token) as { mission: { id: string } }).mission.id).toBe(successor.id);
    expect(successor.state).toBe("active");
    expect(successor.predecessor).toBe(pred.missionId);
    expect(as.kernel.get(pred.missionId)?.termination).toMatchObject({ reason: "superseded", successor: successor.id });
    const op = as.creationIdempotency.find("ap-agent", crid);
    expect(op?.state).toBe("completed");
    expect(op?.missionId).toBe(successor.id);
    expect(successor.approval_basis).toEqual({
      type: "ceiling_drawdown",
      consent_principal: predecessor.approval_basis.consent_principal,
      activation: { policy_id: "drawdown-std", policy_version: "1" },
      activation_actor: { iss: ISSUER, sub: "ap-agent" },
      root_commitment: predecessor.ceiling_hash,
      approved_at: predecessor.created_at,
    });
    // The successor carries the ceiling unchanged, under the same ceiling_hash.
    expect(successor.authority_ceiling).toEqual(predecessor.authority_ceiling);
    expect(successor.drawdown_policy).toEqual(predecessor.drawdown_policy);
    expect(successor.ceiling_hash).toBe(predecessor.ceiling_hash);
    expect(successor.drawdown_count).toBe(1);
    expect(activatingCommits(successor.id)).toHaveLength(1);
  });

  it("keeps the predecessor's subject and authority_source on the successor", async () => {
    const pred = await issueMission(READ, ceilingOf());
    const predecessor = as.kernel.get(pred.missionId) as MissionRecord;
    const body = await drawdown(pred.accessToken, crypto.randomUUID(), READ_LIST);
    const successor = as.kernel.get(body.mission_id) as MissionRecord;
    expect(successor.subject).toEqual(predecessor.subject);
    expect(successor.authority_source).toEqual(predecessor.authority_source);
    expect(successor.client_id).toBe(predecessor.client_id);
  });

  it("verifies the drawdown policy digest before activation and retains the verified snapshot with the successor", async () => {
    const pred = await issueMission(READ, ceilingOf());
    const body = await drawdown(pred.accessToken, crypto.randomUUID(), READ_LIST);
    const successor = as.kernel.get(body.mission_id) as MissionRecord;
    const check = as.kernel.verifyActivationPolicyCommitment(successor);
    expect(check.status).toBe("verified");
    expect(check.status === "verified" && check.ref).toEqual(successor.drawdown_policy);
    expect(
      check.status === "verified" && Buffer.from(check.snapshot.content).toString("utf8"),
    ).toBe(POLICIES["drawdown-std"]?.content);
  });
});

describe("approval_event_id per drawdown reservation (@spec progressive#in-ceiling-expansion, mission#standing-consent-bases)", () => {
  it("each drawdown in a chain records its own approval_event_id, never the ceiling consent's, with approved_at the ceiling consent instant", async () => {
    const root = await issueMission(READ, ceilingOf());
    const rootRecord = as.kernel.get(root.missionId) as MissionRecord;
    const first = await drawdown(root.accessToken, crypto.randomUUID(), READ_LIST);
    const second = await drawdown(first.access_token, crypto.randomUUID(), [...READ_LIST, "payments:payment.schedule"]);
    const a = as.kernel.get(first.mission_id) as MissionRecord;
    const b = as.kernel.get(second.mission_id) as MissionRecord;
    expect(a.id).not.toBe(b.id);
    expect(a.approval_event_id).not.toBe(b.approval_event_id);
    for (const s of [a, b]) {
      expect(s.approval_event_id).not.toBe(rootRecord.approval_event_id);
      expect(s.approval_basis.type).toBe("ceiling_drawdown");
      expect(s.approval_basis.root_commitment).toBe(rootRecord.ceiling_hash);
      expect((s.approval_basis as { approved_at: string }).approved_at).toBe(rootRecord.created_at);
    }
    expect(b.drawdown_count).toBe(2);
  });

  it("a lost-response retry with the same creation_request_id recovers the same successor and approval_event_id, creating nothing", async () => {
    const pred = await issueMission(READ, ceilingOf());
    const crid = crypto.randomUUID();
    const first = await drawdown(pred.accessToken, crid, READ_LIST);
    const eventId = as.kernel.get(first.mission_id)?.approval_event_id;
    const before = as.kernel.allMissions().length;
    const retry = await drawdown(pred.accessToken, crid, READ_LIST);
    expect(retry.mission_id).toBe(first.mission_id);
    expect(retry.access_token).toBe(first.access_token);
    expect(as.kernel.get(retry.mission_id)?.approval_event_id).toBe(eventId);
    expect(as.kernel.allMissions().length).toBe(before);
    expect(activatingCommits(first.mission_id)).toHaveLength(1);
  });

  it("concurrent identical drawdowns create one successor, and every response names it", async () => {
    const pred = await issueMission(READ, ceilingOf());
    const crid = crypto.randomUUID();
    const responses = await Promise.all(
      Array.from({ length: 4 }, () => tokenRequest(expansionParams(pred.accessToken, crid, READ_LIST))),
    );
    const bodies = (await Promise.all(responses.map((r) => r.json()))) as Completed[];
    for (const [i, r] of responses.entries()) expect(r.status, JSON.stringify(bodies[i])).toBe(200);
    const ids = new Set(bodies.map((b) => b.mission_id));
    expect(ids.size).toBe(1);
    expect(successorsOf(pred.missionId)).toHaveLength(1);
    expect(activatingCommits([...ids][0] as string)).toHaveLength(1);
  });

  it("the same creation_request_id with a changed body is refused invalid_request, creating nothing", async () => {
    const pred = await issueMission(READ, ceilingOf());
    const crid = crypto.randomUUID();
    await drawdown(pred.accessToken, crid, READ_LIST);
    const before = as.kernel.allMissions().length;
    const res = await tokenRequest(expansionParams(pred.accessToken, crid, READ_LIST, "A different task"));
    const body = (await res.json()) as { error?: string; error_description?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("invalid_request");
    expect(body.error_description).toContain("different creation request");
    expect(as.kernel.allMissions().length).toBe(before);
  });

  it("another client's identical creation_request_id is its own reservation, with its own successor and approval_event_id", async () => {
    const crid = crypto.randomUUID();
    const mine = await issueMission(READ, ceilingOf());
    const theirs = await issueMission(READ, ceilingOf(), { client: second });
    const a = await drawdown(mine.accessToken, crid, READ_LIST);
    const b = await drawdown(theirs.accessToken, crid, READ_LIST, second);
    expect(a.mission_id).not.toBe(b.mission_id);
    expect(as.kernel.get(a.mission_id)?.predecessor).toBe(mine.missionId);
    expect(as.kernel.get(b.mission_id)?.predecessor).toBe(theirs.missionId);
    expect(as.kernel.get(a.mission_id)?.approval_event_id).not.toBe(as.kernel.get(b.mission_id)?.approval_event_id);
    expect(as.creationIdempotency.find(SECOND_CLIENT, crid)?.missionId).toBe(b.mission_id);
    expect(as.creationIdempotency.find("ap-agent", crid)?.missionId).toBe(a.mission_id);
  });

  it("a failure after the commit and before delivery is recovered by the retry, which delivers the committed successor and creates nothing", async () => {
    const pred = await issueMission(READ, ceilingOf());
    const crid = crypto.randomUUID();
    const before = as.kernel.allMissions().length;
    const crash = vi.spyOn(as.kernel, "publishPendingCommits").mockImplementationOnce(() => {
      throw new Error("crash after the creation commit");
    });
    try {
      const failed = await tokenRequest(expansionParams(pred.accessToken, crid, READ_LIST));
      expect(failed.status).toBe(500);
    } finally {
      crash.mockRestore();
    }
    const committed = successorsOf(pred.missionId);
    expect(committed).toHaveLength(1);
    expect(as.kernel.allMissions().length).toBe(before + 1);
    const successor = committed[0] as MissionRecord;
    expect(as.creationIdempotency.find("ap-agent", crid)?.missionId).toBe(successor.id);
    const retry = await drawdown(pred.accessToken, crid, READ_LIST);
    expect(retry.mission_id).toBe(successor.id);
    expect((decodeJwt(retry.access_token) as { mission: { id: string } }).mission.id).toBe(successor.id);
    expect(as.kernel.get(successor.id)?.approval_event_id).toBe(successor.approval_event_id);
    expect(as.kernel.allMissions().length).toBe(before + 1);
    expect(activatingCommits(successor.id)).toHaveLength(1);
  });

  it("a creation_request_id reused after its tombstone expires is a new drawdown under a new approval_event_id", async () => {
    const root = await issueMission(READ, ceilingOf());
    const crid = crypto.randomUUID();
    const first = await drawdown(root.accessToken, crid, READ_LIST);
    // The published retry horizon passes for this key.
    as.kernel.db
      .prepare("UPDATE creation_idempotency SET expires_at = 0 WHERE client_id = ? AND creation_request_id = ?")
      .run("ap-agent", crid);
    const reused = await drawdown(first.access_token, crid, [...READ_LIST, "payments:payment.schedule"]);
    expect(reused.mission_id).not.toBe(first.mission_id);
    const a = as.kernel.get(first.mission_id) as MissionRecord;
    const b = as.kernel.get(reused.mission_id) as MissionRecord;
    expect(b.predecessor).toBe(a.id);
    expect(b.approval_event_id).not.toBe(a.approval_event_id);
    expect(as.creationIdempotency.find("ap-agent", crid)?.missionId).toBe(b.id);
  });
});

describe("out of ceiling (@spec progressive#in-ceiling-expansion, progressive#denial-reason)", () => {
  it("refuses a successor outside the consented ceiling with out_of_ceiling: no successor, the predecessor untouched, nothing reserved", async () => {
    const pred = await issueMission(READ, ceilingOf("drawdown-std", READ_CEILING));
    const crid = crypto.randomUUID();
    const before = as.kernel.allMissions().length;
    const res = await tokenRequest(expansionParams(pred.accessToken, crid, [...READ, "payments:payment.schedule"]));
    const body = (await res.json()) as { error?: string; mission_denial_reason?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.mission_denial_reason).toBe("out_of_ceiling");
    expect(as.kernel.allMissions().length).toBe(before);
    expect(as.kernel.get(pred.missionId)?.state).toBe("active");
    expect(as.creationIdempotency.find("ap-agent", crid)).toBeUndefined();
  });
});

describe("fresh-approval fallback (@spec progressive#in-ceiling-expansion, progressive#ceiling-review)", () => {
  it("a drawdown policy edited after consent, here its review cadence under an unchanged version, authorizes nothing: the request falls back", async () => {
    const pred = await issueMission(READ, ceilingOf("drawdown-edit"));
    const original = POLICIES["drawdown-edit"] as RegisteredActivationPolicy;
    POLICIES["drawdown-edit"] = { ...original, content: JSON.stringify({ max_added_actions: 1, ceiling_review_cadence_s: 31_536_000 }) };
    try {
      await expectFreshApproval(pred.missionId, pred.accessToken, READ_LIST);
    } finally {
      POLICIES["drawdown-edit"] = original;
    }
    // The committed snapshot restored, the same request is adjudicated by policy.
    await drawdown(pred.accessToken, crypto.randomUUID(), READ_LIST);
  });

  it("a Mission that commits no drawdown policy is never adjudicated by policy", async () => {
    const pred = await issueMission(READ, { authority_ceiling: FULL_CEILING });
    await expectFreshApproval(pred.missionId, pred.accessToken, READ_LIST);
  });

  it("a chain whose ceiling consent is older than the policy's review cadence falls back", async () => {
    const pred = await issueMission(READ, ceilingOf("drawdown-short"));
    await new Promise((r) => setTimeout(r, 1100));
    await expectFreshApproval(pred.missionId, pred.accessToken, READ_LIST);
  });

  it("a drawdown that widens more than the policy's per-drawdown bound falls back; within the bound it is adjudicated", async () => {
    const pred = await issueMission(READ, ceilingOf());
    const twoMore = [...READ_LIST, "payments:payment.schedule"];
    await expectFreshApproval(pred.missionId, pred.accessToken, twoMore);
    const wide = await issueMission(READ, ceilingOf("drawdown-wide"));
    await drawdown(wide.accessToken, crypto.randomUUID(), twoMore);
  });

  it("a drawdown granting a high-consequence, unclassified, or external-communication action falls back", async () => {
    for (const action of ["payments:payment.execute", "payments:remittance.send", "payments:vendor.read"]) {
      const pred = await issueMission(READ, ceilingOf());
      await expectFreshApproval(pred.missionId, pred.accessToken, [...READ, action]);
    }
  });

  it("a predecessor with a non-terminal Child Mission falls back; once the child is terminal it is adjudicated", async () => {
    const pred = await issueMission(READ, ceilingOf());
    const { child } = createChildMission(as.kernel, {
      parentId: pred.missionId,
      intent: { goal: "Read invoices", target_resources: [RESOURCE], expires_at: FAR_EXP },
      proposedAuthority: authority(READ),
      childActor: { sub: "subagent-extractor", sub_profile: "ai_agent" },
    });
    await expectFreshApproval(pred.missionId, pred.accessToken, READ_LIST);
    as.kernel.transition(child.id, "revoke");
    await drawdown(pred.accessToken, crypto.randomUUID(), READ_LIST);
  });

  it("the chain's rate bound stops policy adjudication once reached", async () => {
    const root = await issueMission(READ, ceilingOf());
    const first = await drawdown(root.accessToken, crypto.randomUUID(), READ_LIST);
    const second = await drawdown(first.access_token, crypto.randomUUID(), [...READ_LIST, "payments:payment.schedule"]);
    await expectFreshApproval(second.mission_id, second.access_token, [
      ...READ_LIST,
      "payments:payment.schedule",
      "payments:payment.schedule.cancel",
    ]);
  });
});

describe("containment restrictions of the chain (@spec progressive#in-ceiling-expansion, containment#restoration)", () => {
  const containEvent = (id: string) => ({
    type: "tainted_read",
    source: "https://siem.example/detections",
    observed_at: "2026-07-02T00:00:00Z",
    event_id: id,
  });

  it("a successor overlapping contained authority falls back; one overlapping none stays eligible, and the restriction survives that intervening successor", async () => {
    const root = await issueMission(READ_LIST, ceilingOf());
    as.kernel.contain(root.missionId, {
      event: containEvent(`evt-${crypto.randomUUID()}`),
      remove: [{ resource: RESOURCE, actions: ["payments:invoice.list"] }],
    });
    // Restoring the contained action by policy falls back.
    await expectFreshApproval(root.missionId, root.accessToken, READ_LIST);
    // Unrelated authority remains eligible.
    const next = await drawdown(root.accessToken, crypto.randomUUID(), [...READ, "payments:payment.schedule"]);
    expect(as.kernel.get(next.mission_id)?.containment).toBeUndefined();
    // The successor holds no overlay, yet the chain's restriction still applies.
    await expectFreshApproval(next.mission_id, next.access_token, [
      ...READ_LIST,
      "payments:payment.schedule",
    ]);
  });
});

describe("derivation limits through the drawdown (@spec progressive#in-ceiling-expansion, derivation-limits#effective-limit)", () => {
  it("carries the derivation count forward under a limit a larger request cannot raise, and refuses at exhaustion creating nothing", async () => {
    // Limit 2; the authorization-code token is the first derivation.
    const root = await issueMission(READ, ceilingOf(), { intentExtra: { requested_derivation_limit: 2 } });
    expect(as.kernel.get(root.missionId)?.derivation_count).toBe(1);
    const res = await tokenRequest(
      expansionParams(root.accessToken, crypto.randomUUID(), READ_LIST, "Widen", { requested_derivation_limit: 20 }),
    );
    const body = (await res.json()) as Completed;
    expect(res.status, JSON.stringify(body)).toBe(200);
    const successor = as.kernel.get(body.mission_id) as MissionRecord;
    expect(successor.derivation_limit).toBe(2);
    // The carried count plus the successor token.
    expect(successor.derivation_count).toBe(2);
    // The next drawdown has no derivation left: refused, nothing created, nothing superseded.
    const before = as.kernel.allMissions().length;
    const refused = await tokenRequest(
      expansionParams(body.access_token, crypto.randomUUID(), [...READ_LIST, "payments:payment.schedule"]),
    );
    const rb = (await refused.json()) as { error?: string; mission_error?: string };
    expect(refused.status, JSON.stringify(rb)).toBe(400);
    expect(rb.error).toBe("invalid_grant");
    expect(rb.mission_error).toBe("derivations_exhausted");
    expect(as.kernel.allMissions().length).toBe(before);
    expect(as.kernel.get(successor.id)?.state).toBe("active");
    expect(as.kernel.get(successor.id)?.derivation_count).toBe(2);
  });
});

describe("default off (@spec progressive#in-ceiling-expansion)", () => {
  it("without the progressive option the decision's ceiling is not recorded and a widening expansion takes the fresh-approval path", async () => {
    const m = await issueMission(READ, ceilingOf(), { issuer: OFF_ISSUER, client: apOff });
    const record = asOff.kernel.get(m.missionId) as MissionRecord;
    expect(record.authority_ceiling).toBeUndefined();
    expect(record.ceiling_hash).toBeUndefined();
    const res = await tokenRequest(expansionParams(m.accessToken, crypto.randomUUID(), READ_LIST), apOff, OFF_ISSUER);
    const body = (await res.json()) as { error?: string };
    expect(res.status, JSON.stringify(body)).toBe(400);
    expect(body.error).toBe("authorization_pending");
    expect(asOff.kernel.get(m.missionId)?.state).toBe("active");
  });
});
