/**
 * @spec deferred-approval#deferred-sequencing, mission#submission-processing,
 * mission#intent-submission-evidence (#1300, D479, #1313 item 3): Deferred
 * Mission Approval's evidence check before derivation, over a real AS
 * assembly that configures no model advisor.
 *
 * A governed_policy activation verifies the submission's Intent Submission
 * Evidence before any derivation, and again after a model advisor returns.
 * Where no advisor is configured the second check never runs, so the first
 * is the only one standing between evidence that lapsed while the approval
 * pended and a Mission. The agent `ledger-reconciler` pushes a deferred
 * submission carrying evidence; standing consent to a governed policy root
 * is recorded in process, as in the endpoint suite.
 */

import { type Server } from "node:http";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ALL_PROVIDER_CAPABILITIES,
  buildAuthorizationServer,
  type BuiltAs,
  DEFERRED_GRANT_TYPE,
  type GovernedPolicyRoot,
  IntentError,
  type MissionRecord,
  type RegisteredActivationPolicy,
  recordGovernedPolicyConsent,
  registerIntentSubmissionEvidenceType,
  unregisterIntentSubmissionEvidenceType,
} from "../src/index.js";
import { TEST_APPROVAL_PRINCIPALS } from "./approval-fixture.js";

const PORT = 14314;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const AGENT = "ledger-reconciler";
const WORKLOAD = "agt_ledger_reconciler";
const VERIFIER = "deferred-approval-no-advisor-verifier-0123456789-0123";
const READ = ["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"];

let clockMs = Date.now();
const now = () => new Date(clockMs);

const readEntry = (actions: string[] = READ) => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions,
  constraints: { vendors: ["acme"] },
});

const rootDoc = (over: Partial<GovernedPolicyRoot> = {}): GovernedPolicyRoot => ({
  admits: { clients: [AGENT], subjects: [WORKLOAD], authority_sources: ["service_owned"] },
  authority_ceiling: [readEntry()] as never,
  lifetime: { max_lifetime_s: 3600 },
  rules: { max_entries: 3 },
  recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60 },
  classification: { standard: READ },
  ...over,
});

/** This deployment's governed policy configuration, read live at every activation. */
const governance: { roots: Record<string, RegisteredActivationPolicy>; approvers: Record<string, string[]> } = {
  roots: {},
  approvers: {},
};

let as: BuiltAs;
let server: Server;
let agentKey: CryptoKey;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: { ...TEST_APPROVAL_PRINCIPALS },
    capabilities: new Set([...ALL_PROVIDER_CAPABILITIES, "deferred-approval"]),
    governedPolicyApproval: governance,
    activationPolicies: {},
    // No modelAdvisor: the activation's evidence check before derivation is its only one.
    deferredApproval: { pendingLifetimeS: 600 },
    now,
  });
  server = as.provider.listen(PORT);
  agentKey = (await importJWK(as.ledgerReconcilerClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  server?.close();
});

let rootSeq = 0;
/** Make `doc` the one root this deployment holds, with dana's standing consent to it. */
function useRoot(doc: GovernedPolicyRoot): void {
  for (const k of Object.keys(governance.roots)) delete governance.roots[k];
  for (const k of Object.keys(governance.approvers)) delete governance.approvers[k];
  const id = `urn:root:no-advisor-${++rootSeq}`;
  governance.roots[id] = { version: "1", content_type: "application/json", content: JSON.stringify(doc) };
  governance.approvers[id] = ["dana"];
  recordGovernedPolicyConsent(as.kernel, {
    root: { id, version: "1" },
    approver: { iss: ISSUER, sub: "dana" },
    consentEventId: `gpce-${id}`,
  });
}

/**
 * A test Intent Submission Evidence type: an artifact that verifies until
 * its own `expires_at`, judged against the verifier's (the kernel's) clock.
 */
const EVIDENCE_TYPE = "urn:test:mission:intent-evidence:expiring-admission-no-advisor";
registerIntentSubmissionEvidenceType(EVIDENCE_TYPE, {
  validate(entry) {
    for (const k of Object.keys(entry)) {
      if (!["type", "assertion", "expires_at"].includes(k)) {
        throw new IntentError("invalid_mission_intent_evidence", `unknown member: ${k}`);
      }
    }
    if (typeof entry.assertion !== "string" || typeof entry.expires_at !== "string") {
      throw new IntentError("invalid_mission_intent_evidence", "assertion and expires_at are required");
    }
  },
  async verify(input) {
    if (Date.parse(String(input.entry.expires_at)) <= input.now.getTime()) throw new Error("admission artifact expired");
    return { presenter_client: input.presenter.clientId, bound_intent_hash: input.intentHash };
  },
});
afterAll(() => unregisterIntentSubmissionEvidenceType(EVIDENCE_TYPE));
const evidenceUntil = (ms: number) => ({ type: EVIDENCE_TYPE, assertion: `admission-${ms}`, expires_at: new Date(ms).toISOString() });

const clientAuth = async () => ({
  client_assertion: await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${AGENT}-auth` })
    .setIssuer(AGENT)
    .setSubject(AGENT)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(agentKey),
  client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
});

type Keys = { privateKey: CryptoKey; jwk: JWK; jkt: string };
const newKeys = async (): Promise<Keys> => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(pair.publicKey);
  return { privateKey: pair.privateKey as CryptoKey, jwk, jkt: await calculateJwkThumbprint(jwk) };
};

/** POST /token as the agent with a fresh DPoP proof under `keys`. */
async function tokenRequest(params: Record<string, string>, keys: Keys): Promise<{ status: number; body: Record<string, unknown> }> {
  const htu = `${ISSUER}/token`;
  const dpop = await new SignJWT({ htu, htm: "POST" })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: keys.jwk })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
  const res = await fetch(htu, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop },
    body: new URLSearchParams({ ...params, ...(await clientAuth()) }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/**
 * The agent's deferred submission carrying `evidence` (PAR with
 * `completion_mode=deferred`, the authorization request with no End-User
 * present, and the redemption of the pending-request code): the deferral code.
 */
async function openDeferral(keys: Keys, evidence: unknown[]): Promise<string> {
  const challenge = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER))).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: AGENT,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      code_challenge: challenge,
      code_challenge_method: "S256",
      mission_intent: JSON.stringify({
        intent: { goal: "Reconcile Acme invoices against the ledger", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" },
        evidence,
      }),
      authorization_details: JSON.stringify([readEntry(["payments:invoice.read"])]),
      completion_mode: "deferred",
      ...(await clientAuth()),
    }).toString(),
  });
  expect(par.status, await par.clone().text()).toBe(201);
  const { request_uri } = (await par.json()) as { request_uri: string };
  const jar = new Map<string, string>();
  const keep = (res: Response) => {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = (pair as string).indexOf("=");
      jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
    }
  };
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: AGENT, request_uri })}`, { redirect: "manual" });
  keep(res);
  let location = res.headers.get("location") ?? "";
  while (location.startsWith(ISSUER) || location.startsWith("/")) {
    res = await fetch(new URL(location, ISSUER), { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  const code = location.startsWith(REDIRECT_URI) ? new URL(location).searchParams.get("code") : null;
  expect(code, location).toBeTruthy();
  const r = await tokenRequest(
    { grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT_URI, code_verifier: VERIFIER, completion_mode: "deferred" },
    keys,
  );
  expect(r.status, JSON.stringify(r.body)).toBe(400);
  expect(r.body.error).toBe("authorization_pending");
  return r.body.deferral_code as string;
}

const poll = (deferralCode: string, keys: Keys) => tokenRequest({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: deferralCode }, keys);
const missionCount = () => as.kernel.allMissions().length;

describe("deferred Mission approval evidence check with no model advisor (@spec deferred-approval#deferred-sequencing, mission#submission-processing, #1300, #1313)", () => {
  it("refuses evidence that verified at PAR and lapsed before the activation: access_denied, with no Mission, no record and no token", async () => {
    useRoot(rootDoc());
    const keys = await newKeys();
    const before = missionCount();
    const records = as.kernel.governanceRecords.count();
    const code = await openDeferral(keys, [evidenceUntil(clockMs + 120_000)]);
    clockMs += 180_000;
    const r = await poll(code, keys);
    expect(r.status, JSON.stringify(r.body)).toBe(400);
    expect(r.body.error).toBe("access_denied");
    expect(r.body).not.toHaveProperty("access_token");
    expect(missionCount()).toBe(before);
    expect(as.kernel.governanceRecords.count()).toBe(records);
    expect(as.missionApprovalDeferrals?.resolutionReason(code)).toBe("invalid_mission_intent_evidence");
  });

  it("checks the evidence before selecting a policy or deriving: lapsed evidence under a root that admits no such client is refused for the evidence", async () => {
    useRoot(rootDoc({ admits: { clients: ["no-such-client"], subjects: [WORKLOAD], authority_sources: ["service_owned"] } }));
    const keys = await newKeys();
    const before = missionCount();
    const code = await openDeferral(keys, [evidenceUntil(clockMs + 120_000)]);
    clockMs += 180_000;
    const r = await poll(code, keys);
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("access_denied");
    expect(missionCount()).toBe(before);
    expect(as.missionApprovalDeferrals?.resolutionReason(code)).toBe("invalid_mission_intent_evidence");
  });

  it("records on the Mission the facts its one evidence check verified at the activation", async () => {
    useRoot(rootDoc());
    const keys = await newKeys();
    const code = await openDeferral(keys, [evidenceUntil(clockMs + 3_600_000)]);
    clockMs += 10_000;
    const activatedAt = new Date(clockMs).toISOString();
    const delivered = await poll(code, keys);
    expect(delivered.status, JSON.stringify(delivered.body)).toBe(200);
    const mission = as.kernel.get(delivered.body.mission_id as string) as MissionRecord;
    expect(mission.submission_evidence).toEqual([
      {
        type: EVIDENCE_TYPE,
        artifact_hash: expect.any(String),
        verified_at: activatedAt,
        facts: { presenter_client: AGENT, bound_intent_hash: mission.intent_hash },
      },
    ]);
  });
});
