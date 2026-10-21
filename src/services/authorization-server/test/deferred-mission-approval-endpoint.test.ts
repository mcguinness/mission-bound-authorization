/**
 * @spec deferred-approval#deferred-approval, deferred-approval#deferred-sequencing,
 * deferred-approval#front-channel, deferred-approval#state-machine,
 * deferred-approval#pending-staleness, deferred-approval#queue-pressure,
 * deferred-approval#policy-completion, approval-governance#governed-policy-activation
 * (#1185): Deferred Mission Approval over the real AS assembly and the
 * shipped configuration, completed under the `governed_policy` basis.
 *
 * The agent `ledger-reconciler` pushes its own Mission Intent with
 * `completion_mode=deferred`, sends the authorization request with no
 * End-User present, redeems the pending-request code for a deferral code,
 * and polls. The issuer completes the pending approval under a governed
 * policy whose consented root the administrator `dana` approved, and the
 * resolving poll delivers the Mission-bound token. Standing consent is
 * recorded in process (`recordGovernedPolicyConsent`), as the trusted
 * governance surface would: this assembly serves no consent registration
 * route.
 *
 * The roots, the approvers and the evaluator registry are this deployment's
 * configuration objects, read live at every activation, so a test changes
 * them as a configuration change would.
 */

import { type Server } from "node:http";
import { activationPolicyDigest, approvalPolicyDigest } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { calculateJwkThumbprint, decodeJwt, exportJWK, generateKeyPair, importJWK, type JWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  ALL_PROVIDER_CAPABILITIES,
  buildAuthorizationServer,
  type BuiltAs,
  DEFERRED_GRANT_TYPE,
  type GovernedPolicyRoot,
  type MissionRecord,
  type ModelAdvisorRequest,
  mintActivationPolicyRef,
  type RecordedModelOutput,
  recordGovernedPolicyConsent,
  type RegisteredActivationPolicy,
  verifyApprovalGovernanceRecord,
  withdrawGovernedPolicyConsent,
  IntentError,
  registerIntentSubmissionEvidenceType,
  unregisterIntentSubmissionEvidenceType,
} from "../src/index.js";
import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

const PORT = 14185;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const AGENT = "ledger-reconciler";
const WORKLOAD = "agt_ledger_reconciler";
const VERIFIER = "deferred-mission-approval-verifier-0123456789-01234";
const LIFETIME_S = 600;

let clockMs = Date.now();
const now = () => new Date(clockMs);

const READ = ["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"];
/** The shipped ledger resource, inside the shipped `service_owned` source's ceiling. */
const LEDGER = "http://localhost:4406/mcp";
const ledgerEntry = () => ({
  type: "mission_resource_access",
  resource: LEDGER,
  actions: ["ledger:vendor.read"],
  constraints: { vendors: ["acme"] },
});
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
  classification: {
    standard: [...READ, "payments:payment.schedule", "payments:payment.schedule.cancel", "ledger:vendor.read"],
    irreversible_action: ["payments:payment.execute"],
    external_commitment: ["payments:remittance.send"],
  },
  ...over,
});

const held = (doc: GovernedPolicyRoot, version = "1"): RegisteredActivationPolicy => ({
  version,
  content_type: "application/json",
  content: JSON.stringify(doc),
});

/** This deployment's governed policy configuration and evaluator registry, read live. */
const governance: { roots: Record<string, RegisteredActivationPolicy>; approvers: Record<string, string[]> } = {
  roots: {},
  approvers: {},
};
const evaluators: Record<string, RegisteredActivationPolicy> = {};

/** The deployment's model hook; a test replaces what it answers. */
let advise: (request: ModelAdvisorRequest) => Promise<RecordedModelOutput[]> = async () => [];

let as: BuiltAs;
let server: Server;
let agentKey: CryptoKey;
let otherKey: CryptoKey;

beforeAll(async () => {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    allowHeadlessAdjudication: true,
    serviceTokenPrincipals: { ...TEST_APPROVAL_PRINCIPALS },
    capabilities: new Set([...ALL_PROVIDER_CAPABILITIES, "deferred-approval"]),
    governedPolicyApproval: governance,
    activationPolicies: evaluators,
    deferredApproval: { pendingLifetimeS: LIFETIME_S, maxPendingPerClient: 3, modelAdvisor: (r) => advise(r) },
    now,
  });
  server = as.provider.listen(PORT);
  agentKey = (await importJWK(as.ledgerReconcilerClientJwk as never, "ES256")) as CryptoKey;
  otherKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  server?.close();
});

let rootSeq = 0;
/**
 * Make `doc` the one root this deployment holds, approvable by `approver`
 * (`dana` by default), and record that human's consent to it unless told
 * not to. Clears the queue left by earlier tests (their pending approvals
 * lapse) first.
 */
function useRoot(doc: GovernedPolicyRoot, opts: { approver?: string; consent?: boolean; version?: string } = {}) {
  clockMs += (LIFETIME_S + 1) * 1000;
  for (const k of Object.keys(governance.roots)) delete governance.roots[k];
  for (const k of Object.keys(governance.approvers)) delete governance.approvers[k];
  return addRoot(doc, opts);
}

/** Hold one more root beside the ones this deployment already holds. */
function addRoot(doc: GovernedPolicyRoot, opts: { approver?: string; consent?: boolean; version?: string } = {}) {
  const id = `urn:root:ledger-${++rootSeq}`;
  const version = opts.version ?? "1";
  const approver = opts.approver ?? "dana";
  governance.roots[id] = held(doc, version);
  governance.approvers[id] = [approver];
  const consent =
    opts.consent === false
      ? undefined
      : recordGovernedPolicyConsent(as.kernel, {
          root: { id, version },
          approver: { iss: ISSUER, sub: approver },
          consentEventId: `gpce-${id}`,
        });
  return { id, consent };
}

const clientKeyOf = (client: string) => (client === AGENT ? agentKey : otherKey);

const clientAuth = async (client: string = AGENT) => ({
  client_assertion: await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: `${client}-auth` })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKeyOf(client)),
  client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
});

type Keys = { privateKey: CryptoKey; jwk: JWK; jkt: string };
const newKeys = async (): Promise<Keys> => {
  const pair = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(pair.publicKey);
  return { privateKey: pair.privateKey as CryptoKey, jwk, jkt: await calculateJwkThumbprint(jwk) };
};

const challenge = async (verifier = VERIFIER) =>
  Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))).toString("base64url");

const submission = (intent: Record<string, unknown> = {}, evidence?: unknown[]) =>
  JSON.stringify({
    intent: {
      goal: "Reconcile Acme invoices against the ledger",
      target_resources: [RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
      ...intent,
    },
    ...(evidence ? { evidence } : {}),
  });

/**
 * A test Intent Submission Evidence type: an artifact that verifies until
 * its own `expires_at`, judged against the verifier's (the kernel's) clock.
 */
const EVIDENCE_TYPE = "urn:test:mission:intent-evidence:expiring-admission";
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
const evidenceUntil = (ms: number) => ({
  type: EVIDENCE_TYPE,
  assertion: `admission-${ms}`,
  expires_at: new Date(ms).toISOString(),
});

interface FrontChannel {
  code?: string;
  error?: string;
  state?: string;
  iss?: string;
  /** Where the interaction step sent the user agent. */
  location: string;
  interaction: string;
  cookie: string;
}

/**
 * The agent's own front channel: PAR (with `completion_mode=deferred`
 * unless `completionMode` is null), then the authorization request and the
 * interaction it is sent to, with no End-User present.
 */
async function frontChannel(
  o: {
    client?: string;
    completionMode?: string | null;
    extra?: Record<string, string>;
    authorizationDetails?: unknown[] | null;
    intent?: Record<string, unknown>;
    /** The Submission envelope's `evidence`. */
    evidence?: unknown[];
    /** Stop once the authorization request names its interaction, before visiting it. */
    stopAtInteraction?: boolean;
    /** RFC 8707 `resource` parameters, each sent as its own parameter (repeats included). */
    resources?: string[];
  } = {},
): Promise<FrontChannel> {
  const client = o.client ?? AGENT;
  const body = new URLSearchParams({
    client_id: client,
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    code_challenge: await challenge(),
    code_challenge_method: "S256",
    state: "st-1185",
    mission_intent: submission(o.intent, o.evidence),
    ...(o.authorizationDetails === null
      ? {}
      : { authorization_details: JSON.stringify(o.authorizationDetails ?? [readEntry(["payments:invoice.read"])]) }),
    ...(o.completionMode === null ? {} : { completion_mode: o.completionMode ?? "deferred" }),
    ...(o.extra ?? {}),
    ...(await clientAuth(client)),
  });
  for (const r of o.resources ?? []) body.append("resource", r);
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString(),
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
  let res = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: client, request_uri })}`, { redirect: "manual" });
  keep(res);
  const interaction = res.headers.get("location") ?? "";
  if (o.stopAtInteraction) return { location: interaction, interaction, cookie: cookie() };
  res = await fetch(new URL(interaction, ISSUER), { redirect: "manual", headers: { cookie: cookie() } });
  keep(res);
  let location = res.headers.get("location") ?? "";
  // An error the interaction finished with is rendered through the resume.
  while (location.startsWith(ISSUER) || location.startsWith("/")) {
    res = await fetch(new URL(location, ISSUER), { redirect: "manual", headers: { cookie: cookie() } });
    keep(res);
    location = res.headers.get("location") ?? "";
  }
  const q = location.startsWith(REDIRECT_URI) ? new URL(location).searchParams : new URLSearchParams();
  return {
    location,
    interaction,
    cookie: cookie(),
    ...(q.get("code") ? { code: q.get("code") as string } : {}),
    ...(q.get("error") ? { error: q.get("error") as string } : {}),
    ...(q.get("state") ? { state: q.get("state") as string } : {}),
    ...(q.get("iss") ? { iss: q.get("iss") as string } : {}),
  };
}

/** POST /token as `client` with a fresh DPoP proof under `keys` (none when `keys` is null). */
async function tokenRequest(
  params: Record<string, string>,
  keys: Keys | null,
  client: string = AGENT,
): Promise<{ status: number; body: Record<string, unknown>; headers: Headers }> {
  const htu = `${ISSUER}/token`;
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  if (keys) {
    headers.dpop = await new SignJWT({ htu, htm: "POST" })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: keys.jwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(keys.privateKey);
  }
  const res = await fetch(htu, {
    method: "POST",
    headers,
    body: new URLSearchParams({ ...params, ...(await clientAuth(client)) }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown>, headers: res.headers };
}

const redeem = (code: string, keys: Keys | null, o: { client?: string; params?: Record<string, string> } = {}) =>
  tokenRequest(
    {
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: VERIFIER,
      completion_mode: "deferred",
      ...(o.params ?? {}),
    },
    keys,
    o.client,
  );

const poll = (deferralCode: string, keys: Keys | null, client: string = AGENT, extra: Record<string, string> = {}) =>
  tokenRequest({ grant_type: DEFERRED_GRANT_TYPE, deferral_code: deferralCode, ...extra }, keys, client);

const revoke = async (token: string, client: string = AGENT) =>
  fetch(`${ISSUER}/token/revocation`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      token,
      token_type_hint: "urn:ietf:params:oauth:token-type:deferral-code",
      ...(await clientAuth(client)),
    }).toString(),
  });

/** Front channel and redemption: the deferral code of one fresh pending approval. */
async function openDeferral(keys: Keys, o: Parameters<typeof frontChannel>[0] = {}): Promise<string> {
  const fc = await frontChannel(o);
  expect(fc.code, fc.location).toBeDefined();
  const r = await redeem(fc.code as string, keys, { client: o.client ?? AGENT });
  expect(r.status, JSON.stringify(r.body)).toBe(400);
  expect(r.body.error).toBe("authorization_pending");
  return r.body.deferral_code as string;
}

/** The poll that resolves the approval: an access_denied or the delivered token. */
async function resolve(deferralCode: string, keys: Keys, client: string = AGENT) {
  clockMs += 6_000;
  return poll(deferralCode, keys, client);
}

const missionCount = () => as.kernel.allMissions().length;

const resolveKey = (kid: string) => (kid === as.kernel.statusSigner().kid ? as.kernel.statusVerificationKey() : undefined);

describe("deferred Mission approval wire path (@spec deferred-approval#deferred-approval, deferred-approval#deferred-sequencing)", () => {
  it("defers a PAR-submitted Mission to a deferral code, creates no Mission while pending, and delivers the Mission-bound token on the resolving poll", async () => {
    const { consent } = useRoot(rootDoc());
    const keys = await newKeys();
    const before = missionCount();
    const fc = await frontChannel();
    // The front channel issues a pending-request code: no approval
    // interaction, no Mission, no provider grant.
    expect(fc.code).toMatch(/^mdac_/);
    expect(fc.state).toBe("st-1185");
    expect(fc.iss).toBe(ISSUER);
    expect(missionCount()).toBe(before);
    const r = await redeem(fc.code as string, keys);
    expect(r.status).toBe(400);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.body).toEqual({
      error: "authorization_pending",
      deferral_code: expect.stringMatching(/^mdfr_/),
      expires_in: LIFETIME_S,
      interval: 5,
    });
    const deferralCode = r.body.deferral_code as string;
    // Before approval only the pending request exists.
    expect(missionCount()).toBe(before);
    expect(as.missionApprovalDeferrals?.state(deferralCode)).toBe("pending");

    const delivered = await poll(deferralCode, keys);
    expect(delivered.status, JSON.stringify(delivered.body)).toBe(200);
    expect(missionCount()).toBe(before + 1);
    const mission = as.kernel.get(delivered.body.mission_id as string) as MissionRecord;
    expect(mission.state).toBe("active");
    expect(delivered.body.mission_expires_at).toBe(mission.expires_at);
    expect(delivered.body.token_type).toBe("DPoP");
    expect(delivered.body.authorization_details).toEqual(as.kernel.effectiveAuthoritySet(mission));
    const claims = decodeJwt(delivered.body.access_token as string) as Record<string, unknown> & {
      mission: { id: string };
      cnf: { jkt: string };
    };
    expect(claims.mission.id).toBe(mission.id);
    expect(claims.cnf.jkt).toBe(keys.jkt);
    expect(claims.sub).toBe(WORKLOAD);
    expect(claims.client_id).toBe(AGENT);

    // The governed_policy record's provenance, every member from retained
    // state and the issuer's own evaluation.
    const approvalEventId = as.missionApprovalDeferrals?.approvalEventId(deferralCode);
    expect(mission.approval_event_id).toBe(approvalEventId);
    expect(mission.subject).toEqual({ iss: ISSUER, sub: WORKLOAD });
    expect(mission.client_id).toBe(AGENT);
    expect(mission.authority_source?.type).toBe("service_owned");
    expect(mission.approval_basis).toEqual({
      type: "governed_policy",
      consent_principal: { iss: ISSUER, sub: "dana" },
      approved_at: consent?.approved_at,
      root_commitment: consent?.root.digest,
      activation: { approval_event_id: approvalEventId, policy: consent?.root },
      activation_actor: { iss: ISSUER, sub: AGENT },
      adjudication: {
        kind: "policy",
        policy: { id: consent?.root.id, version: "1" },
        governance_record: true,
      },
    });
    // The signed record committed with it verifies against the Mission.
    const record = as.kernel.governanceRecords.forMission(mission.id);
    expect(record).toBeDefined();
    expect(() => verifyApprovalGovernanceRecord(record as never, { resolveKey, mission })).not.toThrow();
    expect(record?.approval_policy).toEqual(consent?.root);
    expect(record?.assertions[0]).toMatchObject({
      principal: { iss: ISSUER, sub: "dana" },
      kind: "policy",
      authority: { policy_id: consent?.root.id, version: "1", approved_at: consent?.approved_at },
    });

    // Delivered once.
    clockMs += 6_000;
    const again = await poll(deferralCode, keys);
    expect(again.status).toBe(400);
    expect(again.body.error).toBe("invalid_grant");
  });

  it("bounds the activated Mission by the root's authority ceiling and lifetime, whatever the Intent and proposal ask", async () => {
    useRoot(rootDoc({ lifetime: { max_lifetime_s: 1800 } }));
    const keys = await newKeys();
    // The proposal asks for a write action outside the root's ceiling.
    const deferralCode = await openDeferral(keys, {
      authorizationDetails: [readEntry(["payments:invoice.read", "payments:payment.schedule"])],
    });
    const delivered = await poll(deferralCode, keys);
    expect(delivered.status, JSON.stringify(delivered.body)).toBe(200);
    const mission = as.kernel.get(delivered.body.mission_id as string) as MissionRecord;
    expect(mission.authority_set.flatMap((e) => e.actions)).toEqual(["payments:invoice.read"]);
    expect(Date.parse(mission.expires_at) - Date.parse(mission.created_at)).toBe(1800 * 1000);

    // A proposal with nothing inside the ceiling activates nothing.
    const before = missionCount();
    const outside = await openDeferral(keys, { authorizationDetails: [readEntry(["payments:payment.schedule"])] });
    const refused = await poll(outside, keys);
    expect(refused.body.error).toBe("access_denied");
    expect(missionCount()).toBe(before);
    expect(as.missionApprovalDeferrals?.resolutionReason(outside)).toBe("out_of_root_ceiling");

    // An Intent that asks for less than the root's lifetime gets its own expiry.
    const soon = new Date(clockMs + 900_000).toISOString();
    const short = await openDeferral(keys, { intent: { expires_at: soon } });
    const shortMission = await poll(short, keys);
    expect(shortMission.status, JSON.stringify(shortMission.body)).toBe(200);
    expect((as.kernel.get(shortMission.body.mission_id as string) as MissionRecord).expires_at).toBe(soon);

    // A root ceiling wider than the source's: the source ceiling still binds,
    // and a set beyond it activates nothing.
    useRoot(rootDoc({ authority_ceiling: [readEntry([...READ, "payments:payment.schedule"])] as never }));
    const wide = await openDeferral(keys, {
      authorizationDetails: [readEntry(["payments:invoice.read", "payments:payment.schedule"])],
    });
    const beyondSource = await poll(wide, keys);
    expect(beyondSource.body.error).toBe("access_denied");
    expect(beyondSource.body).not.toHaveProperty("access_token");
    // The source-ceiling gate's refusal.
    expect(as.missionApprovalDeferrals?.resolutionReason(wide)).toBe("access_denied");
    expect(missionCount()).toBe(before + 1);
  });

  it("denies, with no Mission and no token, an approval whose requested expiry passed while it pended", async () => {
    useRoot(rootDoc());
    const keys = await newKeys();
    const before = missionCount();
    const deferralCode = await openDeferral(keys, {
      intent: { expires_at: new Date(clockMs + 120_000).toISOString() },
    });
    clockMs += 180_000;
    const r = await poll(deferralCode, keys);
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("access_denied");
    expect(missionCount()).toBe(before);
    expect(as.missionApprovalDeferrals?.state(deferralCode)).toBe("denied");
  });

  it("delivers the token for the resource the submission selected", async () => {
    useRoot(rootDoc({ authority_ceiling: [readEntry(), ledgerEntry()] as never }));
    const both = {
      intent: { target_resources: [RESOURCE, LEDGER] },
      authorizationDetails: [readEntry(["payments:invoice.read"]), ledgerEntry()],
    };
    const audienceOf = (body: Record<string, unknown>) => decodeJwt(body.access_token as string).aud;
    const keys = await newKeys();

    // The PAR selects the ledger: the delivered token is for the ledger.
    const toLedger = await poll(await openDeferral(keys, { ...both, extra: { resource: LEDGER } }), keys);
    expect(toLedger.status, JSON.stringify(toLedger.body)).toBe(200);
    const resources = (toLedger.body.authorization_details as Array<{ resource: string }>).map((e) => e.resource);
    expect(resources).toEqual(expect.arrayContaining([RESOURCE, LEDGER]));
    expect(audienceOf(toLedger.body)).toBe(LEDGER);

    // Selecting payments, or nothing, gives the payments audience.
    const toPayments = await poll(await openDeferral(keys, { ...both, extra: { resource: RESOURCE } }), keys);
    expect(audienceOf(toPayments.body)).toBe(RESOURCE);
    const unselected = await poll(await openDeferral(keys, both), keys);
    expect(audienceOf(unselected.body)).toBe(
      (unselected.body.authorization_details as Array<{ resource: string }>)[0]?.resource,
    );

    // A synchronous approval of the same submission is audienced the same way.
    const direct = await frontChannel({ ...both, completionMode: null, extra: { resource: LEDGER } });
    const uid = direct.interaction.split("/interaction/")[1] as string;
    let res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { ...trustedApprovalHeaders("dana", {}, WORKLOAD), cookie: direct.cookie, "content-type": "application/json" },
      body: JSON.stringify({ decision: "approve" }),
    });
    let location = res.headers.get("location") ?? "";
    while (location.startsWith(ISSUER)) {
      res = await fetch(location, { redirect: "manual", headers: { cookie: direct.cookie } });
      location = res.headers.get("location") ?? "";
    }
    const issued = await redeem(new URL(location).searchParams.get("code") as string, keys);
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    expect(audienceOf(issued.body)).toBe(LEDGER);
  });

  it("honors a repeated PAR resource and refuses an ambiguous one, never falling back to another audience", async () => {
    useRoot(rootDoc({ authority_ceiling: [readEntry(), ledgerEntry()] as never }));
    const both = {
      intent: { target_resources: [RESOURCE, LEDGER] },
      authorizationDetails: [readEntry(["payments:invoice.read"]), ledgerEntry()],
    };
    const keys = await newKeys();
    // The ledger named twice is one selection: a ledger token, never payments.
    const repeated = await poll(await openDeferral(keys, { ...both, resources: [LEDGER, LEDGER] }), keys);
    expect(repeated.status, JSON.stringify(repeated.body)).toBe(200);
    expect(decodeJwt(repeated.body.access_token as string).aud).toBe(LEDGER);
    // Two distinct resources and no selection at the token endpoint: one
    // deferral delivers one token, so the redemption is refused and opens nothing.
    const ambiguous = await frontChannel({ ...both, resources: [LEDGER, RESOURCE] });
    expect(ambiguous.code).toBeDefined();
    const refused = await redeem(ambiguous.code as string, keys);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("invalid_target");
    expect(refused.body).not.toHaveProperty("deferral_code");
  });

  it("takes the resource selected at the token endpoint and refuses one the pending request cannot honor", async () => {
    useRoot(rootDoc({ authority_ceiling: [readEntry(), ledgerEntry()] as never }));
    const both = {
      intent: { target_resources: [RESOURCE, LEDGER] },
      authorizationDetails: [readEntry(["payments:invoice.read"]), ledgerEntry()],
    };
    const keys = await newKeys();
    const audienceOf = async (deferralCode: string) => {
      const r = await poll(deferralCode, keys);
      expect(r.status, JSON.stringify(r.body)).toBe(200);
      return decodeJwt(r.body.access_token as string).aud;
    };
    const redeemFor = (code: string, resource: string) => redeem(code, keys, { params: { resource } });

    // No resource at PAR, the ledger at redemption: a ledger token.
    const unnamed = await frontChannel(both);
    const toLedger = await redeemFor(unnamed.code as string, LEDGER);
    expect(toLedger.body.error).toBe("authorization_pending");
    expect(await audienceOf(toLedger.body.deferral_code as string)).toBe(LEDGER);

    // Outside the Intent's target resources: refused, consuming nothing; the
    // same code then redeems for a resource the request can grant.
    const outside = await frontChannel(both);
    const refused = await redeemFor(outside.code as string, "http://localhost:4410/api");
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("invalid_target");
    expect(refused.body).not.toHaveProperty("deferral_code");
    const honored = await redeemFor(outside.code as string, RESOURCE);
    expect(await audienceOf(honored.body.deferral_code as string)).toBe(RESOURCE);

    // Not a resource the PAR named: refused.
    const ledgerOnly = await frontChannel({ ...both, resources: [LEDGER] });
    const notNamed = await redeemFor(ledgerOnly.code as string, RESOURCE);
    expect(notNamed.body.error).toBe("invalid_target");
    expect(notNamed.body).not.toHaveProperty("deferral_code");

    // Two named at PAR, one chosen at the token endpoint: that one.
    const twoNamed = await frontChannel({ ...both, resources: [LEDGER, RESOURCE] });
    const chosen = await redeemFor(twoNamed.code as string, RESOURCE);
    expect(await audienceOf(chosen.body.deferral_code as string)).toBe(RESOURCE);
  });

  it("keeps an approval deliverable when saving its token fails, then delivers exactly one token", async () => {
    useRoot(rootDoc());
    const keys = await newKeys();
    const deferralCode = await openDeferral(keys);
    const save = vi
      .spyOn(as.provider.AccessToken.prototype, "save")
      .mockRejectedValueOnce(new Error("token store unavailable"));
    const failed = await poll(deferralCode, keys);
    save.mockRestore();
    expect(failed.status).toBe(500);
    expect(failed.body).not.toHaveProperty("access_token");
    // The decision stands and the approval is still deliverable.
    expect(as.missionApprovalDeferrals?.state(deferralCode)).toBe("approved");
    const delivered = await poll(deferralCode, keys);
    expect(delivered.status, JSON.stringify(delivered.body)).toBe(200);
    expect(typeof delivered.body.access_token).toBe("string");
    // Exactly one token: the next poll is invalid_grant.
    expect((await poll(deferralCode, keys)).body.error).toBe("invalid_grant");

    // Concurrent polls of a deliverable approval still deliver once.
    const raced = await openDeferral(keys);
    expect(await as.missionApprovalDeferrals?.completeByPolicy(raced)).toMatchObject({ outcome: "approved" });
    const results = await Promise.all([poll(raced, keys), poll(raced, keys), poll(raced, keys)]);
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect((await poll(raced, keys)).body.error).toBe("invalid_grant");
  });

  it("yields no token for a Mission revoked between the approval decision and the resolving poll", async () => {
    useRoot(rootDoc());
    const keys = await newKeys();
    const deferralCode = await openDeferral(keys);
    // The issuer completes the approval before the client polls.
    const done = await as.missionApprovalDeferrals?.completeByPolicy(deferralCode);
    if (done?.outcome !== "approved") throw new Error(String(done?.outcome));
    as.kernel.transition(done.mission.id, "revoke");
    const r = await poll(deferralCode, keys);
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("access_denied");
    expect(r.body).not.toHaveProperty("access_token");
  });
});

describe("deferred Mission approval front channel (@spec deferred-approval#front-channel)", () => {
  it("binds the pending-request code to the client, its PKCE challenge, its redirect URI and the substrate's opt-in", async () => {
    useRoot(rootDoc());
    const keys = await newKeys();
    const fc = await frontChannel();
    const code = fc.code as string;
    // Without `deferred` in completion_mode: the substrate's hint rule.
    const noHint = await redeem(code, keys, { params: { completion_mode: "" } });
    expect(noHint.status).toBe(400);
    expect(noHint.body.error).toBe("invalid_request");
    // The code is pending-request state: no redemption of it yields a token.
    expect(noHint.body).not.toHaveProperty("access_token");
    // Wrong PKCE verifier, wrong redirect URI, another client: refused.
    const wrongVerifier = await redeem(code, keys, { params: { code_verifier: "x".repeat(50) } });
    expect(wrongVerifier.body.error).toBe("invalid_grant");
    const wrongRedirect = await redeem(code, keys, { params: { redirect_uri: "http://localhost:9999/other" } });
    expect(wrongRedirect.body.error).toBe("invalid_grant");
    const otherClient = await redeem(code, keys, { client: "ap-agent" });
    expect(otherClient.body.error).toBe("invalid_grant");
    // No DPoP proof: no key to bind the deferral to.
    const noProof = await redeem(code, null);
    expect(noProof.body.error).toBe("invalid_request");
    // None of those opened a pending approval or consumed the code.
    const ok = await redeem(code, keys);
    expect(ok.status).toBe(400);
    expect(ok.body.error).toBe("authorization_pending");
    // The code expires like any authorization code.
    const late = await frontChannel();
    clockMs += 61_000;
    const expired = await redeem(late.code as string, keys);
    expect(expired.body.error).toBe("invalid_grant");
  });

  it("refuses a second redemption of the code and cancels what the first opened, concurrent or later", async () => {
    useRoot(rootDoc());
    const keys = await newKeys();
    const before = missionCount();
    const fc = await frontChannel();
    const first = await redeem(fc.code as string, keys);
    const deferralCode = first.body.deferral_code as string;
    const replay = await redeem(fc.code as string, keys);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");
    expect(as.missionApprovalDeferrals?.state(deferralCode)).toBe("cancelled");
    expect((await poll(deferralCode, keys)).body.error).toBe("access_denied");

    // Two concurrent redemptions open one pending approval at most.
    const raced = await frontChannel();
    const [a, b] = await Promise.all([redeem(raced.code as string, keys), redeem(raced.code as string, keys)]);
    const opened = [a, b].filter((r) => r.body.error === "authorization_pending");
    expect(opened).toHaveLength(1);
    expect([a, b].filter((r) => r.body.error === "invalid_grant")).toHaveLength(1);
    expect(missionCount()).toBe(before);
  });

  it("establishes the Subject on the issuer side, never from client input", async () => {
    useRoot(rootDoc());
    const keys = await newKeys();
    const deferralCode = await openDeferral(keys, { extra: { login_hint: "alice", subject: "alice", sub: "alice" } });
    const r = await poll(deferralCode, keys, AGENT, { subject: "alice" });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect((as.kernel.get(r.body.mission_id as string) as MissionRecord).subject).toEqual({ iss: ISSUER, sub: WORKLOAD });
  });

  it("refuses openid on a deferred request: no End-User authenticates on its front channel", async () => {
    useRoot(rootDoc());
    const withOpenid = await frontChannel({ extra: { scope: "openid" } });
    expect(withOpenid.code).toBeUndefined();
    expect(withOpenid.error).toBe("invalid_scope");
  });
});

describe("deferred Mission approval state, lifetime, cancellation and queue (@spec deferred-approval#state-machine, deferred-approval#pending-staleness, deferred-approval#queue-pressure)", () => {
  it("binds every poll to the client and DPoP key the deferral was opened with, and paces it", async () => {
    useRoot(rootDoc());
    const keys = await newKeys();
    const deferralCode = await openDeferral(keys);
    const before = missionCount();
    // Another key, another client, an unknown code: invalid_grant, and no
    // policy completion runs for any of them.
    expect((await poll(deferralCode, await newKeys())).body.error).toBe("invalid_grant");
    expect((await poll(deferralCode, keys, "ap-agent")).body.error).toBe("invalid_grant");
    expect((await poll(`mdfr_${"A".repeat(24)}`, keys)).body.error).toBe("invalid_grant");
    expect(as.missionApprovalDeferrals?.state(deferralCode)).toBe("pending");
    expect(missionCount()).toBe(before);
    // No proof at all is refused before the store is touched.
    expect((await poll(deferralCode, null)).body.error).toBe("invalid_request");
    expect((await poll(deferralCode, keys)).status).toBe(200);
  });

  it("resolves a pending approval to expired_token once its lifetime passes, with no Mission", async () => {
    useRoot(rootDoc({ rules: { max_entries: 3, require_purpose: true } }), { consent: false });
    const keys = await newKeys();
    const before = missionCount();
    const deferralCode = await openDeferral(keys);
    clockMs += (LIFETIME_S + 1) * 1000;
    const r = await poll(deferralCode, keys);
    expect(r.body.error).toBe("expired_token");
    expect(as.missionApprovalDeferrals?.state(deferralCode)).toBe("expired");
    expect(missionCount()).toBe(before);
  });

  it("cancels at the revocation endpoint for the bound client only, and never delivers a cancelled approval", async () => {
    useRoot(rootDoc());
    const keys = await newKeys();
    const before = missionCount();
    const deferralCode = await openDeferral(keys);
    // Another client's revocation answers 200 and changes nothing.
    expect((await revoke(deferralCode, "ap-agent")).status).toBe(200);
    expect(as.missionApprovalDeferrals?.state(deferralCode)).toBe("pending");
    expect((await revoke(deferralCode)).status).toBe(200);
    expect(as.missionApprovalDeferrals?.state(deferralCode)).toBe("cancelled");
    expect((await poll(deferralCode, keys)).body.error).toBe("access_denied");
    expect(missionCount()).toBe(before);

    // Resolved but not delivered: redeemed and then cancelled.
    const approved = await openDeferral(keys);
    const done = await as.missionApprovalDeferrals?.completeByPolicy(approved);
    expect(done?.outcome).toBe("approved");
    expect((await revoke(approved)).status).toBe(200);
    const r = await poll(approved, keys);
    expect(r.body.error).toBe("access_denied");
    expect(r.body).not.toHaveProperty("access_token");
  });

  it("bounds a client's pending approvals and refuses further submissions until the queue drains", async () => {
    useRoot(rootDoc(), { consent: false });
    const keys = await newKeys();
    const open = [await openDeferral(keys), await openDeferral(keys), await openDeferral(keys)];
    const fc = await frontChannel();
    const refused = await redeem(fc.code as string, keys);
    expect(refused.status).toBe(503);
    expect(refused.body.error).toBe("temporarily_unavailable");
    expect(refused.headers.get("retry-after")).toBe("30");
    // The queue drains when one resolves; the refused code was not consumed.
    expect((await revoke(open[0] as string)).status).toBe(200);
    const admitted = await redeem(fc.code as string, keys);
    expect(admitted.body.error).toBe("authorization_pending");
    // One approval decision resolves exactly one pending approval.
    const states = [...open.slice(1), admitted.body.deferral_code as string].map((c) =>
      as.missionApprovalDeferrals?.state(c),
    );
    expect(states).toEqual(["pending", "pending", "pending"]);
  });
});

describe("Deferred Mission Approval capability (@spec deferred-approval#deferred-approval, deferred-approval#policy-completion)", () => {
  /** A second assembly on its own port, torn down by the caller. */
  async function assembly(port: number, o: Parameters<typeof buildAuthorizationServer>[0]) {
    const built = await buildAuthorizationServer(o);
    return { built, server: built.provider.listen(port) };
  }

  it("is off by default (the hint is ignored, an mdfr_ code is unknown, nothing is advertised), and where on advertises deferral and its cancellation", async () => {
    const issuer = "http://localhost:14186";
    // Without Expansion, whose deferred mode also advertises the deferred
    // token response and its cancellation (#1177).
    const { built, server: off } = await assembly(14186, {
      issuer,
      capabilities: new Set(ALL_PROVIDER_CAPABILITIES.filter((c) => c !== "expansion")),
    });
    try {
      expect(built.missionApprovalDeferrals).toBeUndefined();
      const meta = (await (await fetch(`${issuer}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
      expect(meta).not.toHaveProperty("deferred_token_response_supported");
      expect(meta.revocation_endpoint_token_type_values_supported ?? []).not.toContain(
        "urn:ietf:params:oauth:token-type:deferral-code",
      );
      // On: deferral is advertised, and so is its cancellation at the
      // revocation endpoint (DTR -00 Section 7.4).
      const onMeta = (await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
      expect(onMeta.deferred_token_response_supported).toBe(true);
      expect(onMeta.revocation_endpoint).toBe(`${ISSUER}/token/revocation`);
      expect(onMeta.revocation_endpoint_token_type_values_supported).toContain(
        "urn:ietf:params:oauth:token-type:deferral-code",
      );
      // Pushed with the hint, the request reaches the ordinary approval interaction.
      const key = (await importJWK(built.ledgerReconcilerClientJwk as never, "ES256")) as CryptoKey;
      const assertion = async () => ({
        client_assertion: await new SignJWT({})
          .setProtectedHeader({ alg: "ES256", kid: `${AGENT}-auth` })
          .setIssuer(AGENT)
          .setSubject(AGENT)
          .setAudience(issuer)
          .setIssuedAt()
          .setExpirationTime("2m")
          .setJti(crypto.randomUUID())
          .sign(key),
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      });
      const par = await fetch(`${issuer}/request`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: AGENT,
          response_type: "code",
          redirect_uri: REDIRECT_URI,
          code_challenge: await challenge(),
          code_challenge_method: "S256",
          mission_intent: submission(),
          completion_mode: "deferred",
          ...(await assertion()),
        }).toString(),
      });
      expect(par.status).toBe(201);
      const { request_uri } = (await par.json()) as { request_uri: string };
      const auth = await fetch(`${issuer}/auth?${new URLSearchParams({ client_id: AGENT, request_uri })}`, { redirect: "manual" });
      const cookie = auth.headers
        .getSetCookie()
        .map((l) => l.split(";")[0])
        .join("; ");
      const page = await fetch(new URL(auth.headers.get("location") as string, issuer), { redirect: "manual", headers: { cookie } });
      expect(page.status).toBe(200);
      expect(page.headers.get("content-type")).toMatch(/text\/html/);
      // A Mission approval deferral code is unknown here.
      const keys = await newKeys();
      const proof = await new SignJWT({ htu: `${issuer}/token`, htm: "POST" })
        .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: keys.jwk })
        .setIssuedAt()
        .setJti(crypto.randomUUID())
        .sign(keys.privateKey);
      const polled = await fetch(`${issuer}/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", dpop: proof },
        body: new URLSearchParams({
          grant_type: DEFERRED_GRANT_TYPE,
          deferral_code: `mdfr_${"A".repeat(24)}`,
          ...(await assertion()),
        }).toString(),
      });
      expect(((await polled.json()) as { error: string }).error).toBe("invalid_grant");
    } finally {
      off.close();
    }
    // A second assembly generates its own keys; allow for a loaded runner.
  }, 15_000);

  it("refuses to assemble without token revocation, the deferred substrate's cancellation", async () => {
    await expect(
      buildAuthorizationServer({
        issuer: "http://localhost:14187",
        capabilities: new Set([...ALL_PROVIDER_CAPABILITIES.filter((c) => c !== "token-revocation"), "deferred-approval"]),
      }),
    ).rejects.toThrow(/token-revocation/);
  }, 15_000);
});

describe("governed policy completion over the wire (@spec deferred-approval#policy-completion, approval-governance#governed-policy-activation)", () => {
  /** Open, poll once, and report the outcome with what it committed. */
  async function attempt(o: Parameters<typeof frontChannel>[0] = {}) {
    const keys = await newKeys();
    const before = missionCount();
    const records = as.kernel.governanceRecords.count();
    const deferralCode = await openDeferral(keys, o);
    const r = await poll(deferralCode, keys, o.client ?? AGENT);
    return {
      deferralCode,
      keys,
      status: r.status,
      body: r.body,
      reason: as.missionApprovalDeferrals?.resolutionReason(deferralCode),
      missions: missionCount() - before,
      records: as.kernel.governanceRecords.count() - records,
    };
  }

  const nothing = { status: 400, missions: 0, records: 0 };

  /** What a client might send to steer the approval: a basis, a policy, a consent, a human, an instant. */
  const selectorsNaming = (named: { id: string; consent?: { consent_id: string } | undefined }, basis = "governed_policy") => ({
    approval_basis: basis,
    consent_id: named.consent?.consent_id ?? "gpc_named_by_client",
    governed_policy: named.id,
    policy: named.id,
    consent_principal: "bob",
    approved_at: new Date(clockMs).toISOString(),
  });

  /** Open and poll with `selectors` on the PAR, the redemption and the poll. */
  async function attemptNaming(selectors: Record<string, string>) {
    const keys = await newKeys();
    const before = missionCount();
    const fc = await frontChannel({ extra: selectors });
    const opened = await redeem(fc.code as string, keys, { params: selectors });
    const deferralCode = opened.body.deferral_code as string;
    const r = await poll(deferralCode, keys, AGENT, selectors);
    return {
      status: r.status,
      body: r.body,
      reason: as.missionApprovalDeferrals?.resolutionReason(deferralCode),
      missions: missionCount() - before,
    };
  }

  it("never lets the client select the approval basis, the policy, the consent or the human", async () => {
    // Two roots admit the agent; the issuer selects the latest standing
    // consent. The client names the other one, a basis and a human on the
    // PAR, the redemption and every poll.
    const older = useRoot(rootDoc());
    clockMs += 1_000;
    const newer = addRoot(rootDoc({ rules: { max_entries: 2 } }));
    const chosen = await attemptNaming(selectorsNaming(older, "direct"));
    expect(chosen.status, JSON.stringify(chosen.body)).toBe(200);
    const mission = as.kernel.get(chosen.body.mission_id as string) as MissionRecord;
    if (mission.approval_basis.type !== "governed_policy") throw new Error(mission.approval_basis.type);
    expect(mission.approval_basis.root_commitment).toBe(newer.consent?.root.digest);
    expect(mission.approval_basis.root_commitment).not.toBe(older.consent?.root.digest);
    expect(mission.approval_basis.consent_principal).toEqual({ iss: ISSUER, sub: "dana" });
    expect(mission.approval_basis.approved_at).toBe(newer.consent?.approved_at);

    // A consent whose root does not admit this client never completes its
    // request, though the client names it.
    const foreign = useRoot(
      rootDoc({ admits: { clients: ["ap-agent"], subjects: [WORKLOAD], authority_sources: ["service_owned"] } }),
    );
    expect(await attemptNaming(selectorsNaming(foreign))).toMatchObject({
      status: 400,
      body: { error: "access_denied" },
      missions: 0,
      reason: "no_eligible_policy",
    });
  });

  it("refuses a missing, unauthorized or withdrawn standing consent and creates no Mission or token", async () => {
    // No retained consent: a request naming a consent, a human and an
    // instant establishes none.
    const none = useRoot(rootDoc(), { consent: false });
    expect(await attemptNaming(selectorsNaming(none))).toMatchObject({
      status: 400,
      missions: 0,
      reason: "no_eligible_policy",
    });

    const revoked = useRoot(rootDoc());
    governance.approvers[revoked.id] = ["bob"];
    expect(await attempt()).toMatchObject({ ...nothing, reason: "approver_not_authorized" });

    // Withdrawal stops later activations and leaves an earlier one active.
    const withdrawn = useRoot(rootDoc());
    const earlier = await attempt();
    expect(earlier.status).toBe(200);
    withdrawGovernedPolicyConsent(as.kernel, withdrawn.consent?.consent_id as string);
    const later = await attempt();
    expect(later).toMatchObject({ ...nothing, reason: "no_eligible_policy" });
    expect(later.body).not.toHaveProperty("access_token");
    expect(as.kernel.get(earlier.body.mission_id as string)?.state).toBe("active");
  });

  it("refuses a changed root version or bytes, a changed separate evaluator, and a digest from the wrong domain", async () => {
    const bytes = useRoot(rootDoc());
    governance.roots[bytes.id] = held(rootDoc({ rules: { max_entries: 2 } }));
    expect(await attempt()).toMatchObject({ ...nothing, reason: "no_eligible_policy" });
    const version = useRoot(rootDoc());
    governance.roots[version.id] = held(rootDoc(), "2");
    expect(await attempt()).toMatchObject({ ...nothing, reason: "no_eligible_policy" });

    // A root decided by a separate evaluator, which then changes.
    evaluators["urn:policy:ledger-evaluator"] = held({ max_entries: 3 } as never, "e1");
    const ref = mintActivationPolicyRef(ISSUER, evaluators, "urn:policy:ledger-evaluator", "e1");
    const { rules: _rules, ...withoutRules } = rootDoc();
    useRoot({ ...withoutRules, evaluator: ref } as GovernedPolicyRoot);
    const decided = await attempt();
    expect(decided.status).toBe(200);
    const byEvaluator = as.kernel.get(decided.body.mission_id as string) as MissionRecord;
    expect(byEvaluator.approval_basis.type === "governed_policy" && byEvaluator.approval_basis.activation.policy).toEqual(ref);
    evaluators["urn:policy:ledger-evaluator"] = held({ max_entries: 9 } as never, "e1");
    expect(await attempt()).toMatchObject({ ...nothing, reason: "evaluator_changed" });

    // The evaluator committed under the root's digest domain decides nothing.
    evaluators["urn:policy:ledger-evaluator"] = held({ max_entries: 3 } as never, "e1");
    const wrongDomain = {
      id: "urn:policy:ledger-evaluator",
      version: "e1",
      digest: approvalPolicyDigest(ISSUER, evaluators["urn:policy:ledger-evaluator"] as never),
    };
    expect(wrongDomain.digest).not.toBe(activationPolicyDigest(ISSUER, evaluators["urn:policy:ledger-evaluator"] as never));
    useRoot({ ...withoutRules, evaluator: wrongDomain } as GovernedPolicyRoot);
    expect(await attempt()).toMatchObject({ ...nothing, reason: "evaluator_changed" });
  });

  it("refuses a forged approval instant, an approval older than the recency ceiling, and one in the future", async () => {
    const forged = useRoot(rootDoc());
    as.kernel.db
      .prepare("UPDATE governed_policy_consents SET approved_at = ? WHERE consent_id = ?")
      .run(new Date(clockMs + 1_000).toISOString(), forged.consent?.consent_id);
    expect(await attempt()).toMatchObject({ ...nothing, reason: "consent_unauthenticated" });

    useRoot(rootDoc({ recency: { ceilings: { default: 3600 }, clock_skew_s: 60 } }));
    clockMs += 3_700_000;
    expect(await attempt()).toMatchObject({ ...nothing, reason: "recency_exceeded" });

    useRoot(rootDoc());
    const saved = clockMs;
    clockMs -= 120_000;
    expect(await attempt()).toMatchObject({ ...nothing, reason: "approval_in_future" });
    clockMs = saved;
  });

  it("refuses a client, Subject or authority source the root does not admit", async () => {
    useRoot(rootDoc({ admits: { clients: [AGENT], subjects: ["alice"], authority_sources: ["service_owned"] } }));
    expect(await attempt()).toMatchObject({ ...nothing, reason: "subject_not_admitted" });
    useRoot(rootDoc({ admits: { clients: [AGENT], subjects: [WORKLOAD], authority_sources: ["organizational"] } }));
    expect(await attempt()).toMatchObject({ ...nothing, reason: "source_not_admitted" });
    // The root admits ledger-reconciler only: another client's request finds no policy.
    useRoot(rootDoc());
    const keys = await newKeys();
    const before = missionCount();
    const fc = await frontChannel({ client: "ap-agent" });
    const opened = await redeem(fc.code as string, keys, { client: "ap-agent" });
    const r = await poll(opened.body.deferral_code as string, keys, "ap-agent");
    expect(r.body.error).toBe("access_denied");
    expect(missionCount()).toBe(before);
  });

  it("activates a high-risk class only under the root's committed, class-named exception", async () => {
    // The shipped `service_owned` source carries no high-risk action, so this
    // runs on the shipped `user_delegated` source: `ap-agent` for alice, under
    // a root bob (one of that source's activators) approved.
    const execute = {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    };
    const forAlice = (over: Partial<GovernedPolicyRoot> = {}) =>
      rootDoc({
        admits: { clients: ["ap-agent"], subjects: ["alice"], authority_sources: ["user_delegated"] },
        authority_ceiling: [readEntry(), execute] as never,
        ...over,
      });
    const proposal = [readEntry(["payments:invoice.read"]), execute];
    useRoot(forAlice(), { approver: "bob" });
    expect(await attempt({ client: "ap-agent", authorizationDetails: proposal })).toMatchObject({
      ...nothing,
      reason: "high_risk_without_exception",
    });
    useRoot(
      forAlice({
        recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60, exceptions: { irreversible_action: { max_age_s: 3600 } } },
      }),
      { approver: "bob" },
    );
    const admitted = await attempt({ client: "ap-agent", authorizationDetails: proposal });
    expect(admitted.status, JSON.stringify(admitted.body)).toBe(200);
    expect(admitted.records).toBe(1);
    const mission = as.kernel.get(admitted.body.mission_id as string) as MissionRecord;
    expect(mission.authority_set.flatMap((e) => e.actions)).toContain("payments:payment.execute");
  });

  it("re-verifies submission evidence at activation, refusing evidence that lapsed and recording evidence that verifies", async () => {
    useRoot(rootDoc());
    const keys = await newKeys();
    // Verifies at PAR, lapses before the activation: no Mission, no token.
    const before = missionCount();
    const lapsing = await openDeferral(keys, { evidence: [evidenceUntil(clockMs + 120_000)] });
    clockMs += 180_000;
    const refused = await poll(lapsing, keys);
    expect(refused.status).toBe(400);
    expect(refused.body.error).toBe("access_denied");
    expect(refused.body).not.toHaveProperty("access_token");
    expect(missionCount()).toBe(before);
    expect(as.missionApprovalDeferrals?.resolutionReason(lapsing)).toBe("invalid_mission_intent_evidence");

    // Still valid: verified again at the activation, and the facts that
    // verification produced are recorded on the Mission.
    const lasting = await openDeferral(keys, { evidence: [evidenceUntil(clockMs + 3_600_000)] });
    clockMs += 10_000;
    const activatedAt = new Date(clockMs).toISOString();
    const delivered = await poll(lasting, keys);
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

  it("verifies submission evidence again after a delayed model call, so evidence that expires meanwhile creates no Mission", async () => {
    useRoot(rootDoc());
    const keys = await newKeys();
    const before = missionCount();
    const records = as.kernel.governanceRecords.count();
    // Valid when the poll starts (120 s left); the model takes 180 s.
    const code = await openDeferral(keys, { evidence: [evidenceUntil(clockMs + 120_000)] });
    advise = async () => {
      clockMs += 180_000;
      return [];
    };
    const r = await poll(code, keys);
    advise = async () => [];
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("access_denied");
    expect(r.body).not.toHaveProperty("access_token");
    expect(missionCount()).toBe(before);
    expect(as.kernel.governanceRecords.count()).toBe(records);
    expect(as.missionApprovalDeferrals?.resolutionReason(code)).toBe("invalid_mission_intent_evidence");
  });

  it("never counts a model output bound to another approval event", async () => {
    const model = { id: "urn:model:ledger-review", version: "m1" };
    useRoot(rootDoc({ rules: { max_entries: 3, models: [model] } }));
    let captured: RecordedModelOutput | undefined;
    advise = async (req) => {
      captured = {
        model,
        approval_event_id: req.approval_event_id,
        intent_hash: req.intent_hash,
        authority_hash: req.authority_hash,
        verdict: "no_objection",
      };
      return [captured];
    };
    const first = await attempt();
    expect(first.status).toBe(200);
    // The same output, replayed for the next activation.
    const replayed = captured as RecordedModelOutput;
    advise = async () => [replayed];
    expect(await attempt()).toMatchObject({ ...nothing, reason: "model_input_missing" });
    advise = async () => [];
  });

  it("leaves no Mission and no credential when the record cannot be signed or persisted, and completes on a later poll", async () => {
    useRoot(rootDoc());
    const faults = [
      () =>
        vi.spyOn(as.kernel, "statusSigner").mockImplementation(() => {
          throw new Error("signing key unavailable");
        }),
      () =>
        vi.spyOn(as.kernel.governanceRecords, "retainInCallerTx").mockImplementation(() => {
          throw new Error("record store unavailable");
        }),
    ];
    for (const inject of faults) {
      const keys = await newKeys();
      const before = missionCount();
      const records = as.kernel.governanceRecords.count();
      const deferralCode = await openDeferral(keys);
      const fault = inject();
      const failed = await poll(deferralCode, keys);
      fault.mockRestore();
      expect(failed.status).toBe(500);
      expect(failed.body).not.toHaveProperty("access_token");
      expect(missionCount()).toBe(before);
      expect(as.kernel.governanceRecords.count()).toBe(records);
      expect(as.missionApprovalDeferrals?.state(deferralCode)).toBe("pending");
      // Too soon to retry; then the retry completes under the same event.
      expect((await poll(deferralCode, keys)).body.error).toBe("slow_down");
      const retried = await resolve(deferralCode, keys);
      expect(retried.status).toBe(200);
      expect((as.kernel.get(retried.body.mission_id as string) as MissionRecord).approval_event_id).toBe(
        as.missionApprovalDeferrals?.approvalEventId(deferralCode),
      );
    }
  });

  it("resolves concurrent completions to one Mission, one record and one delivery; distinct activations get distinct approval events", async () => {
    useRoot(rootDoc());
    advise = async () => {
      await new Promise((r) => setTimeout(r, 20));
      return [];
    };
    const keys = await newKeys();
    const before = missionCount();
    const records = as.kernel.governanceRecords.count();
    const deferralCode = await openDeferral(keys);
    const [a, b] = await Promise.all([poll(deferralCode, keys), poll(deferralCode, keys)]);
    advise = async () => [];
    expect([a.status, b.status].sort()).toEqual([200, 400]);
    // The other poll found the delivery in flight (still pending) or done.
    expect(["authorization_pending", "invalid_grant"]).toContain([a, b].find((r) => r.status === 400)?.body.error);
    expect(missionCount()).toBe(before + 1);
    expect(as.kernel.governanceRecords.count()).toBe(records + 1);
    // Single use: nothing more is delivered.
    expect((await resolve(deferralCode, keys)).body.error).toBe("invalid_grant");

    const second = await attempt();
    const firstMission = as.kernel.get(([a, b].find((r) => r.status === 200)?.body.mission_id as string)) as MissionRecord;
    const secondMission = as.kernel.get(second.body.mission_id as string) as MissionRecord;
    expect(secondMission.id).not.toBe(firstMission.id);
    expect(secondMission.approval_event_id).not.toBe(firstMission.approval_event_id);
  });

  it("keeps a direct approval a human decision, alongside the deferred path", async () => {
    useRoot(rootDoc());
    // An ordinary submission on the same assembly is decided by an
    // authenticated human and redeemed through the same authorization_code grant.
    const fc = await frontChannel({ completionMode: null, extra: { resource: RESOURCE } });
    expect(fc.code).toBeUndefined();
    const uid = fc.interaction.split("/interaction/")[1] as string;
    let res = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { ...trustedApprovalHeaders("dana", {}, WORKLOAD), cookie: fc.cookie, "content-type": "application/json" },
      body: JSON.stringify({ decision: "approve" }),
    });
    let location = res.headers.get("location") ?? "";
    while (location.startsWith(ISSUER)) {
      res = await fetch(location, { redirect: "manual", headers: { cookie: fc.cookie } });
      location = res.headers.get("location") ?? "";
    }
    const code = new URL(location).searchParams.get("code") as string;
    const keys = await newKeys();
    const issued = await redeem(code, keys);
    expect(issued.status, JSON.stringify(issued.body)).toBe(200);
    const mission = as.kernel.get(issued.body.mission_id as string) as MissionRecord;
    expect(mission.approval_basis).toMatchObject({ type: "direct", consent_principal: { iss: ISSUER, sub: "dana" } });
    expect(mission.approval_basis).not.toHaveProperty("adjudication");
    expect(as.kernel.governanceRecords.forMission(mission.id)).toBeUndefined();

    // A deferred request is never decided on its interaction: an approval
    // posted there commits nothing, and the interaction still completes
    // into the deferred state.
    const before = missionCount();
    const pending = await frontChannel({ stopAtInteraction: true });
    const deferredUid = pending.interaction.split("/interaction/")[1] as string;
    const decide = await fetch(`${ISSUER}/interaction/${deferredUid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { ...trustedApprovalHeaders("dana", {}, WORKLOAD), cookie: pending.cookie, "content-type": "application/json" },
      body: JSON.stringify({ decision: "approve" }),
    });
    expect(decide.status).toBe(400);
    expect(((await decide.json()) as { error: string }).error).toBe("invalid_request");
    expect(missionCount()).toBe(before);
  });
});
