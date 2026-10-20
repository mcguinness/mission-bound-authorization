import { createHash } from "node:crypto";
import { activationPolicyDigest, approvalPolicyDigest, authorityHash } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  activateGovernedPolicy,
  AGR_JWS_CTY,
  AGR_JWS_TYP,
  type ApprovalGovernanceRecord,
  assertGovernedPolicyRecord,
  type AuthorityEntry,
  type AuthoritySourceCatalog,
  type CapabilitySourceResolver,
  eligibleGovernedPolicyConsents,
  type GovernedActivation,
  type GovernedPolicyApprovalConfig,
  GovernedPolicyConfigError,
  GovernedPolicyError,
  type GovernedPolicyRoot,
  IntentError,
  MissionKernel,
  type MissionRecord,
  mintActivationPolicyRef,
  parseGovernedPolicyRoot,
  previewGovernedActivation,
  recheckGovernedActivation,
  type RecordedModelOutput,
  recordGovernedPolicyConsent,
  type RegisteredActivationPolicy,
  type UnsignedApprovalGovernanceRecord,
  validateMissionIntent,
  verifyApprovalGovernanceRecord,
  withdrawGovernedPolicyConsent,
} from "../src/index.js";

/**
 * @spec approval-governance#governed-policy: the `governed_policy`
 * standing-consent basis. A human approves a bounded root once; the root (or
 * the evaluator it commits) then activates eligible proposals, each with a
 * signed Approval Governance Record committed in the Mission's own creation
 * transaction, after the nine activation checks.
 */

const ISS = "https://as.test";
const T0 = Date.parse("2026-07-01T00:00:00Z");
let clockMs = T0;
const now = () => new Date(clockMs);
const iso = (ms: number) => new Date(ms).toISOString();

let key: CryptoKey;
let seq = 0;

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});

beforeEach(() => {
  clockMs = T0;
});

const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const DEPLOYMENT_CEILING = DERIVATION_POLICY.ceiling as unknown as AuthorityEntry[];
const READS = ["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"];
const ROOT_ID = "urn:policy:reconciler-root";
const EVAL_ID = "urn:policy:reconciler-evaluator";

const readEntry = (actions = READS): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions,
  constraints: { vendors: ["acme"] },
});
const executeEntry = (): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:payment.execute"],
  constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
});

const catalog = (svcCeiling: AuthorityEntry[] = DEPLOYMENT_CEILING): AuthoritySourceCatalog => ({
  humanPrincipals: ["alice", "bob", "dana"],
  entries: [
    { id: "people", type: "user_delegated", clients: ["ap-agent"], activators: ["bob"], ceiling: DEPLOYMENT_CEILING },
    {
      id: "reconciler",
      type: "service_owned",
      clients: ["svc-agent"],
      subjects: ["svc-reconciler"],
      activators: ["dana"],
      principals: ["svc-reconciler"],
      ceiling: svcCeiling,
    },
  ],
});

/** Every payments action the deployment ceiling derives, each classified. */
const CLASSIFICATION: GovernedPolicyRoot["classification"] = {
  standard: [...READS, "payments:payment.schedule", "payments:payment.schedule.cancel"],
  irreversible_action: ["payments:payment.execute"],
  external_commitment: ["payments:remittance.send"],
};

const rootDoc = (over: Partial<GovernedPolicyRoot> = {}): GovernedPolicyRoot => ({
  admits: { clients: ["svc-agent"], subjects: ["svc-reconciler"], authority_sources: ["service_owned"] },
  authority_ceiling: [readEntry()],
  lifetime: { max_lifetime_s: 3600 },
  rules: { max_entries: 3 },
  recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60 },
  classification: CLASSIFICATION,
  ...over,
});

/** A root decided by a separate evaluator instead of its own rules. */
const evaluatorRoot = (evaluator: unknown): GovernedPolicyRoot => {
  const { rules: _rules, ...rest } = rootDoc();
  return { ...rest, evaluator } as GovernedPolicyRoot;
};

const held = (doc: GovernedPolicyRoot, version = "1"): RegisteredActivationPolicy => ({
  version,
  content_type: "application/json",
  content: JSON.stringify(doc),
});

/** A mutable configuration object: a test edits it to stand for a deployment configuration change. */
const config = (doc: GovernedPolicyRoot = rootDoc()) => ({
  roots: { [ROOT_ID]: held(doc) } as Record<string, RegisteredActivationPolicy>,
  approvers: { [ROOT_ID]: ["dana"] } as Record<string, string[]>,
});

const makeKernel = (
  opts: {
    doc?: GovernedPolicyRoot;
    config?: GovernedPolicyApprovalConfig;
    activationPolicies?: Record<string, RegisteredActivationPolicy>;
    catalog?: AuthoritySourceCatalog;
    capabilityResolver?: CapabilitySourceResolver;
  } = {},
) =>
  new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    statusKey: key,
    statusKid: "as-status",
    authoritySourceCatalog: (opts.catalog ?? catalog()) as never,
    governedPolicyApproval: opts.config ?? config(opts.doc),
    ...(opts.activationPolicies ? { activationPolicies: opts.activationPolicies } : {}),
    ...(opts.capabilityResolver ? { capabilityResolver: opts.capabilityResolver } : {}),
    now,
  });

const intent = (over: Record<string, unknown> = {}) =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Reconcile Acme invoices",
      target_resources: [RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
      ...over,
    }),
    { now: now() },
  );

const consent = (kernel: MissionKernel, approver = "dana") =>
  recordGovernedPolicyConsent(kernel, {
    root: { id: ROOT_ID, version: "1" },
    approver: { iss: ISS, sub: approver },
    consentEventId: `gpce-${seq++}`,
  });

const activate = (
  kernel: MissionKernel,
  consentId: string,
  over: Partial<Parameters<typeof activateGovernedPolicy>[1]> = {},
): GovernedActivation =>
  activateGovernedPolicy(kernel, {
    consentId,
    approvalEventId: `ape-${seq++}`,
    intent: intent(),
    clientId: "svc-agent",
    ...over,
  });

/** The refusal code an activation raises, or "activated". */
const outcome = (fn: () => unknown): string => {
  try {
    fn();
  } catch (e) {
    if (e instanceof GovernedPolicyError) return e.code;
    if (e instanceof IntentError) return `intent:${e.code}`;
    throw e;
  }
  return "activated";
};

const activationRows = (kernel: MissionKernel) =>
  (kernel.db.prepare("SELECT COUNT(*) AS n FROM governed_policy_activations").get() as { n: number }).n;

const nothingCommitted = (kernel: MissionKernel) => {
  expect(kernel.allMissions()).toHaveLength(0);
  expect(kernel.governanceRecords.count()).toBe(0);
};

const resolveKey = (kernel: MissionKernel) => (kid: string) => (kid === "as-status" ? kernel.statusVerificationKey() : undefined);

const ROOT_DIGEST = (doc: GovernedPolicyRoot = rootDoc()) => approvalPolicyDigest(ISS, held(doc));

describe("governed policy root and record (@spec approval-governance#governed-policy-root, approval-governance#governed-policy-record)", () => {
  it("records every governed_policy approval_basis member from retained state and the issuer's evaluation", () => {
    const kernel = makeKernel();
    const c = consent(kernel);
    clockMs = T0 + 60_000;
    const { mission } = activate(kernel, c.consent_id, { approvalEventId: "ape-members" });
    const digest = ROOT_DIGEST();
    expect(mission.approval_basis).toEqual({
      type: "governed_policy",
      consent_principal: { iss: ISS, sub: "dana" },
      approved_at: iso(T0),
      root_commitment: digest,
      activation: { approval_event_id: "ape-members", policy: { id: ROOT_ID, version: "1", digest } },
      activation_actor: { iss: ISS, sub: "svc-agent" },
      adjudication: { kind: "policy", policy: { id: ROOT_ID, version: "1" }, governance_record: true },
    });
    expect(mission.approval_event_id).toBe("ape-members");
    expect(mission.approval_basis.activation_actor).not.toEqual(mission.approval_basis.consent_principal);
    // Round-tripped through the store unchanged.
    expect(kernel.get(mission.id)?.approval_basis).toEqual(mission.approval_basis);
    expect(mission.subject).toEqual({ iss: ISS, sub: "svc-reconciler" });
    expect(mission.authority_source).toEqual({ type: "service_owned" });
  });

  it("references the human-approved root as approval_policy, whose retained snapshot commits every root term", () => {
    const kernel = makeKernel();
    const c = consent(kernel);
    const { record } = activate(kernel, c.consent_id);
    expect(record.approval_policy).toEqual({ id: ROOT_ID, version: "1", digest: ROOT_DIGEST() });
    expect(record.approval_policy).toEqual(c.root);
    const retained = kernel.governedPolicyConsents.rootSnapshot(ISS, record.approval_policy);
    expect(retained && approvalPolicyDigest(ISS, retained)).toBe(record.approval_policy.digest);
    const root = parseGovernedPolicyRoot((retained as { content: Uint8Array }).content);
    expect(root.admits).toEqual(rootDoc().admits);
    expect(root.authority_ceiling).toEqual(rootDoc().authority_ceiling);
    expect(root.lifetime).toEqual({ max_lifetime_s: 3600 });
    expect(root.rules).toEqual({ max_entries: 3 });
    expect(root.recency).toEqual(rootDoc().recency);
    // A root missing any committed term is refused at load, never defaulted.
    for (const missing of ["admits", "authority_ceiling", "lifetime", "rules", "recency", "classification"] as const) {
      const { [missing]: _drop, ...rest } = rootDoc();
      expect(() => parseGovernedPolicyRoot(JSON.stringify(rest))).toThrow(GovernedPolicyConfigError);
    }
    // A separate evaluator is committed as an activation policy reference.
    expect(() => parseGovernedPolicyRoot(JSON.stringify(evaluatorRoot({ id: EVAL_ID, version: "e1" })))).toThrow(
      GovernedPolicyConfigError,
    );
  });

  it("decides by the root itself or by the evaluator the root commits, with that policy's typed digest", () => {
    // Root decides: the deciding digest is the root's mission-approval-policy digest.
    const rootKernel = makeKernel();
    const byRoot = activate(rootKernel, consent(rootKernel).consent_id).mission;
    if (byRoot.approval_basis.type !== "governed_policy") throw new Error("basis");
    expect(byRoot.approval_basis.activation.policy).toEqual({ id: ROOT_ID, version: "1", digest: ROOT_DIGEST() });
    expect(rootKernel.verifyActivationPolicyCommitment(byRoot)).toEqual({ status: "not_applicable" });

    // Evaluator decides: the deciding digest is the evaluator's mission-activation-policy digest.
    const registry: Record<string, RegisteredActivationPolicy> = {
      [EVAL_ID]: { version: "e1", content_type: "application/json", content: JSON.stringify({ max_entries: 3 }) },
    };
    const evalRef = mintActivationPolicyRef(ISS, registry, EVAL_ID, "e1");
    const evalKernel = makeKernel({ doc: evaluatorRoot(evalRef), activationPolicies: registry });
    const byEval = activate(evalKernel, consent(evalKernel).consent_id).mission;
    if (byEval.approval_basis.type !== "governed_policy") throw new Error("basis");
    expect(byEval.approval_basis.activation.policy).toEqual(evalRef);
    expect(byEval.approval_basis.activation.policy.digest).toBe(activationPolicyDigest(ISS, registry[EVAL_ID] as never));
    expect(byEval.approval_basis.adjudication.policy).toEqual({ id: EVAL_ID, version: "e1" });
    // The evaluator snapshot is retained with the Mission (#985).
    expect(evalKernel.verifyActivationPolicyCommitment(byEval).status).toBe("verified");

    // A root committing an evaluator this issuer does not hold decides nothing:
    // no other policy stands in for it.
    const orphan = makeKernel({
      doc: evaluatorRoot({ id: "urn:policy:other", version: "e1", digest: evalRef?.digest }),
      activationPolicies: registry,
    });
    expect(outcome(() => activate(orphan, consent(orphan).consent_id))).toBe("evaluator_changed");
    nothingCommitted(orphan);
  });

  it("commits one Mission and one record per approval event; retries and racing activations resolve to them, distinct activations get distinct events", () => {
    const kernel = makeKernel();
    const c = consent(kernel);
    const first = activate(kernel, c.consent_id, { approvalEventId: "ape-once" });
    // A retry of the same event returns the committed Mission and record.
    const retry = activate(kernel, c.consent_id, { approvalEventId: "ape-once" });
    expect(retry.mission.id).toBe(first.mission.id);
    expect(retry.record).toEqual(first.record);
    // A racing activation that passed the committed-activation lookup before
    // the winner committed loses on the event's uniqueness and recovers it.
    const real = kernel.findByApprovalEvent.bind(kernel);
    const spy = vi.spyOn(kernel, "findByApprovalEvent").mockImplementationOnce(() => undefined);
    const raced = activate(kernel, c.consent_id, { approvalEventId: "ape-once" });
    spy.mockRestore();
    expect(raced.mission.id).toBe(first.mission.id);
    expect(real("ape-once")?.id).toBe(first.mission.id);
    expect(kernel.allMissions()).toHaveLength(1);
    expect(kernel.governanceRecords.count()).toBe(1);
    // A distinct activation is a distinct event and a distinct Mission; none
    // carries the human's root-approval event.
    const second = activate(kernel, c.consent_id, { approvalEventId: "ape-twice" });
    expect(second.mission.id).not.toBe(first.mission.id);
    expect(new Set(kernel.allMissions().map((m) => m.approval_event_id))).toEqual(new Set(["ape-once", "ape-twice"]));
    expect(kernel.allMissions().map((m) => m.approval_event_id)).not.toContain(c.consent_event_id);
    expect(kernel.governanceRecords.count()).toBe(2);
  });

  it("never turns an approval event that committed a direct Mission into a governed_policy activation", () => {
    const kernel = makeKernel();
    const c = consent(kernel);
    kernel.approve({
      intent: intent(),
      subject: { iss: ISS, sub: "svc-reconciler" },
      approver: { iss: ISS, sub: "dana" },
      clientId: "svc-agent",
      approvalEventId: "ape-direct",
    });
    expect(outcome(() => activate(kernel, c.consent_id, { approvalEventId: "ape-direct" }))).toBe("approval_event_used");
    // The same holds when the activation reaches the commit before seeing it.
    const spy = vi.spyOn(kernel, "findByApprovalEvent").mockImplementationOnce(() => undefined);
    expect(outcome(() => activate(kernel, c.consent_id, { approvalEventId: "ape-direct" }))).toBe("approval_event_used");
    spy.mockRestore();
    expect(kernel.allMissions().map((m) => m.approval_basis.type)).toEqual(["direct"]);
    expect(kernel.governanceRecords.count()).toBe(0);
  });

  it("refuses a record whose accountable assertion is not the consent principal's policy assertion naming the deciding policy and approved_at", () => {
    const kernel = makeKernel();
    const { mission, record } = activate(kernel, consent(kernel).consent_id);
    if (mission.approval_basis.type !== "governed_policy") throw new Error("basis");
    const basis = mission.approval_basis;
    const { envelope: _e, ...unsigned } = record;
    expect(() => assertGovernedPolicyRecord(unsigned, basis)).not.toThrow();
    const variant = (edit: (a: UnsignedApprovalGovernanceRecord["assertions"][number]) => void) => {
      const copy = JSON.parse(JSON.stringify(unsigned)) as UnsignedApprovalGovernanceRecord;
      edit(copy.assertions[0] as never);
      return copy;
    };
    // A human or service assertion in its place fails the accountable-approver
    // rule itself, even with an authority valid for its own kind that also
    // carries the deciding policy's members.
    for (const bad of [
      variant((a) => Object.assign(a, { kind: "human", authority: { ...a.authority, auth_time: iso(T0) } })),
      variant((a) =>
        Object.assign(a, { kind: "service", authority: { ...a.authority, logic_id: "risk-model", logic_version: "3" } }),
      ),
    ]) {
      expect(() => assertGovernedPolicyRecord(bad, basis)).toThrow(/exactly one approve assertion of kind policy/);
    }
    for (const bad of [
      variant((a) => (a.principal = { iss: ISS, sub: "bob" })),
      variant((a) => (a.authority.policy_id = "urn:policy:other")),
      variant((a) => (a.authority.version = "2")),
      variant((a) => (a.authority.approved_at = iso(T0 + 1000))),
    ]) {
      expect(() => assertGovernedPolicyRecord(bad, basis)).toThrow(/governed_policy record/);
    }
    expect(
      () => assertGovernedPolicyRecord({ ...unsigned, approval_policy: { ...unsigned.approval_policy, digest: activationPolicyDigest(ISS, held(rootDoc())) } }, basis),
    ).toThrow(/approval_policy.digest/);
  });
});

describe("governed policy activation (@spec approval-governance#governed-policy-activation)", () => {
  it("is off unless the deployment configures it: no consent, no activation, no eligible policy", () => {
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: DERIVATION_POLICY as never,
      statusKey: key,
      statusKid: "as-status",
      authoritySourceCatalog: catalog() as never,
      now,
    });
    expect(kernel.governedPolicyApproval()).toBeUndefined();
    expect(outcome(() => consent(kernel))).toBe("not_configured");
    expect(outcome(() => activate(kernel, "gpc_any"))).toBe("not_configured");
    expect(eligibleGovernedPolicyConsents(kernel, "svc-agent")).toEqual([]);
    nothingCommitted(kernel);
  });

  it("activates a bounded Mission and commits a signed Approval Governance Record with it", () => {
    const kernel = makeKernel();
    const c = consent(kernel);
    clockMs = T0 + 60_000;
    const { mission, record } = activate(kernel, c.consent_id);
    expect(mission.state).toBe("active");
    const stored = kernel.governanceRecords.forMission(mission.id) as ApprovalGovernanceRecord;
    expect(stored).toEqual(record);
    // Signed under the issuer's published key with the Approval Governance pair.
    const header = JSON.parse(Buffer.from(stored.envelope.value.split(".")[0] as string, "base64url").toString("utf8"));
    expect(header).toMatchObject({ alg: "ES256", kid: "as-status", typ: AGR_JWS_TYP, cty: AGR_JWS_CTY });
    expect(() =>
      verifyApprovalGovernanceRecord(stored, { resolveKey: resolveKey(kernel), mission: kernel.get(mission.id) as MissionRecord }),
    ).not.toThrow();
    expect(stored.mission).toEqual({ issuer: ISS, intent_hash: mission.intent_hash, authority_hash: mission.authority_hash });
    expect(stored.approval_event_id).toBe(mission.approval_event_id);
    expect(stored.assertions).toEqual([
      {
        assertion_id: "ast_policy",
        principal: { iss: ISS, sub: "dana" },
        kind: "policy",
        decision: "approve",
        decided_at: mission.created_at,
        authority: { policy_id: ROOT_ID, version: "1", approved_at: iso(T0) },
      },
    ]);
    expect(stored.evaluation).toEqual({ decision: "approved", evaluated_at: mission.created_at, contributing: ["ast_policy"] });
  });

  it("refuses a missing or withdrawn standing consent and creates no Mission", () => {
    const kernel = makeKernel();
    expect(outcome(() => activate(kernel, "gpc_never_retained"))).toBe("consent_unavailable");
    nothingCommitted(kernel);
    const c = consent(kernel);
    expect(withdrawGovernedPolicyConsent(kernel, c.consent_id)).toBe(true);
    expect(outcome(() => activate(kernel, c.consent_id))).toBe("consent_withdrawn");
    nothingCommitted(kernel);
  });

  it("stops every later activation once the consent is withdrawn", () => {
    const kernel = makeKernel();
    const c = consent(kernel);
    activate(kernel, c.consent_id);
    withdrawGovernedPolicyConsent(kernel, c.consent_id);
    for (const t of [1_000, 60_000, 3_600_000]) {
      clockMs = T0 + t;
      expect(outcome(() => activate(kernel, c.consent_id))).toBe("consent_withdrawn");
    }
    expect(kernel.allMissions()).toHaveLength(1);
    expect(kernel.governanceRecords.count()).toBe(1);
  });

  it("leaves a Mission activated before withdrawal active under its ordinary lifecycle", () => {
    const kernel = makeKernel();
    const c = consent(kernel);
    const { mission } = activate(kernel, c.consent_id);
    withdrawGovernedPolicyConsent(kernel, c.consent_id);
    clockMs = T0 + 60_000;
    expect(kernel.applyExpiry(kernel.get(mission.id) as MissionRecord).state).toBe("active");
    expect(kernel.gateDerivation(mission.id).state).toBe("active");
    // Its ordinary lifecycle still ends it: expiry, not the withdrawal.
    clockMs = Date.parse(mission.expires_at) + 1;
    expect(kernel.applyExpiry(kernel.get(mission.id) as MissionRecord).state).toBe("terminated");
  });

  it("establishes the standing consent only from retained, authenticated governance state", () => {
    const kernel = makeKernel();
    // The request has nowhere to carry a consent, a consenting human, or an
    // approval instant: an Intent naming one is refused at intake.
    for (const member of ["approved_at", "standing_consent", "consent_principal"]) {
      expect(() => intent({ [member]: "2026-01-01T00:00:00Z" })).toThrow(IntentError);
    }
    // A consent identifier the issuer never retained activates nothing.
    expect(outcome(() => activate(kernel, "gpc_forged"))).toBe("consent_unavailable");
    // The approval instant is the issuer's own clock at the human's approval.
    clockMs = T0 + 5_000;
    const c = consent(kernel);
    expect(c.approved_at).toBe(iso(T0 + 5_000));
    // A retained row altered at rest no longer carries the issuer's
    // attestation, so it establishes nothing.
    kernel.db.prepare("UPDATE governed_policy_consents SET approver_sub = 'bob' WHERE consent_id = ?").run(c.consent_id);
    expect(outcome(() => activate(kernel, c.consent_id))).toBe("consent_unauthenticated");
    nothingCommitted(kernel);
  });

  it("refuses an unauthorized human: no consent from them, and no activation once their authority is revoked", () => {
    const cfg = config();
    const kernel = makeKernel({ config: cfg });
    expect(outcome(() => consent(kernel, "bob"))).toBe("approver_not_authorized");
    const c = consent(kernel);
    cfg.approvers[ROOT_ID] = ["erin"];
    expect(outcome(() => activate(kernel, c.consent_id))).toBe("approver_not_authorized");
    nothingCommitted(kernel);
  });

  it("refuses a changed root version or changed root bytes under the consented version", () => {
    const cfg = config();
    const kernel = makeKernel({ config: cfg });
    const c = consent(kernel);
    const original = cfg.roots[ROOT_ID] as RegisteredActivationPolicy;
    cfg.roots[ROOT_ID] = held(rootDoc({ lifetime: { max_lifetime_s: 7200 } }));
    expect(outcome(() => activate(kernel, c.consent_id))).toBe("root_changed");
    cfg.roots[ROOT_ID] = { ...original, version: "2" };
    expect(outcome(() => activate(kernel, c.consent_id))).toBe("root_changed");
    nothingCommitted(kernel);
    cfg.roots[ROOT_ID] = original;
    expect(outcome(() => activate(kernel, c.consent_id))).toBe("activated");
  });

  it("refuses a retained root whose bytes no longer reproduce the consented digest, and a forged approval instant", () => {
    const tampered = makeKernel();
    const c1 = consent(tampered);
    tampered.db
      .prepare("UPDATE governed_policy_roots SET content = ?")
      .run(Buffer.from(JSON.stringify(rootDoc({ rules: { max_entries: 99 } })), "utf8"));
    expect(outcome(() => activate(tampered, c1.consent_id))).toBe("root_digest_mismatch");
    nothingCommitted(tampered);

    const forged = makeKernel();
    const c2 = consent(forged);
    forged.db
      .prepare("UPDATE governed_policy_consents SET approved_at = ? WHERE consent_id = ?")
      .run(iso(T0 + 86_400_000), c2.consent_id);
    expect(outcome(() => activate(forged, c2.consent_id))).toBe("consent_unauthenticated");
    nothingCommitted(forged);
  });

  it("refuses when the separate evaluator's snapshot differs from the digest the root commits", () => {
    const registry: Record<string, RegisteredActivationPolicy> = {
      [EVAL_ID]: { version: "e1", content_type: "application/json", content: JSON.stringify({ max_entries: 3 }) },
    };
    const evalRef = mintActivationPolicyRef(ISS, registry, EVAL_ID, "e1");
    const kernel = makeKernel({ doc: evaluatorRoot(evalRef), activationPolicies: registry });
    const c = consent(kernel);
    registry[EVAL_ID] = { ...(registry[EVAL_ID] as RegisteredActivationPolicy), content: JSON.stringify({ max_entries: 9 }) };
    expect(outcome(() => activate(kernel, c.consent_id))).toBe("evaluator_changed");
    nothingCommitted(kernel);
  });

  it("keeps the root and evaluator digest domains distinct: neither digest is accepted for the other", () => {
    // An evaluator committed under the root's mission-approval-policy domain.
    const registry: Record<string, RegisteredActivationPolicy> = {
      [EVAL_ID]: { version: "e1", content_type: "application/json", content: JSON.stringify({ max_entries: 3 }) },
    };
    const wrongDomain = { id: EVAL_ID, version: "e1", digest: approvalPolicyDigest(ISS, registry[EVAL_ID] as never) };
    const evalKernel = makeKernel({ doc: evaluatorRoot(wrongDomain), activationPolicies: registry });
    expect(outcome(() => activate(evalKernel, consent(evalKernel).consent_id))).toBe("evaluator_changed");
    nothingCommitted(evalKernel);

    // A root checked against its bytes' mission-activation-policy digest.
    const kernel = makeKernel();
    const c = consent(kernel);
    const actDigest = activationPolicyDigest(ISS, held(rootDoc()));
    expect(actDigest).not.toBe(c.root.digest);
    kernel.db.prepare("UPDATE governed_policy_roots SET digest = ?").run(actDigest);
    kernel.db.prepare("UPDATE governed_policy_consents SET digest = ?").run(actDigest);
    expect(outcome(() => activate(kernel, c.consent_id))).toBe("root_digest_mismatch");
    nothingCommitted(kernel);
  });

  it("refuses a client, Subject, or authority source the root does not admit", () => {
    const kernel = makeKernel();
    expect(outcome(() => activate(kernel, consent(kernel).consent_id, { clientId: "ap-agent" }))).toBe("client_not_admitted");
    nothingCommitted(kernel);

    const otherSubject = makeKernel({
      doc: rootDoc({ admits: { clients: ["svc-agent"], subjects: ["svc-other"], authority_sources: ["service_owned"] } }),
    });
    expect(outcome(() => activate(otherSubject, consent(otherSubject).consent_id))).toBe("subject_not_admitted");
    nothingCommitted(otherSubject);

    const otherSource = makeKernel({
      doc: rootDoc({ admits: { clients: ["svc-agent"], subjects: ["svc-reconciler"], authority_sources: ["user_delegated"] } }),
    });
    expect(outcome(() => activate(otherSource, consent(otherSource).consent_id))).toBe("source_not_admitted");
    nothingCommitted(otherSource);
  });

  it("bounds authority by the source and root ceilings and expiry by the Intent and the root lifetime", () => {
    const kernel = makeKernel();
    const c = consent(kernel);
    // The proposal asks for a write the root ceiling omits: it does not activate.
    const proposal: AuthorityEntry[] = [
      readEntry(["payments:invoice.read"]),
      { ...executeEntry(), actions: ["payments:payment.schedule"], constraints: { max_amount: { amount: "100.00", currency: "USD" }, vendors: ["acme"] } },
    ];
    const { mission } = activate(kernel, c.consent_id, { proposedAuthority: proposal });
    expect(mission.authority_set.flatMap((e) => e.actions)).toEqual(["payments:invoice.read"]);
    // Root lifetime: the Intent asks for months, the root allows an hour.
    expect(Date.parse(mission.expires_at)).toBe(Date.parse(mission.created_at) + 3600 * 1000);
    // The Intent's own ceiling binds when it is the earlier.
    const short = activate(kernel, c.consent_id, { intent: intent({ expires_at: iso(T0 + 600_000) }) }).mission;
    expect(short.expires_at).toBe(iso(T0 + 600_000));
    // A proposal wholly outside the root ceiling activates nothing.
    expect(outcome(() => activate(kernel, c.consent_id, { proposedAuthority: [executeEntry()] }))).toBe("out_of_root_ceiling");
    expect(kernel.allMissions()).toHaveLength(2);
    // The source ceiling refuses rather than narrows.
    const narrowSource = makeKernel({ catalog: catalog([readEntry(["payments:invoice.read"])]) });
    expect(outcome(() => activate(narrowSource, consent(narrowSource).consent_id))).toBe("intent:access_denied");
    nothingCommitted(narrowSource);
  });

  it("refuses an approval older than the strictest applicable ceiling, and one later than the evaluation instant beyond the skew", () => {
    const doc = rootDoc({ recency: { ceilings: { default: 3600 }, clock_skew_s: 60 } });
    const aged = makeKernel({ doc });
    const c1 = consent(aged);
    clockMs = T0 + 3601_000;
    expect(outcome(() => activate(aged, c1.consent_id))).toBe("recency_exceeded");
    nothingCommitted(aged);
    clockMs = T0 + 3600_000;
    expect(outcome(() => activate(aged, c1.consent_id))).toBe("activated");

    const future = makeKernel({ doc });
    clockMs = T0;
    const c2 = consent(future);
    clockMs = T0 - 61_000;
    expect(outcome(() => activate(future, c2.consent_id))).toBe("approval_in_future");
    nothingCommitted(future);
    clockMs = T0 - 59_000;
    expect(outcome(() => activate(future, c2.consent_id))).toBe("activated");
  });

  it("refuses an action the root does not classify instead of treating it as low-risk", () => {
    const ceiling = [readEntry(), executeEntry()];
    const proposal = [{ ...executeEntry(), constraints: { max_amount: { amount: "100.00", currency: "USD" }, vendors: ["acme"] } }];
    // The root classifies the reads but never names payment.execute.
    const partial = makeKernel({
      doc: rootDoc({ authority_ceiling: ceiling, classification: { standard: CLASSIFICATION.standard } }),
    });
    const c = consent(partial);
    expect(outcome(() => activate(partial, c.consent_id, { proposedAuthority: proposal }))).toBe("unclassified_action");
    // Configured mapping derives it too, and is refused the same way.
    expect(outcome(() => activate(partial, c.consent_id))).toBe("unclassified_action");
    nothingCommitted(partial);
    // A root with no classification, or one naming an action both standard
    // and high-risk, is not a root.
    const { classification: _drop, ...unclassified } = rootDoc();
    expect(() => parseGovernedPolicyRoot(JSON.stringify(unclassified))).toThrow(GovernedPolicyConfigError);
    expect(() =>
      parseGovernedPolicyRoot(
        JSON.stringify(
          rootDoc({
            classification: {
              ...CLASSIFICATION,
              standard: [...(CLASSIFICATION.standard ?? []), "payments:payment.execute"],
            },
          }),
        ),
      ),
    ).toThrow(GovernedPolicyConfigError);
    // Classified, the same proposal is held to its high-risk class.
    const classified = makeKernel({ doc: rootDoc({ authority_ceiling: ceiling }) });
    expect(outcome(() => activate(classified, consent(classified).consent_id, { proposedAuthority: proposal }))).toBe(
      "high_risk_without_exception",
    );
  });

  it("activates a high-risk class only under a committed, class-named exception, whose age then binds", () => {
    const ceiling = [readEntry(), executeEntry()];
    const proposal = [{ ...executeEntry(), constraints: { max_amount: { amount: "100.00", currency: "USD" }, vendors: ["acme"] } }];
    const bare = makeKernel({ doc: rootDoc({ authority_ceiling: ceiling }) });
    expect(outcome(() => activate(bare, consent(bare).consent_id, { proposedAuthority: proposal }))).toBe(
      "high_risk_without_exception",
    );
    nothingCommitted(bare);
    // An exception for another class does not admit this one.
    const otherClass = makeKernel({
      doc: rootDoc({
        authority_ceiling: ceiling,
        recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60, exceptions: { external_commitment: { max_age_s: 600 } } },
      }),
    });
    expect(outcome(() => activate(otherClass, consent(otherClass).consent_id, { proposedAuthority: proposal }))).toBe(
      "high_risk_without_exception",
    );
    const excepted = makeKernel({
      doc: rootDoc({
        authority_ceiling: ceiling,
        recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60, exceptions: { irreversible_action: { max_age_s: 600 } } },
      }),
    });
    const c = consent(excepted);
    clockMs = T0 + 599_000;
    expect(outcome(() => activate(excepted, c.consent_id, { proposedAuthority: proposal }))).toBe("activated");
    // The exception's age is the strictest that applies across the Mission.
    clockMs = T0 + 601_000;
    expect(outcome(() => activate(excepted, c.consent_id, { proposedAuthority: proposal }))).toBe("recency_exceeded");
    // A Mission without the class is held only to the default ceiling.
    expect(outcome(() => activate(excepted, c.consent_id, { proposedAuthority: [readEntry()] }))).toBe("activated");
  });

  it("re-checks against the capability resolution retained at activation, while a new activation resolves current trusted state", () => {
    const digestA = `sha-256:${createHash("sha256").update("definition A").digest("base64url")}`;
    const digestB = `sha-256:${createHash("sha256").update("definition B").digest("base64url")}`;
    let digest = digestA;
    const resolver: CapabilitySourceResolver = {
      resolve: (entries) =>
        entries.flatMap((e) =>
          e.actions
            .filter((a) => a === "payments:invoice.read")
            .map((action) => ({
              resource: e.resource,
              action,
              binding: {
                action,
                tool_id: "get_invoice",
                source_uri: "https://catalog.test/payments",
                source_digest: digest,
                operation_ref: "get_invoice",
              },
            })),
        ),
    };
    const kernel = makeKernel({ capabilityResolver: resolver });
    const c = consent(kernel);
    const first = activate(kernel, c.consent_id).mission;
    expect(first.authority_set[0]?.capability_sources?.map((b) => b.source_digest)).toEqual([digestA]);
    expect(recheckGovernedActivation(kernel, first.id).reproduced).toBe(true);
    // The trusted resolver's answer legitimately changes.
    digest = digestB;
    // The historical comparison replays what the activation resolved.
    expect(recheckGovernedActivation(kernel, first.id).reproduced).toBe(true);
    // A new activation resolves against current trusted state.
    const second = activate(kernel, c.consent_id).mission;
    expect(second.authority_set[0]?.capability_sources?.map((b) => b.source_digest)).toEqual([digestB]);
    expect(recheckGovernedActivation(kernel, second.id).reproduced).toBe(true);
    // The retained resolution is what is replayed: without it, nothing reproduces.
    kernel.db
      .prepare("UPDATE governed_policy_activations SET capability_resolutions_json = '[]' WHERE mission_id = ?")
      .run(first.id);
    expect(recheckGovernedActivation(kernel, first.id).reproduced).toBe(false);
  });

  it("re-evaluating the recorded policy version over the recorded inputs reproduces the decision", () => {
    const kernel = makeKernel({ doc: rootDoc({ rules: { max_entries: 3, require_purpose: true } }) });
    const c = consent(kernel);
    expect(outcome(() => activate(kernel, c.consent_id))).toBe("policy_refused");
    const { mission } = activate(kernel, c.consent_id, { intent: intent({ purpose: "Quarter-end close" }) });
    const recheck = recheckGovernedActivation(kernel, mission.id);
    expect(recheck.reproduced).toBe(true);
    expect(recheck.decision).toEqual({ decision: "approve", authority: mission.authority_set });
    // The re-check re-evaluates: altered recorded inputs no longer reproduce it.
    kernel.db
      .prepare("UPDATE governed_policy_activations SET inputs_json = json_set(inputs_json, '$.purpose_present', json('false'))")
      .run();
    expect(recheckGovernedActivation(kernel, mission.id)).toEqual({
      reproduced: false,
      decision: { decision: "deny", reason: "purpose_required" },
    });
  });

  it("lets a recorded model output refuse or narrow an activation, never widen it, and records it as a service assertion", () => {
    const MODEL = { id: "risk-model", version: "3" };
    const kernel = makeKernel({ doc: rootDoc({ rules: { max_entries: 3, models: [MODEL] } }) });
    const c = consent(kernel);
    const run = (approvalEventId: string, out: Partial<RecordedModelOutput> | undefined) => {
      const view = previewGovernedActivation(kernel, { consentId: c.consent_id, approvalEventId, intent: intent(), clientId: "svc-agent" });
      const output: RecordedModelOutput = {
        model: MODEL,
        approval_event_id: view.approval_event_id,
        intent_hash: view.intent_hash,
        authority_hash: view.authority_hash,
        verdict: "no_objection",
        ...out,
      };
      return { view, act: () => activate(kernel, c.consent_id, { approvalEventId, modelOutputs: out ? [output] : [] }) };
    };
    // A consulted model is a required input.
    expect(outcome(run("ape-m0", undefined).act)).toBe("policy_refused");
    // It can refuse.
    expect(outcome(run("ape-m1", { verdict: "refuse" }).act)).toBe("policy_refused");
    expect(kernel.allMissions()).toHaveLength(0);
    // With no objection, the activation is the bounded set the policy alone yields.
    const plain = run("ape-m2", {});
    const unchanged = plain.act().mission;
    expect(unchanged.authority_set).toEqual(plain.view.authority);
    // It can narrow.
    const narrowed = run("ape-m3", { remove: [{ resource: RESOURCE, actions: ["payments:vendor.read"] }], reason: "vendor data" });
    const { mission, record } = narrowed.act();
    expect(mission.authority_set.flatMap((e) => e.actions)).toEqual(["payments:invoice.list", "payments:invoice.read"]);
    // It never widens: a removal naming nothing held, and members that would
    // add authority, leave the no-objection set exactly as it was.
    const elsewhere = DEPLOYMENT_CEILING.find((e) => e.resource !== RESOURCE) as AuthorityEntry;
    const widen = run("ape-m4", {
      remove: [{ resource: "https://elsewhere.test" }],
      ...({ add: [elsewhere], authority: [elsewhere] } as object),
    });
    expect(widen.act().mission.authority_set).toEqual(widen.view.authority);
    // The model is a recorded service input, never the deciding policy.
    if (mission.approval_basis.type !== "governed_policy") throw new Error("basis");
    expect(mission.approval_basis.adjudication.policy).toEqual({ id: ROOT_ID, version: "1" });
    expect(record.assertions.find((a) => a.kind === "service")).toEqual({
      assertion_id: "ast_model_1",
      principal: { iss: ISS, sub: "model:risk-model" },
      kind: "service",
      decision: "approve",
      decided_at: mission.created_at,
      authority: { logic_id: "risk-model", logic_version: "3", model_id: "risk-model", model_version: "3" },
      reason: "narrowed",
    });
    expect(record.evaluation.contributing).toEqual(["ast_policy", "ast_model_1"]);
  });

  it("does not count an assertion captured for another activation's approval event", () => {
    const MODEL = { id: "risk-model", version: "3" };
    const kernel = makeKernel({ doc: rootDoc({ rules: { max_entries: 3, models: [MODEL] } }) });
    const c = consent(kernel);
    const view = previewGovernedActivation(kernel, { consentId: c.consent_id, approvalEventId: "ape-a", intent: intent(), clientId: "svc-agent" });
    const captured: RecordedModelOutput = { model: MODEL, ...view, verdict: "no_objection" };
    const { authority: _drop, ...bindingOnly } = captured as RecordedModelOutput & { authority?: unknown };
    // Replayed into a different activation: not an input there.
    expect(outcome(() => activate(kernel, c.consent_id, { approvalEventId: "ape-b", modelOutputs: [bindingOnly] }))).toBe(
      "policy_refused",
    );
    // Bound to a different Authority Set: not an input either.
    expect(
      outcome(() =>
        activate(kernel, c.consent_id, {
          approvalEventId: "ape-a",
          modelOutputs: [{ ...bindingOnly, authority_hash: authorityHash(ISS, [readEntry(["payments:invoice.read"])] as never) }],
        }),
      ),
    ).toBe("policy_refused");
    nothingCommitted(kernel);
    // Its own activation counts it.
    const { record } = activate(kernel, c.consent_id, { approvalEventId: "ape-a", modelOutputs: [bindingOnly] });
    expect(record.approval_event_id).toBe("ape-a");
    expect(record.assertions.map((a) => a.assertion_id)).toEqual(["ast_policy", "ast_model_1"]);
  });

  it("does not count an assertion bound to another Intent under the same approval event and Authority Set", () => {
    const MODEL = { id: "risk-model", version: "3" };
    const kernel = makeKernel({ doc: rootDoc({ rules: { max_entries: 3, models: [MODEL] } }) });
    const c = consent(kernel);
    const view = previewGovernedActivation(kernel, { consentId: c.consent_id, approvalEventId: "ape-i", intent: intent(), clientId: "svc-agent" });
    const captured: RecordedModelOutput = { model: MODEL, ...view, verdict: "no_objection" };
    const { authority: _drop, ...bindingOnly } = captured as RecordedModelOutput & { authority?: unknown };
    const otherIntent = { ...bindingOnly, intent_hash: "sha-256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU" };
    expect(outcome(() => activate(kernel, c.consent_id, { approvalEventId: "ape-i", modelOutputs: [otherIntent] }))).toBe(
      "policy_refused",
    );
    nothingCommitted(kernel);
    const { record } = activate(kernel, c.consent_id, { approvalEventId: "ape-i", modelOutputs: [bindingOnly] });
    expect(record.assertions.map((a) => a.assertion_id)).toEqual(["ast_policy", "ast_model_1"]);
  });

  it("leaves no Mission, no record, and no retained inputs when signing or persistence fails", () => {
    const signing = makeKernel();
    const c1 = consent(signing);
    const sign = vi.spyOn(signing, "statusSigner").mockImplementation(() => {
      throw new Error("signing key unavailable");
    });
    expect(() => activate(signing, c1.consent_id, { approvalEventId: "ape-sign" })).toThrow(/signing key unavailable/);
    sign.mockRestore();
    expect(signing.findByApprovalEvent("ape-sign")).toBeUndefined();
    nothingCommitted(signing);

    const persisting = makeKernel();
    const c2 = consent(persisting);
    const retain = vi.spyOn(persisting.governanceRecords, "retainInCallerTx").mockImplementation(() => {
      throw new Error("record store unavailable");
    });
    expect(() => activate(persisting, c2.consent_id, { approvalEventId: "ape-persist" })).toThrow(/record store unavailable/);
    retain.mockRestore();
    expect(persisting.findByApprovalEvent("ape-persist")).toBeUndefined();
    expect(activationRows(persisting)).toBe(0);
    nothingCommitted(persisting);
    // The same event commits once the fault clears.
    expect(activate(persisting, c2.consent_id, { approvalEventId: "ape-persist" }).mission.state).toBe("active");
  });

  it("creates no Mission and no record when any activation check fails", () => {
    const kernel = makeKernel({ doc: rootDoc({ rules: { max_entries: 3, refuse_actions: ["payments:vendor.read"] } }) });
    const c = consent(kernel);
    expect(outcome(() => activate(kernel, c.consent_id))).toBe("policy_refused");
    expect(outcome(() => activate(kernel, c.consent_id, { clientId: "ap-agent" }))).toBe("client_not_admitted");
    expect(outcome(() => activate(kernel, "gpc_none"))).toBe("consent_unavailable");
    nothingCommitted(kernel);
    expect(activationRows(kernel)).toBe(0);
  });
});

describe("governed activation retains child-actor provenance (@spec child-delegation#fanout, #1304)", () => {
  it("a root ceiling granting children without allowed_child_actors defers the activated entry's child actor to policy, keeping the deployment's list as a restriction", () => {
    const deferring = { ...readEntry(), delegation: { max_depth: 2, children: { max_children: 2, max_child_depth: 2 } } };
    const kernel = makeKernel({ doc: rootDoc({ authority_ceiling: [deferring as AuthorityEntry] }) });
    const { mission } = activate(kernel, consent(kernel).consent_id);
    const children = mission.authority_set[0]?.delegation?.children as Record<string, unknown>;
    expect(children.allowed_child_actors).toEqual([{ sub_profile: "ai_agent" }]);
    expect(mission.child_actor_provenance).toEqual(["policy"]);
    expect(kernel.get(mission.id)?.child_actor_provenance).toEqual(["policy"]);
  });
});
