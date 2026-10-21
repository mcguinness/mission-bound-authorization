import { approvalPolicyDigest } from "@mission/core";
import { DERIVATION_POLICY, WRITE_ACTIONS } from "@mission/demo-data";
import { withTransaction } from "@mission/store";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  type AgrAssertion,
  type ApprovalGovernanceRecord,
  approvalGovernanceRecordDigest,
  assertDrawdownRecord,
  type AuthorityEntry,
  consentProvenanceOf,
  drawdownGovernanceGate,
  drawdownRecordingRuleFrom,
  drawdownRecordingRuleRef,
  MissionKernel,
  type MissionRecord,
  parseDrawdownRecordingRule,
  recheckApprovalGovernanceRecord,
  type RegisteredActivationPolicy,
  type RegisteredDrawdownRecordingRule,
  signApprovalGovernanceRecord,
  type UnsignedApprovalGovernanceRecord,
  validateMissionIntent,
  verifyApprovalGovernanceRecord,
} from "../src/index.js";
import { createCeilingDrawdownInCallerTx, DrawdownRefusal, type ProgressiveDrawdownOptions } from "../src/kernel/progressive.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

/**
 * @spec approval-governance#accountable-assertion, approval-governance#recency-high-risk,
 * approval-governance#recency-evaluation, approval-governance#atomic-commitment,
 * approval-governance#re-check (#1470 slice 2, D626): the default-off voluntary
 * Approval Governance Record for a policy-adjudicated `ceiling_drawdown`
 * successor, its eligibility gate over the whole successor, and its re-check
 * from retained state.
 */

const ISS = "https://as.test";
const T0 = Date.parse("2026-07-01T00:00:00Z");
const HOUR = 3_600_000;
let clockMs = T0;
let ticking = false;
const now = () => new Date(ticking ? clockMs++ : clockMs);
const iso = (ms: number) => new Date(ms).toISOString();
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const EXP = "2027-01-01T00:00:00Z";
const BOB = { iss: ISS, sub: "bob" };
const ALICE = { iss: ISS, sub: "alice" };
const SOURCE_ROOT = "test-user-delegated";

const POLICY: RegisteredActivationPolicy = {
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ max_added_actions: 1, ceiling_review_cadence_s: 30 * 86400 }),
};
/** The same, retiring the vendor read a successor does not hold from the ceiling it carries (#1468). */
const NARROWING: RegisteredActivationPolicy = {
  version: "1",
  content_type: "application/json",
  content: JSON.stringify({ max_added_actions: 1, ceiling_review_cadence_s: 30 * 86400, retire_undrawn_actions: ["payments:vendor.read"] }),
};
const REGISTRY: Record<string, RegisteredActivationPolicy> = { "drawdown-std": POLICY, "drawdown-narrow": NARROWING };
const CEILING = DERIVATION_POLICY.ceiling.filter((e) => e.resource === RESOURCE) as unknown as AuthorityEntry[];
const CLASSES: ProgressiveDrawdownOptions["actionClasses"] = {
  "payments:invoice.list": "consequential_read",
  "payments:invoice.read": "consequential_read",
  "payments:vendor.read": "consequential_read",
  "payments:payment.schedule": "consequential_write",
  "payments:payment.schedule.cancel": "consequential_write",
  "payments:payment.execute": "irreversible_action",
  "payments:remittance.send": "external_commitment",
};
const OPTIONS: ProgressiveDrawdownOptions = { chainRateBound: { maxDrawdowns: 5, windowSeconds: 3600 }, actionClasses: CLASSES };
const CATALOG = testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["parent-agent"], ["bob"]);

const reads = (actions: string[]): AuthorityEntry[] => [
  { type: "mission_resource_access", resource: RESOURCE, actions, constraints: { vendors: ["acme"] } },
];
const execute = (): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:payment.execute"],
  constraints: { max_amount: { amount: "100.00", currency: "USD" }, vendors: ["acme"] },
});

/** The recording rule, built the way the assembly builds it. */
const ruleFrom = (over: Partial<Parameters<typeof drawdownRecordingRuleFrom>[1]> = {}): RegisteredDrawdownRecordingRule =>
  drawdownRecordingRuleFrom(ISS, {
    recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60 },
    activationPolicies: REGISTRY,
    actionClasses: CLASSES,
    knownSubjects: new Set(["alice", "bob"]),
    approverApprovesFor: new Map([["bob", new Set(["alice"])]]),
    approverRoleSubs: new Set(["bob"]),
    writeActions: WRITE_ACTIONS,
    catalog: CATALOG,
    ...over,
  });
const RULE = ruleFrom();

let key: CryptoKey;
let seq = 0;
beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
});
beforeEach(() => {
  clockMs = T0;
  ticking = false;
});

/** A kernel recording drawdowns under `rule`, or recording none when it is null. */
const makeKernel = (rule: RegisteredDrawdownRecordingRule | null = RULE) =>
  new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: CATALOG,
    statusKey: key,
    statusKid: "as-status",
    now,
    activationPolicies: REGISTRY,
    ...(rule ? { ceilingDrawdownRecording: { rule } } : {}),
  });

const intentFor = (goal: string) =>
  validateMissionIntent(JSON.stringify({ goal, target_resources: [RESOURCE], expires_at: EXP }), { now: now() });

/** A Mission whose Approver consented the payments ceiling and the drawdown policy, at the current instant. */
const predecessorOn = (kernel: MissionKernel, proposal: AuthorityEntry[] = reads(["payments:invoice.read"]), policyId = "drawdown-std") =>
  kernel.approve({
    intent: intentFor("Read Acme invoices"),
    proposedAuthority: proposal,
    subject: ALICE,
    approver: BOB,
    clientId: "parent-agent",
    approvalEventId: `pred-${seq++}`,
    ceiling: { authority_ceiling: CEILING, drawdown_policy: { id: policyId, version: "1" } },
  });

/** The in-ceiling successor the predecessor's own agent requested, committed as the adapter commits it. */
const drawdownOn = (
  kernel: MissionKernel,
  pred: MissionRecord,
  proposal: AuthorityEntry[] = reads(["payments:invoice.read", "payments:invoice.list"]),
  isCrossDomain: (resource: string) => boolean = () => false,
) =>
  withTransaction(kernel.db, () =>
    createCeilingDrawdownInCallerTx(kernel, {
      predecessorId: pred.id,
      intent: intentFor(`Widen ${seq++}`),
      proposedAuthority: proposal,
      activationActor: { iss: ISS, sub: "parent-agent" },
      policy: { ref: pred.drawdown_policy as never, snapshot: REGISTRY[(pred.drawdown_policy as { id: string }).id] as RegisteredActivationPolicy },
      restrictionsAtAdjudication: { containment: 0, discharge: 0 },
      governance: { options: OPTIONS, isCrossDomain },
    }),
  );

/** The fallback reason a drawdown commit refuses with, or "activated". */
const outcome = (fn: () => unknown): string => {
  try {
    fn();
  } catch (e) {
    if (e instanceof DrawdownRefusal) return `${e.code}:${e.reason ?? ""}`;
    throw e;
  }
  return "activated";
};

const resolveKey = (kernel: MissionKernel) => (kid: string) => (kid === "as-status" ? kernel.statusVerificationKey() : undefined);
const recheck = (kernel: MissionKernel, missionId: string) => recheckApprovalGovernanceRecord(kernel, missionId, { resolveKey: resolveKey(kernel) });

/** Re-sign the committed record with `edit` applied: a record that verifies but says something else. */
const resign = (kernel: MissionKernel, missionId: string, edit: (r: UnsignedApprovalGovernanceRecord) => void) => {
  const { envelope: _drop, ...unsigned } = kernel.governanceRecords.forMission(missionId) as ApprovalGovernanceRecord;
  const copy = structuredClone(unsigned);
  edit(copy);
  const signed = signApprovalGovernanceRecord(copy, kernel.statusSigner());
  kernel.db
    .prepare("UPDATE approval_governance_records SET record_json = ?, record_digest = ? WHERE mission_id = ?")
    .run(JSON.stringify(signed), approvalGovernanceRecordDigest(signed), missionId);
};
const tamperInputs = (kernel: MissionKernel, path: string, json: string) =>
  kernel.db.prepare(`UPDATE drawdown_record_inputs SET inputs_json = json_set(inputs_json, '${path}', json(?))`).run(json);

/** A recorded drawdown an hour after the consent. */
const recorded = (rule: RegisteredDrawdownRecordingRule = RULE) => {
  const kernel = makeKernel(rule);
  const pred = predecessorOn(kernel);
  clockMs = T0 + HOUR;
  return { kernel, pred, successor: drawdownOn(kernel, pred) };
};

describe("a recorded ceiling drawdown (@spec approval-governance#accountable-assertion, approval-governance#atomic-commitment)", () => {
  it("records nothing by default: the successor's adjudication carries no governance_record and no record commits", () => {
    const kernel = makeKernel(null);
    const pred = predecessorOn(kernel);
    clockMs = T0 + HOUR;
    const successor = drawdownOn(kernel, pred);
    expect(successor.approval_basis).toMatchObject({ type: "ceiling_drawdown", adjudication: { kind: "policy" } });
    expect((successor.approval_basis as { adjudication: object }).adjudication).not.toHaveProperty("governance_record");
    expect(kernel.governanceRecords.count()).toBe(0);
  });

  it("commits one signed record whose one contributing policy assertion is the drawdown policy's, by the ceiling's consenting human", () => {
    const { kernel, pred, successor } = recorded();
    expect(successor.approval_basis).toMatchObject({
      type: "ceiling_drawdown",
      consent_principal: BOB,
      approved_at: iso(T0),
      adjudication: { kind: "policy", policy: { id: "drawdown-std", version: "1" }, governance_record: true },
    });
    const record = kernel.governanceRecords.forMission(successor.id) as ApprovalGovernanceRecord;
    expect(() => verifyApprovalGovernanceRecord(record, { resolveKey: resolveKey(kernel), mission: successor })).not.toThrow();
    expect(record.approval_policy).toEqual(drawdownRecordingRuleRef(ISS, RULE));
    expect(record.assertions).toEqual([
      {
        assertion_id: "ast_policy",
        principal: BOB,
        kind: "policy",
        decision: "approve",
        // The drawdown decision instant, not the consent instant.
        decided_at: iso(T0 + HOUR),
        authority: { policy_id: "drawdown-std", version: "1", approved_at: iso(T0) },
      },
    ]);
    expect(record.evaluation).toEqual({ decision: "approved", evaluated_at: successor.created_at, contributing: ["ast_policy"] });
    // The ceiling consent the record stands on is the predecessor's.
    expect(pred.ceiling_consented_at).toBe(iso(T0));
  });

  it("retains the recording rule and the inputs the commit-time decision read", () => {
    const { kernel, pred, successor } = recorded();
    const ref = drawdownRecordingRuleRef(ISS, RULE);
    const snapshot = kernel.drawdownApprovalRecords.ruleSnapshot(ISS, ref);
    expect(snapshot && approvalPolicyDigest(ISS, snapshot)).toBe(ref.digest);
    const rule = parseDrawdownRecordingRule((snapshot as { content: Uint8Array }).content);
    expect(rule.deciding_policies).toHaveLength(2);
    expect(rule.deciding_policies).toContainEqual(pred.drawdown_policy);
    expect(rule.consent.activators).toEqual({ [SOURCE_ROOT]: ["bob"] });
    const retained = kernel.drawdownApprovalRecords.inputs(successor.id);
    expect(retained?.inputs).toMatchObject({
      approval_event_id: successor.approval_event_id,
      intent_hash: successor.intent_hash,
      authority: successor.authority_set,
      decided_at: successor.created_at,
      consent: { mission_id: pred.id, principal: BOB, consented_at: iso(T0), subject: ALICE, source_root: SOURCE_ROOT, ceiling: CEILING },
      adjudication: {
        predecessor_id: pred.id,
        requested: successor.authority_set,
        drawdown_policy: pred.drawdown_policy,
        policy_verified: true,
        now: successor.created_at,
        live_children: [],
        chain_drawdowns: [],
        cross_domain: { [RESOURCE]: false },
      },
    });
  });

  it("re-checks the committed record from retained state", () => {
    const { kernel, successor } = recorded();
    expect(recheck(kernel, successor.id)).toEqual({ rechecked: true });
  });

  it("finds the consent through a narrowed chain: the oldest Mission carrying it, whose ceiling reproduces the commitment", () => {
    const kernel = makeKernel();
    const pred = predecessorOn(kernel, undefined, "drawdown-narrow");
    clockMs = T0 + HOUR;
    const first = drawdownOn(kernel, pred);
    // The first successor carries a narrowed ceiling under its own hash; the consent's commitment is unchanged.
    expect(first.ceiling_hash).not.toBe(first.ceiling_consent_hash);
    expect(first.ceiling_consent_hash).toBe(pred.ceiling_hash);
    clockMs = T0 + 2 * HOUR;
    const second = drawdownOn(kernel, first);
    const consent = kernel.drawdownApprovalRecords.inputs(second.id)?.inputs.consent;
    expect(consent?.mission_id).toBe(pred.id);
    expect(consent?.ceiling).toEqual(CEILING);
    expect(recheck(kernel, second.id)).toEqual({ rechecked: true });
  });

  it("reads the inputs at the successor's creation instant, whatever the clock reads after it", () => {
    const kernel = makeKernel();
    const pred = predecessorOn(kernel);
    clockMs = T0 + HOUR;
    ticking = true;
    const successor = drawdownOn(kernel, pred);
    ticking = false;
    expect(kernel.drawdownApprovalRecords.inputs(successor.id)?.inputs.adjudication.now).toBe(successor.created_at);
    expect(recheck(kernel, successor.id)).toEqual({ rechecked: true });
  });

  it("decides again at the commit: a drawdown the commit-time decision sends to a fresh approval refuses with its reason, nothing written", () => {
    const kernel = makeKernel();
    const pred = predecessorOn(kernel);
    clockMs = T0 + HOUR;
    expect(outcome(() => drawdownOn(kernel, pred, undefined, () => true))).toBe("governance_refused:cross_domain");
    expect(kernel.allMissions()).toHaveLength(1);
    expect(kernel.governanceRecords.count()).toBe(0);
  });

  it("retains its evidence only inside the Mission's creation transaction", () => {
    const { kernel, successor } = recorded();
    const inputs = kernel.drawdownApprovalRecords.inputs(successor.id)?.inputs;
    if (!inputs) throw new Error("no inputs");
    expect(() =>
      kernel.drawdownApprovalRecords.retainInCallerTx("mis_x", ISS, drawdownRecordingRuleRef(ISS, RULE), RULE, { ...inputs, approval_event_id: "cdd_x" }),
    ).toThrow(/creation transaction/);
  });
});

describe("the eligibility gate over the whole successor (@spec approval-governance#recency-high-risk, approval-governance#recency-evaluation, D626 Q8)", () => {
  it("sends a successor that keeps approved high-risk authority to a fresh approval, though Progressive would activate it", () => {
    const kernel = makeKernel();
    const pred = predecessorOn(kernel, [execute(), ...reads(["payments:invoice.read"])]);
    clockMs = T0 + HOUR;
    const keepsExecute = [execute(), ...reads(["payments:invoice.read", "payments:invoice.list"])];
    expect(outcome(() => drawdownOn(kernel, pred, keepsExecute))).toBe("governance_refused:governance_high_risk");
    expect(kernel.allMissions()).toHaveLength(1);
    expect(kernel.governanceRecords.count()).toBe(0);
    // With recording off, Progressive alone activates the same drawdown.
    const unrecorded = makeKernel(null);
    clockMs = T0;
    const p2 = predecessorOn(unrecorded, [execute(), ...reads(["payments:invoice.read"])]);
    clockMs = T0 + HOUR;
    expect(outcome(() => drawdownOn(unrecorded, p2, keepsExecute))).toBe("activated");
  });

  it("sends an unclassified action, a stale consent, an ineligible deciding policy or consent to a fresh approval, nothing written", () => {
    const { vendor: _drop, ...partial } = { vendor: 0, ...CLASSES } as Record<string, unknown>;
    delete partial["payments:vendor.read"];
    const cases: Array<[string, RegisteredDrawdownRecordingRule, AuthorityEntry[], AuthorityEntry[] | undefined]> = [
      [
        "governance_unclassified_action",
        ruleFrom({ actionClasses: partial as never }),
        reads(["payments:invoice.read", "payments:vendor.read"]),
        reads(["payments:invoice.read", "payments:vendor.read", "payments:invoice.list"]),
      ],
      ["governance_recency", ruleFrom({ recency: { ceilings: { default: 600 }, clock_skew_s: 60 } }), reads(["payments:invoice.read"]), undefined],
      ["governance_policy_ineligible", ruleFrom({ activationPolicies: {} }), reads(["payments:invoice.read"]), undefined],
      [
        "governance_consent_ineligible",
        ruleFrom({ approverApprovesFor: new Map([["bob", new Set<string>()]]) }),
        reads(["payments:invoice.read"]),
        undefined,
      ],
      [
        "governance_consent_ineligible",
        ruleFrom({ catalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["parent-agent"], ["dana"]) }),
        reads(["payments:invoice.read"]),
        undefined,
      ],
    ];
    for (const [reason, rule, predecessorProposal, successorProposal] of cases) {
      clockMs = T0;
      const kernel = makeKernel(rule);
      const pred = predecessorOn(kernel, predecessorProposal);
      clockMs = T0 + HOUR;
      expect(outcome(() => drawdownOn(kernel, pred, successorProposal)), reason).toBe(`governance_refused:${reason}`);
      expect(kernel.allMissions(), reason).toHaveLength(1);
      expect(kernel.governanceRecords.count(), reason).toBe(0);
      expect((kernel.db.prepare("SELECT COUNT(*) AS n FROM drawdown_record_inputs").get() as { n: number }).n, reason).toBe(0);
    }
  });

  it("verifies the consent's commitment to the exact drawdown policy version, and its principal's eligibility as the consenting approval enforced it", () => {
    const kernel = makeKernel();
    const pred = predecessorOn(kernel);
    const consent = consentProvenanceOf(kernel, pred);
    if (!consent) throw new Error("no consent provenance");
    const rule = parseDrawdownRecordingRule(RULE.content);
    const at = iso(T0 + HOUR);
    const base = { deciding: pred.drawdown_policy, consent, authority: reads(["payments:invoice.read"]), decided_at: at };
    expect(drawdownGovernanceGate(ISS, rule, base)).toEqual({ ok: true });
    // Another version or digest than the consent committed.
    const other = { ...(pred.drawdown_policy as NonNullable<MissionRecord["drawdown_policy"]>), digest: "sha-256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU" };
    expect(drawdownGovernanceGate(ISS, { ...rule, deciding_policies: [other] }, { ...base, deciding: other })).toEqual({ ok: false, reason: "governance_consent_unverified" });
    // A ceiling that does not reproduce the consent's commitment.
    expect(drawdownGovernanceGate(ISS, rule, { ...base, consent: { ...consent, ceiling: reads(["payments:invoice.read"]) } })).toEqual({
      ok: false,
      reason: "governance_consent_unverified",
    });
    // Write separation over the consenting approval's own Authority Set: a self-consent of write-bearing authority.
    const selfWrite = { ...consent, subject: BOB, authority: [{ ...execute(), actions: ["payments:payment.schedule"] }] };
    expect(drawdownGovernanceGate(ISS, rule, { ...base, consent: selfWrite })).toEqual({ ok: false, reason: "governance_consent_ineligible" });
    // A Subject the rule does not name, though the principal may approve for it.
    const forDave = parseDrawdownRecordingRule(ruleFrom({ approverApprovesFor: new Map([["bob", new Set(["alice", "dave"])]]) }).content);
    const dave = { ...consent, subject: { iss: ISS, sub: "dave" } };
    expect(drawdownGovernanceGate(ISS, forDave, { ...base, consent: dave })).toEqual({ ok: false, reason: "governance_consent_ineligible" });
    expect(drawdownGovernanceGate(ISS, { ...forDave, consent: { ...forDave.consent, subjects: [...forDave.consent.subjects, "dave"] } }, { ...base, consent: dave })).toEqual({
      ok: true,
    });
    // The decision instant must not precede the consent beyond the skew, nor be malformed.
    expect(drawdownGovernanceGate(ISS, rule, { ...base, decided_at: iso(T0 - 61_000) })).toEqual({ ok: false, reason: "governance_recency" });
    expect(drawdownGovernanceGate(ISS, rule, { ...base, decided_at: "not-a-date" })).toEqual({ ok: false, reason: "governance_recency" });
    // Parseable, but not an RFC 3339 instant (no offset).
    expect(drawdownGovernanceGate(ISS, rule, { ...base, decided_at: "2026-07-01T01:00:00" })).toEqual({ ok: false, reason: "governance_recency" });
  });
});

describe("the ceiling-drawdown record commit gate (@spec approval-governance#accountable-assertion, approval-governance#assertion-authority)", () => {
  it("admits the one contributing policy assertion, and refuses another principal, policy, instant, or contributing set", () => {
    const { kernel, successor } = recorded();
    const { envelope: _e, ...unsigned } = kernel.governanceRecords.forMission(successor.id) as ApprovalGovernanceRecord;
    const basis = successor.approval_basis as never;
    const ref = drawdownRecordingRuleRef(ISS, RULE);
    const deciding = successor.drawdown_policy as NonNullable<MissionRecord["drawdown_policy"]>;
    expect(assertDrawdownRecord(unsigned, basis, ref, deciding).assertion_id).toBe("ast_policy");
    const a = unsigned.assertions[0] as AgrAssertion;
    const variant = (edit: (r: UnsignedApprovalGovernanceRecord) => void) => {
      const copy = structuredClone(unsigned);
      edit(copy);
      return copy;
    };
    const cases: Array<[UnsignedApprovalGovernanceRecord, RegExp]> = [
      [variant((r) => ((r.assertions[0] as AgrAssertion).principal = ALICE)), /principal is not the ceiling consent principal/],
      [variant((r) => ((r.assertions[0] as AgrAssertion).authority.policy_id = "other")), /does not name the deciding policy/],
      [variant((r) => ((r.assertions[0] as AgrAssertion).authority.approved_at = iso(T0 + 1000))), /approved_at is not the ceiling consent instant/],
      [variant((r) => ((r.assertions[0] as AgrAssertion).decided_at = iso(T0))), /not decided at the evaluation instant/],
      [variant((r) => (r.evaluation.contributing = [])), /contributing|not exactly/],
      [variant((r) => r.assertions.push({ ...a, assertion_id: "ast_second" })), /not exactly one approving policy assertion/],
      [variant((r) => (r.approval_policy = { ...ref, version: "other" })), /not the recording rule/],
    ];
    for (const [record, why] of cases) expect(() => assertDrawdownRecord(record, basis, ref, deciding)).toThrow(why);
  });
});

describe("re-checking a ceiling-drawdown record (@spec approval-governance#re-check)", () => {
  it("step 2: refuses a recording rule snapshot that is missing or does not reproduce approval_policy.digest", () => {
    const altered = recorded();
    altered.kernel.db.prepare("UPDATE drawdown_recording_rules SET content = ?").run(Buffer.from("{}", "utf8"));
    expect(recheck(altered.kernel, altered.successor.id)).toEqual({
      rechecked: false,
      step: 2,
      reason: "the retained recording rule snapshot does not reproduce approval_policy.digest",
    });
    const missing = recorded();
    missing.kernel.db.prepare("DELETE FROM drawdown_recording_rules").run();
    expect(recheck(missing.kernel, missing.successor.id)).toEqual({ rechecked: false, step: 2, reason: "the recording rule snapshot the record names is not retained" });
  });

  it("step 3: refuses a drawdown policy whose retained snapshot does not verify, or another deciding policy than the inputs name", () => {
    const altered = recorded();
    altered.kernel.db.prepare("UPDATE activation_policy_snapshots SET content = ?").run(Buffer.from('{"max_added_actions":9,"ceiling_review_cadence_s":1}', "utf8"));
    expect(recheck(altered.kernel, altered.successor.id)).toEqual({ rechecked: false, step: 3, reason: "the retained drawdown policy snapshot does not verify" });
    const renamed = recorded();
    tamperInputs(renamed.kernel, "$.adjudication.drawdown_policy.version", '"2"');
    expect(recheck(renamed.kernel, renamed.successor.id)).toEqual({
      rechecked: false,
      step: 3,
      reason: "the deciding policy is not the one the inputs, the assertion and the basis name",
    });
    // An assertion naming another version than the inputs and the basis do.
    const named = recorded();
    resign(named.kernel, named.successor.id, (r) => {
      (r.assertions[0] as AgrAssertion).authority.version = "2";
    });
    expect(recheck(named.kernel, named.successor.id)).toEqual({
      rechecked: false,
      step: 3,
      reason: "the deciding policy is not the one the inputs, the assertion and the basis name",
    });
    const rules = recorded();
    tamperInputs(rules.kernel, "$.adjudication.rules.max_added_actions", "5");
    expect(recheck(rules.kernel, rules.successor.id)).toEqual({
      rechecked: false,
      step: 3,
      reason: "the retained drawdown policy does not parse to the rules the inputs record",
    });
  });

  it("step 4: refuses missing inputs, and inputs not bound to the event, Intent, Authority Set, predecessor, consent, Subject, source or instant", () => {
    const missing = recorded();
    missing.kernel.db.prepare("DELETE FROM drawdown_record_inputs").run();
    expect(recheck(missing.kernel, missing.successor.id)).toEqual({ rechecked: false, step: 4, reason: "no recorded inputs to replay" });
    const BOUND = "the recorded inputs are not bound to this approval event, Intent and Authority Set";
    const CONSENT = "the recorded inputs do not carry this Mission's ceiling consent, Subject and authority source";
    const PROVENANCE = "the recorded consent provenance is not the consenting Mission's retained record";
    const INSTANT = "the recorded inputs were not read at the evaluation instant";
    const other = JSON.stringify(reads(["payments:invoice.read"]));
    const tampers: Array<[Array<[string, string]>, string]> = [
      [[["$.approval_event_id", '"cdd_other"']], BOUND],
      [[["$.intent_hash", '"sha-256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"']], BOUND],
      [[["$.adjudication.requested", other]], BOUND],
      // Another set recorded both as the committed and the requested one.
      [[["$.authority", other], ["$.adjudication.requested", other]], BOUND],
      [[["$.adjudication.predecessor_id", '"mis_other"']], "the recorded inputs name another predecessor"],
      [[["$.consent.principal.sub", '"dana"']], CONSENT],
      [[["$.consent.consented_at", JSON.stringify(iso(T0 + 1000))]], CONSENT],
      [[["$.consent.consent_hash", '"sha-256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"']], CONSENT],
      [[["$.adjudication.ceiling_consented_at", JSON.stringify(iso(T0 + 1000))]], CONSENT],
      [[["$.consent.subject.sub", '"bob"']], CONSENT],
      [[["$.consent.source_root", '"another-source"']], CONSENT],
      [[["$.consent.mission_id", '"mis_other"']], PROVENANCE],
      [[["$.consent.ceiling", other]], PROVENANCE],
      [[["$.consent.authority", JSON.stringify([{ ...execute(), actions: ["payments:payment.schedule"] }])]], PROVENANCE],
      [[["$.consent.drawdown_policy.version", '"2"']], PROVENANCE],
      [[["$.decided_at", JSON.stringify(iso(T0 + 2 * HOUR))]], INSTANT],
      [[["$.adjudication.now", JSON.stringify(iso(T0 + 2 * HOUR))]], INSTANT],
    ];
    for (const [paths, reason] of tampers) {
      const r = recorded();
      for (const [path, value] of paths) tamperInputs(r.kernel, path, value);
      expect(recheck(r.kernel, r.successor.id), paths[0]?.[0]).toEqual({ rechecked: false, step: 4, reason });
    }
    // The inputs table's own event column.
    const column = recorded();
    column.kernel.db.prepare("UPDATE drawdown_record_inputs SET approval_event_id = 'cdd_other'").run();
    expect(recheck(column.kernel, column.successor.id)).toEqual({ rechecked: false, step: 4, reason: BOUND });
    // A twin Mission consented the same ceiling at the same instant, but is no ancestor of this successor.
    const kernel = makeKernel();
    const pred = predecessorOn(kernel);
    const twin = predecessorOn(kernel);
    clockMs = T0 + HOUR;
    const successor = drawdownOn(kernel, pred);
    expect(consentProvenanceOf(kernel, twin)?.consent_hash).toBe(consentProvenanceOf(kernel, pred)?.consent_hash);
    tamperInputs(kernel, "$.consent.mission_id", JSON.stringify(twin.id));
    expect(recheck(kernel, successor.id)).toEqual({ rechecked: false, step: 4, reason: PROVENANCE });
  });

  it("step 5: refuses a decision that replays to a fallback, a malformed evaluation instant, and a record failing the commit gate", () => {
    const children = recorded();
    tamperInputs(children.kernel, "$.adjudication.live_children", '["mis_child"]');
    expect(recheck(children.kernel, children.successor.id)).toEqual({
      rechecked: false,
      step: 5,
      reason: "the drawdown decision does not replay to a policy activation: live_children",
    });
    const restricted = recorded();
    tamperInputs(restricted.kernel, "$.adjudication.restrictions", JSON.stringify([{ resource: RESOURCE, actions: ["payments:invoice.list"] }]));
    expect(recheck(restricted.kernel, restricted.successor.id)).toMatchObject({ rechecked: false, step: 5, reason: expect.stringMatching(/restricted_overlap$/) });
    const rate = recorded();
    tamperInputs(rate.kernel, "$.adjudication.chain_drawdowns", JSON.stringify(Array.from({ length: 5 }, () => iso(T0 + HOUR - 1000))));
    expect(recheck(rate.kernel, rate.successor.id)).toMatchObject({ rechecked: false, step: 5, reason: expect.stringMatching(/chain_rate_bound$/) });
    const classes = recorded();
    tamperInputs(classes.kernel, "$.adjudication.action_classes", JSON.stringify({ ...CLASSES, "payments:invoice.list": "irreversible_action" }));
    expect(recheck(classes.kernel, classes.successor.id)).toMatchObject({ rechecked: false, step: 5, reason: expect.stringMatching(/fresh_approval_class$/) });
    const cross = recorded();
    tamperInputs(cross.kernel, "$.adjudication.cross_domain", JSON.stringify({ [RESOURCE]: true }));
    expect(recheck(cross.kernel, cross.successor.id)).toMatchObject({ rechecked: false, step: 5, reason: expect.stringMatching(/cross_domain$/) });
    const malformed = recorded();
    resign(malformed.kernel, malformed.successor.id, (r) => {
      r.evaluation.evaluated_at = "not-a-date";
    });
    expect(recheck(malformed.kernel, malformed.successor.id)).toEqual({ rechecked: false, step: 5, reason: "evaluation.evaluated_at is not an RFC 3339 timestamp" });
    const gate = recorded();
    resign(gate.kernel, gate.successor.id, (r) => {
      (r.assertions[0] as AgrAssertion).principal = ALICE;
    });
    expect(recheck(gate.kernel, gate.successor.id)).toMatchObject({ rechecked: false, step: 5, reason: expect.stringMatching(/ceiling consent principal/) });
  });

  it("step 6: replays the eligibility gate and recency at the evaluation instant", () => {
    const rule = ruleFrom({ recency: { ceilings: { default: 2 * 3600 }, clock_skew_s: 60 } });
    const stale = recorded(rule);
    expect(recheck(stale.kernel, stale.successor.id)).toEqual({ rechecked: true });
    // The same record re-evaluated later than the rule's ceiling admits.
    const later = iso(T0 + 3 * HOUR);
    resign(stale.kernel, stale.successor.id, (r) => {
      r.evaluation.evaluated_at = later;
      (r.assertions[0] as AgrAssertion).decided_at = later;
    });
    tamperInputs(stale.kernel, "$.decided_at", JSON.stringify(later));
    tamperInputs(stale.kernel, "$.adjudication.now", JSON.stringify(later));
    expect(recheck(stale.kernel, stale.successor.id)).toEqual({
      rechecked: false,
      step: 6,
      reason: "the eligibility gate does not replay: governance_recency",
    });
  });
});
