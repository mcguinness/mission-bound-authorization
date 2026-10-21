/**
 * @spec approval-governance#accountable-assertion, approval-governance#recency-high-risk,
 * approval-governance#recency-evaluation, approval-governance#atomic-commitment,
 * approval-governance#re-check (#1470 slice 2, D626): a voluntary Approval
 * Governance Record for a policy-adjudicated `ceiling_drawdown` successor,
 * default off.
 *
 * The basis stands in for the accountable assertion: the ceiling consent's
 * authenticated principal, commitment and instant. The record carries one
 * contributing `policy` assertion of the drawdown policy that decided, by the
 * human who consented the ceiling (and with it that policy version), with the
 * consent instant as `approved_at` and the drawdown decision instant as
 * `decided_at`. Its `approval_policy` is a recording rule: the recency
 * declarations, the eligible deciding policies, the eligibility that verifies
 * the ceiling consent, and the classification the eligibility gate reads.
 *
 * The gate sees the whole successor: an unclassified action, or any of the
 * high-risk conditions, with no exception in this rule, sends the drawdown to
 * a fresh human approval before activation, as does a stale or unverifiable
 * consent. The reference's closed Intent admits no consumption bound, so the
 * fourth condition cannot arise here. The inputs the commit-time decision
 * read are retained with the Mission and the record, and a re-check replays
 * the drawdown decision, the gate and recency from them alone.
 */
import { createHash } from "node:crypto";
import {
  type ActivationPolicyRef,
  activationPolicyDigest,
  approvalPolicyDigest,
  authorityHash,
  canonicalize,
  isRfc3339Instant,
  type JsonValue,
} from "@mission/core";
import type { Database } from "@mission/store";
import {
  type AgrAssertion,
  type ApprovalGovernanceRecord,
  ApprovalGovernanceError,
  assertAccountableApprover,
  assertAssertionAuthority,
  assertContributing,
  type UnsignedApprovalGovernanceRecord,
} from "./approval-governance.js";
import type { MissionKernel } from "./kernel.js";
import {
  ceilingConsentHash,
  ceilingConsentPrincipal,
  ceilingHash,
  decideDrawdown,
  type DrawdownAdjudicationInputs,
  type DrawdownGovernanceReason,
  drawdownRulesOf,
  isRuntimeActionClass,
  type RuntimeActionClass,
} from "./progressive.js";
import type { ApprovalBasisCeilingDrawdown, AuthorityEntry, MissionRecord } from "./types.js";

/** The default identifier of the ceiling-drawdown recording rule. */
export const DRAWDOWN_RECORDING_RULE_ID = "urn:mission:ceiling-drawdown-recording-rule";

/** The high-risk conditions an action class can carry (the fourth, a consumption bound, has no Intent member here). */
const HIGH_RISK_CLASSES: ReadonlySet<RuntimeActionClass> = new Set<RuntimeActionClass>([
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
]);

/** The recording rule a ceiling-drawdown record names as its `approval_policy`. */
export interface DrawdownRecordingRule {
  /** @spec approval-governance#recency-declarations: the recency ceiling and clock-skew allowance; no class-named exception. */
  recency: { ceilings: { default: number }; clock_skew_s: number };
  /** The drawdown policy versions eligible to decide. */
  deciding_policies: ActivationPolicyRef[];
  /** The eligibility that verifies the ceiling consent, as the consenting approval enforced it. */
  consent: {
    subjects: string[];
    approvers: Record<string, { approves_for: string[]; write: boolean }>;
    write_actions: string[];
    activators: Record<string, string[]>;
  };
  /** Each action's class under the deployment's classification. */
  classification: Record<string, RuntimeActionClass>;
}

/** A registered rule version. */
export interface RegisteredDrawdownRecordingRule {
  id: string;
  version: string;
  content_type: "application/json";
  content: string;
}

/** The ceiling consent a drawdown stands on, as retained state shows it. */
export interface DrawdownConsentProvenance {
  /** The Mission at whose approval the ceiling was consented. */
  mission_id: string;
  principal: { iss: string; sub: string };
  consented_at: string;
  consent_hash: string;
  /** The ceiling as consented, which the consent hash commits. */
  ceiling: AuthorityEntry[];
  drawdown_policy?: ActivationPolicyRef;
  subject: { iss: string; sub: string };
  source_root: string;
  /** The consenting Mission's Authority Set, over which its write separation ran. */
  authority: AuthorityEntry[];
}

/** The inputs a recorded drawdown's commit-time decision read. */
export interface DrawdownRecordInputs {
  approval_event_id: string;
  intent_hash: string;
  /** The successor's committed Authority Set. */
  authority: AuthorityEntry[];
  adjudication: DrawdownAdjudicationInputs;
  consent: DrawdownConsentProvenance;
  /** The drawdown decision instant: the successor's creation instant. */
  decided_at: string;
}

/** A rule configuration fault: refused at kernel construction. */
export class DrawdownRecordingRuleError extends Error {}

const sortedRecord = <T>(entries: Array<[string, T]>): Record<string, T> =>
  Object.fromEntries(entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));

/**
 * Build the rule from the configuration the deployment enforces: its recency
 * declaration, the registered activation policies that parse as drawdown
 * rules, the approval surface's eligibility, the catalog's activators and the
 * Progressive action classification.
 */
export function drawdownRecordingRuleFrom(
  issuer: string,
  config: {
    recency: DrawdownRecordingRule["recency"];
    activationPolicies: Readonly<Record<string, { version: string; content_type: string; content: string }>>;
    actionClasses: Readonly<Record<string, RuntimeActionClass>>;
    knownSubjects: ReadonlySet<string>;
    approverApprovesFor: ReadonlyMap<string, ReadonlySet<string>>;
    approverRoleSubs: ReadonlySet<string>;
    writeActions: ReadonlySet<string>;
    catalog: { entries: ReadonlyArray<{ id: string; activators: readonly string[] }> };
  },
  id: string = DRAWDOWN_RECORDING_RULE_ID,
): RegisteredDrawdownRecordingRule {
  const deciding: ActivationPolicyRef[] = [];
  for (const [pid, held] of Object.entries(config.activationPolicies).sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (!drawdownRulesOf(held as never)) continue;
    deciding.push({ id: pid, version: held.version, digest: activationDigest(issuer, held) });
  }
  const approvers: DrawdownRecordingRule["consent"]["approvers"] = {};
  for (const sub of [...new Set([...config.approverApprovesFor.keys(), ...config.approverRoleSubs])].sort()) {
    approvers[sub] = { approves_for: [...(config.approverApprovesFor.get(sub) ?? [])].sort(), write: config.approverRoleSubs.has(sub) };
  }
  const rule: DrawdownRecordingRule = {
    recency: config.recency,
    deciding_policies: deciding,
    consent: {
      subjects: [...config.knownSubjects].sort(),
      approvers,
      write_actions: [...config.writeActions].sort(),
      activators: sortedRecord(config.catalog.entries.map((e) => [e.id, [...e.activators].sort()])),
    },
    classification: sortedRecord(Object.entries(config.actionClasses)),
  };
  const content = canonicalize(rule as unknown as JsonValue);
  const version = createHash("sha256").update(content, "utf8").digest("base64url").slice(0, 16);
  return { id, version, content_type: "application/json", content };
}

/** The activation-policy digest of a held policy, the domain a ceiling commits. */
function activationDigest(issuer: string, held: { content_type: string; content: string }): string {
  return activationPolicyDigest(issuer, held);
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");
const exactly = (o: Record<string, unknown>, keys: string[]): boolean =>
  Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));
const isNonNegativeInteger = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const isRef = (v: unknown): v is ActivationPolicyRef =>
  isObject(v) && exactly(v, ["id", "version", "digest"]) && typeof v.id === "string" && typeof v.version === "string" && typeof v.digest === "string";

/** Parse a rule snapshot strictly; its bytes are evaluated as they are. */
export function parseDrawdownRecordingRule(content: string | Uint8Array): DrawdownRecordingRule {
  const fail = (why: string): never => {
    throw new DrawdownRecordingRuleError(`ceiling-drawdown recording rule: ${why}`);
  };
  let raw: unknown;
  try {
    raw = JSON.parse(typeof content === "string" ? content : Buffer.from(content).toString("utf8"));
  } catch {
    return fail("not JSON");
  }
  if (!isObject(raw) || !exactly(raw, ["recency", "deciding_policies", "consent", "classification"])) {
    fail("members are not recency, deciding_policies, consent, classification");
  }
  const r = raw as Record<string, unknown>;
  const recency = r.recency;
  if (!isObject(recency) || !exactly(recency, ["ceilings", "clock_skew_s"]) || !isNonNegativeInteger(recency.clock_skew_s)) {
    fail("recency is not {ceilings, clock_skew_s}");
  }
  const ceilings = (recency as Record<string, unknown>).ceilings;
  if (!isObject(ceilings) || !exactly(ceilings, ["default"]) || !Number.isSafeInteger(ceilings.default) || (ceilings.default as number) <= 0) {
    fail("recency.ceilings is not {default} with a positive integer ceiling");
  }
  if (!Array.isArray(r.deciding_policies) || !r.deciding_policies.every(isRef)) fail("deciding_policies are not policy references");
  const consent = r.consent;
  if (!isObject(consent) || !exactly(consent, ["subjects", "approvers", "write_actions", "activators"])) fail("consent members are wrong");
  const c = consent as Record<string, unknown>;
  if (!isStringArray(c.subjects) || !isStringArray(c.write_actions)) fail("consent subjects and write_actions are string arrays");
  if (!isObject(c.approvers)) fail("consent approvers is an object");
  for (const [sub, a] of Object.entries(c.approvers as Record<string, unknown>)) {
    if (!isObject(a) || !exactly(a, ["approves_for", "write"]) || !isStringArray(a.approves_for) || typeof a.write !== "boolean") {
      fail(`consent approver ${sub} is not {approves_for, write}`);
    }
  }
  if (!isObject(c.activators) || !Object.values(c.activators).every(isStringArray)) fail("consent activators map each source to a string array");
  if (!isObject(r.classification) || !Object.values(r.classification).every(isRuntimeActionClass)) {
    fail("classification maps each action to a runtime action class");
  }
  return raw as unknown as DrawdownRecordingRule;
}

/** The `approval_policy` reference of a registered rule version. */
export function drawdownRecordingRuleRef(issuer: string, rule: RegisteredDrawdownRecordingRule): ActivationPolicyRef {
  return { id: rule.id, version: rule.version, digest: approvalPolicyDigest(issuer, rule) };
}

const sameRef = (a: ActivationPolicyRef | undefined, b: ActivationPolicyRef | undefined): boolean =>
  !!a && !!b && a.id === b.id && a.version === b.version && a.digest === b.digest;

/**
 * The ceiling consent a drawdown of `predecessor` stands on: the oldest
 * Mission of the chain carrying this consent's commitment and instant, at
 * whose approval the ceiling was consented. Undefined when the chain does not
 * show it.
 */
export function consentProvenanceOf(kernel: MissionKernel, predecessor: MissionRecord): DrawdownConsentProvenance | undefined {
  const hash = ceilingConsentHash(predecessor);
  const at = predecessor.ceiling_consented_at;
  if (!hash || !at) return undefined;
  let consenting: MissionRecord | undefined;
  const seen = new Set<string>();
  for (let m: MissionRecord | undefined = predecessor; m && !seen.has(m.id); m = m.predecessor ? kernel.get(m.predecessor) : undefined) {
    seen.add(m.id);
    if (ceilingConsentHash(m) === hash && m.ceiling_consented_at === at) consenting = m;
  }
  const binding = consenting ? kernel.sourceBindings.get(consenting.id) : undefined;
  if (!consenting?.authority_ceiling || !binding) return undefined;
  return {
    mission_id: consenting.id,
    principal: ceilingConsentPrincipal(predecessor),
    consented_at: at,
    consent_hash: hash,
    ceiling: consenting.authority_ceiling,
    ...(consenting.drawdown_policy ? { drawdown_policy: consenting.drawdown_policy } : {}),
    subject: consenting.subject,
    source_root: binding.rootId,
    authority: consenting.authority_set,
  };
}

/**
 * @spec approval-governance#assertion-validation, approval-governance#recency-high-risk,
 * approval-governance#recency-evaluation: the eligibility gate a recorded
 * drawdown passes before it activates: the deciding policy is one the rule
 * admits and the one the ceiling consent committed; the consent reproduces its
 * commitment and its principal was eligible as the consenting approval
 * enforced it; every action of the whole successor is classified and none is
 * high-risk (no exception is declared); and the consent is within the
 * recency ceiling at the decision instant, in order within the skew.
 */
export function drawdownGovernanceGate(
  issuer: string,
  rule: DrawdownRecordingRule,
  facts: {
    deciding?: ActivationPolicyRef;
    consent: DrawdownConsentProvenance;
    authority: readonly AuthorityEntry[];
    decided_at: string;
  },
): { ok: true } | { ok: false; reason: DrawdownGovernanceReason } {
  const no = (reason: DrawdownGovernanceReason) => ({ ok: false as const, reason });
  const { consent } = facts;
  if (!facts.deciding || !rule.deciding_policies.some((p) => sameRef(p, facts.deciding))) return no("governance_policy_ineligible");
  if (!sameRef(consent.drawdown_policy, facts.deciding) || ceilingHash(issuer, consent.ceiling, consent.drawdown_policy) !== consent.consent_hash) {
    return no("governance_consent_unverified");
  }
  const principal = consent.principal.sub;
  const subject = consent.subject.sub;
  const grants = Object.hasOwn(rule.consent.approvers, principal) ? rule.consent.approvers[principal] : undefined;
  const activators = Object.hasOwn(rule.consent.activators, consent.source_root) ? rule.consent.activators[consent.source_root] : undefined;
  const writes = new Set(rule.consent.write_actions);
  if (
    !rule.consent.subjects.includes(subject) ||
    !activators?.includes(principal) ||
    (subject !== principal && !grants?.approves_for.includes(subject)) ||
    (consent.authority.some((e) => e.actions.some((a) => writes.has(a))) && (subject === principal || !grants?.write))
  ) {
    return no("governance_consent_ineligible");
  }
  const classOf = (a: string): RuntimeActionClass | undefined =>
    Object.hasOwn(rule.classification, a) ? rule.classification[a] : undefined;
  const actions = facts.authority.flatMap((e) => e.actions);
  if (actions.some((a) => classOf(a) === undefined)) return no("governance_unclassified_action");
  if (actions.some((a) => HIGH_RISK_CLASSES.has(classOf(a) as RuntimeActionClass))) return no("governance_high_risk");
  const decidedMs = Date.parse(facts.decided_at);
  const approvedMs = Date.parse(consent.consented_at);
  const skewMs = rule.recency.clock_skew_s * 1000;
  if (
    !isRfc3339Instant(facts.decided_at) ||
    !Number.isFinite(decidedMs) ||
    !Number.isFinite(approvedMs) ||
    !(approvedMs <= decidedMs + skewMs) ||
    !(decidedMs - approvedMs <= rule.recency.ceilings.default * 1000)
  ) {
    return no("governance_recency");
  }
  return { ok: true };
}

/** The contributing assertion's identifier. */
export const DRAWDOWN_ASSERTION_ID = "ast_policy";

/** The unsigned record of a recorded drawdown. */
export function buildDrawdownRecord(
  mission: MissionRecord,
  ruleRef: ActivationPolicyRef,
  deciding: ActivationPolicyRef,
): UnsignedApprovalGovernanceRecord {
  const basis = mission.approval_basis as ApprovalBasisCeilingDrawdown;
  const assertion: AgrAssertion = {
    assertion_id: DRAWDOWN_ASSERTION_ID,
    principal: basis.consent_principal,
    kind: "policy",
    decision: "approve",
    decided_at: mission.created_at,
    authority: { policy_id: deciding.id, version: deciding.version, approved_at: basis.approved_at },
  };
  return {
    approval_event_id: mission.approval_event_id,
    mission: { issuer: mission.issuer, intent_hash: mission.intent_hash, authority_hash: mission.authority_hash },
    approval_policy: ruleRef,
    assertions: [assertion],
    evaluation: { decision: "approved", evaluated_at: mission.created_at, contributing: [DRAWDOWN_ASSERTION_ID] },
  };
}

/**
 * @spec approval-governance#accountable-assertion, approval-governance#assertion-authority:
 * the commit gate for a ceiling-drawdown record. No accountable assertion
 * (the basis stands in); exactly one approving `policy` assertion, counted
 * and the only one counted, by the consent principal, naming the deciding
 * policy at the basis's consent instant, decided at the evaluation instant;
 * `approval_policy` the rule this issuer holds.
 */
export function assertDrawdownRecord(
  record: UnsignedApprovalGovernanceRecord,
  basis: ApprovalBasisCeilingDrawdown,
  ruleRef: ActivationPolicyRef,
  deciding: ActivationPolicyRef,
): AgrAssertion {
  const fail = (why: string): never => {
    throw new ApprovalGovernanceError(`ceiling_drawdown record: ${why}`);
  };
  const ids = record.assertions.map((a) => a.assertion_id);
  if (new Set(ids).size !== ids.length) fail("assertion_id values are not unique");
  for (const x of record.assertions) {
    try {
      assertAssertionAuthority(x);
    } catch (e) {
      fail((e as Error).message);
    }
  }
  if (!sameRef(record.approval_policy, ruleRef)) fail("approval_policy is not the recording rule this issuer holds");
  if (record.evaluation.decision !== "approved") fail("evaluation did not approve");
  try {
    assertContributing(record);
    assertAccountableApprover(record, basis);
  } catch (e) {
    fail((e as Error).message);
  }
  const policies = record.assertions.filter((a) => a.kind === "policy" && a.decision === "approve");
  if (policies.length !== 1) fail("the record carries not exactly one approving policy assertion");
  const a = policies[0] as AgrAssertion;
  const auth = a.authority as { policy_id?: unknown; version?: unknown; approved_at?: unknown };
  if (a.principal.iss !== basis.consent_principal.iss || a.principal.sub !== basis.consent_principal.sub) {
    fail("the policy assertion's principal is not the ceiling consent principal");
  }
  if (auth.policy_id !== deciding.id || auth.version !== deciding.version) fail("the policy assertion does not name the deciding policy");
  if (basis.adjudication.policy.id !== deciding.id || basis.adjudication.policy.version !== deciding.version) {
    fail("the deciding policy is not the basis's adjudication policy");
  }
  if (auth.approved_at !== basis.approved_at) fail("the policy assertion's approved_at is not the ceiling consent instant");
  if (a.decided_at !== record.evaluation.evaluated_at) fail("the policy assertion was not decided at the evaluation instant");
  const contributing = record.evaluation.contributing;
  if (contributing.length !== 1 || contributing[0] !== a.assertion_id) fail("contributing is not exactly the policy assertion");
  return a;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS drawdown_recording_rules (
  issuer TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  content_type TEXT NOT NULL,
  content BLOB NOT NULL,
  PRIMARY KEY (issuer, policy_id, version, digest)
) STRICT;
CREATE TABLE IF NOT EXISTS drawdown_record_inputs (
  approval_event_id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL UNIQUE,
  inputs_json TEXT NOT NULL
) STRICT;
`;

/**
 * @spec approval-governance#approval-policy: the retained recording-rule
 * snapshots (never pruned) and each recorded drawdown's inputs.
 */
export class DrawdownApprovalRecordStore {
  constructor(private readonly db: Database) {
    db.exec(SCHEMA);
  }

  retainInCallerTx(
    missionId: string,
    issuer: string,
    ruleRef: ActivationPolicyRef,
    rule: RegisteredDrawdownRecordingRule,
    inputs: DrawdownRecordInputs,
  ): void {
    if (!this.db.inTransaction) throw new Error("drawdown governance evidence is retained only in the Mission's creation transaction");
    this.db
      .prepare(
        "INSERT OR IGNORE INTO drawdown_recording_rules (issuer, policy_id, version, digest, content_type, content) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(issuer, ruleRef.id, ruleRef.version, ruleRef.digest, rule.content_type, Buffer.from(rule.content, "utf8"));
    this.db
      .prepare("INSERT INTO drawdown_record_inputs (approval_event_id, mission_id, inputs_json) VALUES (?, ?, ?)")
      .run(inputs.approval_event_id, missionId, JSON.stringify(inputs));
  }

  ruleSnapshot(issuer: string, ref: ActivationPolicyRef): { content_type: string; content: Uint8Array } | undefined {
    const row = this.db
      .prepare("SELECT content_type, content FROM drawdown_recording_rules WHERE issuer = ? AND policy_id = ? AND version = ? AND digest = ?")
      .get(issuer, ref.id, ref.version, ref.digest) as { content_type: string; content: Buffer } | undefined;
    return row ? { content_type: row.content_type, content: new Uint8Array(row.content) } : undefined;
  }

  inputs(missionId: string): { approval_event_id: string; inputs: DrawdownRecordInputs } | undefined {
    const row = this.db.prepare("SELECT approval_event_id, inputs_json FROM drawdown_record_inputs WHERE mission_id = ?").get(missionId) as
      | { approval_event_id: string; inputs_json: string }
      | undefined;
    return row ? { approval_event_id: row.approval_event_id, inputs: JSON.parse(row.inputs_json) as DrawdownRecordInputs } : undefined;
  }
}

const samePrincipal = (a: { iss: string; sub: string }, b: { iss: string; sub: string }): boolean => a.iss === b.iss && a.sub === b.sub;
const sameJson = (a: unknown, b: unknown): boolean => canonicalize((a ?? null) as JsonValue) === canonicalize((b ?? null) as JsonValue);

/**
 * @spec approval-governance#re-check: steps 2 to 6 for a verified
 * ceiling-drawdown record, from retained state alone. (2) The recording
 * rule's snapshot reproduces `approval_policy.digest`. (3) The deciding
 * drawdown policy is the one the inputs name, the assertion and the basis
 * name, and its retained snapshot verifies under its own digest and parses to
 * the rules the inputs record. (4) The retained inputs are bound to this
 * event, Intent and Authority Set, to the predecessor, and to the basis's
 * consent principal, commitment and instant, and name the Mission's Subject
 * and authority source. (5) The drawdown decision replays to a policy
 * activation, and the record passes the commit gate with exactly its policy
 * assertion contributing. (6) The eligibility gate and recency replay at the
 * decision instant, which is `evaluation.evaluated_at`.
 */
export function recheckDrawdownApprovalRecord(
  kernel: MissionKernel,
  mission: MissionRecord,
  record: ApprovalGovernanceRecord,
):
  | { rechecked: true }
  | { rechecked: false; step: 2 | 3 | 4 | 5 | 6; reason: string } {
  const no = (step: 2 | 3 | 4 | 5 | 6, reason: string) => ({ rechecked: false as const, step, reason });
  const basis = mission.approval_basis as ApprovalBasisCeilingDrawdown;
  const store = kernel.drawdownApprovalRecords;
  const snapshot = store.ruleSnapshot(mission.issuer, record.approval_policy);
  if (!snapshot) return no(2, "the recording rule snapshot the record names is not retained");
  if (approvalPolicyDigest(mission.issuer, snapshot) !== record.approval_policy.digest) {
    return no(2, "the retained recording rule snapshot does not reproduce approval_policy.digest");
  }
  let rule: DrawdownRecordingRule;
  try {
    rule = parseDrawdownRecordingRule(snapshot.content);
  } catch {
    return no(2, "the retained recording rule snapshot is not a recording rule");
  }
  const retained = store.inputs(mission.id);
  if (!retained) return no(4, "no recorded inputs to replay");
  const inputs = retained.inputs;
  const deciding = inputs.adjudication.drawdown_policy;
  const named = record.assertions.find((a) => a.kind === "policy")?.authority as { policy_id?: unknown; version?: unknown } | undefined;
  if (
    !deciding ||
    named?.policy_id !== deciding.id ||
    named?.version !== deciding.version ||
    basis.activation.policy_id !== deciding.id ||
    basis.activation.policy_version !== deciding.version
  ) {
    return no(3, "the deciding policy is not the one the inputs, the assertion and the basis name");
  }
  const held = kernel.activationPolicySnapshots.verify(mission.issuer, deciding);
  if (held.status !== "verified") return no(3, "the retained drawdown policy snapshot does not verify");
  const rules = drawdownRulesOf({
    version: deciding.version,
    content_type: held.snapshot.content_type,
    content: Buffer.from(held.snapshot.content).toString("utf8"),
  } as never);
  if (!rules || !sameJson(rules, inputs.adjudication.rules)) return no(3, "the retained drawdown policy does not parse to the rules the inputs record");
  if (
    retained.approval_event_id !== record.approval_event_id ||
    inputs.approval_event_id !== record.approval_event_id ||
    inputs.intent_hash !== record.mission.intent_hash ||
    authorityHash(mission.issuer, inputs.authority as never) !== mission.authority_hash ||
    !sameJson(inputs.adjudication.requested, inputs.authority)
  ) {
    return no(4, "the recorded inputs are not bound to this approval event, Intent and Authority Set");
  }
  if (inputs.adjudication.predecessor_id !== mission.predecessor) return no(4, "the recorded inputs name another predecessor");
  const binding = kernel.sourceBindings.get(mission.id);
  const c = inputs.consent;
  if (
    !samePrincipal(c.principal, basis.consent_principal) ||
    c.consented_at !== basis.approved_at ||
    c.consent_hash !== basis.root_commitment ||
    inputs.adjudication.ceiling_consented_at !== basis.approved_at ||
    !samePrincipal(c.subject, mission.subject) ||
    !binding ||
    c.source_root !== binding.rootId
  ) {
    return no(4, "the recorded inputs do not carry this Mission's ceiling consent, Subject and authority source");
  }
  // The consent provenance is the consenting Mission's own retained record,
  // an ancestor of this successor: its ceiling, policy, Authority Set and
  // Subject as committed, never values the inputs alone assert.
  const consenting = kernel.get(c.mission_id);
  let ancestor = false;
  const seen = new Set<string>();
  for (let m: string | undefined = mission.predecessor; m && !seen.has(m); m = kernel.get(m)?.predecessor) {
    seen.add(m);
    if (m === c.mission_id) ancestor = true;
  }
  if (
    !consenting ||
    !ancestor ||
    ceilingConsentHash(consenting) !== c.consent_hash ||
    consenting.ceiling_consented_at !== c.consented_at ||
    !sameJson(consenting.authority_ceiling, c.ceiling) ||
    !sameJson(consenting.drawdown_policy, c.drawdown_policy) ||
    !sameJson(consenting.authority_set, c.authority) ||
    !samePrincipal(consenting.subject, c.subject) ||
    kernel.sourceBindings.get(consenting.id)?.rootId !== c.source_root
  ) {
    return no(4, "the recorded consent provenance is not the consenting Mission's retained record");
  }
  if (!isRfc3339Instant(record.evaluation.evaluated_at)) return no(5, "evaluation.evaluated_at is not an RFC 3339 timestamp");
  if (inputs.decided_at !== record.evaluation.evaluated_at || inputs.adjudication.now !== inputs.decided_at) {
    return no(4, "the recorded inputs were not read at the evaluation instant");
  }
  const decision = decideDrawdown(inputs.adjudication);
  if (decision.outcome !== "policy") {
    return no(5, `the drawdown decision does not replay to a policy activation: ${decision.outcome === "fresh_approval" ? decision.reason : decision.outcome}`);
  }
  try {
    assertDrawdownRecord(record, basis, record.approval_policy, deciding);
  } catch (e) {
    return no(5, (e as Error).message);
  }
  const gate = drawdownGovernanceGate(mission.issuer, rule, {
    deciding,
    consent: c,
    authority: inputs.authority,
    decided_at: inputs.decided_at,
  });
  if (!gate.ok) return no(6, `the eligibility gate does not replay: ${gate.reason}`);
  return { rechecked: true };
}
