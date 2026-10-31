/**
 * @spec approval-governance#accountable-assertion, approval-governance#recency-declarations,
 * approval-governance#recency-evaluation, approval-governance#recency-high-risk,
 * approval-governance#atomic-commitment, approval-governance#re-check,
 * mission-template#prohibited-classes (#813, D814, D830 ruling 9): the
 * Approval Governance Record every standing-payment instance commits.
 *
 * Mirrors the ceiling-drawdown record (drawdown-approval-record.ts). The
 * instance's `template` basis stands in for the accountable assertion: the
 * template consent's authenticated human, commitment and instant. The record
 * carries one contributing `policy` assertion of the Dispatch Policy, by that
 * human, with the consent instant as `approved_at` and the dispatch instant as
 * `decided_at`. Its `approval_policy` is a recording rule built from the
 * Dispatch Policy's committed terms: the recency ceiling, the clock-skew
 * allowance and the class-named exceptions (`irreversible_action`, and
 * `consumption_bound`, the reference-local key of the consumption-bound class),
 * the deciding policy, and the classification of the template ceiling.
 *
 * The gate sees the whole instance: an unclassified action, or a high-risk
 * class (the consumption bound included, present whenever the Intent carries
 * `max_budget`) with no class-named exception, refuses the dispatch, as does a
 * consent older than the strictest applicable maximum at the dispatch instant.
 * The inputs the decision read are retained with the instance and the record,
 * and a re-check replays the gate and recency from them alone.
 */
import { createHash } from "node:crypto";
import {
  type ActivationPolicyRef,
  approvalPolicyDigest,
  authorityHash,
  canonicalize,
  isRfc3339Instant,
  type JsonValue,
} from "@mission/core";
import type { Database } from "@mission/store";
import {
  type AgrAssertion,
  ApprovalGovernanceError,
  type ApprovalGovernanceRecord,
  assertAssertionAuthority,
  assertContributing,
  type UnsignedApprovalGovernanceRecord,
} from "./approval-governance.js";
import {
  CONSUMPTION_BOUND_CLASS,
  type GovernanceExceptionClass,
  isHumanFloorConsent,
  type StandingPaymentGovernance,
  type StandingPaymentTerms,
  standingPaymentTermsOf,
  type TemplateConsentProvenance,
  type UsdAmount,
} from "./standing-payment.js";
import type { ApprovalBasisTemplate, AuthorityEntry, MissionRecord } from "./types.js";
import { resolvedAnchors } from "./anchors.js";

/** The identifier of the standing-payment template recording rule. */
export const TEMPLATE_RECORDING_RULE_ID = "urn:mission:template-standing-payment-recording-rule";

/** The high-risk classes an action class can carry; the fourth is the consumption bound. */
const HIGH_RISK_ACTION_CLASSES: ReadonlySet<string> = new Set([
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
]);

/** The recording rule a standing-payment record names as its `approval_policy`. */
export interface TemplateRecordingRule {
  /** @spec approval-governance#recency-declarations: copied from the committed Dispatch Policy. */
  recency: StandingPaymentGovernance["recency"];
  /** The Dispatch Policy the template committed, the one policy eligible to decide. */
  deciding_policy: ActivationPolicyRef;
  /** Each template ceiling action's classes under the published classification. */
  classification: Record<string, string[]>;
}

/** A registered rule version. */
export interface RegisteredTemplateRecordingRule {
  id: string;
  version: string;
  content_type: "application/json";
  content: string;
}

/** Why the gate refused. */
export type TemplateGovernanceReason =
  | "governance_policy_ineligible"
  | "governance_unclassified_action"
  | "governance_high_risk"
  | "governance_recency";

/** A malformed recording rule. */
export class TemplateRecordingRuleError extends Error {}

const sortedRecord = <T>(entries: Array<[string, T]>): Record<string, T> =>
  Object.fromEntries(entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));

/**
 * The rule for one template: the Dispatch Policy's committed recency terms,
 * the policy itself as the deciding policy, and the classification of the
 * template ceiling's actions, so every instance of the template names the same
 * rule version.
 */
export function templateRecordingRuleFor(
  deciding: ActivationPolicyRef,
  terms: StandingPaymentTerms,
  classification: Readonly<Record<string, readonly string[]>>,
): RegisteredTemplateRecordingRule {
  const rule: TemplateRecordingRule = {
    recency: {
      ceilings: { default: terms.approval_governance.recency.ceilings.default },
      clock_skew_s: terms.approval_governance.recency.clock_skew_s,
      exceptions: sortedRecord(
        Object.entries(terms.approval_governance.recency.exceptions),
      ) as TemplateRecordingRule["recency"]["exceptions"],
    },
    deciding_policy: { id: deciding.id, version: deciding.version, digest: deciding.digest },
    classification: sortedRecord(
      Object.entries(classification).map(([a, c]) => [a, [...c].sort()]),
    ),
  };
  const content = canonicalize(rule as unknown as JsonValue);
  const version = createHash("sha256").update(content, "utf8").digest("base64url").slice(0, 16);
  return { id: TEMPLATE_RECORDING_RULE_ID, version, content_type: "application/json", content };
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const exactly = (o: Record<string, unknown>, keys: string[]): boolean =>
  Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));
const isRef = (v: unknown): v is ActivationPolicyRef =>
  isObject(v) &&
  exactly(v, ["id", "version", "digest"]) &&
  typeof v.id === "string" &&
  typeof v.version === "string" &&
  typeof v.digest === "string";

/** Parse a rule snapshot strictly; its bytes are evaluated as they are. */
export function parseTemplateRecordingRule(content: string | Uint8Array): TemplateRecordingRule {
  const fail = (why: string): never => {
    throw new TemplateRecordingRuleError(`template recording rule: ${why}`);
  };
  let raw: unknown;
  try {
    raw = JSON.parse(typeof content === "string" ? content : Buffer.from(content).toString("utf8"));
  } catch {
    return fail("not JSON");
  }
  if (!isObject(raw) || !exactly(raw, ["recency", "deciding_policy", "classification"])) {
    fail("members are not recency, deciding_policy, classification");
  }
  const r = raw as Record<string, unknown>;
  const recency = r.recency;
  if (!isObject(recency) || !exactly(recency, ["ceilings", "clock_skew_s", "exceptions"]))
    fail("recency is not {ceilings, clock_skew_s, exceptions}");
  const rec = recency as Record<string, unknown>;
  if (
    !isObject(rec.ceilings) ||
    !exactly(rec.ceilings, ["default"]) ||
    !Number.isSafeInteger(rec.ceilings.default) ||
    (rec.ceilings.default as number) <= 0
  ) {
    fail("recency.ceilings is not {default} with a positive integer ceiling");
  }
  if (!Number.isSafeInteger(rec.clock_skew_s) || (rec.clock_skew_s as number) < 0)
    fail("recency.clock_skew_s is not a non-negative integer");
  if (!isObject(rec.exceptions)) fail("recency.exceptions is not an object");
  for (const [cls, e] of Object.entries(rec.exceptions as Record<string, unknown>)) {
    if (cls !== "irreversible_action" && cls !== CONSUMPTION_BOUND_CLASS)
      fail(`recency.exceptions names ${cls}`);
    if (
      !isObject(e) ||
      !exactly(e, ["max_age_s"]) ||
      !Number.isSafeInteger(e.max_age_s) ||
      (e.max_age_s as number) <= 0
    ) {
      fail(`recency.exceptions.${cls} is not {max_age_s}`);
    }
  }
  if (!isRef(r.deciding_policy)) fail("deciding_policy is not a policy reference");
  if (
    !isObject(r.classification) ||
    !Object.values(r.classification).every(
      (c) => Array.isArray(c) && c.every((x) => typeof x === "string"),
    )
  ) {
    fail("classification maps each action to an array of classes");
  }
  return raw as unknown as TemplateRecordingRule;
}

/** The `approval_policy` reference of a registered rule version. */
export function templateRecordingRuleRef(
  issuer: string,
  rule: RegisteredTemplateRecordingRule,
): ActivationPolicyRef {
  return { id: rule.id, version: rule.version, digest: approvalPolicyDigest(issuer, rule) };
}

const sameRef = (a: ActivationPolicyRef | undefined, b: ActivationPolicyRef | undefined): boolean =>
  !!a && !!b && a.id === b.id && a.version === b.version && a.digest === b.digest;

/**
 * @spec approval-governance#recency-evaluation, approval-governance#recency-high-risk:
 * the eligibility gate a standing-payment instance passes before it
 * activates. The deciding policy is the rule's; every action of the whole
 * instance is classified; every high-risk class present, the consumption bound
 * included, has a class-named exception; and the consent's age at the
 * decision instant is within the strictest applicable maximum (each present
 * class's exception never lengthens the default ceiling), in order within the
 * clock-skew allowance.
 */
export function templateGovernanceGate(
  rule: TemplateRecordingRule,
  facts: {
    deciding?: ActivationPolicyRef;
    approved_at: string;
    authority: readonly AuthorityEntry[];
    consumptionBound: boolean;
    decided_at: string;
  },
): { ok: true } | { ok: false; reason: TemplateGovernanceReason; detail: string } {
  const no = (reason: TemplateGovernanceReason, detail: string) => ({
    ok: false as const,
    reason,
    detail,
  });
  if (!sameRef(facts.deciding, rule.deciding_policy)) {
    return no(
      "governance_policy_ineligible",
      "the deciding policy is not the Dispatch Policy the rule admits",
    );
  }
  const present = new Set<string>();
  for (const action of facts.authority.flatMap((e) => e.actions)) {
    const classes = Object.hasOwn(rule.classification, action)
      ? rule.classification[action]
      : undefined;
    if (!classes || classes.length === 0)
      return no("governance_unclassified_action", `${action} is unclassified`);
    for (const c of classes) if (HIGH_RISK_ACTION_CLASSES.has(c)) present.add(c);
  }
  if (facts.consumptionBound) present.add(CONSUMPTION_BOUND_CLASS);
  let maximum = rule.recency.ceilings.default;
  for (const cls of [...present].sort()) {
    const exception = Object.hasOwn(rule.recency.exceptions, cls)
      ? rule.recency.exceptions[cls as GovernanceExceptionClass]
      : undefined;
    if (!exception) {
      return no(
        "governance_high_risk",
        `the high-risk class ${cls} has no committed class-named exception`,
      );
    }
    maximum = Math.min(maximum, exception.max_age_s);
  }
  const decidedMs = Date.parse(facts.decided_at);
  const approvedMs = Date.parse(facts.approved_at);
  const skewMs = rule.recency.clock_skew_s * 1000;
  if (
    !isRfc3339Instant(facts.decided_at) ||
    !isRfc3339Instant(facts.approved_at) ||
    !Number.isFinite(decidedMs) ||
    !Number.isFinite(approvedMs) ||
    !(approvedMs <= decidedMs + skewMs) ||
    !(decidedMs - approvedMs <= maximum * 1000)
  ) {
    return no(
      "governance_recency",
      `the template consent is older than the applicable maximum of ${maximum}s, or out of order`,
    );
  }
  return { ok: true };
}

/** The contributing assertion's identifier. */
export const TEMPLATE_ASSERTION_ID = "ast_policy";

/** The unsigned record of a standing-payment instance. */
export function buildTemplateRecord(
  mission: MissionRecord,
  ruleRef: ActivationPolicyRef,
  deciding: ActivationPolicyRef,
): UnsignedApprovalGovernanceRecord {
  const basis = mission.approval_basis as ApprovalBasisTemplate;
  const assertion: AgrAssertion = {
    assertion_id: TEMPLATE_ASSERTION_ID,
    principal: basis.consent_principal,
    kind: "policy",
    decision: "approve",
    decided_at: mission.created_at,
    authority: {
      policy_id: deciding.id,
      version: deciding.version,
      approved_at: basis.approved_at,
    },
  };
  // @spec mission#integrity-anchors (#1917, D1061): the Mission's anchors,
  // recorded or implied, computed at approval whether or not retained.
  const { intent_hash, authority_hash } = resolvedAnchors(mission);
  return {
    approval_event_id: mission.approval_event_id,
    mission: { issuer: mission.issuer, intent_hash, authority_hash },
    approval_policy: ruleRef,
    assertions: [assertion],
    evaluation: {
      decision: "approved",
      evaluated_at: mission.created_at,
      contributing: [TEMPLATE_ASSERTION_ID],
    },
  };
}

/**
 * @spec approval-governance#accountable-assertion, approval-governance#assertion-authority:
 * the commit gate for a standing-payment record. Exactly one approving
 * `policy` assertion, counted and the only one counted, by the template's
 * consent principal (never the Dispatcher that activated the instance),
 * naming the Dispatch Policy at the consent instant, decided at the
 * evaluation instant; `approval_policy` the rule this issuer built.
 */
export function assertTemplateRecord(
  record: UnsignedApprovalGovernanceRecord,
  basis: ApprovalBasisTemplate,
  ruleRef: ActivationPolicyRef,
  deciding: ActivationPolicyRef,
): AgrAssertion {
  const fail = (why: string): never => {
    throw new ApprovalGovernanceError(`template record: ${why}`);
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
  if (!sameRef(record.approval_policy, ruleRef))
    fail("approval_policy is not the recording rule this issuer holds");
  if (record.evaluation.decision !== "approved") fail("evaluation did not approve");
  try {
    assertContributing(record);
  } catch (e) {
    fail((e as Error).message);
  }
  const policies = record.assertions.filter((a) => a.kind === "policy" && a.decision === "approve");
  if (policies.length !== 1) fail("the record carries not exactly one approving policy assertion");
  const a = policies[0] as AgrAssertion;
  if (
    a.principal.iss !== basis.consent_principal.iss ||
    a.principal.sub !== basis.consent_principal.sub
  ) {
    fail("the policy assertion's principal is not the template consent principal");
  }
  if (
    a.principal.iss === basis.activation_actor.iss &&
    a.principal.sub === basis.activation_actor.sub
  ) {
    fail("the policy assertion's principal is the Dispatcher, not a human consent");
  }
  const auth = a.authority as { policy_id?: unknown; version?: unknown; approved_at?: unknown };
  if (auth.policy_id !== deciding.id || auth.version !== deciding.version)
    fail("the policy assertion does not name the Dispatch Policy");
  if (auth.approved_at !== basis.approved_at)
    fail("the policy assertion's approved_at is not the template consent instant");
  if (a.decided_at !== record.evaluation.evaluated_at)
    fail("the policy assertion was not decided at the evaluation instant");
  const contributing = record.evaluation.contributing;
  if (contributing.length !== 1 || contributing[0] !== a.assertion_id)
    fail("contributing is not exactly the policy assertion");
  return a;
}

/** The inputs a recorded standing-payment decision read. */
export interface TemplateRecordInputs {
  approval_event_id: string;
  intent_hash: string;
  /** The instance's committed Authority Set. */
  authority: AuthorityEntry[];
  /** The Intent's `max_budget`, the consumption bound the gate classified. */
  consumption_bound: UsdAmount | null;
  deciding: ActivationPolicyRef;
  consent: {
    template_id: string;
    template_hash: string;
    principal: { iss: string; sub: string };
    approved_at: string;
    provenance: TemplateConsentProvenance;
  };
  /** The dispatch instant: the instance's creation instant. */
  decided_at: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS template_recording_rules (
  issuer TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  content_type TEXT NOT NULL,
  content BLOB NOT NULL,
  PRIMARY KEY (issuer, policy_id, version, digest)
) STRICT;
CREATE TABLE IF NOT EXISTS template_record_inputs (
  approval_event_id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL UNIQUE,
  inputs_json TEXT NOT NULL
) STRICT;
`;

/**
 * @spec approval-governance#approval-policy: the retained recording-rule
 * snapshots (never pruned) and each recorded instance's inputs.
 */
export class TemplateApprovalRecordStore {
  constructor(private readonly db: Database) {
    db.exec(SCHEMA);
  }

  retainInCallerTx(
    missionId: string,
    issuer: string,
    ruleRef: ActivationPolicyRef,
    rule: RegisteredTemplateRecordingRule,
    inputs: TemplateRecordInputs,
  ): void {
    if (!this.db.inTransaction)
      throw new Error(
        "template governance evidence is retained only in the instance's creation transaction",
      );
    this.db
      .prepare(
        "INSERT OR IGNORE INTO template_recording_rules (issuer, policy_id, version, digest, content_type, content) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(
        issuer,
        ruleRef.id,
        ruleRef.version,
        ruleRef.digest,
        rule.content_type,
        Buffer.from(rule.content, "utf8"),
      );
    this.db
      .prepare(
        "INSERT INTO template_record_inputs (approval_event_id, mission_id, inputs_json) VALUES (?, ?, ?)",
      )
      .run(inputs.approval_event_id, missionId, JSON.stringify(inputs));
  }

  ruleSnapshot(
    issuer: string,
    ref: ActivationPolicyRef,
  ): { content_type: string; content: Uint8Array } | undefined {
    const row = this.db
      .prepare(
        "SELECT content_type, content FROM template_recording_rules WHERE issuer = ? AND policy_id = ? AND version = ? AND digest = ?",
      )
      .get(issuer, ref.id, ref.version, ref.digest) as
      | { content_type: string; content: Buffer }
      | undefined;
    return row
      ? { content_type: row.content_type, content: new Uint8Array(row.content) }
      : undefined;
  }

  inputs(
    missionId: string,
  ): { approval_event_id: string; inputs: TemplateRecordInputs } | undefined {
    const row = this.db
      .prepare(
        "SELECT approval_event_id, inputs_json FROM template_record_inputs WHERE mission_id = ?",
      )
      .get(missionId) as { approval_event_id: string; inputs_json: string } | undefined;
    return row
      ? {
          approval_event_id: row.approval_event_id,
          inputs: JSON.parse(row.inputs_json) as TemplateRecordInputs,
        }
      : undefined;
  }
}

const sameJson = (a: unknown, b: unknown): boolean =>
  canonicalize((a ?? null) as JsonValue) === canonicalize((b ?? null) as JsonValue);

/** What a re-check reads from the kernel. */
export interface TemplateRecheckKernel {
  templateApprovalRecords: TemplateApprovalRecordStore;
  activationPolicySnapshots: {
    verify(
      issuer: string,
      ref: ActivationPolicyRef,
    ):
      | { status: "verified"; snapshot: { content_type: string; content: Uint8Array | string } }
      | { status: string };
  };
}

/**
 * @spec approval-governance#re-check: steps 2 to 6 for a verified
 * standing-payment record, from retained state alone. (2) The recording
 * rule's snapshot reproduces `approval_policy.digest`. (3) The retained
 * Dispatch Policy snapshot verifies under its own digest, and its committed
 * recency terms are the rule's. (4) The retained inputs are bound to this
 * event, Intent and Authority Set, and carry the basis's consent principal,
 * commitment and instant with a human consent at the approval floor. (5) The
 * record passes the commit gate. (6) The eligibility gate and recency replay
 * at the decision instant.
 */
export function recheckTemplateApprovalRecord(
  kernel: TemplateRecheckKernel,
  mission: MissionRecord,
  record: ApprovalGovernanceRecord,
): { rechecked: true } | { rechecked: false; step: 2 | 3 | 4 | 5 | 6; reason: string } {
  const no = (step: 2 | 3 | 4 | 5 | 6, reason: string) => ({
    rechecked: false as const,
    step,
    reason,
  });
  const basis = mission.approval_basis as ApprovalBasisTemplate;
  const store = kernel.templateApprovalRecords;
  const snapshot = store.ruleSnapshot(mission.issuer, record.approval_policy);
  if (!snapshot) return no(2, "the recording rule snapshot the record names is not retained");
  if (approvalPolicyDigest(mission.issuer, snapshot) !== record.approval_policy.digest) {
    return no(2, "the retained recording rule snapshot does not reproduce approval_policy.digest");
  }
  let rule: TemplateRecordingRule;
  try {
    rule = parseTemplateRecordingRule(snapshot.content);
  } catch {
    return no(2, "the retained recording rule snapshot is not a recording rule");
  }
  const retained = store.inputs(mission.id);
  if (!retained) return no(4, "no recorded inputs to replay");
  const inputs = retained.inputs;
  const deciding = inputs.deciding;
  const held = kernel.activationPolicySnapshots.verify(mission.issuer, deciding);
  if (held.status !== "verified" || !("snapshot" in held))
    return no(3, "the retained Dispatch Policy snapshot does not verify");
  let terms: StandingPaymentTerms | undefined;
  try {
    terms = standingPaymentTermsOf({
      content_type: held.snapshot.content_type,
      content: held.snapshot.content,
    });
  } catch {
    terms = undefined;
  }
  if (
    !terms ||
    !sameJson(terms.approval_governance.recency, rule.recency) ||
    !sameRef(rule.deciding_policy, deciding)
  ) {
    return no(3, "the retained Dispatch Policy does not commit the recording rule's recency terms");
  }
  if (
    retained.approval_event_id !== record.approval_event_id ||
    inputs.approval_event_id !== record.approval_event_id ||
    inputs.intent_hash !== record.mission.intent_hash ||
    authorityHash(mission.issuer, inputs.authority as never) !== resolvedAnchors(mission).authority_hash ||
    !sameJson(inputs.consumption_bound, mission.intent.max_budget ?? null)
  ) {
    return no(
      4,
      "the recorded inputs are not bound to this approval event, Intent and Authority Set",
    );
  }
  const c = inputs.consent;
  if (
    c.principal.iss !== basis.consent_principal.iss ||
    c.principal.sub !== basis.consent_principal.sub ||
    c.approved_at !== basis.approved_at ||
    c.template_hash !== basis.root_commitment ||
    c.template_id !== basis.activation.template_id ||
    !isHumanFloorConsent(c.provenance) ||
    c.provenance.principal.sub !== c.principal.sub
  ) {
    return no(4, "the recorded inputs do not carry this instance's human template consent");
  }
  if (
    inputs.decided_at !== record.evaluation.evaluated_at ||
    inputs.decided_at !== mission.created_at
  ) {
    return no(4, "the recorded inputs were not read at the evaluation instant");
  }
  try {
    assertTemplateRecord(record, basis, record.approval_policy, deciding);
  } catch (e) {
    return no(5, (e as Error).message);
  }
  const gate = templateGovernanceGate(rule, {
    deciding,
    approved_at: c.approved_at,
    authority: inputs.authority,
    consumptionBound: inputs.consumption_bound !== null,
    decided_at: inputs.decided_at,
  });
  if (!gate.ok) return no(6, `the eligibility gate does not replay: ${gate.reason}`);
  return { rechecked: true };
}
