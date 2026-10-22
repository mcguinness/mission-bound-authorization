/**
 * @spec approval-governance#triggers, approval-governance#accountable-assertion,
 * approval-governance#atomic-commitment, approval-governance#re-check (#1470
 * slice 1, D597): a voluntary Approval Governance Record for a `direct`
 * approval, default off.
 *
 * The record's `approval_policy` is the direct approval rule: the
 * approval-authentication floor and the approver eligibility the approval
 * surface enforces, and the authority-source activators the kernel enforces,
 * built from the same configuration objects each is given
 * (`directApprovalRuleFrom`), so the record names the rule that actually
 * admitted the human. The issuer evaluates that rule again at the
 * commit, over inputs it retains, and refuses the Mission when it denies. One
 * `human` assertion, the Approver's, carries the authentication the approval
 * surface verified. The rule snapshot, the inputs and the signed record commit
 * in the Mission's creation transaction, and a Relying Auditor re-checks the
 * record by replaying the rule over them (`recheckDirectApprovalRecord`).
 */
import { createHash } from "node:crypto";
import { approvalPolicyDigest, authorityHash, canonicalize, isRfc3339Instant, type JsonValue } from "@mission/core";
import { type ApprovalFloorPolicy, loadApprovalFloor } from "@mission/demo-data";
import type { Database } from "@mission/store";
import { evaluateApprovalFloor } from "./approval-floor.js";
import {
  type AgrAssertion,
  type ApprovalGovernanceRecord,
  ApprovalGovernanceError,
  assertAccountableApprover,
  assertAssertionAuthority,
  assertContributing,
  type UnsignedApprovalGovernanceRecord,
} from "./approval-governance.js";
import type { ApprovalBasisDirect, AuthorityEntry, MissionRecord } from "./types.js";

/** The default identifier of the direct approval rule. */
export const DIRECT_APPROVAL_RULE_ID = "urn:mission:direct-approval-rule";

/**
 * The direct approval rule: who may approve for whom, which actions need an
 * Approver distinct from the Subject, and the approval-authentication floor.
 */
export interface DirectApprovalRule {
  /** The approval-authentication floor, by action class. */
  floor: ApprovalFloorPolicy;
  /** The principals a Mission may be approved for. */
  subjects: string[];
  /** Each human who may approve for another principal, and whether they may approve write-bearing authority. */
  approvers: Record<string, { approves_for: string[]; write: boolean }>;
  /** Actions whose approval needs an Approver distinct from the Subject, holding `write`. */
  write_actions: string[];
  /** Each authority source's Approvers: who may activate it (the catalog's `activators`). */
  activators: Record<string, string[]>;
}

/** A registered rule version: its identifier, version and exact bytes. */
export interface RegisteredDirectApprovalRule {
  id: string;
  version: string;
  content_type: "application/json";
  content: string;
}

/** The inputs the rule evaluated, retained with the Mission. */
export interface DirectApprovalInputs {
  approval_event_id: string;
  intent_hash: string;
  approver: { iss: string; sub: string };
  subject: { iss: string; sub: string };
  /** The authority source the approval resolved: its catalog entry id. */
  source_root: string;
  /** The committed Authority Set. */
  authority: AuthorityEntry[];
  /** A Progressive ceiling consented at this approval, classified with the set. */
  ceiling?: AuthorityEntry[];
  /** The authentication the approval surface verified for the Approver. */
  authentication: DirectApprovalAuthentication;
}

/** The Approver's authentication at the approval event. */
export interface DirectApprovalAuthentication {
  acr: string;
  /** Seconds since the epoch. */
  auth_time: number;
  /** Whether the Approver decided on the interactive approval surface. */
  interactive: boolean;
}

export type DirectApprovalDecision = { decision: "approve" } | { decision: "deny"; reason: string };

/** A rule configuration fault: refused at kernel construction, never at an approval. */
export class DirectApprovalRuleError extends Error {}

/**
 * Build the rule document from the configuration objects the approval surface
 * enforces, so the recorded rule is the enforced one. The version is the
 * content's own short digest: a configuration change is a new version.
 */
export function directApprovalRuleFrom(
  config: {
    floor: ApprovalFloorPolicy;
    knownSubjects: ReadonlySet<string>;
    approverApprovesFor: ReadonlyMap<string, ReadonlySet<string>>;
    approverRoleSubs: ReadonlySet<string>;
    writeActions: ReadonlySet<string>;
    /** The authority-source catalog the kernel enforces. */
    catalog: { entries: ReadonlyArray<{ id: string; activators: readonly string[] }> };
  },
  id: string = DIRECT_APPROVAL_RULE_ID,
): RegisteredDirectApprovalRule {
  const approvers: DirectApprovalRule["approvers"] = {};
  for (const sub of [...new Set([...config.approverApprovesFor.keys(), ...config.approverRoleSubs])].sort()) {
    approvers[sub] = {
      approves_for: [...(config.approverApprovesFor.get(sub) ?? [])].sort(),
      write: config.approverRoleSubs.has(sub),
    };
  }
  const rule: DirectApprovalRule = {
    floor: config.floor,
    subjects: [...config.knownSubjects].sort(),
    approvers,
    write_actions: [...config.writeActions].sort(),
    activators: Object.fromEntries(config.catalog.entries.map((e) => [e.id, [...e.activators].sort()])),
  };
  const content = canonicalize(rule as unknown as JsonValue);
  const version = createHash("sha256").update(content, "utf8").digest("base64url").slice(0, 16);
  return { id, version, content_type: "application/json", content };
}

const isStringArray = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const exactly = (o: Record<string, unknown>, keys: string[]): boolean =>
  Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

/** Parse a rule snapshot strictly: exactly the members above, each well-typed. Its bytes are evaluated as they are. */
export function parseDirectApprovalRule(content: string | Uint8Array): DirectApprovalRule {
  const fail = (why: string): never => {
    throw new DirectApprovalRuleError(`direct approval rule: ${why}`);
  };
  let raw: unknown;
  try {
    raw = JSON.parse(typeof content === "string" ? content : Buffer.from(content).toString("utf8"));
  } catch {
    return fail("not JSON");
  }
  if (!isObject(raw) || !exactly(raw, ["floor", "subjects", "approvers", "write_actions", "activators"])) {
    fail("members are not floor, subjects, approvers, write_actions, activators");
  }
  const r = raw as Record<string, unknown>;
  if (!isStringArray(r.subjects) || !isStringArray(r.write_actions)) fail("subjects and write_actions are string arrays");
  if (!isObject(r.activators) || !Object.values(r.activators).every(isStringArray)) fail("activators maps each source to a string array");
  if (!isObject(r.approvers)) fail("approvers is an object");
  for (const [sub, a] of Object.entries(r.approvers as Record<string, unknown>)) {
    if (!isObject(a) || !exactly(a, ["approves_for", "write"]) || !isStringArray(a.approves_for) || typeof a.write !== "boolean") {
      fail(`approver ${sub} is not {approves_for, write}`);
    }
  }
  // The floor passes the approval-floor policy's own strict validation (known
  // action classes, floor bounds, accepted acr values); its retained bytes,
  // not the loader's output, are what the rule evaluates.
  try {
    loadApprovalFloor(JSON.stringify(r.floor));
  } catch (e) {
    fail(`floor: ${(e as Error).message}`);
  }
  return raw as unknown as DirectApprovalRule;
}

/**
 * Evaluate the rule over the inputs at `evaluatedAt`: the Approver may
 * activate the authority source the approval resolved; the Subject is one the
 * rule names; an approval for another principal needs the Approver's
 * approve-for; write-bearing authority needs a distinct Approver holding
 * `write`; and the approval-authentication floor holds over the set and any
 * consented ceiling at that instant.
 */
export function evaluateDirectApprovalRule(
  rule: DirectApprovalRule,
  inputs: DirectApprovalInputs,
  evaluatedAt: string,
): DirectApprovalDecision {
  // The floor's age bound is measured at this instant; one that is not a
  // timestamp would make every age comparison false, so it refuses.
  const nowMs = Date.parse(evaluatedAt);
  if (!isRfc3339Instant(evaluatedAt) || !Number.isFinite(nowMs)) {
    return { decision: "deny", reason: "the evaluation instant is not an RFC 3339 timestamp" };
  }
  const approver = inputs.approver.sub;
  const subject = inputs.subject.sub;
  const activators = Object.hasOwn(rule.activators, inputs.source_root) ? rule.activators[inputs.source_root] : undefined;
  if (!activators?.includes(approver)) {
    return { decision: "deny", reason: `${approver} may not activate the authority source ${inputs.source_root}` };
  }
  if (!rule.subjects.includes(subject)) return { decision: "deny", reason: `${subject} is not a principal this rule approves for` };
  const grants = Object.hasOwn(rule.approvers, approver) ? rule.approvers[approver] : undefined;
  if (subject !== approver && !grants?.approves_for.includes(subject)) {
    return { decision: "deny", reason: `${approver} may not approve for ${subject}` };
  }
  const writes = new Set(rule.write_actions);
  const evaluated = [...inputs.authority, ...(inputs.ceiling ?? [])];
  if (evaluated.some((e) => e.actions.some((a) => writes.has(a))) && (subject === approver || !grants?.write)) {
    return { decision: "deny", reason: "write-bearing authority needs a distinct Approver holding write" };
  }
  const floor = evaluateApprovalFloor(
    rule.floor,
    evaluated,
    { acr: inputs.authentication.acr, auth_time: inputs.authentication.auth_time },
    { interactive: inputs.authentication.interactive, nowSeconds: Math.floor(nowMs / 1000) },
  );
  if (floor.outcome === "refused") return { decision: "deny", reason: floor.reason };
  return { decision: "approve" };
}

/** The `approval_policy` reference of a registered rule version. */
export function directApprovalRuleRef(issuer: string, rule: RegisteredDirectApprovalRule): { id: string; version: string; digest: string } {
  return { id: rule.id, version: rule.version, digest: approvalPolicyDigest(issuer, rule) };
}

/** The accountable `human` assertion's identifier. */
export const DIRECT_ASSERTION_ID = "ast_human";

/** The unsigned record of a direct approval the rule approved. */
export function buildDirectApprovalRecord(
  mission: MissionRecord,
  ruleRef: { id: string; version: string; digest: string },
  inputs: DirectApprovalInputs,
): UnsignedApprovalGovernanceRecord {
  const human: AgrAssertion = {
    assertion_id: DIRECT_ASSERTION_ID,
    principal: inputs.approver,
    kind: "human",
    decision: "approve",
    decided_at: mission.created_at,
    authority: { auth_time: new Date(inputs.authentication.auth_time * 1000).toISOString(), acr: inputs.authentication.acr },
  };
  return {
    approval_event_id: mission.approval_event_id,
    mission: { issuer: mission.issuer, intent_hash: mission.intent_hash, authority_hash: mission.authority_hash },
    approval_policy: ruleRef,
    assertions: [human],
    evaluation: { decision: "approved", evaluated_at: mission.created_at, contributing: [DIRECT_ASSERTION_ID] },
  };
}

/**
 * @spec approval-governance#accountable-assertion, approval-governance#issuance-relationship:
 * the commit gate for a direct record: well-formed, approving assertions;
 * exactly one `human` approve assertion of `consent_principal`, counted; its
 * kind equal to the basis's `adjudication.kind`; and `approval_policy` the
 * rule version the issuer holds.
 */
export function assertDirectApprovalRecord(
  record: UnsignedApprovalGovernanceRecord,
  basis: ApprovalBasisDirect,
  ruleRef: { id: string; version: string; digest: string },
): AgrAssertion {
  const fail = (why: string): never => {
    throw new ApprovalGovernanceError(`direct record: ${why}`);
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
  const p = record.approval_policy;
  if (p.id !== ruleRef.id || p.version !== ruleRef.version || p.digest !== ruleRef.digest) {
    fail("approval_policy is not the direct approval rule this issuer holds");
  }
  if (record.evaluation.decision !== "approved") fail("evaluation did not approve");
  try {
    assertContributing(record);
  } catch (e) {
    fail((e as Error).message);
  }
  let accountable: AgrAssertion | undefined;
  try {
    accountable = assertAccountableApprover(record, basis);
  } catch (e) {
    fail((e as Error).message);
  }
  const a = accountable as AgrAssertion;
  if (basis.adjudication && basis.adjudication.kind !== a.kind) fail("the accountable assertion's kind is not adjudication.kind");
  if (!record.evaluation.contributing.includes(a.assertion_id)) fail("the evaluation does not count the accountable assertion");
  return a;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS direct_approval_rules (
  issuer TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  content_type TEXT NOT NULL,
  content BLOB NOT NULL,
  PRIMARY KEY (issuer, policy_id, version, digest)
) STRICT;
CREATE TABLE IF NOT EXISTS direct_approval_inputs (
  approval_event_id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL UNIQUE,
  inputs_json TEXT NOT NULL
) STRICT;
`;

/**
 * @spec approval-governance#approval-policy: the retained rule snapshots (kept
 * with no pruning, so every Mission's audit horizon is covered) and the inputs
 * each recorded direct approval evaluated, on the kernel database.
 */
export class DirectApprovalRecordStore {
  constructor(private readonly db: Database) {
    db.exec(SCHEMA);
  }

  /** Retain the rule snapshot and the evaluated inputs; only inside the Mission's creation transaction. */
  retainInCallerTx(
    missionId: string,
    issuer: string,
    ruleRef: { id: string; version: string; digest: string },
    rule: RegisteredDirectApprovalRule,
    inputs: DirectApprovalInputs,
  ): void {
    if (!this.db.inTransaction) throw new Error("direct approval evidence is retained only in the Mission's creation transaction");
    this.db
      .prepare(
        "INSERT OR IGNORE INTO direct_approval_rules (issuer, policy_id, version, digest, content_type, content) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(issuer, ruleRef.id, ruleRef.version, ruleRef.digest, rule.content_type, Buffer.from(rule.content, "utf8"));
    this.db
      .prepare("INSERT INTO direct_approval_inputs (approval_event_id, mission_id, inputs_json) VALUES (?, ?, ?)")
      .run(inputs.approval_event_id, missionId, JSON.stringify(inputs));
  }

  ruleSnapshot(issuer: string, ref: { id: string; version: string; digest: string }): { content_type: string; content: Uint8Array } | undefined {
    const row = this.db
      .prepare(
        "SELECT content_type, content FROM direct_approval_rules WHERE issuer = ? AND policy_id = ? AND version = ? AND digest = ?",
      )
      .get(issuer, ref.id, ref.version, ref.digest) as { content_type: string; content: Buffer } | undefined;
    return row ? { content_type: row.content_type, content: new Uint8Array(row.content) } : undefined;
  }

  /** The approval event the inputs were retained under, and the inputs. */
  inputs(missionId: string): { approval_event_id: string; inputs: DirectApprovalInputs } | undefined {
    const row = this.db.prepare("SELECT approval_event_id, inputs_json FROM direct_approval_inputs WHERE mission_id = ?").get(missionId) as
      | { approval_event_id: string; inputs_json: string }
      | undefined;
    return row ? { approval_event_id: row.approval_event_id, inputs: JSON.parse(row.inputs_json) as DirectApprovalInputs } : undefined;
  }
}

const samePrincipal = (a: { iss: string; sub: string }, b: { iss: string; sub: string }): boolean => a.iss === b.iss && a.sub === b.sub;

const isAuthentication = (a: unknown): a is DirectApprovalAuthentication =>
  isObject(a) && typeof a.acr === "string" && a.acr.length > 0 && Number.isSafeInteger(a.auth_time) && typeof a.interactive === "boolean";

/**
 * @spec approval-governance#re-check: steps 2 to 6 for a verified direct
 * record. (2) the retained rule snapshot reproduces `approval_policy.digest`;
 * (3) no separate evaluator decides a direct approval; (4) the retained inputs
 * are bound to this event and Intent, name this Mission's Approver and
 * Subject, the authority source its retained binding names and the ceiling it
 * consented, and record a well-formed authentication; (5) the replay of the
 * rule over the inputs at `evaluation.evaluated_at` (bound in step 1 to the
 * Mission's creation) approves the committed Authority Set, the record
 * passes the commit gate, its human assertion carries the authentication the
 * inputs record, and `contributing` is exactly that assertion; (6)
 * policy-approval recency does not apply to a `human` assertion, whose
 * `decided_at` is the approval instant itself.
 */
export function recheckDirectApprovalRecord(
  store: DirectApprovalRecordStore,
  sourceBinding: { rootId: string } | undefined,
  mission: MissionRecord,
  record: ApprovalGovernanceRecord,
):
  | { rechecked: true }
  | { rechecked: false; step: 2 | 4 | 5; reason: string } {
  const no = (step: 2 | 4 | 5, reason: string) => ({ rechecked: false as const, step, reason });
  const basis = mission.approval_basis as ApprovalBasisDirect;
  const snapshot = store.ruleSnapshot(mission.issuer, record.approval_policy);
  if (!snapshot) return no(2, "the rule snapshot the record names is not retained");
  if (approvalPolicyDigest(mission.issuer, snapshot) !== record.approval_policy.digest) {
    return no(2, "the retained rule snapshot does not reproduce approval_policy.digest");
  }
  let rule: DirectApprovalRule;
  try {
    rule = parseDirectApprovalRule(snapshot.content);
  } catch {
    return no(2, "the retained rule snapshot is not a direct approval rule");
  }
  const retained = store.inputs(mission.id);
  if (!retained) return no(4, "no recorded inputs to replay");
  const inputs = retained.inputs;
  if (
    retained.approval_event_id !== record.approval_event_id ||
    inputs.approval_event_id !== record.approval_event_id ||
    inputs.intent_hash !== record.mission.intent_hash
  ) {
    return no(4, "the recorded inputs are not bound to this approval event and Intent");
  }
  if (!samePrincipal(inputs.approver, basis.consent_principal) || !samePrincipal(inputs.subject, mission.subject)) {
    return no(4, "the recorded inputs do not name this Mission's Approver and Subject");
  }
  // The inputs carry what the Mission committed: the authority source its
  // retained binding names, and the ceiling it consented.
  if (!sourceBinding || inputs.source_root !== sourceBinding.rootId) {
    return no(4, "the recorded inputs do not name the Mission's authority source");
  }
  if (canonicalize((inputs.ceiling ?? null) as JsonValue) !== canonicalize((mission.authority_ceiling ?? null) as unknown as JsonValue)) {
    return no(4, "the recorded inputs do not carry the Mission's consented ceiling");
  }
  if (!isAuthentication(inputs.authentication)) return no(4, "the recorded authentication is malformed");
  let accountable: AgrAssertion;
  try {
    accountable = assertDirectApprovalRecord(record, basis, record.approval_policy);
  } catch (e) {
    return no(5, (e as Error).message);
  }
  const auth = accountable.authority as { auth_time?: unknown; acr?: unknown };
  if (auth.acr !== inputs.authentication.acr || auth.auth_time !== new Date(inputs.authentication.auth_time * 1000).toISOString()) {
    return no(5, "the human assertion is not the authentication the inputs record");
  }
  const decision = evaluateDirectApprovalRule(rule, inputs, record.evaluation.evaluated_at);
  if (decision.decision !== "approve") return no(5, `the replay does not approve: ${decision.reason}`);
  if (authorityHash(mission.issuer, inputs.authority as never) !== mission.authority_hash) {
    return no(5, "the replay approves a different Authority Set");
  }
  const contributing = record.evaluation.contributing;
  if (contributing.length !== 1 || contributing[0] !== accountable.assertion_id) {
    return no(5, "contributing is not the set the replay counts");
  }
  return { rechecked: true };
}
