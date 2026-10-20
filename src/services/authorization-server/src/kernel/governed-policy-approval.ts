/**
 * @spec approval-governance#governed-policy, approval-governance#governed-policy-root,
 * approval-governance#governed-policy-record, approval-governance#governed-policy-activation
 *: the `governed_policy` standing-consent basis. An accountable human approves
 * a bounded policy version (the consented root) once; that policy then
 * activates eligible Mission proposals with no fresh human decision per
 * instance, each activation committing a signed Approval Governance Record
 * with the Mission.
 *
 * Not to be confused with an `organizational` authority source's
 * `authority_source.policy` (typ `mission-governed-policy`), which bounds
 * WHOSE authority a Mission draws on. The root here decides WHETHER an
 * instance activates, and commits under typ `mission-approval-policy`.
 *
 * Default off: a kernel constructed without
 * {@link GovernedPolicyApprovalConfig} records no consent and activates
 * nothing under this basis.
 *
 * Three kinds of state, each from trusted sources only:
 * - CONFIGURATION ({@link GovernedPolicyApprovalConfig}): the roots this
 *   issuer currently holds (eligibility, like the activation policy registry)
 *   and the humans authorized to approve each.
 * - RETAINED GOVERNANCE STATE ({@link GovernedPolicyConsentStore}): each
 *   human approval of an exact root version, with the root's bytes and an
 *   issuer attestation over the consent (the human, the root digest, and the
 *   approval instant), so a row edited at rest no longer verifies.
 * - RECORDED INPUTS: what the deciding policy evaluated for each activation,
 *   retained with the Mission so re-evaluating the recorded version over them
 *   reproduces the decision.
 *
 * A model's output is only ever a recorded input: it can refuse an
 * activation or narrow the authority activated, never supply authority or
 * decide the approval.
 */

import { randomBytes, verify } from "node:crypto";
import {
  type ActivationPolicyRef,
  approvalPolicyDigest,
  authorityHash,
  canonicalize,
  entryOverlapsResource,
  intentHash,
  isActivationPolicyRef,
  isAuthorityEntry,
  type JsonValue,
  proposalHash,
} from "@mission/core";
import { UniqueViolationError, withTransaction, type Database } from "@mission/store";
import { type RegisteredActivationPolicy, verifiedActivationPolicy } from "./activation-policy.js";
import {
  type AgrAssertion,
  type ApprovalGovernanceRecord,
  assertGovernedPolicyRecord,
  signApprovalGovernanceRecord,
  type UnsignedApprovalGovernanceRecord,
} from "./approval-governance.js";
import { AUTHORITY_SOURCE_TYPES, isAuthoritySourceType } from "./authority-source.js";
import {
  type CapabilitySourceResolution,
  type CapabilitySourceResolver,
  resolveFreshCapabilitySources,
} from "./capability-binding.js";
import { deriveAuthoritySetWithProvenance, isSubsetSet } from "./derive.js";
import { inheritChildActorOrigins } from "./child-actor-eligibility.js";
import { inheritOrigins, type RetainedOrigin } from "./eligibility-provenance.js";
import { IntentError } from "./intent.js";
import type { MissionKernel } from "./kernel.js";
import { newMissionId } from "./mission-id.js";
import type {
  ApprovalBasisGovernedPolicy,
  AuthorityEntry,
  AuthoritySourceType,
  IntentSubmissionEvidenceFact,
  MissionIntent,
  MissionRecord,
} from "./types.js";

// ---------------------------------------------------------------------------
// The consented root and the deterministic rules.
// ---------------------------------------------------------------------------

/**
 * @spec mission#approval-authentication, approval-governance#policy-approval-recency:
 * the high-risk action classes, under the deployment's classification. The
 * fourth high-risk class, a consumption bound, is carried by a Mission Intent
 * member this Authorization Server's closed Intent does not admit, so no
 * activation here can carry one.
 */
export type HighRiskClass = "irreversible_action" | "external_commitment" | "privileged_administration";
export const HIGH_RISK_CLASSES: readonly HighRiskClass[] = [
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
];

/** The classification an action the root positively classifies as not high-risk carries. */
export const STANDARD_CLASS = "standard";

/**
 * The deterministic decision rules a deciding policy carries: the root's own
 * `rules`, or a separate evaluator's whole snapshot. Pure over the recorded
 * inputs, so the same version over the same inputs reproduces the decision.
 */
export interface GovernedPolicyRules {
  /** Refuse when the activated set has more entries than this. */
  max_entries?: number;
  /** Refuse when the activated set carries any of these actions. */
  refuse_actions?: string[];
  /** Refuse an Intent without a `purpose`. */
  require_purpose?: boolean;
  /**
   * The model outputs this policy consults, each by model `id` and `version`.
   * Each is REQUIRED: an activation without exactly one bound output from each
   * is refused. An output from any other model is not an input.
   */
  models?: Array<{ id: string; version: string }>;
}

/**
 * @spec approval-governance#governed-policy-root: the consented root's
 * content: the eligible clients, Subjects and sources, the authority ceiling
 * and lifetime limit, the decision rules (or the separate evaluator that
 * decides), the recency ceilings, clock skew and class-named exceptions, and
 * the deployment's complete classification of actions: each action is
 * `standard` or one or more high-risk classes. A closed JSON object; the
 * snapshot bytes are what `approval_policy.digest` commits.
 */
export interface GovernedPolicyRoot {
  admits: {
    clients: string[];
    /** Subjects, as subject strings of this kernel's principal namespace. */
    subjects: string[];
    authority_sources: AuthoritySourceType[];
  };
  authority_ceiling: AuthorityEntry[];
  lifetime: { max_lifetime_s: number };
  /** Present exactly when the root itself decides. */
  rules?: GovernedPolicyRules;
  /** Present exactly when a separate evaluator decides: its activation policy reference. */
  evaluator?: ActivationPolicyRef;
  recency: {
    /** Per consequence class; `default` applies to every activation. */
    ceilings: { default: number } & Partial<Record<HighRiskClass, number>>;
    clock_skew_s: number;
    /** Class-named exceptions admitting a `policy` accountable assertion for that high-risk class. */
    exceptions?: Partial<Record<HighRiskClass, { max_age_s: number }>>;
  };
  /**
   * REQUIRED and complete: every action an activation proposes or derives is
   * listed under `standard` or under a high-risk class. An unlisted action is
   * refused, never treated as low-risk.
   */
  classification: Partial<Record<typeof STANDARD_CLASS | HighRiskClass, string[]>>;
}

/** Bounded so a root cannot declare an unbounded clock skew. */
const MAX_CLOCK_SKEW_S = 300;

/** A configuration or document fault, never a request refusal. */
export class GovernedPolicyConfigError extends Error {}

const isObj = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);
const isStrings = (v: unknown, nonEmpty = true): v is string[] =>
  Array.isArray(v) && (!nonEmpty || v.length > 0) && v.every((s) => typeof s === "string" && s.length > 0);
const isPosInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v > 0;

function closed(where: string, o: Record<string, unknown>, allowed: readonly string[]): void {
  for (const k of Object.keys(o)) {
    if (!allowed.includes(k)) throw new GovernedPolicyConfigError(`${where}: unknown member '${k}'`);
  }
}

/** Validate the deterministic rules object (a root's `rules`, or an evaluator snapshot). */
export function parseGovernedPolicyRules(raw: unknown, where = "rules"): GovernedPolicyRules {
  if (!isObj(raw)) throw new GovernedPolicyConfigError(`${where} must be an object`);
  closed(where, raw, ["max_entries", "refuse_actions", "require_purpose", "models"]);
  if (raw.max_entries !== undefined && !isPosInt(raw.max_entries)) {
    throw new GovernedPolicyConfigError(`${where}.max_entries must be a positive integer`);
  }
  if (raw.refuse_actions !== undefined && !isStrings(raw.refuse_actions, false)) {
    throw new GovernedPolicyConfigError(`${where}.refuse_actions must be an array of strings`);
  }
  if (raw.require_purpose !== undefined && typeof raw.require_purpose !== "boolean") {
    throw new GovernedPolicyConfigError(`${where}.require_purpose must be a boolean`);
  }
  if (raw.models !== undefined) {
    if (
      !Array.isArray(raw.models) ||
      !raw.models.every(
        (m) => isObj(m) && Object.keys(m).length === 2 && typeof m.id === "string" && m.id.length > 0 &&
          typeof m.version === "string" && m.version.length > 0,
      )
    ) {
      throw new GovernedPolicyConfigError(`${where}.models must be an array of {id, version}`);
    }
  }
  return raw as GovernedPolicyRules;
}

/**
 * @spec approval-governance#governed-policy-root: parse and validate a root
 * snapshot's content. Exactly one of `rules` and `evaluator`: the deciding
 * policy is the root itself or the one evaluator it commits, never another.
 */
export function parseGovernedPolicyRoot(content: string | Uint8Array): GovernedPolicyRoot {
  let raw: unknown;
  try {
    raw = JSON.parse(typeof content === "string" ? content : Buffer.from(content).toString("utf8"));
  } catch {
    throw new GovernedPolicyConfigError("root snapshot is not JSON");
  }
  if (!isObj(raw)) throw new GovernedPolicyConfigError("root must be an object");
  closed("root", raw, ["admits", "authority_ceiling", "lifetime", "rules", "evaluator", "recency", "classification"]);
  const admits = raw.admits;
  if (!isObj(admits)) throw new GovernedPolicyConfigError("root.admits must be an object");
  closed("root.admits", admits, ["clients", "subjects", "authority_sources"]);
  if (!isStrings(admits.clients) || !isStrings(admits.subjects)) {
    throw new GovernedPolicyConfigError("root.admits.clients and subjects must be non-empty string arrays");
  }
  if (!Array.isArray(admits.authority_sources) || admits.authority_sources.length === 0 ||
      !admits.authority_sources.every(isAuthoritySourceType)) {
    throw new GovernedPolicyConfigError(
      `root.admits.authority_sources must be a non-empty array of ${AUTHORITY_SOURCE_TYPES.join(", ")}`,
    );
  }
  if (!Array.isArray(raw.authority_ceiling) || raw.authority_ceiling.length === 0 ||
      !raw.authority_ceiling.every(isAuthorityEntry)) {
    throw new GovernedPolicyConfigError("root.authority_ceiling must be a non-empty Authority Set");
  }
  if (!isObj(raw.lifetime) || !isPosInt(raw.lifetime.max_lifetime_s) || Object.keys(raw.lifetime).length !== 1) {
    throw new GovernedPolicyConfigError("root.lifetime must be {max_lifetime_s} with a positive integer");
  }
  if ((raw.rules === undefined) === (raw.evaluator === undefined)) {
    throw new GovernedPolicyConfigError("root carries exactly one of rules and evaluator");
  }
  if (raw.rules !== undefined) parseGovernedPolicyRules(raw.rules, "root.rules");
  if (raw.evaluator !== undefined && !isActivationPolicyRef(raw.evaluator)) {
    throw new GovernedPolicyConfigError("root.evaluator must be an activation policy reference");
  }
  const recency = raw.recency;
  if (!isObj(recency)) throw new GovernedPolicyConfigError("root.recency must be an object");
  closed("root.recency", recency, ["ceilings", "clock_skew_s", "exceptions"]);
  const ceilings = recency.ceilings;
  if (!isObj(ceilings) || !isPosInt(ceilings.default)) {
    throw new GovernedPolicyConfigError("root.recency.ceilings.default must be a positive integer");
  }
  closed("root.recency.ceilings", ceilings, ["default", ...HIGH_RISK_CLASSES]);
  for (const c of HIGH_RISK_CLASSES) {
    if (ceilings[c] !== undefined && !isPosInt(ceilings[c])) {
      throw new GovernedPolicyConfigError(`root.recency.ceilings.${c} must be a positive integer`);
    }
  }
  const skew = recency.clock_skew_s;
  if (typeof skew !== "number" || !Number.isInteger(skew) || skew < 0 || skew > MAX_CLOCK_SKEW_S) {
    throw new GovernedPolicyConfigError(`root.recency.clock_skew_s must be an integer from 0 to ${MAX_CLOCK_SKEW_S}`);
  }
  if (recency.exceptions !== undefined) {
    if (!isObj(recency.exceptions)) throw new GovernedPolicyConfigError("root.recency.exceptions must be an object");
    closed("root.recency.exceptions", recency.exceptions, HIGH_RISK_CLASSES);
    for (const [c, e] of Object.entries(recency.exceptions)) {
      if (!isObj(e) || !isPosInt(e.max_age_s) || Object.keys(e).length !== 1) {
        throw new GovernedPolicyConfigError(`root.recency.exceptions.${c} must be {max_age_s}`);
      }
    }
  }
  // The classification is REQUIRED: an action it does not name is unknown,
  // and an activation never treats an unknown action as low-risk. An action
  // named both `standard` and high-risk is ambiguous and refused here.
  if (!isObj(raw.classification)) throw new GovernedPolicyConfigError("root.classification must be an object");
  closed("root.classification", raw.classification, [STANDARD_CLASS, ...HIGH_RISK_CLASSES]);
  for (const [c, actions] of Object.entries(raw.classification)) {
    if (!isStrings(actions)) throw new GovernedPolicyConfigError(`root.classification.${c} must list actions`);
  }
  const standard = new Set((raw.classification[STANDARD_CLASS] as string[] | undefined) ?? []);
  for (const c of HIGH_RISK_CLASSES) {
    const both = ((raw.classification[c] as string[] | undefined) ?? []).find((a) => standard.has(a));
    if (both !== undefined) {
      throw new GovernedPolicyConfigError(`root.classification names ${both} both standard and ${c}`);
    }
  }
  return raw as unknown as GovernedPolicyRoot;
}

/**
 * @spec approval-governance#governed-policy: the deployment's governed
 * policy configuration. Trusted configuration, never assembled from a request.
 */
export interface GovernedPolicyApprovalConfig {
  /**
   * The roots this issuer currently holds, keyed by root `id`: the CURRENT
   * eligibility source, like the activation policy registry. A changed version
   * or changed bytes under an unchanged version is no longer the root a human
   * approved, and removing an `id` retires it.
   */
  roots: Readonly<Record<string, RegisteredActivationPolicy>>;
  /**
   * Per root `id`, the humans (subject strings of the kernel's principal
   * namespace) authorized to approve that root. Read at consent and again at
   * every activation, so revoking an approver's authority stops later
   * activations under their consent.
   */
  approvers: Readonly<Record<string, readonly string[]>>;
}

/** Validate the configuration at kernel construction: every root parses and has approvers. */
export function validateGovernedPolicyApprovalConfig(config: GovernedPolicyApprovalConfig): void {
  if (!isObj(config) || !isObj(config.roots) || !isObj(config.approvers)) {
    throw new GovernedPolicyConfigError("governed policy configuration needs roots and approvers");
  }
  for (const [id, root] of Object.entries(config.roots)) {
    if (!isObj(root) || typeof root.version !== "string" || root.version.length === 0 ||
        typeof root.content_type !== "string" || typeof root.content !== "string") {
      throw new GovernedPolicyConfigError(`governed policy root '${id}' must carry version, content_type, and content`);
    }
    parseGovernedPolicyRoot(root.content);
    if (!isStrings(config.approvers[id])) {
      throw new GovernedPolicyConfigError(`governed policy root '${id}' declares no authorized approver`);
    }
  }
}

/**
 * @spec approval-governance#governed-policy-activation, mission#standing-consent-bases
 *: one model's output, recorded with the model's identifier and version and
 * bound to the activation it was produced for: the approval event, the Intent
 * commitment, and the commitment over the Authority Set it evaluated. It can
 * refuse, or narrow by removal; it has no member that adds authority.
 */
export interface RecordedModelOutput {
  model: { id: string; version: string };
  approval_event_id: string;
  intent_hash: string;
  /** `authority_hash` over the bounded set the model evaluated. */
  authority_hash: string;
  verdict: "no_objection" | "refuse";
  /** Narrowing by removal: a whole resource (no `actions`), or those actions. */
  remove?: Array<{ resource: string; actions?: string[] }>;
  reason?: string;
}

/** The inputs a deciding policy evaluates, recorded with the activation. */
export interface GovernedPolicyInputs {
  client_id: string;
  subject: { iss: string; sub: string };
  authority_source: AuthoritySourceType;
  intent_hash: string;
  purpose_present: boolean;
  /** The set bounded by the deployment policy, the root ceiling, and the source. */
  authority: AuthorityEntry[];
  /** Only the outputs bound to this activation that the policy consults. */
  model_outputs: RecordedModelOutput[];
}

export type GovernedPolicyDecision =
  | { decision: "approve"; authority: AuthorityEntry[] }
  | { decision: "deny"; reason: string };

/**
 * Remove the named resources or actions; never adds an entry or an action.
 *
 * @spec resource-access#resource-matching, resource-access#subset (#1440): a
 * removal pairs with every entry whose resource set overlaps the resource it
 * names, through the shared matcher ({@link entryOverlapsResource}): an entry
 * naming it, an entry within its tree, and a `prefix` entry whose base
 * contains it. An entry containing the removed resource cannot be split, so
 * the removal applies to the whole entry. That over-removes, which only
 * narrows, where pairing by string equality would leave a descendant's
 * authority standing.
 */
function removeAuthority(
  set: readonly AuthorityEntry[],
  removals: ReadonlyArray<{ resource: string; actions?: string[] }>,
): AuthorityEntry[] {
  const out: AuthorityEntry[] = [];
  for (const entry of set) {
    const hits = removals.filter((r) => entryOverlapsResource(entry, r.resource));
    if (hits.some((r) => r.actions === undefined)) continue;
    const drop = new Set(hits.flatMap((r) => r.actions ?? []));
    const actions = entry.actions.filter((a) => !drop.has(a));
    if (actions.length === 0) continue;
    out.push(actions.length === entry.actions.length ? entry : { ...entry, actions });
  }
  return out;
}

const sameModel = (a: { id: string; version: string }, b: { id: string; version: string }): boolean =>
  a.id === b.id && a.version === b.version;

/**
 * @spec approval-governance#governed-policy-activation (step 6): evaluate the
 * deciding policy's rules over the recorded inputs. Pure: no clock, no
 * request, no state, so the recorded version over the recorded inputs always
 * reproduces the decision. Every consulted model must have contributed
 * exactly one output; a `refuse` verdict denies; a `remove` narrows. The
 * result is never wider than the input set.
 */
export function evaluateGovernedPolicyRules(
  rules: GovernedPolicyRules,
  inputs: GovernedPolicyInputs,
): GovernedPolicyDecision {
  let authority = inputs.authority;
  for (const model of rules.models ?? []) {
    const outputs = inputs.model_outputs.filter((o) => sameModel(o.model, model));
    if (outputs.length !== 1) return { decision: "deny", reason: "model_input_missing" };
    const [output] = outputs as [RecordedModelOutput];
    if (output.verdict !== "no_objection") return { decision: "deny", reason: "model_refused" };
    if (output.remove?.length) authority = removeAuthority(authority, output.remove);
  }
  if (authority.length === 0) return { decision: "deny", reason: "nothing_activated" };
  if (rules.require_purpose && !inputs.purpose_present) return { decision: "deny", reason: "purpose_required" };
  const refused = new Set(rules.refuse_actions ?? []);
  if (authority.some((e) => e.actions.some((a) => refused.has(a)))) {
    return { decision: "deny", reason: "refused_action" };
  }
  if (rules.max_entries !== undefined && authority.length > rules.max_entries) {
    return { decision: "deny", reason: "too_many_entries" };
  }
  return { decision: "approve", authority };
}

/**
 * The high-risk classes an Authority Set carries under the root's
 * classification. Only meaningful over a set {@link unclassifiedActions}
 * found complete: an action no class names is unknown, not low-risk.
 */
export function classifyHighRisk(
  set: readonly AuthorityEntry[],
  classification: GovernedPolicyRoot["classification"],
): HighRiskClass[] {
  return HIGH_RISK_CLASSES.filter((c) => {
    const actions = new Set(classification[c] ?? []);
    return set.some((e) => e.actions.some((a) => actions.has(a)));
  });
}

/**
 * @spec approval-governance#policy-approval-recency: the actions of these
 * sets the root's classification does not name, under `standard` or a
 * high-risk class. An activation refuses any, rather than reading an unknown
 * action as one that needs no exception.
 */
export function unclassifiedActions(
  sets: ReadonlyArray<readonly AuthorityEntry[]>,
  classification: GovernedPolicyRoot["classification"],
): string[] {
  const known = new Set(Object.values(classification).flatMap((actions) => actions ?? []));
  const unknown = new Set<string>();
  for (const set of sets) for (const e of set) for (const a of e.actions) if (!known.has(a)) unknown.add(a);
  return [...unknown].sort();
}

// ---------------------------------------------------------------------------
// Retained governance state.
// ---------------------------------------------------------------------------

/**
 * Why an activation (or a consent) is refused. LOCAL to this module: none is
 * a protocol error code, and none is added to any draft's enumeration.
 */
export type GovernedPolicyRefusal =
  | "not_configured"
  | "approver_not_authorized"
  | "root_not_held"
  | "consent_unavailable"
  | "consent_withdrawn"
  | "consent_unauthenticated"
  | "root_changed"
  | "root_digest_mismatch"
  | "evaluator_changed"
  | "client_not_admitted"
  | "subject_not_admitted"
  | "source_not_admitted"
  | "out_of_root_ceiling"
  | "policy_refused"
  | "approval_in_future"
  | "recency_exceeded"
  | "high_risk_without_exception"
  | "approval_event_used"
  | "unclassified_action";

export class GovernedPolicyError extends Error {
  constructor(
    readonly code: GovernedPolicyRefusal,
    message: string,
    /** The deciding policy's own reason, for `policy_refused`. */
    readonly reason?: string,
  ) {
    super(message);
  }
}

/** A retained human approval of one exact root version. */
export interface GovernedPolicyConsent {
  consent_id: string;
  issuer: string;
  /** The consented root: `id`, `version`, and its `mission-approval-policy` digest. */
  root: ActivationPolicyRef;
  approver: { iss: string; sub: string };
  /** The issuer's own instant at the human's approval, never a caller's value. */
  approved_at: string;
  /** The governance event the human approved the root at; never a Mission's approval event. */
  consent_event_id: string;
  /** Issuer-signed JWS over the consent members above. */
  attestation: string;
  withdrawn_at?: string;
}

/** The members an attestation commits, in a fixed shape. */
const attested = (c: Omit<GovernedPolicyConsent, "attestation" | "withdrawn_at">): JsonValue => ({
  consent_id: c.consent_id,
  issuer: c.issuer,
  root: { id: c.root.id, version: c.root.version, digest: c.root.digest },
  approver: { iss: c.approver.iss, sub: c.approver.sub },
  approved_at: c.approved_at,
  consent_event_id: c.consent_event_id,
});

const CONSENT_ATTESTATION_TYP = "mission-governed-policy-consent+jws";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS governed_policy_roots (
  issuer TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  content_type TEXT NOT NULL,
  content BLOB NOT NULL,
  PRIMARY KEY (issuer, policy_id, version, digest)
) STRICT;
CREATE TABLE IF NOT EXISTS governed_policy_consents (
  consent_id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  approver_iss TEXT NOT NULL,
  approver_sub TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  consent_event_id TEXT NOT NULL UNIQUE,
  attestation TEXT NOT NULL,
  withdrawn_at TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS governed_policy_activations (
  approval_event_id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL UNIQUE,
  consent_id TEXT NOT NULL,
  deciding_json TEXT NOT NULL,
  inputs_json TEXT NOT NULL,
  capability_resolutions_json TEXT
) STRICT;
`;

/**
 * @spec approval-governance#governed-policy-root: the retained, authenticated
 * governance state on the kernel database: the consented roots' bytes (under
 * their `mission-approval-policy` digest, kept with no pruning, so every
 * Mission's audit horizon is covered), the human consents to them, and each
 * activation's recorded inputs. Rows are written only through the functions
 * below; nothing here reads a request.
 */
export class GovernedPolicyConsentStore {
  constructor(private readonly db: Database) {
    this.db.exec(SCHEMA);
  }

  /** A consent by identifier, or undefined. */
  get(consentId: string): GovernedPolicyConsent | undefined {
    const row = this.db.prepare("SELECT * FROM governed_policy_consents WHERE consent_id = ?").get(consentId) as
      | Record<string, unknown>
      | undefined;
    return row ? consentOf(row) : undefined;
  }

  /** The consent recorded for a governance event, or undefined. */
  byConsentEvent(consentEventId: string): GovernedPolicyConsent | undefined {
    const row = this.db
      .prepare("SELECT * FROM governed_policy_consents WHERE consent_event_id = ?")
      .get(consentEventId) as Record<string, unknown> | undefined;
    return row ? consentOf(row) : undefined;
  }

  /** Consents not withdrawn, in a fixed order (latest approval first, then identifier). */
  standing(): GovernedPolicyConsent[] {
    return (
      this.db
        .prepare(
          "SELECT * FROM governed_policy_consents WHERE withdrawn_at IS NULL ORDER BY approved_at DESC, consent_id",
        )
        .all() as Record<string, unknown>[]
    ).map(consentOf);
  }

  /** The retained bytes of a consented root, or undefined. */
  rootSnapshot(issuer: string, root: ActivationPolicyRef): { content_type: string; content: Uint8Array } | undefined {
    const row = this.db
      .prepare(
        "SELECT content_type, content FROM governed_policy_roots WHERE issuer = ? AND policy_id = ? AND version = ? AND digest = ?",
      )
      .get(issuer, root.id, root.version, root.digest) as { content_type: string; content: Buffer } | undefined;
    return row ? { content_type: row.content_type, content: new Uint8Array(row.content) } : undefined;
  }

  /**
   * The recorded inputs and deciding policy of a governed activation, or
   * undefined. `capability_resolutions` is the trusted capability resolution
   * the activation applied to the decided set (null when the deployment
   * configured no resolver), retained so a re-check replays it.
   */
  activation(missionId: string):
    | {
        approval_event_id: string;
        consent_id: string;
        deciding: ActivationPolicyRef;
        inputs: GovernedPolicyInputs;
        capability_resolutions: CapabilitySourceResolution[] | null;
      }
    | undefined {
    const row = this.db.prepare("SELECT * FROM governed_policy_activations WHERE mission_id = ?").get(missionId) as
      | Record<string, string>
      | undefined;
    if (!row) return undefined;
    return {
      approval_event_id: row.approval_event_id as string,
      consent_id: row.consent_id as string,
      deciding: JSON.parse(row.deciding_json as string) as ActivationPolicyRef,
      inputs: JSON.parse(row.inputs_json as string) as GovernedPolicyInputs,
      capability_resolutions: row.capability_resolutions_json
        ? (JSON.parse(row.capability_resolutions_json) as CapabilitySourceResolution[])
        : null,
    };
  }

  insertConsent(c: GovernedPolicyConsent, snapshot: { content_type: string; content: string }): void {
    withTransaction(this.db, () => {
      this.db
        .prepare(
          `INSERT INTO governed_policy_roots (issuer, policy_id, version, digest, content_type, content)
           VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`,
        )
        .run(c.issuer, c.root.id, c.root.version, c.root.digest, snapshot.content_type, Buffer.from(snapshot.content, "utf8"));
      this.db
        .prepare(
          `INSERT INTO governed_policy_consents (consent_id, issuer, policy_id, version, digest, approver_iss,
             approver_sub, approved_at, consent_event_id, attestation)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          c.consent_id,
          c.issuer,
          c.root.id,
          c.root.version,
          c.root.digest,
          c.approver.iss,
          c.approver.sub,
          c.approved_at,
          c.consent_event_id,
          c.attestation,
        );
    });
  }

  withdraw(consentId: string, at: string): boolean {
    return (
      this.db
        .prepare("UPDATE governed_policy_consents SET withdrawn_at = ? WHERE consent_id = ? AND withdrawn_at IS NULL")
        .run(at, consentId).changes === 1
    );
  }

  retainActivationInCallerTx(row: {
    approval_event_id: string;
    mission_id: string;
    consent_id: string;
    deciding: ActivationPolicyRef;
    inputs: GovernedPolicyInputs;
    capability_resolutions: CapabilitySourceResolution[] | null;
  }): void {
    if (!this.db.inTransaction) {
      throw new Error("governed activation inputs are retained only inside the Mission's creation transaction");
    }
    this.db
      .prepare(
        `INSERT INTO governed_policy_activations (approval_event_id, mission_id, consent_id, deciding_json, inputs_json,
           capability_resolutions_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.approval_event_id,
        row.mission_id,
        row.consent_id,
        JSON.stringify(row.deciding),
        JSON.stringify(row.inputs),
        row.capability_resolutions ? JSON.stringify(row.capability_resolutions) : null,
      );
  }
}

function consentOf(row: Record<string, unknown>): GovernedPolicyConsent {
  return {
    consent_id: row.consent_id as string,
    issuer: row.issuer as string,
    root: { id: row.policy_id as string, version: row.version as string, digest: row.digest as string },
    approver: { iss: row.approver_iss as string, sub: row.approver_sub as string },
    approved_at: row.approved_at as string,
    consent_event_id: row.consent_event_id as string,
    attestation: row.attestation as string,
    ...(row.withdrawn_at ? { withdrawn_at: row.withdrawn_at as string } : {}),
  };
}

const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64url");

function signConsent(kernel: MissionKernel, c: Omit<GovernedPolicyConsent, "attestation" | "withdrawn_at">): string {
  const signer = kernel.statusSigner();
  const input = `${b64(canonicalize({ alg: "ES256", kid: signer.kid, typ: CONSENT_ATTESTATION_TYP }))}.${b64(canonicalize(attested(c)))}`;
  return `${input}.${signer.sign(input).toString("base64url")}`;
}

/** True when the consent row still carries the issuer's attestation over exactly its members. */
function consentAuthentic(kernel: MissionKernel, c: GovernedPolicyConsent): boolean {
  const parts = c.attestation.split(".");
  if (parts.length !== 3) return false;
  const [h, p, s] = parts as [string, string, string];
  const ok = verify(
    "sha256",
    Buffer.from(`${h}.${p}`, "utf8"),
    { key: kernel.statusVerificationKey(), dsaEncoding: "ieee-p1363" },
    Buffer.from(s, "base64url"),
  );
  return ok && Buffer.from(p, "base64url").toString("utf8") === canonicalize(attested(c));
}

function requireConfig(kernel: MissionKernel): GovernedPolicyApprovalConfig {
  const config = kernel.governedPolicyApproval();
  if (!config) throw new GovernedPolicyError("not_configured", "governed policy approval is not configured");
  return config;
}

/** Whether `approver` is a human this deployment authorizes to approve root `id`, now. */
function approverAuthorized(
  kernel: MissionKernel,
  config: GovernedPolicyApprovalConfig,
  rootId: string,
  approver: { iss: string; sub: string },
): boolean {
  const issuer = kernel.authoritySourceOptions().authoritySourceCatalog.principalIssuer;
  return approver.iss === issuer && (config.approvers[rootId] ?? []).includes(approver.sub);
}

/**
 * @spec approval-governance#governed-policy-root: record a human's approval
 * of an exact root version, from the deployment's authenticated governance
 * surface: the caller has authenticated `approver` and hands over the
 * principal, the root it approved by `id` and `version`, and the governance
 * event. The issuer refuses an approver not authorized for that root and a
 * root it does not hold at that version, mints the root's
 * `mission-approval-policy` digest over the bytes it holds, retains those
 * bytes, and stamps the approval instant from its own clock. Idempotent on
 * `consentEventId`.
 */
export function recordGovernedPolicyConsent(
  kernel: MissionKernel,
  input: { root: { id: string; version: string }; approver: { iss: string; sub: string }; consentEventId: string },
): GovernedPolicyConsent {
  const config = requireConfig(kernel);
  const approver = kernel.assertDeploymentPrincipal(input.approver, "approver");
  const existing = kernel.governedPolicyConsents.byConsentEvent(input.consentEventId);
  if (existing) return existing;
  if (!approverAuthorized(kernel, config, input.root.id, approver)) {
    throw new GovernedPolicyError(
      "approver_not_authorized",
      `${approver.sub} is not authorized to approve governed policy ${input.root.id}`,
    );
  }
  const held = Object.hasOwn(config.roots, input.root.id) ? config.roots[input.root.id] : undefined;
  if (!held || held.version !== input.root.version) {
    throw new GovernedPolicyError(
      "root_not_held",
      `governed policy ${input.root.id} version ${input.root.version} is not a root this issuer holds`,
    );
  }
  parseGovernedPolicyRoot(held.content);
  const issuer = kernel.issuerId();
  const unsigned = {
    consent_id: `gpc_${randomBytes(16).toString("base64url")}`,
    issuer,
    root: { id: input.root.id, version: held.version, digest: approvalPolicyDigest(issuer, held) },
    approver,
    approved_at: kernel.nowDate().toISOString(),
    consent_event_id: input.consentEventId,
  };
  const consent: GovernedPolicyConsent = { ...unsigned, attestation: signConsent(kernel, unsigned) };
  try {
    kernel.governedPolicyConsents.insertConsent(consent, held);
  } catch (e) {
    if (e instanceof UniqueViolationError) {
      const winner = kernel.governedPolicyConsents.byConsentEvent(input.consentEventId);
      if (winner) return winner;
    }
    throw e;
  }
  return consent;
}

/**
 * @spec approval-governance#governed-policy-activation: withdraw a standing
 * consent: every later activation under it is refused at step 1. A Mission
 * already activated keeps its ordinary lifecycle; nothing here touches one.
 */
export function withdrawGovernedPolicyConsent(kernel: MissionKernel, consentId: string): boolean {
  return kernel.governedPolicyConsents.withdraw(consentId, kernel.nowDate().toISOString());
}

// ---------------------------------------------------------------------------
// Activation.
// ---------------------------------------------------------------------------

/** One governed activation request, as the issuer hands it over (never the client). */
export interface GovernedActivationInput {
  /** The standing consent the issuer selected; a client never names one. */
  consentId: string;
  /** This instance's approval event, allocated once per pending proposal. */
  approvalEventId: string;
  intent: MissionIntent;
  proposedAuthority?: AuthorityEntry[];
  /** The authenticated client that requested this activation. */
  clientId: string;
  /** Model outputs gathered for this activation: recorded inputs only. */
  modelOutputs?: readonly RecordedModelOutput[];
  /**
   * @spec mission#intent-submission-evidence, mission#submission-processing
   * (step 8): the Intent Submission Evidence facts the issuer verified for
   * this activation, recorded on the Mission as `submission_evidence`
   * (provenance outside every anchor), as a direct approval records them.
   */
  submissionEvidence?: readonly IntentSubmissionEvidenceFact[];
}

export interface GovernedActivation {
  mission: MissionRecord;
  record: ApprovalGovernanceRecord;
}

/** The deciding policy and its rules, resolved for a consented root. */
interface Deciding {
  ref: ActivationPolicyRef;
  rules: GovernedPolicyRules;
  /** The evaluator snapshot to retain, when a separate evaluator decides. */
  evaluator?: RegisteredActivationPolicy;
}

/**
 * @spec approval-governance#governed-policy-activation: steps 1 to 3: the
 * standing consent from retained, authenticated state; the human's authority
 * over the exact root version and its approval instant; the root's digest
 * recomputed over the retained snapshot and matched against the root this
 * issuer currently holds; and a separate evaluator's digest over the exact
 * snapshot evaluated.
 */
function resolveConsentedRoot(
  kernel: MissionKernel,
  config: GovernedPolicyApprovalConfig,
  consentId: string,
): { consent: GovernedPolicyConsent; root: GovernedPolicyRoot; deciding: Deciding } {
  const issuer = kernel.issuerId();
  // Step 1.
  const consent = kernel.governedPolicyConsents.get(consentId);
  if (!consent || consent.issuer !== issuer) {
    throw new GovernedPolicyError("consent_unavailable", "no retained standing consent by that identifier");
  }
  if (consent.withdrawn_at !== undefined) {
    throw new GovernedPolicyError("consent_withdrawn", `standing consent ${consentId} was withdrawn`);
  }
  // Step 2: the retained bytes reproduce the committed digest, under the
  // root's own `mission-approval-policy` domain; the retained consent is the
  // issuer's own, unaltered (its human, root, and approval instant); its human
  // is still authorized for this root; and the root this issuer holds now is
  // exactly that root.
  const retained = kernel.governedPolicyConsents.rootSnapshot(issuer, consent.root);
  if (!retained || approvalPolicyDigest(issuer, retained) !== consent.root.digest) {
    throw new GovernedPolicyError("root_digest_mismatch", `the retained root ${consent.root.id} does not reproduce its digest`);
  }
  if (!consentAuthentic(kernel, consent)) {
    throw new GovernedPolicyError("consent_unauthenticated", `standing consent ${consentId} does not verify`);
  }
  if (!approverAuthorized(kernel, config, consent.root.id, consent.approver)) {
    throw new GovernedPolicyError(
      "approver_not_authorized",
      `${consent.approver.sub} is no longer authorized to approve governed policy ${consent.root.id}`,
    );
  }
  const held = Object.hasOwn(config.roots, consent.root.id) ? config.roots[consent.root.id] : undefined;
  if (!held || held.version !== consent.root.version || approvalPolicyDigest(issuer, held) !== consent.root.digest) {
    throw new GovernedPolicyError(
      "root_changed",
      `governed policy ${consent.root.id} is no longer the version and bytes the human approved`,
    );
  }
  const root = parseGovernedPolicyRoot(retained.content);
  // Step 3: the deciding policy is the root itself or the one evaluator it
  // commits, verified under the evaluator's own digest domain.
  if (root.evaluator) {
    const snapshot = verifiedActivationPolicy(issuer, kernel.activationPolicies(), root.evaluator);
    if (!snapshot) {
      throw new GovernedPolicyError(
        "evaluator_changed",
        `evaluator ${root.evaluator.id} no longer matches the digest the root commits`,
      );
    }
    let rules: GovernedPolicyRules;
    try {
      rules = parseGovernedPolicyRules(JSON.parse(snapshot.content), "evaluator");
    } catch {
      throw new GovernedPolicyError("evaluator_changed", `evaluator ${root.evaluator.id} is not a rules document`);
    }
    return { consent, root, deciding: { ref: root.evaluator, rules, evaluator: snapshot } };
  }
  return { consent, root, deciding: { ref: consent.root, rules: root.rules as GovernedPolicyRules } };
}

/**
 * @spec approval-governance#governed-policy-activation (step 4): the Subject
 * is established by the issuer, never taken from the client: the one Subject
 * the root admits for which this client resolves a trusted source. None, or
 * more than one, establishes nothing.
 */
function establishSubject(kernel: MissionKernel, root: GovernedPolicyRoot, clientId: string): { iss: string; sub: string } {
  const iss = kernel.authoritySourceOptions().authoritySourceCatalog.principalIssuer;
  const resolvable = root.admits.subjects.filter((sub) => {
    try {
      kernel.resolveAuthoritySource({ clientId, subject: { iss, sub } });
      return true;
    } catch {
      return false;
    }
  });
  if (resolvable.length !== 1) {
    throw new GovernedPolicyError(
      "subject_not_admitted",
      resolvable.length === 0
        ? `no Subject the root admits resolves a source for client ${clientId}`
        : `the root admits several Subjects for client ${clientId}`,
    );
  }
  return { iss, sub: resolvable[0] as string };
}

/** Steps 1 to 5, resolved once for an activation (or a preview of one). */
interface PreparedActivation {
  consent: GovernedPolicyConsent;
  root: GovernedPolicyRoot;
  deciding: Deciding;
  actor: { iss: string; sub: string };
  subject: { iss: string; sub: string };
  resolvedSource: ReturnType<MissionKernel["establishAuthoritySource"]>;
  proposal?: AuthorityEntry[];
  /** The set bounded by the deployment policy, the root ceiling, and the source. */
  bounded: AuthorityEntry[];
  /**
   * @spec resource-access#delegate-eligibility: each bounded entry's
   * eligibility origin from both derivations, index-aligned with `bounded`.
   */
  boundedProvenance: RetainedOrigin[];
  /**
   * @spec child-delegation#fanout (#1304): each bounded entry's child-actor
   * origin from both derivations, kept apart, index-aligned with `bounded`.
   */
  boundedChildActorProvenance: RetainedOrigin[];
  intentHash: string;
  boundedHash: string;
}

/**
 * @spec approval-governance#governed-policy-activation: steps 1 to 5: the
 * consented root and deciding policy (steps 1 to 3); the requesting client,
 * the issuer-established Subject, and the source, each admitted by the root,
 * with the source gates run for the consenting human as activator (step 4);
 * and the Authority Set derived under the deployment policy and the proposal,
 * then bounded by the root's authority ceiling (the template double
 * intersection), with the source ceiling refusing rather than narrowing
 * (step 5).
 */
function prepareGovernedActivation(
  kernel: MissionKernel,
  config: GovernedPolicyApprovalConfig,
  input: Pick<GovernedActivationInput, "consentId" | "intent" | "proposedAuthority" | "clientId">,
): PreparedActivation {
  const issuer = kernel.issuerId();
  // Steps 1 to 3.
  const { consent, root, deciding } = resolveConsentedRoot(kernel, config, input.consentId);
  // The activation actor is the requesting client, never the consenting human.
  const actor = { iss: issuer, sub: input.clientId };
  if (actor.iss === consent.approver.iss && actor.sub === consent.approver.sub) {
    throw new GovernedPolicyError("client_not_admitted", "the activation actor cannot be the consenting human");
  }

  // Step 4.
  if (!root.admits.clients.includes(input.clientId)) {
    throw new GovernedPolicyError("client_not_admitted", `client ${input.clientId} is not admitted by root ${consent.root.id}`);
  }
  const subject = establishSubject(kernel, root, input.clientId);
  const resolvedSource = kernel.establishAuthoritySource({ clientId: input.clientId, subject, approver: consent.approver });
  if (!root.admits.authority_sources.includes(resolvedSource.provenance.type)) {
    throw new GovernedPolicyError(
      "source_not_admitted",
      `authority source ${resolvedSource.provenance.type} is not admitted by root ${consent.root.id}`,
    );
  }

  // Step 5.
  const proposal = input.proposedAuthority?.length ? input.proposedAuthority : undefined;
  const first = kernel.deriveWithProvenance(input.intent, proposal);
  const derived = first.entries;
  // Step 7 classifies the whole derived Mission from trusted, complete
  // classification: every action proposed or derived must be one the root
  // classifies, so no unknown action reaches the activation as low-risk.
  const unknown = unclassifiedActions([proposal ?? [], derived], root.classification);
  if (unknown.length > 0) {
    throw new GovernedPolicyError(
      "unclassified_action",
      `root ${consent.root.id} does not classify ${unknown.join(", ")}`,
    );
  }
  let bounded: AuthorityEntry[];
  // @spec resource-access#delegate-eligibility: the root-ceiling derivation
  // keeps the policy derivation's origins and adds the root ceiling's.
  let boundedProvenance: RetainedOrigin[];
  let boundedChildActorProvenance: RetainedOrigin[];
  try {
    ({
      entries: bounded,
      provenance: boundedProvenance,
      childActorProvenance: boundedChildActorProvenance,
    } = deriveAuthoritySetWithProvenance(
      input.intent,
      { policy_version: consent.root.version, ceiling: root.authority_ceiling },
      derived,
      first.provenance,
      first.childActorProvenance,
    ));
  } catch (e) {
    if (e instanceof IntentError) {
      throw new GovernedPolicyError("out_of_root_ceiling", `the proposal yields no authority within root ${consent.root.id}`);
    }
    throw e;
  }
  if (!isSubsetSet(bounded, derived) || !isSubsetSet(bounded, root.authority_ceiling)) {
    throw new Error("governed activation violated the root-ceiling intersection invariant");
  }
  kernel.assertAuthorityWithinSource(resolvedSource, bounded);
  return {
    consent,
    root,
    deciding,
    actor,
    subject,
    resolvedSource,
    ...(proposal ? { proposal } : {}),
    bounded,
    boundedProvenance,
    boundedChildActorProvenance,
    intentHash: intentHash(issuer, input.intent as never),
    boundedHash: authorityHash(issuer, bounded as never),
  };
}

/**
 * @spec approval-governance#governed-policy-activation: what a model is
 * asked to evaluate for one activation: the approval event, the Intent
 * commitment, and the bounded Authority Set with its commitment. A model
 * output counts at activation only when it is bound to exactly these.
 * Running steps 1 to 5 here also refuses early what the activation would.
 */
export function previewGovernedActivation(
  kernel: MissionKernel,
  input: Pick<GovernedActivationInput, "consentId" | "approvalEventId" | "intent" | "proposedAuthority" | "clientId">,
): { approval_event_id: string; intent_hash: string; authority: AuthorityEntry[]; authority_hash: string } {
  const prepared = prepareGovernedActivation(kernel, requireConfig(kernel), input);
  return {
    approval_event_id: input.approvalEventId,
    intent_hash: prepared.intentHash,
    authority: prepared.bounded,
    authority_hash: prepared.boundedHash,
  };
}

/**
 * @spec approval-governance#governed-policy-activation: activate one Mission
 * under `governed_policy`, running the nine checks in order at the atomic
 * creation commit. A refusal at any step creates no Mission and no record.
 * Retried or concurrent activations of one approval event resolve to the one
 * Mission and the one record that event committed.
 */
export function activateGovernedPolicy(kernel: MissionKernel, input: GovernedActivationInput): GovernedActivation {
  const config = requireConfig(kernel);
  const issuer = kernel.issuerId();
  // A committed activation of this event is returned as committed: the one
  // Mission and the one record, never a second evaluation.
  const committed = committedActivation(kernel, input.approvalEventId);
  if (committed) return committed;

  // Steps 1 to 5.
  const prepared = prepareGovernedActivation(kernel, config, input);
  const { consent, root, deciding, actor, subject, resolvedSource, proposal, bounded } = prepared;
  const iHash = prepared.intentHash;
  const boundedHash = prepared.boundedHash;

  // Step 6: evaluate the deciding policy over recorded inputs. Only model
  // outputs bound to THIS approval event, Intent, and evaluated set count; an
  // output captured for another activation is not an input here.
  const createdAt = kernel.nowDate().toISOString();
  const consulted = deciding.rules.models ?? [];
  const inputs: GovernedPolicyInputs = {
    client_id: input.clientId,
    subject,
    authority_source: resolvedSource.provenance.type,
    intent_hash: iHash,
    purpose_present: typeof input.intent.purpose === "string" && input.intent.purpose.length > 0,
    authority: bounded,
    model_outputs: (input.modelOutputs ?? []).filter(
      (o) =>
        o.approval_event_id === input.approvalEventId &&
        o.intent_hash === iHash &&
        o.authority_hash === boundedHash &&
        consulted.some((m) => sameModel(m, o.model)),
    ),
  };
  const decision = evaluateGovernedPolicyRules(deciding.rules, inputs);
  if (decision.decision !== "approve") {
    throw new GovernedPolicyError("policy_refused", `the deciding policy refused: ${decision.reason}`, decision.reason);
  }
  // A model input narrows or refuses; it never widens. Structural, not trusted.
  if (!isSubsetSet(decision.authority, bounded)) {
    throw new Error("governed policy evaluation widened the bounded set");
  }
  // The trusted capability resolution runs against CURRENT trusted state, and
  // what it returned is retained with the activation so a re-check replays
  // it rather than resolving again.
  const capability = recordingResolution(kernel.authoritySourceOptions().capabilityResolver);
  const final = resolveFreshCapabilitySources(decision.authority, capability.resolver);
  // @spec resource-access#delegate-eligibility: the deciding policy may narrow
  // the bounded set, so each final entry keeps the origin of every bounded
  // entry it falls within.
  const finalProvenance = inheritOrigins(
    final,
    final.map((): RetainedOrigin => "list"),
    bounded.map((entry, i) => ({ entry, origin: prepared.boundedProvenance[i] ?? null })),
  );
  // @spec child-delegation#fanout (#1304): the child-actor origins the same way.
  const finalChildActorProvenance = inheritChildActorOrigins(
    final,
    final.map((): RetainedOrigin => "list"),
    bounded.map((entry, i) => ({ entry, origin: prepared.boundedChildActorProvenance[i] ?? null })),
  );
  const expiresAt = kernel.resolveEffectiveExpiry({
    requested: input.intent.expires_at,
    createdAt,
    ceilings: { governedPolicy: { maxLifetimeS: root.lifetime.max_lifetime_s } },
  });

  // Step 7: policy-approval recency across the whole derived Mission. The
  // evaluation instant is this creation instant.
  const nowMs = Date.parse(createdAt);
  const approvedMs = Date.parse(consent.approved_at);
  const skewMs = root.recency.clock_skew_s * 1000;
  if (approvedMs > nowMs + skewMs) {
    throw new GovernedPolicyError("approval_in_future", "the root approval instant is later than the evaluation instant");
  }
  const classes = classifyHighRisk(final, root.classification);
  let maxAgeS = root.recency.ceilings.default;
  for (const c of classes) {
    const exception = root.recency.exceptions?.[c];
    if (!exception) {
      throw new GovernedPolicyError(
        "high_risk_without_exception",
        `the Mission carries ${c} and root ${consent.root.id} commits no exception admitting a policy decision for it`,
      );
    }
    maxAgeS = Math.min(maxAgeS, exception.max_age_s, root.recency.ceilings[c] ?? Number.POSITIVE_INFINITY);
  }
  if (nowMs - approvedMs > maxAgeS * 1000) {
    throw new GovernedPolicyError(
      "recency_exceeded",
      `the root approval is older than the applicable ${maxAgeS}s ceiling`,
    );
  }

  // Step 8: the record and every assertion bind to this approval event and
  // these anchors.
  const aHash = authorityHash(issuer, final as never);
  const basis: ApprovalBasisGovernedPolicy = {
    type: "governed_policy",
    consent_principal: consent.approver,
    approved_at: consent.approved_at,
    root_commitment: consent.root.digest,
    activation: { approval_event_id: input.approvalEventId, policy: deciding.ref },
    activation_actor: actor,
    adjudication: {
      kind: "policy",
      policy: { id: deciding.ref.id, version: deciding.ref.version },
      governance_record: true,
    },
  };
  const id = newMissionId();
  const record: MissionRecord = {
    id,
    issuer,
    state: "active",
    intent: input.intent,
    ...(proposal ? { proposed_authority: proposal } : {}),
    authority_set: final,
    eligibility_provenance: finalProvenance,
    child_actor_provenance: finalChildActorProvenance,
    intent_hash: iHash,
    ...(proposal ? { proposal_hash: proposalHash(issuer, proposal as never) } : {}),
    authority_hash: aHash,
    subject,
    approval_basis: basis,
    authority_source: resolvedSource.provenance,
    client_id: input.clientId,
    policy_version: kernel.policyVersion(),
    approval_event_id: input.approvalEventId,
    created_at: createdAt,
    expires_at: expiresAt,
    version: 1,
    derivation_limit: kernel.resolveDerivationLimit(input.intent.requested_derivation_limit),
    ...(input.submissionEvidence?.length ? { submission_evidence: [...input.submissionEvidence] } : {}),
    derivation_count: 0,
    grant_id: null,
    status_list_idx: null,
  };
  const assertions: AgrAssertion[] = [
    {
      assertion_id: "ast_policy",
      principal: consent.approver,
      kind: "policy",
      decision: "approve",
      decided_at: createdAt,
      authority: { policy_id: deciding.ref.id, version: deciding.ref.version, approved_at: consent.approved_at },
    },
    ...inputs.model_outputs.map(
      (o, i): AgrAssertion => ({
        assertion_id: `ast_model_${i + 1}`,
        principal: { iss: issuer, sub: `model:${o.model.id}` },
        kind: "service",
        decision: "approve",
        decided_at: createdAt,
        // The model is the whole logic here, so the logic pair names it too.
        authority: {
          logic_id: o.model.id,
          logic_version: o.model.version,
          model_id: o.model.id,
          model_version: o.model.version,
        },
        ...(o.remove?.length ? { reason: "narrowed" } : {}),
      }),
    ),
  ];
  const unsigned: UnsignedApprovalGovernanceRecord = {
    approval_event_id: input.approvalEventId,
    mission: { issuer, intent_hash: iHash, authority_hash: aHash },
    approval_policy: consent.root,
    assertions,
    evaluation: { decision: "approved", evaluated_at: createdAt, contributing: assertions.map((a) => a.assertion_id) },
  };
  assertGovernedPolicyRecord(unsigned, basis);

  // Step 9: sign, then persist the record with the active Mission in ONE
  // commit. Any failure rolls back the Mission with it.
  let signed: ApprovalGovernanceRecord | undefined;
  try {
    withTransaction(kernel.db, () => {
      signed = signApprovalGovernanceRecord(unsigned, kernel.statusSigner());
      kernel.insertRecord(record, undefined, {
        source: resolvedSource,
        ...(deciding.evaluator ? { activationPolicies: [{ ref: deciding.ref, snapshot: deciding.evaluator }] } : {}),
      });
      kernel.governanceRecords.retainInCallerTx(id, signed);
      kernel.governedPolicyConsents.retainActivationInCallerTx({
        approval_event_id: input.approvalEventId,
        mission_id: id,
        consent_id: consent.consent_id,
        deciding: deciding.ref,
        inputs,
        capability_resolutions: capability.recorded,
      });
    });
  } catch (e) {
    if (e instanceof UniqueViolationError) {
      const winner = committedActivation(kernel, input.approvalEventId);
      if (winner) return winner;
    }
    throw e;
  }
  return { mission: record, record: signed as ApprovalGovernanceRecord };
}

/**
 * The Mission and record an approval event already committed under this
 * basis, if any. An event that already committed a Mission under another
 * basis (a `direct` approval of the same pending proposal) is refused: it
 * never becomes a `governed_policy` activation.
 */
function committedActivation(kernel: MissionKernel, approvalEventId: string): GovernedActivation | undefined {
  const mission = kernel.findByApprovalEvent(approvalEventId);
  if (!mission) return undefined;
  const record = kernel.governanceRecords.forMission(mission.id);
  if (mission.approval_basis.type !== "governed_policy" || !record) {
    throw new GovernedPolicyError(
      "approval_event_used",
      `approval event ${approvalEventId} already committed a ${mission.approval_basis.type} Mission`,
    );
  }
  return { mission, record };
}

/**
 * @spec approval-governance#governed-policy-activation (step 6): the
 * auditor's re-check: re-evaluate the recorded deciding policy version, from
 * its retained snapshot, over the recorded inputs. Reproduced when the
 * re-evaluation approves exactly the committed Authority Set.
 */
export function recheckGovernedActivation(
  kernel: MissionKernel,
  missionId: string,
): { reproduced: boolean; decision?: GovernedPolicyDecision } {
  const mission = kernel.get(missionId);
  const activation = kernel.governedPolicyConsents.activation(missionId);
  if (!mission || mission.approval_basis.type !== "governed_policy" || !activation) return { reproduced: false };
  const issuer = mission.issuer;
  const basis = mission.approval_basis;
  let rules: GovernedPolicyRules;
  if (activation.deciding.digest === basis.root_commitment) {
    const snapshot = kernel.governedPolicyConsents.rootSnapshot(issuer, activation.deciding);
    if (!snapshot || approvalPolicyDigest(issuer, snapshot) !== basis.root_commitment) return { reproduced: false };
    rules = parseGovernedPolicyRoot(snapshot.content).rules as GovernedPolicyRules;
  } else {
    const check = kernel.activationPolicySnapshots.verify(issuer, activation.deciding);
    if (check.status !== "verified") return { reproduced: false };
    rules = parseGovernedPolicyRules(JSON.parse(Buffer.from(check.snapshot.content).toString("utf8")), "evaluator");
  }
  const decision = evaluateGovernedPolicyRules(rules, activation.inputs);
  // The historical comparison replays the capability resolution retained at
  // activation; the resolver's current answer is for new activations only.
  let replayed: AuthorityEntry[] | undefined;
  if (decision.decision === "approve") {
    try {
      replayed = resolveFreshCapabilitySources(decision.authority, replayResolution(activation.capability_resolutions));
    } catch {
      replayed = undefined;
    }
  }
  const reproduced = replayed !== undefined && authorityHash(issuer, replayed as never) === mission.authority_hash;
  return { reproduced, decision };
}

/**
 * The deployment's trusted capability resolver, wrapped to record what it
 * returned for this activation (null when none is configured).
 */
function recordingResolution(resolver: CapabilitySourceResolver | undefined): {
  resolver: CapabilitySourceResolver | undefined;
  recorded: CapabilitySourceResolution[] | null;
} {
  if (!resolver) return { resolver: undefined, recorded: null };
  const recorded: CapabilitySourceResolution[] = [];
  return {
    recorded,
    resolver: {
      resolve: (entries) => {
        const out = resolver.resolve(entries);
        recorded.push(...out);
        return out;
      },
    },
  };
}

/**
 * A resolver that answers from a retained resolution, for each entry only
 * the resolutions naming that entry's resource and actions; null replays no
 * resolver at all, as at an activation that had none.
 */
function replayResolution(recorded: CapabilitySourceResolution[] | null): CapabilitySourceResolver | undefined {
  if (!recorded) return undefined;
  const distinct = [...new Map(recorded.map((r) => [JSON.stringify(r), r])).values()];
  return {
    resolve: (entries) =>
      distinct.filter((r) => entries.some((e) => e.resource === r.resource && e.actions.includes(r.action))),
  };
}

/**
 * @spec deferred-approval#policy-completion: the issuer's selection for a
 * pending proposal: the standing consents, latest first, whose root this
 * issuer still holds unchanged and admits the requesting client. A client
 * never names one. Eligibility only; the activation runs every check again.
 */
export function eligibleGovernedPolicyConsents(kernel: MissionKernel, clientId: string): GovernedPolicyConsent[] {
  const config = kernel.governedPolicyApproval();
  if (!config) return [];
  const issuer = kernel.issuerId();
  return kernel.governedPolicyConsents.standing().filter((c) => {
    const held = Object.hasOwn(config.roots, c.root.id) ? config.roots[c.root.id] : undefined;
    if (!held || held.version !== c.root.version || approvalPolicyDigest(issuer, held) !== c.root.digest) return false;
    try {
      return parseGovernedPolicyRoot(held.content).admits.clients.includes(clientId);
    } catch {
      return false;
    }
  });
}
