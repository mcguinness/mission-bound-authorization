/**
 * @spec draft-mcguinness-oauth-mission-progressive
 *
 * Progressive authorization: an authority ceiling and a drawdown policy the
 * Approver consents at the initial approval event, and the policy-adjudicated
 * in-ceiling drawdown that creates an Expansion successor under the
 * `ceiling_drawdown` basis and completes in the token-exchange response.
 *
 * Default off. A deployment selects the drawdown path by configuring
 * {@link ProgressiveDrawdownOptions}; without it, an expansion of a Mission
 * that carries a ceiling takes the ordinary fresh-approval path.
 *
 * Adjudication ({@link adjudicateDrawdown}) refuses an out-of-ceiling request
 * with `out_of_ceiling`. An in-ceiling request falls back to a fresh human
 * approval, never to a refusal, whenever: the Mission commits no drawdown
 * policy; the held snapshot no longer matches the committed `digest` (only
 * the current registry is read, never a retained snapshot); the snapshot
 * states no usable per-drawdown bound or review cadence; the ceiling consent
 * is older than that cadence; a widened action is unclassified, in a
 * high-consequence class, satisfies the external-communication predicate, or
 * is cross-domain; the predecessor has a non-terminal Child Mission; the
 * successor overlaps a containment or discharge restriction of its expansion
 * chain; the drawdown exceeds the per-drawdown bound; or the chain has reached
 * its rate bound.
 */

import { randomBytes } from "node:crypto";
import type { ApprovalFloorPolicy } from "@mission/demo-data";
import {
  type ActivationPolicyRef,
  authorityHash,
  computeAnchor,
  intentHash,
  isSubsetSetIgnoringCapabilitySources,
  type JsonValue,
  proposalHash,
} from "@mission/core";
import {
  type ActivationPolicyRegistry,
  mintActivationPolicyRef,
  type RegisteredActivationPolicy,
  verifiedActivationPolicy,
} from "./activation-policy.js";
import { inheritCapabilitySources } from "./capability-binding.js";
import { entryDigest } from "./discharge.js";
import { childActorCeilingOrigin, inheritChildActorOrigins } from "./child-actor-eligibility.js";
import { ceilingOrigin, inheritOrigins } from "./eligibility-provenance.js";
import { IntentError, validateAuthorityProposal } from "./intent.js";
import type { MissionKernel } from "./kernel.js";
import { newMissionId } from "./mission-id.js";
import {
  type ApprovalBasis,
  type AuthorityEntry,
  type IntentSubmissionEvidenceFact,
  type MissionIntent,
  type MissionRecord,
  TERMINAL_STATES,
} from "./types.js";

/** @spec progressive#progressive-authorization: the `ceiling_hash` envelope `typ`. */
export const MISSION_AUTHORITY_CEILING_TYP = "mission-authority-ceiling";

/**
 * @spec progressive#progressive-authorization: `ceiling_hash`, an object of
 * exactly `authority_ceiling` and, when the Mission carries one,
 * `drawdown_policy` (omitted otherwise, never null or empty).
 */
export function ceilingHash(
  iss: string,
  authorityCeiling: readonly AuthorityEntry[],
  drawdownPolicy?: ActivationPolicyRef,
): string {
  const value = {
    authority_ceiling: authorityCeiling,
    ...(drawdownPolicy ? { drawdown_policy: drawdownPolicy } : {}),
  };
  return computeAnchor(MISSION_AUTHORITY_CEILING_TYP, iss, value as unknown as JsonValue);
}

/** The ceiling an approval surface reports the Approver consented. */
export interface CeilingConsent {
  authority_ceiling: AuthorityEntry[];
  /** The policy's `id` and `version`; the `digest` is minted from the snapshot this issuer holds. */
  drawdown_policy?: { id: string; version: string };
}

/**
 * The ceiling members of an approval decision, as the approval surface posted
 * them; {@link consentCeiling} validates them. Undefined when the decision
 * consents no ceiling.
 */
export function ceilingConsentOf(decision: Record<string, unknown>): CeilingConsent | undefined {
  if (decision.authority_ceiling === undefined) return undefined;
  return {
    authority_ceiling: decision.authority_ceiling as AuthorityEntry[],
    ...(decision.drawdown_policy !== undefined
      ? { drawdown_policy: decision.drawdown_policy as { id: string; version: string } }
      : {}),
  };
}

/** The ceiling members a Mission record carries. */
export interface MissionCeiling {
  authority_ceiling: AuthorityEntry[];
  drawdown_policy?: ActivationPolicyRef;
  ceiling_hash: string;
  ceiling_consented_at: string;
  drawdown_count: number;
}

/**
 * @spec progressive#progressive-authorization: the consented ceiling's
 * entries, each with an Authority Set entry's shape. A malformed ceiling is
 * refused `invalid_request`. The approval decision reads them before any
 * write, to hold the ceiling to the approval-authentication floor
 * (mission#approval-authentication, #1255).
 */
export function consentedCeilingEntries(consent: CeilingConsent): AuthorityEntry[] {
  const entries = consent.authority_ceiling as unknown;
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new IntentError("invalid_request", "authority_ceiling must be a non-empty array");
  }
  const resources: string[] = [];
  for (const e of entries) {
    const resource = (e as { resource?: unknown } | null)?.resource;
    const actions = (e as { actions?: unknown } | null)?.actions;
    if (typeof resource !== "string" || !Array.isArray(actions) || actions.length === 0) {
      throw new IntentError("invalid_request", "each authority_ceiling entry needs a resource and actions");
    }
    resources.push(resource);
  }
  return validateAuthorityProposal(JSON.stringify(entries), resources);
}

/**
 * @spec progressive#progressive-authorization: the consented drawdown
 * policy's reference, minted over the snapshot this issuer holds, or
 * undefined when the consent names none. A policy this issuer does not hold
 * at that version is refused `invalid_request`: the approval cannot commit
 * content the issuer cannot evaluate. The approval decision checks it before
 * any write, with the ceiling's entries (#1255).
 */
export function consentedDrawdownPolicy(
  iss: string,
  registry: ActivationPolicyRegistry | undefined,
  consent: CeilingConsent,
): ActivationPolicyRef | undefined {
  if (consent.drawdown_policy === undefined) return undefined;
  const { id, version } = (consent.drawdown_policy ?? {}) as { id?: unknown; version?: unknown };
  const drawdownPolicy =
    typeof id === "string" && typeof version === "string"
      ? mintActivationPolicyRef(iss, registry, id, version)
      : undefined;
  if (!drawdownPolicy) {
    throw new IntentError("invalid_request", "drawdown_policy names no policy this issuer holds at that version");
  }
  return drawdownPolicy;
}

/**
 * @spec progressive#progressive-authorization: validate a consented ceiling
 * and commit it. Each entry has an Authority Set entry's shape, and the
 * drawdown policy reference is minted by {@link consentedDrawdownPolicy}.
 */
export function consentCeiling(
  iss: string,
  registry: ActivationPolicyRegistry | undefined,
  consent: CeilingConsent,
  consentedAt: string,
): MissionCeiling {
  const ceiling = consentedCeilingEntries(consent);
  const drawdownPolicy = consentedDrawdownPolicy(iss, registry, consent);
  return {
    authority_ceiling: ceiling,
    ...(drawdownPolicy ? { drawdown_policy: drawdownPolicy } : {}),
    ceiling_hash: ceilingHash(iss, ceiling, drawdownPolicy),
    ceiling_consented_at: consentedAt,
    drawdown_count: 0,
  };
}

/** The stored form of a record's ceiling members, or null when it carries none. */
export function serializeCeiling(record: MissionRecord): string | null {
  if (!record.authority_ceiling || !record.ceiling_hash || !record.ceiling_consented_at) return null;
  const stored: MissionCeiling = {
    authority_ceiling: record.authority_ceiling,
    ...(record.drawdown_policy ? { drawdown_policy: record.drawdown_policy } : {}),
    ceiling_hash: record.ceiling_hash,
    ceiling_consented_at: record.ceiling_consented_at,
    drawdown_count: record.drawdown_count ?? 0,
  };
  return JSON.stringify(stored);
}

/** Hydrate a stored ceiling column; an absent column is no ceiling. */
export function ceilingMembersOf(raw: unknown): Partial<MissionCeiling> {
  if (typeof raw !== "string" || !raw) return {};
  return JSON.parse(raw) as MissionCeiling;
}

/** The runtime profile's action classes, the vocabulary of the published classification. */
export type RuntimeActionClass =
  | "non_consequential"
  | "consequential_read"
  | "consequential_write"
  | "irreversible_action"
  | "external_commitment"
  | "privileged_administration";

const RUNTIME_ACTION_CLASSES: ReadonlySet<string> = new Set<RuntimeActionClass>([
  "non_consequential",
  "consequential_read",
  "consequential_write",
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
]);

/** @spec progressive#in-ceiling-expansion: the classes a drawdown never grants by policy alone. */
const FRESH_APPROVAL_CLASSES: ReadonlySet<RuntimeActionClass> = new Set<RuntimeActionClass>([
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
]);

/**
 * @spec progressive#in-ceiling-expansion: the deployment's selection of the
 * policy-adjudicated drawdown path, with the bounds its Mission Deployment
 * Profile publishes. Absent, no drawdown is adjudicated by policy.
 */
export interface ProgressiveDrawdownOptions {
  /** Policy-adjudicated drawdowns per expansion chain, keyed by its root, per window. */
  chainRateBound: { maxDrawdowns: number; windowSeconds: number };
  /**
   * The mapping from action identifiers to the runtime profile's action
   * classes. A widened action with no entry is not policy-adjudicated.
   */
  actionClasses: Readonly<Record<string, RuntimeActionClass>>;
  /** Actions that satisfy the runtime profile's external-communication predicate. */
  externalCommunicationActions?: readonly string[];
}

const isPositiveInteger = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) > 0;

/**
 * Validate the typed deployment configuration; throws on any malformed member,
 * and on a mapping that disagrees with the approval-authentication floor
 * ({@link assertDrawdownClassesMeetApprovalFloor}).
 */
export function validateProgressiveDrawdownOptions(
  o: ProgressiveDrawdownOptions,
  approvalFloor: ApprovalFloorPolicy,
): ProgressiveDrawdownOptions {
  if (!isPositiveInteger(o?.chainRateBound?.maxDrawdowns) || !isPositiveInteger(o.chainRateBound.windowSeconds)) {
    throw new Error("progressive chainRateBound needs positive integer maxDrawdowns and windowSeconds");
  }
  if (!o.actionClasses || typeof o.actionClasses !== "object") {
    throw new Error("progressive actionClasses must map action identifiers to runtime action classes");
  }
  for (const [action, cls] of Object.entries(o.actionClasses)) {
    if (!RUNTIME_ACTION_CLASSES.has(cls)) {
      throw new Error(`progressive actionClasses: ${action} has unknown class ${String(cls)}`);
    }
  }
  if (o.externalCommunicationActions !== undefined && !o.externalCommunicationActions.every((a) => typeof a === "string")) {
    throw new Error("progressive externalCommunicationActions must be action identifiers");
  }
  assertDrawdownClassesMeetApprovalFloor(o, approvalFloor);
  return o;
}

/**
 * @spec progressive#in-ceiling-expansion, mission#approval-authentication
 * (#1255): the drawdown's published mapping agrees with the
 * approval-authentication floor's classification. An action the floor
 * classifies, at any resource, in a class some floor `applies_to` must not map
 * in `actionClasses` to a class outside the fresh-approval set, or a drawdown
 * would grant by policy alone authority whose approval the floor guards.
 * `actionClasses` is keyed by action alone, so one floor-invoking
 * classification of the action is enough to refuse. An action with no
 * `actionClasses` entry needs nothing here: its drawdown falls back
 * (`unclassified_action`). Throws, so the deployment does not start.
 */
export function assertDrawdownClassesMeetApprovalFloor(
  o: ProgressiveDrawdownOptions,
  approvalFloor: ApprovalFloorPolicy,
): void {
  const invoking = new Set<string>(approvalFloor.floors.flatMap((f) => f.applies_to));
  for (const entry of approvalFloor.classification) {
    for (const [action, floorClass] of Object.entries(entry.actions)) {
      if (!invoking.has(floorClass) || !Object.hasOwn(o.actionClasses, action)) continue;
      const mapped = o.actionClasses[action] as RuntimeActionClass;
      if (!FRESH_APPROVAL_CLASSES.has(mapped)) {
        throw new Error(
          `progressive actionClasses: ${action} maps to ${mapped}, which a drawdown grants by policy, but the approval-authentication floor ${approvalFloor.policy_id} classifies it ${floorClass} at ${entry.resource}, which invokes a floor`,
        );
      }
    }
  }
}

/**
 * @spec progressive#in-ceiling-expansion, progressive#ceiling-review: what a
 * drawdown policy snapshot states, read from its JSON content: the
 * per-drawdown bound (`max_added_actions`, the widened resource-action pairs
 * one drawdown may add) and the review cadence effective under this version
 * (`ceiling_review_cadence_s`). Undefined when either is missing or malformed:
 * such a snapshot authorizes nothing.
 */
export interface DrawdownPolicyRules {
  max_added_actions: number;
  ceiling_review_cadence_s: number;
}

export function drawdownRulesOf(policy: RegisteredActivationPolicy): DrawdownPolicyRules | undefined {
  if (policy.content_type !== "application/json") return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(policy.content);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const { max_added_actions, ceiling_review_cadence_s } = parsed as Record<string, unknown>;
  if (!isPositiveInteger(max_added_actions) || !isPositiveInteger(ceiling_review_cadence_s)) return undefined;
  return { max_added_actions, ceiling_review_cadence_s };
}

/** Why an in-ceiling drawdown falls back to a fresh human approval. */
export type DrawdownFallbackReason =
  | "no_drawdown_policy"
  | "drawdown_policy_changed"
  | "drawdown_policy_unusable"
  | "ceiling_review_overdue"
  | "unclassified_action"
  | "fresh_approval_class"
  | "external_communication"
  | "cross_domain"
  | "live_children"
  | "restricted_overlap"
  | "entire_remaining_ceiling"
  | "per_drawdown_bound"
  | "chain_rate_bound";

export type DrawdownAdjudication =
  | { outcome: "out_of_ceiling" }
  | { outcome: "fresh_approval"; reason: DrawdownFallbackReason }
  | { outcome: "policy"; ref: ActivationPolicyRef; snapshot: RegisteredActivationPolicy };

/** One widened resource-action pair: authority the predecessor's effective set does not already hold. */
interface WidenedPair {
  resource: string;
  action: string;
}

function widenedPairs(requested: readonly AuthorityEntry[], effective: readonly AuthorityEntry[]): WidenedPair[] {
  const out: WidenedPair[] = [];
  for (const e of requested) {
    for (const action of e.actions) {
      if (!isSubsetSetIgnoringCapabilitySources([{ ...e, actions: [action] }], effective as AuthorityEntry[])) {
        out.push({ resource: e.resource, action });
      }
    }
  }
  return out;
}

/**
 * @spec progressive#drawdown-bounds: the successor would hold all the
 * authority the ceiling grants. Each ceiling entry, one action at a time, is
 * compared under the subset relation, constraints and resource included, so
 * entry boundaries and counts do not decide it. The relation is total here:
 * ceiling entries were validated at consent, and the successor already passed
 * the ceiling test over the same members.
 */
function activatesEntireCeiling(requested: readonly AuthorityEntry[], ceiling: readonly AuthorityEntry[]): boolean {
  return ceiling.every((c) =>
    c.actions.every((action) => isSubsetSetIgnoringCapabilitySources([{ ...c, actions: [action] }], requested)),
  );
}

/** The Missions of an expansion chain, from `missionId` back to its root. */
function chainOf(kernel: MissionKernel, missionId: string): MissionRecord[] {
  const chain: MissionRecord[] = [];
  const seen = new Set<string>();
  let next: string | undefined = missionId;
  while (next && !seen.has(next)) {
    seen.add(next);
    const m = kernel.get(next);
    if (!m) break;
    chain.push(m);
    next = m.predecessor;
  }
  return chain;
}

/**
 * @spec progressive#in-ceiling-expansion, containment#restoration,
 * discharge#discharge: every capability under a containment or discharge
 * restriction of the chain. The reference has no explicit restoration
 * disclosure, so no restriction clears.
 */
function chainRestrictions(chain: readonly MissionRecord[]): Array<{ resource: string; actions?: string[] }> {
  const out: Array<{ resource: string; actions?: string[] }> = [];
  for (const m of chain) {
    for (const c of m.containment?.contained ?? []) out.push(c);
    for (const d of m.discharged ?? []) {
      const entry = m.authority_set.find((e) => entryDigest(m.issuer, e) === d.entry_digest);
      if (entry) out.push({ resource: entry.resource, actions: entry.actions });
    }
  }
  return out;
}

/** Overlap in authority: the same resource and at least one shared action (a whole-resource restriction overlaps every action). */
function overlaps(entry: AuthorityEntry, restricted: { resource: string; actions?: string[] }): boolean {
  if (entry.resource !== restricted.resource) return false;
  if (!restricted.actions) return true;
  return entry.actions.some((a) => (restricted.actions as string[]).includes(a));
}

/**
 * @spec progressive#in-ceiling-expansion: adjudicate an expansion of a
 * Mission that carries an `authority_ceiling`. `requested` is the successor's
 * complete derived Authority Set. Reads only current state: the current
 * activation policy registry, the chain's records and the clock.
 */
export function adjudicateDrawdown(
  kernel: MissionKernel,
  options: ProgressiveDrawdownOptions,
  input: {
    predecessor: MissionRecord;
    requested: readonly AuthorityEntry[];
    isCrossDomain: (resource: string) => boolean;
  },
): DrawdownAdjudication {
  const { predecessor, requested } = input;
  const ceiling = predecessor.authority_ceiling ?? [];
  // @spec progressive#in-ceiling-expansion: in-ceiling when every successor
  // entry is a subset of some ceiling entry; otherwise refused out_of_ceiling.
  if (!isSubsetSetIgnoringCapabilitySources(requested as AuthorityEntry[], ceiling)) {
    return { outcome: "out_of_ceiling" };
  }
  const fallback = (reason: DrawdownFallbackReason): DrawdownAdjudication => ({ outcome: "fresh_approval", reason });
  const ref = predecessor.drawdown_policy;
  if (!ref) return fallback("no_drawdown_policy");
  // @spec mission#standing-consent-bases, progressive#in-ceiling-expansion: a
  // snapshot that does not match the committed digest authorizes nothing.
  const snapshot = verifiedActivationPolicy(predecessor.issuer, kernel.activationPolicies(), ref);
  if (!snapshot) return fallback("drawdown_policy_changed");
  const rules = drawdownRulesOf(snapshot);
  if (!rules) return fallback("drawdown_policy_unusable");
  const nowMs = kernel.nowDate().getTime();
  // @spec progressive#ceiling-review: no policy adjudication for a chain whose
  // most recent human approval of the ceiling is older than the cadence.
  const consentedAt = Date.parse(predecessor.ceiling_consented_at ?? "");
  if (!Number.isFinite(consentedAt) || nowMs - consentedAt > rules.ceiling_review_cadence_s * 1000) {
    return fallback("ceiling_review_overdue");
  }
  const widened = widenedPairs(requested, kernel.effectiveAuthoritySet(predecessor));
  const external = new Set(options.externalCommunicationActions ?? []);
  for (const { resource, action } of widened) {
    const cls = Object.hasOwn(options.actionClasses, action) ? options.actionClasses[action] : undefined;
    if (cls === undefined) return fallback("unclassified_action");
    if (FRESH_APPROVAL_CLASSES.has(cls)) return fallback("fresh_approval_class");
    if (external.has(action)) return fallback("external_communication");
    if (input.isCrossDomain(resource)) return fallback("cross_domain");
  }
  // @spec progressive#in-ceiling-expansion: no policy adjudication while the
  // predecessor has non-terminal Child Missions.
  if (kernel.findChildren(predecessor.id).some((c) => !TERMINAL_STATES.has(kernel.observe(c).state))) {
    return fallback("live_children");
  }
  const chain = chainOf(kernel, predecessor.id);
  const restrictions = chainRestrictions(chain);
  if (requested.some((e) => restrictions.some((r) => overlaps(e, r)))) return fallback("restricted_overlap");
  // @spec progressive#drawdown-bounds: never the entire remaining ceiling by
  // policy; the final increment takes a fresh human approval.
  if (activatesEntireCeiling(requested, ceiling)) return fallback("entire_remaining_ceiling");
  if (widened.length > rules.max_added_actions) return fallback("per_drawdown_bound");
  const windowStart = nowMs - options.chainRateBound.windowSeconds * 1000;
  const recent = chain.filter(
    (m) => m.approval_basis.type === "ceiling_drawdown" && Date.parse(m.created_at) > windowStart,
  ).length;
  if (recent >= options.chainRateBound.maxDrawdowns) return fallback("chain_rate_bound");
  return { outcome: "policy", ref, snapshot };
}

/** A drawdown refused at its activating commit; nothing is created or superseded. */
export class DrawdownRefusal extends Error {
  constructor(
    readonly code: "derivations_exhausted" | "predecessor_not_active",
    message: string,
  ) {
    super(message);
  }
}

export interface CeilingDrawdownInput {
  predecessorId: string;
  /** The widened intent, derived under policy exactly as an ordinary expansion's. */
  intent: MissionIntent;
  proposedAuthority?: AuthorityEntry[];
  /** The verified Intent Submission Evidence facts, landed outside all anchors. */
  submissionEvidence?: IntentSubmissionEvidenceFact[];
  /** The requesting client, the basis's `activation_actor`. */
  activationActor: { iss: string; sub: string };
  /** The policy and the held snapshot {@link adjudicateDrawdown} verified. */
  policy: { ref: ActivationPolicyRef; snapshot: RegisteredActivationPolicy };
}

/**
 * @spec progressive#in-ceiling-expansion, expansion#successor-source,
 * expansion#superseded-state: create the policy-adjudicated successor and
 * supersede the predecessor. NO OWN TRANSACTION: the caller runs this inside
 * the transaction that also commits the `(client, creation_request_id)`
 * reservation, so activation, supersession and reservation commit as one.
 *
 * The successor's `approval_event_id` is allocated here, once per
 * reservation, and identifies this drawdown, never the ceiling consent. Its
 * Subject, authority source, client and ceiling members are the
 * predecessor's; the source ceiling is checked against the root as it stands
 * at this commit. Where the predecessor has a finite `derivation_limit`, the
 * successor carries its committed count forward under a limit never above
 * the predecessor's (Mission Derivation Limits), and a drawdown whose token
 * would exceed it is refused before anything is written.
 */
export function createCeilingDrawdownInCallerTx(kernel: MissionKernel, input: CeilingDrawdownInput): MissionRecord {
  const predecessor = kernel.get(input.predecessorId);
  if (!predecessor || predecessor.state !== "active" || kernel.observe(predecessor).state !== "active") {
    throw new DrawdownRefusal("predecessor_not_active", "predecessor is not active");
  }
  if (!predecessor.authority_ceiling || !predecessor.ceiling_hash || !predecessor.ceiling_consented_at) {
    throw new Error("a ceiling drawdown requires a predecessor that carries a consented ceiling");
  }
  const proposal = input.proposedAuthority?.length ? input.proposedAuthority : undefined;
  // The successor's Authority Set is derived exactly as an ordinary
  // expansion's, carrying the predecessor's recorded capability bindings.
  const derived = kernel.deriveWithProvenance(input.intent, proposal);
  const authoritySet = kernel.resolveFreshCapabilities(
    inheritCapabilitySources(derived.entries, predecessor.authority_set),
  );
  if (!isSubsetSetIgnoringCapabilitySources(authoritySet, predecessor.authority_ceiling)) {
    throw new Error("ceiling drawdown successor is not within the consented ceiling");
  }
  // @spec resource-access#delegate-eligibility: the drawdown keeps its own
  // derivation's origins and every obligation of the consented ceiling entries
  // it falls within (an entry there without `allowed_delegates` defers to
  // policy).
  const provenance = inheritOrigins(
    authoritySet,
    derived.provenance,
    predecessor.authority_ceiling.map((entry) => ({ entry, origin: ceilingOrigin(entry) })),
  );
  // @spec child-delegation#fanout (#1304): the child-actor origins the same
  // way, kept apart (a consented ceiling `children` grant without
  // `allowed_child_actors` defers to the child-creation policy).
  const childActorProvenance = inheritChildActorOrigins(
    authoritySet,
    derived.childActorProvenance,
    predecessor.authority_ceiling.map((entry) => ({ entry, origin: childActorCeilingOrigin(entry) })),
  );
  // @spec expansion#successor-source: the predecessor's Subject and source,
  // checked against the committed root's declaration current at this commit.
  const root = kernel.committedSourceBinding(predecessor.id);
  const resolved = kernel.assertInheritedAuthoritySource(root, authoritySet);
  kernel.assertInheritedSubjectDiscipline(resolved, predecessor.subject);

  // @spec progressive#in-ceiling-expansion (Derivation limits): the inherited
  // finite limit is never raised; a stricter request or policy ceiling narrows it.
  const own = kernel.resolveDerivationLimit(input.intent.requested_derivation_limit);
  const inherited = predecessor.derivation_limit;
  const derivationLimit = inherited === null ? own : own === null ? inherited : Math.min(own, inherited);
  const derivationCount = predecessor.derivation_count;
  if (derivationLimit !== null && derivationCount + 1 > derivationLimit) {
    throw new DrawdownRefusal(
      "derivations_exhausted",
      `the carried derivation count ${derivationCount} leaves no derivation under limit ${derivationLimit}`,
    );
  }

  const createdAt = kernel.nowDate().toISOString();
  const expiresAt = kernel.resolveEffectiveExpiry({
    requested: input.intent.expires_at,
    createdAt,
    ceilings: { predecessor: predecessor.expires_at },
  });
  // @spec mission#standing-consent-bases, progressive#in-ceiling-expansion:
  // one value per reservation, never derived from creation_request_id, so a
  // key reused after its tombstone expires creates a new event.
  const approvalEventId = `cdd_${randomBytes(16).toString("base64url")}`;
  const approvalBasis: ApprovalBasis = {
    type: "ceiling_drawdown",
    consent_principal: predecessor.approval_basis.consent_principal,
    activation: { policy_id: input.policy.ref.id, policy_version: input.policy.ref.version },
    activation_actor: input.activationActor,
    root_commitment: predecessor.ceiling_hash,
    approved_at: predecessor.ceiling_consented_at,
  };
  const id = newMissionId();
  const record: MissionRecord = {
    id,
    issuer: predecessor.issuer,
    state: "active",
    intent: input.intent,
    ...(proposal ? { proposed_authority: proposal } : {}),
    authority_set: authoritySet,
    eligibility_provenance: provenance,
    child_actor_provenance: childActorProvenance,
    intent_hash: intentHash(predecessor.issuer, input.intent as never),
    ...(proposal ? { proposal_hash: proposalHash(predecessor.issuer, proposal as never) } : {}),
    ...(input.submissionEvidence?.length ? { submission_evidence: input.submissionEvidence } : {}),
    authority_hash: authorityHash(predecessor.issuer, authoritySet as never),
    subject: predecessor.subject,
    approval_basis: approvalBasis,
    authority_source: predecessor.authority_source,
    client_id: predecessor.client_id,
    policy_version: predecessor.policy_version,
    approval_event_id: approvalEventId,
    created_at: createdAt,
    expires_at: expiresAt,
    version: 1,
    derivation_limit: derivationLimit,
    derivation_count: derivationCount,
    grant_id: null,
    status_list_idx: null,
    predecessor: predecessor.id,
    // @spec progressive#in-ceiling-expansion: carried unchanged, under the same `ceiling_hash`.
    authority_ceiling: predecessor.authority_ceiling,
    ...(predecessor.drawdown_policy ? { drawdown_policy: predecessor.drawdown_policy } : {}),
    ceiling_hash: predecessor.ceiling_hash,
    ceiling_consented_at: predecessor.ceiling_consented_at,
    // @spec progressive#audit-linkage: the chain's cumulative drawdown count.
    drawdown_count: (predecessor.drawdown_count ?? 0) + 1,
  };
  kernel.insertRecord(record, undefined, {
    source: { inherited: root },
    // @spec mission#standing-consent-bases: the drawdown policy snapshot this
    // adjudication verified, retained for the successor's audit horizon.
    activationPolicies: [{ ref: input.policy.ref, snapshot: input.policy.snapshot }],
  });
  if (!kernel.supersedeInCallerTx(id)) {
    throw new Error("ceiling drawdown predecessor supersession failed inside the creation transaction");
  }
  return record;
}
