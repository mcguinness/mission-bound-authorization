/**
 * @spec draft-mcguinness-oauth-mission-child-delegation
 *
 * Mission Child-Delegation: a Child Mission is a NEW Mission (its own
 * `mission_id`, actor, lifecycle, and `act` chain) whose authority is a strict
 * subset of a PARENT Mission. It is distinct from Attenuation (same-mission
 * token narrowing) and from Expansion (same-subject widening successor).
 *
 * This is a standalone kernel module (mirrors kernel/expansion.ts and
 * kernel/cross-domain.ts); it is not wired to an endpoint. It imports
 * {@link isSubsetSet} read-only. The child's terminal-cascade behaviour lives in
 * the kernel ({@link MissionKernel.cascadeChildren}), fired from the
 * terminal-commit path so the Status List and Mission Signals propagate for free.
 *
 * Deferred (named in the PR): the PAR wire params (`parent`, `parent_token`,
 * front-channel carve-outs), the child-bound JWT authorization grant issuance
 * (§child-client-identity), suspend-projection + restore-on-resume
 * (§cascade reversible trigger), the consumer-verified cascade modes, discovery
 * metadata, and cross-issuer.
 *
 * Realized here (PR2, @spec child-delegation#fanout, #fanout-accounting,
 * #denial-reasons, #child-evidence): fan-out accounting derived from the parent
 * Authority Set's per-entry `delegation.children` (the S-15 on-switch, provided
 * by the core extension), and the Child Evidence record. Kernel lifecycle /
 * suspend and the AS wire remain out of scope; `kernel.findChildren` is used
 * READ-ONLY for the fan-out count.
 */

import { randomBytes } from "node:crypto";
import { type ActObject, ActorChainError, extendChain, validateActChain } from "@mission/actor-chain";
import { authorityHash, canonicalize, intentHash, type JsonValue, proposalHash } from "@mission/core";
import { activationPolicyMatches } from "./activation-policy.js";
import { inheritCapabilitySources } from "./capability-binding.js";
import { type DelegateCandidate, delegatePermitted } from "./delegate-matcher.js";
import { isSubsetEntry, isSubsetSet } from "./derive.js";
import { withoutCapabilitySources } from "@mission/core";
import type { MissionKernel } from "./kernel.js";
import { newMissionId } from "./mission-id.js";
import {
  type ApprovalBasis,
  type AuthorityEntry,
  type CascadeMode,
  type ChildEvidence,
  type ChildFanoutControls,
  type MissionIntent,
  type IntentSubmissionEvidenceFact,
  type MissionRecord,
  type ParentRef,
  TERMINAL_STATES,
} from "./types.js";

/**
 * Hard child-generation depth cap (defence-in-depth). The per-entry
 * `children.max_child_depth` ceiling (@spec child-delegation#fanout) AUGMENTS
 * this: both are enforced and the stricter one wins.
 */
export const MAX_CHILD_DEPTH = 2;

/**
 * @spec child-delegation#child-evidence-canonical — the Child Evidence media
 * type; its canonical bytes are the JCS canonicalization of the record.
 */
export const CHILD_EVIDENCE_MEDIA_TYPE = "application/mission-child-evidence+json";

/**
 * @spec child-delegation#denial-reasons — why child creation was refused.
 * `delegation_not_permitted` is the on-switch refusal (a justifying parent entry
 * carries no `delegation.children`); it is DISTINCT from `policy_denied`, the
 * refusal when a carried `child_creation_policy` no longer matches its
 * committed digest.
 */
export type ChildDenialReason =
  | "parent_not_active"
  | "parent_mismatch"
  | "not_strict_subset"
  | "delegation_not_permitted"
  | "child_actor_not_allowed"
  | "fanout_exceeded"
  | "policy_denied";

/**
 * A refusal of child creation, carrying the machine-readable reason and (when
 * the refusal occurs after the child identity is known) the deny Child Evidence
 * record (@spec child-delegation#child-evidence, `decision: "denied"`).
 */
export class ChildDelegationError extends Error {
  constructor(
    readonly reason: ChildDenialReason,
    message: string,
    readonly evidence?: ChildEvidence,
  ) {
    super(message);
  }
}

/**
 * @spec child-delegation#child-creation — the child actor, in the issuance
 * profile's actor vocabulary. Its `sub` becomes the Child Mission's `client_id`.
 */
export interface ChildActor {
  sub: string;
  iss?: string;
  sub_profile?: string;
}

export interface CreateChildInput {
  /** The Parent Mission identifier. */
  parentId: string;
  /** The proposed Child Mission Intent. */
  intent: MissionIntent;
  /**
   * @spec mission#authority-proposal — the authority proposal submitted on the
   * standard `authorization_details` parameter of the child-creation exchange
   * (already validated at intake). Recorded on the child and committed by
   * `proposal_hash` iff present; absent means template-mode derivation.
   */
  proposedAuthority?: AuthorityEntry[];
  /** The child actor that holds/executes under the Child Mission. */
  childActor: ChildActor;
  /**
   * @spec child-delegation#attenuation (#825, D353): the authority the
   * presented `subject_token` itself carries. When supplied, every child entry
   * MUST also be a subset of it, so a down-scoped token never mints a child
   * broader than itself. The token-endpoint exchange always supplies it.
   */
  presentedAuthority?: readonly AuthorityEntry[];
  /** The recorded cascade mode. Defaults to (and today only supports) `immediate`. */
  cascadeMode?: CascadeMode;
  /** Optional Mission-Issuer-defined identifier for the delegation event. */
  delegationId?: string;
  /**
   * @spec mission#intent-submission-evidence — the VERIFIED Intent Submission
   * Evidence facts of the child submission (stage-2 output). Landed on the
   * child record's `submission_evidence`, outside all anchors.
   */
  submissionEvidence?: IntentSubmissionEvidenceFact[];
}

export interface ChildResult {
  child: MissionRecord;
  /** The Parent Mission identifier (mirrors ExpansionResult.predecessor). */
  parent: string;
  /** @spec child-delegation#child-evidence — the permit Child Evidence record. */
  evidence: ChildEvidence;
}

// ---------------------------------------------------------------------------
// @spec child-delegation#fanout — fan-out accounting helpers.
// ---------------------------------------------------------------------------

/** A plain-JSON value read as an integer, else undefined. */
export function asNum(v: JsonValue | undefined): number | undefined {
  return typeof v === "number" ? v : undefined;
}

/**
 * The `delegation.children` fan-out controls of a parent entry, or undefined
 * when the entry carries no `children` object (the on-switch is absent). Read
 * through this local reader so the `delegation` open index in types.ts stays
 * `JsonValue`-shaped and derive.ts is untouched.
 */
export function childrenOf(entry: AuthorityEntry): ChildFanoutControls | undefined {
  const c = entry.delegation?.children;
  return c !== null && typeof c === "object" && !Array.isArray(c)
    ? (c as ChildFanoutControls)
    : undefined;
}

/**
 * @spec txn-authorization#applicability — carry `requires_action_approval:
 * true` down to every child entry an ancestor entry for the same resource set
 * it on. Run BEFORE the strict-subset proof, so a delegated leaf that simply
 * omits the member is NORMALIZED (and therefore still challenged and enforced
 * at the resource) rather than refused: the constraint is monotonic, `false` is
 * equivalent to omission, and a child can only ever add it.
 */
export function inheritActionApprovalRequirement(
  childAuthority: AuthorityEntry[],
  parentEffective: readonly AuthorityEntry[],
): AuthorityEntry[] {
  return childAuthority.map((entry) => {
    if (entry.constraints?.requires_action_approval === true) return entry;
    const required = parentEffective.some(
      (p) => p.resource === entry.resource && p.constraints?.requires_action_approval === true,
    );
    if (!required) return entry;
    return { ...entry, constraints: { ...entry.constraints, requires_action_approval: true } };
  });
}

/**
 * @spec child-delegation#fanout-accounting — the justifying parent entry for a
 * child entry: the index of the FIRST parent entry (Authority Set order) the
 * child entry is a subset of. -1 only if none (never for a proven-subset child).
 */
export function justifyingIndex(childEntry: AuthorityEntry, parentSet: AuthorityEntry[]): number {
  return parentSet.findIndex((p) => isSubsetEntry(childEntry, p));
}

/**
 * @spec child-delegation#fanout-accounting — count the parent's NON-terminal
 * existing Child Missions, BUCKETED by justifying parent-entry index. Each child
 * counts once per distinct parent entry it draws on (recomputed by the same
 * first-in-order justifying selection). Read-only over `kernel.findChildren`.
 */
export function countChildBuckets(kernel: MissionKernel, parent: MissionRecord): Map<number, number> {
  const buckets = new Map<number, number>();
  for (const found of kernel.findChildren(parent.id)) {
    // Only non-terminal children count, as OBSERVED: a child past its own
    // `expires_at` is terminated whether or not that has been persisted.
    const existing = kernel.observe(found);
    if (TERMINAL_STATES.has(existing.state)) continue;
    const drawnOn = new Set<number>();
    for (const ce of existing.authority_set) {
      const pi = justifyingIndex(ce, parent.authority_set);
      if (pi < 0) continue;
      drawnOn.add(pi);
    }
    for (const pi of drawnOn) buckets.set(pi, (buckets.get(pi) ?? 0) + 1);
  }
  return buckets;
}

/** A refusal the presented token's child-creation controls produce. */
export interface PresentedTokenRefusal {
  reason: ChildDenialReason;
  message: string;
  fanout?: { active_children: number; max_children: number };
}

/**
 * @spec child-delegation#attenuation, child-delegation#fanout (#825, D353,
 * #1192 review): the presented `subject_token` must authorize THIS
 * child-creation operation, not only bound the authority copied into the
 * child. Each child entry is attributed to the entry of the token's authority
 * it is a subset of (capability sources set aside, as for the authority bound);
 * that token entry's `children` object (present, since the child's is a subset
 * of it) MUST admit the child actor (`allowed_child_actors`) and the child's
 * depth (`max_child_depth`), alongside the parent entry's controls. The count control is
 * {@link presentedTokenFanoutRefusal}, run inside the creation transaction.
 */
export function presentedTokenChildRefusal(
  kernel: MissionKernel,
  childAuthority: readonly AuthorityEntry[],
  childActorSub: string,
  depth: number,
  presentedAuthority: readonly AuthorityEntry[],
): PresentedTokenRefusal | undefined {
  const token = withoutCapabilitySources(presentedAuthority);
  const tokenIdx = withoutCapabilitySources(childAuthority).map((ce) => token.findIndex((te) => isSubsetEntry(ce, te)));
  if (tokenIdx.some((ti) => ti < 0)) {
    return { reason: "not_strict_subset", message: "child Authority Set exceeds the presented token's authority" };
  }
  // A child entry always carries its justifying parent entry's `children`
  // object or a narrower one, so the authority bound above already refuses a
  // token entry without one (a token without the delegation right).
  const drawn = [...new Set(tokenIdx)].map((ti) => token[ti] as AuthorityEntry);
  const candidate: DelegateCandidate = { sub: childActorSub, assertedProfile: kernel.actorProfile(childActorSub) };
  if (drawn.some((te) => !delegatePermitted(candidate, childrenOf(te)?.allowed_child_actors))) {
    return { reason: "child_actor_not_allowed", message: "child actor is not permitted by the presented token's allowed_child_actors" };
  }
  for (const te of drawn) {
    const maxChildDepth = asNum(childrenOf(te)?.max_child_depth) ?? 1;
    if (depth > maxChildDepth) {
      return {
        reason: "fanout_exceeded",
        message: `child-generation depth ${depth} exceeds the presented token's max_child_depth ${maxChildDepth}`,
      };
    }
  }
  return undefined;
}

/**
 * @spec child-delegation#fanout-accounting (#825, D353, #1192 review): the
 * presented token's `max_children` bounds the SAME count as the parent
 * entry's: the parent's non-terminal children drawn on the parent entry each
 * child entry is justified by. At creation this child would add one; on
 * recovery the recorded child is already counted (`recordedChildCounted`).
 */
export function presentedTokenFanoutRefusal(
  kernel: MissionKernel,
  parent: MissionRecord,
  childAuthority: readonly AuthorityEntry[],
  presentedAuthority: readonly AuthorityEntry[],
  recordedChildCounted: boolean,
): PresentedTokenRefusal | undefined {
  const token = withoutCapabilitySources(presentedAuthority);
  const child = withoutCapabilitySources(childAuthority);
  const buckets = countChildBuckets(kernel, parent);
  for (let i = 0; i < childAuthority.length; i++) {
    const te = token.find((t) => isSubsetEntry(child[i] as AuthorityEntry, t));
    const maxChildren = te ? asNum(childrenOf(te)?.max_children) : undefined;
    if (maxChildren === undefined) continue;
    const active = buckets.get(justifyingIndex(childAuthority[i] as AuthorityEntry, parent.authority_set)) ?? 0;
    if ((recordedChildCounted ? active : active + 1) > maxChildren) {
      return {
        reason: "fanout_exceeded",
        message: `this child exceeds the presented token's max_children ${maxChildren}`,
        fanout: { active_children: active, max_children: maxChildren },
      };
    }
  }
  return undefined;
}

/** @spec child-delegation#child-evidence-canonical — the record's JCS bytes. */
export function childEvidenceBytes(evidence: ChildEvidence): string {
  return canonicalize(evidence as unknown as JsonValue);
}

/**
 * @spec child-delegation#child-creation, #fanout, #fanout-accounting,
 * #denial-reasons, #child-evidence — create a Child Mission from a Parent.
 *
 * Mirrors {@link createExpansion}: resolve and active-check the parent, derive
 * and PROVE strict-subset authority, clamp expiry to the parent, assemble the
 * `parent` lineage, restart the actor chain at the child actor, and insert. The
 * delegation event IS the child's approval event (no separate human approval).
 *
 * On top of that, the delegation decision is derived from the parent Authority
 * Set's per-entry `delegation.children` (PR1's S-15 core extension), NOT from an
 * explicit flag: each child entry is attributed to its justifying parent entry
 * (first-in-order subset), which is then the accounting basis for the four
 * fan-out controls. A permit returns a Child Evidence record; a refusal (after
 * the child identity is known) attaches a deny Child Evidence record to the
 * thrown {@link ChildDelegationError}.
 */
export function createChildMission(kernel: MissionKernel, input: CreateChildInput): ChildResult {
  const parent = kernel.get(input.parentId);
  if (!parent) throw new Error("unknown parent mission");

  const cascadeMode: CascadeMode = input.cascadeMode ?? "immediate";
  const nowIso = kernel.nowDate().toISOString();

  // @spec child-delegation#child-creation — the parent MUST be active. Uses the
  // applyExpiry state check (as createExpansion does), NOT gateDerivation: child
  // creation is not a token derivation and MUST NOT consume the parent's
  // derivation cap. (Pre-attenuation: no evidence — the child is not yet known.)
  if (kernel.applyExpiry(parent).state !== "active") {
    throw new ChildDelegationError("parent_not_active", `parent mission ${parent.id} is not active`);
  }

  // @spec child-delegation#child-client-identity — the child actor is the OAuth
  // client of the Child Mission; its identifier is the child record's client_id.
  // The child's own `act` chain restarts at the child actor (a fresh hop at depth
  // 0): child credentials never transit the parent.
  if (!input.childActor?.sub) {
    throw new ChildDelegationError("child_actor_not_allowed", "child actor missing sub");
  }
  let childAct: ActObject;
  try {
    childAct = extendChain(
      {
        sub: input.childActor.sub,
        iss: input.childActor.iss ?? parent.issuer,
        ...(input.childActor.sub_profile ? { sub_profile: input.childActor.sub_profile } : {}),
      },
      undefined,
    );
    validateActChain(childAct);
  } catch (e) {
    if (e instanceof ActorChainError) {
      throw new ChildDelegationError("child_actor_not_allowed", e.message);
    }
    throw e;
  }
  const clientId = childAct.sub;

  // @spec child-delegation#parent-member — child-generation depth counts UP from
  // 1 (1 for a child of a root Mission). Distinct from the per-entry
  // max_child_depth ceiling below, which is a decrementing bound the child depth
  // is measured against; the two are never conflated.
  const depth = (parent.parent?.depth ?? 0) + 1;

  // @spec child-delegation#strict-subset — derive the child Authority Set under
  // the ORIGINAL derivation policy (the child Intent is untrusted, like any
  // Intent). The parent Authority Set is the ceiling, enforced by REFUSAL rather
  // than silent clamping. Reusing the core isSubsetEntry: a child that OMITS a
  // constraint the parent narrowed (max_amount / vendors) is refused, so a child
  // MUST restate constraints at or below the parent's.
  const proposal = input.proposedAuthority?.length ? input.proposedAuthority : undefined;
  // The parent's EFFECTIVE set (approved minus the containment overlay) is the
  // grantor for both inheritance steps and for the strict-subset proof below.
  const parentEffective = kernel.effectiveAuthoritySet(parent);
  // @spec capability-binding#capability-source-binding — carry the parent's
  // recorded bindings for every retained catalog-sourced action, BEFORE the
  // child `authority_hash` below and before the strict-subset proof: a child
  // that dropped a parent binding is correctly refused by isSubsetEntry, so
  // the derived path inherits rather than leaving the member bare. The grantor
  // is the EFFECTIVE set, unlike createExpansion's approved-set grantor: a
  // contained capability MUST NOT re-derive into a child, while an Expansion
  // successor's own approval MAY restore one.
  const childAuthority = inheritCapabilitySources(
    inheritActionApprovalRequirement(kernel.derive(input.intent, proposal), parentEffective),
    parentEffective,
  );

  // @spec mission#authority-sources — a child drawdown draws on the PARENT's
  // established source, so the child inherits `authority_source` verbatim: the
  // record member is immutable, and re-establishing it at drawdown would let a
  // child change provenance with no approval event. The child inherits the
  // parent's committed ROOT too (#827), with the root's own context, whatever
  // client the child presents. Only the source ceiling is re-asserted, against
  // that root's declaration current at the moment authority is drawn, and it
  // runs BEFORE the child's anchors are computed.
  const parentRoot = kernel.committedSourceBinding(parent.id);
  kernel.assertInheritedAuthoritySource(parentRoot, childAuthority);

  // The prospective child identity, computed BEFORE the fan-out gates so a deny
  // Child Evidence record carries a real `child` member (REQUIRED unconditionally,
  // @spec child-delegation#child-evidence-object). The same id and hash are then
  // used for the inserted record on permit.
  const childId = newMissionId();
  const childAuthorityHash = authorityHash(parent.issuer, childAuthority as never);

  const makeEvidence = (
    decision: "created" | "denied",
    attenuationResult: string,
    denialReason?: ChildDenialReason,
    fanout?: { active_children: number; max_children?: number },
  ): ChildEvidence => ({
    evidence_id: `chd_${randomBytes(9).toString("base64url")}`,
    parent: { id: parent.id, issuer: parent.issuer, authority_hash: parent.authority_hash },
    child: { id: childId, issuer: parent.issuer, authority_hash: childAuthorityHash },
    child_actor: {
      sub: input.childActor.sub,
      ...(input.childActor.iss ? { iss: input.childActor.iss } : {}),
      ...(input.childActor.sub_profile ? { sub_profile: input.childActor.sub_profile } : {}),
    },
    attenuation: { result: attenuationResult },
    ...(fanout ? { fanout } : {}),
    cascade_mode: cascadeMode,
    decision,
    ...(denialReason ? { denial_reason: denialReason } : {}),
    created_at: nowIso,
  });

  // Containment: the parent ceiling is its EFFECTIVE set (approved minus the
  // containment overlay), so a contained capability cannot be re-derived into a
  // child. The justifying-index attribution below still runs over the approved
  // set: a subset of an effective entry is a subset of its approved entry, so
  // every index resolves, and fan-out controls live on the approved entries.
  if (!isSubsetSet(childAuthority, parentEffective)) {
    throw new ChildDelegationError(
      "not_strict_subset",
      "child Authority Set is not a strict subset of the parent",
      makeEvidence("denied", "not_strict_subset", "not_strict_subset"),
    );
  }
  // @spec child-delegation#attenuation (#825, D353): the presented token's own
  // authority is a second ceiling, as Self-Exchange rule 2 bounds a family, and
  // the token MUST authorize this creation: its `children` controls apply
  // alongside the parent entry's (#1192 review). Capability sources are
  // bindings, not authority, so they are set aside here (they are checked
  // against the parent above). The evidence names this bound.
  if (input.presentedAuthority) {
    const refusal = presentedTokenChildRefusal(kernel, childAuthority, input.childActor.sub, depth, input.presentedAuthority);
    if (refusal) {
      throw new ChildDelegationError(
        refusal.reason,
        refusal.message,
        makeEvidence("denied", "exceeds_presented_authority", refusal.reason),
      );
    }
  }

  // @spec child-delegation#fanout-accounting — attribute each child entry to its
  // justifying parent entry (first-in-order subset). All indices are >= 0 because
  // isSubsetSet passed. This mapping is the accounting basis for every control.
  const justifying = childAuthority.map((ce) => justifyingIndex(ce, parent.authority_set));
  const drawnOn = [...new Set(justifying)];
  const parentEntry = (pi: number): AuthorityEntry => parent.authority_set[pi] as AuthorityEntry;

  // @spec child-delegation#fanout — on-switch: EVERY justifying parent entry MUST
  // carry a `delegation.children` object, else refuse `delegation_not_permitted`
  // (kept DISTINCT from `policy_denied`).
  for (const pi of drawnOn) {
    if (!childrenOf(parentEntry(pi))) {
      throw new ChildDelegationError(
        "delegation_not_permitted",
        "a justifying parent Authority Set entry does not permit child delegation",
        makeEvidence("denied", "strict_subset", "delegation_not_permitted"),
      );
    }
  }

  // @spec mission#standing-consent-bases, child-delegation#child-creation —
  // every justifying entry that carries a `child_creation_policy` names a
  // separate policy that adjudicates this creation; the snapshot this issuer
  // would evaluate MUST match the committed `digest`, else creation is denied
  // `policy_denied`. Content edited under an unchanged version is a mismatch.
  for (const pi of drawnOn) {
    const policyRef = childrenOf(parentEntry(pi))?.child_creation_policy;
    if (policyRef && !activationPolicyMatches(parent.issuer, kernel.activationPolicies(), policyRef)) {
      throw new ChildDelegationError(
        "policy_denied",
        `child creation policy ${policyRef.id} does not match its committed digest`,
        makeEvidence("denied", "strict_subset", "policy_denied"),
      );
    }
  }

  // @spec child-delegation#fanout — allowed_child_actors: the child actor MUST be
  // permitted by every justifying entry, under the SAME shared matcher as the
  // core's allowed_delegates ({@link delegatePermitted}). The child actor's
  // `sub_profile` is matched ONLY against the profile the AS asserts for its `sub`
  // (kernel.actorProfile, from deployment config); the request-supplied
  // `input.childActor.sub_profile` is self-asserted and is used ONLY for the act
  // chain and Child Evidence, never to satisfy a `sub_profile` matcher. An absent
  // allowed_child_actors list DENIES (fail-closed), never blanket-allows.
  const childCandidate: DelegateCandidate = {
    sub: input.childActor.sub,
    assertedProfile: kernel.actorProfile(input.childActor.sub),
  };
  for (const pi of drawnOn) {
    if (!delegatePermitted(childCandidate, childrenOf(parentEntry(pi))?.allowed_child_actors)) {
      throw new ChildDelegationError(
        "child_actor_not_allowed",
        "child actor is not permitted by a justifying entry's allowed_child_actors",
        makeEvidence("denied", "strict_subset", "child_actor_not_allowed"),
      );
    }
  }

  // @spec child-delegation#fanout — max_child_depth: a per-entry, DECREMENTING
  // ceiling (default 1) the child-generation `depth` is measured against. The
  // hard MAX_CHILD_DEPTH is checked first as defence-in-depth; the per-entry
  // ceiling AUGMENTS it (the stricter one refuses).
  if (depth > MAX_CHILD_DEPTH) {
    throw new ChildDelegationError(
      "fanout_exceeded",
      `child-generation depth ${depth} exceeds the hard maximum ${MAX_CHILD_DEPTH}`,
      makeEvidence("denied", "strict_subset", "fanout_exceeded"),
    );
  }
  for (const pi of drawnOn) {
    const maxChildDepth = asNum(childrenOf(parentEntry(pi))?.max_child_depth) ?? 1;
    if (depth > maxChildDepth) {
      throw new ChildDelegationError(
        "fanout_exceeded",
        `child-generation depth ${depth} exceeds a justifying entry's max_child_depth ${maxChildDepth}`,
        makeEvidence("denied", "strict_subset", "fanout_exceeded"),
      );
    }
  }

  // @spec child-delegation#fanout-accounting — max_children: a per-entry cap on
  // concurrently non-terminal children. Count existing children bucketed by
  // justifying entry, then refuse if THIS child would push any bucket over its
  // cap. Admission runs inside the same transaction as insertion.
  let buckets: ReturnType<typeof countChildBuckets>;
  const assertFanout = () => {
    buckets = countChildBuckets(kernel, parent);
    for (const pi of drawnOn) {
      const maxChildren = asNum(childrenOf(parentEntry(pi))?.max_children);
      const active = buckets.get(pi) ?? 0;
      if (maxChildren !== undefined && active + 1 > maxChildren) {
        throw new ChildDelegationError(
          "fanout_exceeded",
          `creating this child would exceed max_children ${maxChildren} for a justifying parent entry`,
          makeEvidence("denied", "strict_subset", "fanout_exceeded", {
            active_children: active,
            max_children: maxChildren,
          }),
        );
      }
    }
    if (input.presentedAuthority) {
      const refusal = presentedTokenFanoutRefusal(kernel, parent, childAuthority, input.presentedAuthority, false);
      if (refusal) {
        throw new ChildDelegationError(
          refusal.reason,
          refusal.message,
          makeEvidence("denied", "exceeds_presented_authority", refusal.reason, refusal.fanout),
        );
      }
    }
  };

  // @spec child-delegation#attenuation — the child's expires_at MUST NOT be later
  // than the parent's. Established through the single effective-expiry hook, so
  // the parent bound composes with this deployment's own `max_mission_lifetime_s`
  // and with the requested ceiling, all measured from the ONE creation instant
  // (`nowIso`) the child record commits as its `created_at`.
  const expiresAt = kernel.resolveEffectiveExpiry({
    requested: input.intent.expires_at,
    createdAt: nowIso,
    ceilings: { parent: parent.expires_at },
  });

  const parentRef: ParentRef = {
    id: parent.id,
    issuer: parent.issuer,
    authority_hash: parent.authority_hash,
    depth,
    cascade_mode: cascadeMode,
    ...(input.delegationId ? { delegation_id: input.delegationId } : {}),
    created_at: nowIso,
  };

  // @spec child-delegation#child-evidence — the PRIMARY justifying entry (the
  // child's first Authority Set entry) is also the approval-basis anchor: its
  // `child_creation_policy`, when carried, is the drawdown policy reference.
  const primaryPi = justifying[0] as number;
  const primaryChildren = childrenOf(parentEntry(primaryPi));
  const primaryPolicy = primaryChildren?.child_creation_policy;
  const approvalEventId = `dlg_${randomBytes(12).toString("base64url")}`;
  // @spec mission#approval-basis, child-delegation#child-creation — every
  // child creation in this reference implementation is policy-adjudicated
  // (the fan-out on-switch above), never a separate per-child human
  // approval: consent_principal is the parent's accountable human (== the
  // inherited approver); activation_actor is the parent agent that requested
  // this child (the parent's own client_id, distinct from consent_principal);
  // root_commitment is the `digest` of the justifying entry's
  // `child_creation_policy` when carried, else the parent's own
  // authority_hash (the integrity anchor of the consented root the drawdown
  // draws against). With a policy, `activation` carries its id, version, and
  // digest; without one it carries only the event identifier.
  const approvalBasis: ApprovalBasis = {
    type: "policy_drawdown",
    consent_principal: parent.approval_basis.consent_principal,
    activation: {
      ...(primaryPolicy
        ? { policy_id: primaryPolicy.id, policy_version: primaryPolicy.version, policy_digest: primaryPolicy.digest }
        : {}),
      activation_event_id: approvalEventId,
    },
    activation_actor: { iss: parent.issuer, sub: parent.client_id },
    root_commitment: primaryPolicy?.digest ?? parent.authority_hash,
    // @spec mission#mission-record (#580) — the consented root (the parent's
    // authority_hash, or the entry-carried child_creation_policy digest
    // riding the committed entry) was approved at the PARENT's approval
    // event: retained state, never the child-creation request.
    approved_at: parent.created_at,
  };

  const child: MissionRecord = {
    id: childId,
    // @spec child-delegation#cross-issuer — the child issuer equals parent.issuer.
    issuer: parent.issuer,
    state: "active",
    intent: input.intent,
    ...(proposal ? { proposed_authority: proposal } : {}),
    authority_set: childAuthority,
    intent_hash: intentHash(parent.issuer, input.intent as never),
    ...(proposal ? { proposal_hash: proposalHash(parent.issuer, proposal as never) } : {}),
    ...(input.submissionEvidence?.length ? { submission_evidence: input.submissionEvidence } : {}),
    // @spec child-delegation#attenuation — authority_hash over the CHILD set.
    authority_hash: childAuthorityHash,
    // Subject and human accountability are inherited from the Parent Mission
    // (§issuance-relationship): a Child Mission is created under a parent grant.
    subject: parent.subject,
    approval_basis: approvalBasis,
    // @spec mission#authority-sources — inherited verbatim from the Parent
    // Mission, like `subject` and the Approver (`consent_principal`).
    authority_source: parent.authority_source,
    // @spec child-delegation#child-client-identity — client_id == child actor sub.
    client_id: clientId,
    policy_version: parent.policy_version,
    // @spec child-delegation#record-requirements — the delegation event IS the
    // child's approval event (dlg_-prefixed; no separate human approval).
    approval_event_id: approvalEventId,
    created_at: nowIso,
    expires_at: expiresAt,
    version: 1,
    // @spec child-delegation#child-creation, mission#derivation-issuance-policy
    // — the Child Mission's derivation ceiling comes from the CHILD's own
    // Intent (its `requested_derivation_limit`), independent of the parent's
    // (the rule PR #408 standardized), mirroring template.ts's
    // dispatch-instance mapping, and clamped by THIS deployment's own policy
    // ceiling exactly like an ordinary Mission approval; it is NOT inherited
    // from the parent, and an omitted request is not "unbounded" but simply
    // no client-requested narrowing of the deployment's own ceiling.
    derivation_limit: kernel.resolveDerivationLimit(input.intent.requested_derivation_limit),
    derivation_count: 0,
    grant_id: null,
    status_list_idx: null,
    parent: parentRef,
  };
  kernel.insertRecord(child, assertFanout, { source: { inherited: parentRoot } });

  // @spec child-delegation#child-evidence — permit record. `fanout` is recorded
  // for the PRIMARY justifying entry (the child's first Authority Set entry);
  // active_children is the bucket count AFTER this insert.
  const primaryMax = asNum(primaryChildren?.max_children);
  const evidence = makeEvidence("created", "strict_subset", undefined, {
    active_children: (buckets!.get(primaryPi) ?? 0) + 1,
    ...(primaryMax !== undefined ? { max_children: primaryMax } : {}),
  });

  return { child, parent: parent.id, evidence };
}

/**
 * @spec child-delegation#parent-member — the Child Mission's `mission` claim,
 * adding the `parent` lineage member (mirrors {@link successorMissionClaim}).
 */
export function childMissionClaim(
  kernel: MissionKernel,
  child: MissionRecord,
): Record<string, unknown> {
  return { ...kernel.missionClaim(child), parent: child.parent };
}
