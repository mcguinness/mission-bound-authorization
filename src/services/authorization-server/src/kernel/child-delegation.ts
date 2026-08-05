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
import { authorityHash, canonicalize, intentHash, type JsonValue } from "@mission/core";
import { isSubsetEntry, isSubsetSet } from "./derive.js";
import type { MissionKernel } from "./kernel.js";
import {
  type AuthorityEntry,
  type CascadeMode,
  type ChildEvidence,
  type ChildFanoutControls,
  type MissionIntent,
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
 * carries no `delegation.children`); it is DISTINCT from `policy_denied`, which
 * is retained for a genuine `child_creation_policy` denial (not yet wired).
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
  /** The child actor that holds/executes under the Child Mission. */
  childActor: ChildActor;
  /** The recorded cascade mode. Defaults to (and today only supports) `immediate`. */
  cascadeMode?: CascadeMode;
  /** Optional Mission-Issuer-defined identifier for the delegation event. */
  delegationId?: string;
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
function asNum(v: JsonValue | undefined): number | undefined {
  return typeof v === "number" ? v : undefined;
}

/**
 * The `delegation.children` fan-out controls of a parent entry, or undefined
 * when the entry carries no `children` object (the on-switch is absent). Read
 * through this local reader so the `delegation` open index in types.ts stays
 * `JsonValue`-shaped and derive.ts is untouched.
 */
function childrenOf(entry: AuthorityEntry): ChildFanoutControls | undefined {
  const c = entry.delegation?.children;
  return c !== null && typeof c === "object" && !Array.isArray(c)
    ? (c as ChildFanoutControls)
    : undefined;
}

/**
 * @spec child-delegation#fanout-accounting — the justifying parent entry for a
 * child entry: the index of the FIRST parent entry (Authority Set order) the
 * child entry is a subset of. -1 only if none (never for a proven-subset child).
 */
function justifyingIndex(childEntry: AuthorityEntry, parentSet: AuthorityEntry[]): number {
  return parentSet.findIndex((p) => isSubsetEntry(childEntry, p));
}

/**
 * @spec child-delegation#fanout — an `allowed_child_actors` list is satisfied
 * when SOME matcher matches: a matcher matches when every field it carries
 * (`sub` and/or `sub_profile`) equals the child actor's. An absent list is
 * unconstrained. Mirrors the core `allowed_delegates` matching direction.
 */
function actorAllowed(actor: ChildActor, matchers: unknown): boolean {
  if (!Array.isArray(matchers)) return true; // no allowed_child_actors -> any actor
  return matchers.some((m) => {
    if (m === null || typeof m !== "object" || Array.isArray(m)) return false;
    const mm = m as { sub?: unknown; sub_profile?: unknown };
    if (mm.sub !== undefined && mm.sub !== actor.sub) return false;
    if (mm.sub_profile !== undefined && mm.sub_profile !== actor.sub_profile) return false;
    return true;
  });
}

/**
 * @spec child-delegation#fanout-accounting — count the parent's NON-terminal
 * existing Child Missions, BUCKETED by justifying parent-entry index. Each child
 * counts once per distinct parent entry it draws on (recomputed by the same
 * first-in-order justifying selection). Read-only over `kernel.findChildren`.
 */
function countChildBuckets(kernel: MissionKernel, parent: MissionRecord): Map<number, number> {
  const buckets = new Map<number, number>();
  for (const existing of kernel.findChildren(parent.id)) {
    if (TERMINAL_STATES.has(existing.state)) continue; // only non-terminal count
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
  const childAuthority = kernel.derive(input.intent);

  // The prospective child identity, computed BEFORE the fan-out gates so a deny
  // Child Evidence record carries a real `child` member (REQUIRED unconditionally,
  // @spec child-delegation#child-evidence-object). The same id and hash are then
  // used for the inserted record on permit.
  const childId = `msn_${randomBytes(18).toString("base64url")}`;
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

  if (!isSubsetSet(childAuthority, parent.authority_set)) {
    throw new ChildDelegationError(
      "not_strict_subset",
      "child Authority Set is not a strict subset of the parent",
      makeEvidence("denied", "not_strict_subset", "not_strict_subset"),
    );
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

  // @spec child-delegation#fanout — allowed_child_actors: the child actor MUST be
  // permitted by every justifying entry that constrains it.
  for (const pi of drawnOn) {
    if (!actorAllowed(input.childActor, childrenOf(parentEntry(pi))?.allowed_child_actors)) {
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
  // cap. The in-process kernel is single-threaded and createChildMission is fully
  // synchronous, so this count -> check -> insertRecord runs with no interleaving
  // (no await between the count and the insert): count-then-insert is effectively
  // atomic and the "no bucket exceeds max_children" invariant holds without a lock.
  const buckets = countChildBuckets(kernel, parent);
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

  // @spec child-delegation#attenuation — the child's expires_at MUST NOT be later
  // than the parent's (clamp; mirrors createExpansion's approved_until clamp).
  const expiresAt =
    Date.parse(input.intent.expires_at) <= Date.parse(parent.expires_at)
      ? input.intent.expires_at
      : parent.expires_at;

  const parentRef: ParentRef = {
    id: parent.id,
    issuer: parent.issuer,
    authority_hash: parent.authority_hash,
    depth,
    cascade_mode: cascadeMode,
    ...(input.delegationId ? { delegation_id: input.delegationId } : {}),
    created_at: nowIso,
  };

  const child: MissionRecord = {
    id: childId,
    // @spec child-delegation#cross-issuer — the child issuer equals parent.issuer.
    issuer: parent.issuer,
    state: "active",
    intent: input.intent,
    authority_set: childAuthority,
    intent_hash: intentHash(parent.issuer, input.intent as never),
    // @spec child-delegation#attenuation — authority_hash over the CHILD set.
    authority_hash: childAuthorityHash,
    // Subject and human accountability are inherited from the Parent Mission
    // (§issuance-relationship): a Child Mission is created under a parent grant.
    subject: parent.subject,
    approver: parent.approver,
    // @spec child-delegation#child-client-identity — client_id == child actor sub.
    client_id: clientId,
    policy_version: parent.policy_version,
    // @spec child-delegation#record-requirements — the delegation event IS the
    // child's approval event (dlg_-prefixed; no separate human approval).
    approval_event_id: `dlg_${randomBytes(12).toString("base64url")}`,
    created_at: nowIso,
    expires_at: expiresAt,
    version: 1,
    max_derivations: parent.max_derivations,
    derivation_count: 0,
    grant_id: null,
    status_list_idx: null,
    parent: parentRef,
  };
  kernel.insertRecord(child);

  // @spec child-delegation#child-evidence — permit record. `fanout` is recorded
  // for the PRIMARY justifying entry (the child's first Authority Set entry);
  // active_children is the bucket count AFTER this insert.
  const primaryPi = justifying[0] as number;
  const primaryChildren = childrenOf(parentEntry(primaryPi));
  const primaryMax = asNum(primaryChildren?.max_children);
  const evidence = makeEvidence("created", "strict_subset", undefined, {
    active_children: (buckets.get(primaryPi) ?? 0) + 1,
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
