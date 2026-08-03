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
 * (§cascade reversible trigger), full fan-out accounting (`max_children`,
 * `allowed_child_actors`, `max_child_depth`, per-entry `children`), the
 * `AuthorityEntry.delegation` core extension (S-15), the consumer-verified
 * cascade modes, child Decision Evidence, discovery metadata, and cross-issuer.
 */

import { randomBytes } from "node:crypto";
import { type ActObject, ActorChainError, extendChain, validateActChain } from "@mission/actor-chain";
import { authorityHash, intentHash } from "@mission/core";
import { isSubsetSet } from "./derive.js";
import type { MissionKernel } from "./kernel.js";
import type { CascadeMode, MissionIntent, MissionRecord, ParentRef } from "./types.js";

/** Hard child-generation depth cap (defence-in-depth; §fanout max_child_depth deferred). */
export const MAX_CHILD_DEPTH = 2;

/**
 * @spec child-delegation#denial-reasons — why child creation was refused.
 */
export type ChildDenialReason =
  | "parent_not_active"
  | "parent_mismatch"
  | "not_strict_subset"
  | "child_actor_not_allowed"
  | "fanout_exceeded"
  | "policy_denied";

/** A refusal of child creation, carrying the machine-readable reason. */
export class ChildDelegationError extends Error {
  constructor(
    readonly reason: ChildDenialReason,
    message: string,
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
  /**
   * @spec child-delegation#fanout (on-switch): child creation is permitted only
   * where the applicable parent Authority Set entry's `delegation` member carries
   * a `children` object. `AuthorityEntry` has no `delegation` member in the core
   * implementation (gap S-15, shared with Attenuation), so the resolved
   * permission is supplied here explicitly (precedent: {@link deriveAttenuationRoot}
   * takes `delMaxDepth` explicitly). Full fan-out accounting is deferred.
   */
  delegationAllowed: boolean;
  /** The recorded cascade mode. Defaults to (and today only supports) `immediate`. */
  cascadeMode?: CascadeMode;
  /** Optional Mission-Issuer-defined identifier for the delegation event. */
  delegationId?: string;
}

export interface ChildResult {
  child: MissionRecord;
  /** The Parent Mission identifier (mirrors ExpansionResult.predecessor). */
  parent: string;
}

/**
 * @spec child-delegation#child-creation — create a Child Mission from a Parent.
 * Mirrors {@link createExpansion}: resolve and active-check the parent, derive
 * and PROVE strict-subset authority, clamp expiry to the parent, assemble the
 * `parent` lineage, restart the actor chain at the child actor, and insert. The
 * delegation event IS the child's approval event (no separate human approval).
 */
export function createChildMission(kernel: MissionKernel, input: CreateChildInput): ChildResult {
  const parent = kernel.get(input.parentId);
  if (!parent) throw new Error("unknown parent mission");

  // @spec child-delegation#child-creation — the parent MUST be active. Uses the
  // applyExpiry state check (as createExpansion does), NOT gateDerivation: child
  // creation is not a token derivation and MUST NOT consume the parent's
  // derivation cap.
  if (kernel.applyExpiry(parent).state !== "active") {
    throw new ChildDelegationError("parent_not_active", `parent mission ${parent.id} is not active`);
  }

  // @spec child-delegation#fanout — the delegation on-switch (see delegationAllowed).
  if (!input.delegationAllowed) {
    throw new ChildDelegationError(
      "policy_denied",
      "parent authority does not permit child delegation",
    );
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

  // @spec child-delegation#parent-member — child-generation depth counts up from
  // 1 (1 for a child of a root Mission). Small hard cap; the per-entry
  // max_child_depth fan-out ceiling is deferred.
  const depth = (parent.parent?.depth ?? 0) + 1;
  if (depth > MAX_CHILD_DEPTH) {
    throw new ChildDelegationError(
      "fanout_exceeded",
      `child-generation depth ${depth} exceeds the maximum ${MAX_CHILD_DEPTH}`,
    );
  }

  // @spec child-delegation#strict-subset — derive the child Authority Set under
  // the ORIGINAL derivation policy (the child Intent is untrusted, like any
  // Intent), then PROVE it is a strict subset of the parent's. The parent
  // Authority Set is the ceiling, enforced by REFUSAL rather than silent
  // clamping, as §strict-subset mandates ("MUST refuse ... with
  // not_strict_subset"). Consequence of reusing the core isSubsetEntry: a child
  // that OMITS a constraint the parent narrowed (max_amount / vendors) is refused
  // (isSubsetEntry fails when `granted` has a constraint and `candidate` lacks
  // it), so a child MUST restate constraints at or below the parent's.
  const childAuthority = kernel.derive(input.intent);
  if (!isSubsetSet(childAuthority, parent.authority_set)) {
    throw new ChildDelegationError(
      "not_strict_subset",
      "child Authority Set is not a strict subset of the parent",
    );
  }

  // @spec child-delegation#attenuation — the child's expires_at MUST NOT be later
  // than the parent's (clamp; mirrors createExpansion's approved_until clamp).
  const expiresAt =
    Date.parse(input.intent.expires_at) <= Date.parse(parent.expires_at)
      ? input.intent.expires_at
      : parent.expires_at;

  const nowIso = kernel.nowDate().toISOString();
  const parentRef: ParentRef = {
    id: parent.id,
    issuer: parent.issuer,
    authority_hash: parent.authority_hash,
    depth,
    cascade_mode: input.cascadeMode ?? "immediate",
    ...(input.delegationId ? { delegation_id: input.delegationId } : {}),
    created_at: nowIso,
  };

  const child: MissionRecord = {
    id: `msn_${randomBytes(18).toString("base64url")}`,
    // @spec child-delegation#cross-issuer — the child issuer equals parent.issuer.
    issuer: parent.issuer,
    state: "active",
    intent: input.intent,
    authority_set: childAuthority,
    intent_hash: intentHash(parent.issuer, input.intent as never),
    // @spec child-delegation#attenuation — authority_hash over the CHILD set.
    authority_hash: authorityHash(parent.issuer, childAuthority as never),
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
  return { child, parent: parent.id };
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
