/**
 * @spec draft-mcguinness-oauth-mission-child-delegation (#carryover,
 * #carryover-manifest, #carryover-cas, #carryover-generations,
 * #carryover-no-reset, #carryover-records, #carryover-commit,
 * #carryover-evidence)
 *
 * Child Mission Carryover: the OPTIONAL, capability-gated batch that creates
 * explicitly approved REPLACEMENT Child Missions while an Expansion successor
 * activates. It never preserves an old record by re-parenting it.
 *
 * Two APIs, deliberately separated:
 *  - {@link prepareCarryover} is READ-ONLY. It walks the whole predecessor
 *    subtree, decides eligibility generation by generation against each
 *    prospective parent's effective set, RESERVES the proposed successor and
 *    replacement identifiers, and snapshots every mutable eligibility and
 *    transfer input. Reservation creates no authority: it fixes which
 *    identifiers the approval may authenticate, nothing else.
 *  - {@link applyCarryoverInCallerTx} is TRANSACTION-ONLY. It runs inside the
 *    expansion completion transaction, re-enumerates the whole current subtree,
 *    compares descendant-set MEMBERSHIP with the committed manifest,
 *    compare-and-sets every committed mutable input per row, derives and
 *    inserts the replacements in generation order, terminates the whole old
 *    subtree through the kernel's one carried-terminal funnel, and retains the
 *    complete map plus authenticated Carryover Evidence.
 *
 * Completion verifies the COMMITTED result. It never invents an identity that
 * was absent from the approved manifest, and it never turns a rendered cascade
 * into a carry or silently adds a replacement.
 */

import { randomBytes } from "node:crypto";
import { type ActObject, ActorChainError, extendChain, validateActChain } from "@mission/actor-chain";
import {
  authorityHash,
  canonicalize,
  computeAnchor,
  intentHash,
  isSubsetSetIgnoringCapabilitySources,
  type JsonValue,
} from "@mission/core";
import { withTransaction, type Database } from "@mission/store";
import { inheritCapabilitySources } from "./capability-binding.js";
import {
  asNum,
  childrenOf,
  countChildBuckets,
  inheritActionApprovalRequirement,
  justifyingIndex,
  MAX_CHILD_DEPTH,
} from "./child-delegation.js";
import { type DelegateCandidate, delegatePermitted } from "./delegate-matcher.js";
import { isSubsetSet } from "./derive.js";
import type { MissionKernel } from "./kernel.js";
import { newMissionId } from "./mission-id.js";
import {
  type ApprovalBasis,
  type AuthorityEntry,
  type AuthoritySource,
  type ChildEvidence,
  type MissionIntent,
  type MissionRecord,
  type MissionState,
  type ParentRef,
  TERMINAL_STATES,
} from "./types.js";

/**
 * @spec child-delegation#carryover-manifest — the manifest commitment typ. The
 * `manifest_hash` is the issuance profile's default commitment construction
 * (the family anchor idiom, `{typ, iss, value}` under JCS) over the canonical
 * manifest, `exclusion_policy` included.
 */
export const CARRYOVER_MANIFEST_TYP = "mission-carryover-manifest";

/**
 * @spec child-delegation#carryover-manifest — the per-child approval-event
 * commitment typ. Each child-specific event identifier is derived from the
 * COMMITTED expansion approval event identifier and the qualified old-child
 * identity under the same construction, so it is stable on retry.
 */
export const CARRYOVER_APPROVAL_EVENT_TYP = "mission-carryover-approval-event";

/** @spec child-delegation#carryover-evidence — the Carryover Evidence commitment typ. */
export const CARRYOVER_EVIDENCE_TYP = "mission-carryover-evidence";

/** @spec child-delegation#carryover-evidence — the retained evidence media type. */
export const CARRYOVER_EVIDENCE_MEDIA_TYPE = "application/mission-carryover-evidence+json";

/** The JWS `typ` of the authenticated Carryover Evidence envelope. */
export const CARRYOVER_EVIDENCE_JWS_TYP = "mission-carryover-evidence+jwt";

/**
 * @spec child-delegation#carryover-cas — the CHANGE CLASSES a
 * `disclosed_exclusions` policy may commit. Only a class the manifest actually
 * committed can exclude a rendered row; anything else requires a fresh render
 * and approval. Under `all_or_nothing` no class excludes: any relevant change
 * requires fresh approval.
 */
export const CARRYOVER_CHANGE_CLASSES = [
  /** A rendered row is no longer effectively `active` (terminated, suspended, held). */
  "state_changed",
  /** A rendered row's record is gone from the current subtree. */
  "record_missing",
  /** Effective authority, containment or discharge moved after rendering. */
  "authority_narrowed",
  /** `derivation_count` moved with no lifecycle-version increment. */
  "derivation_consumed",
  /** The old child's non-terminal child occupancy moved after rendering. */
  "fanout_occupancy_changed",
  /** The rendered `expires_at` no longer holds. */
  "expiry_changed",
  /** An external meter or latch cannot participate in the completion transaction. */
  "external_transfer_unavailable",
  /** A descendant present now was absent from the manifest. */
  "unrendered_descendant",
] as const;

export type CarryoverChangeClass = (typeof CARRYOVER_CHANGE_CLASSES)[number];

/**
 * @spec child-delegation#carryover-manifest — the committed exclusion policy.
 * `all_or_nothing` is the reference default: ANY relevant change, the
 * disappearance or termination of a rendered row included, requires a fresh
 * render and approval. `disclosed_exclusions` names the change classes that MAY
 * exclude rows, and must disclose dependent-descendant exclusion and
 * unrendered-child cascade explicitly. Neither mode silently adds a replacement
 * or turns a rendered cascade into a carry.
 */
export type CarryoverExclusionPolicy =
  | { mode: "all_or_nothing" }
  | {
      mode: "disclosed_exclusions";
      change_classes: CarryoverChangeClass[];
      dependent_descendant_exclusion: true;
      unrendered_child_cascade: true;
    };

/** A qualified Mission reference: `issuer` plus the Mission identifier. */
export interface CarryoverRef {
  issuer: string;
  mission_id: string;
}

/**
 * @spec child-delegation#carryover-manifest — the rendered replacement facts a
 * `carry` entry commits. `replacement_id` is a RESERVED identifier; completion
 * uses exactly this value.
 */
export interface CarryoverReplacementProposal {
  replacement_id: string;
  intent_hash: string;
  authority_hash: string;
  actor: { sub: string; iss?: string; sub_profile?: string };
  parent: CarryoverRef;
  authority_source: AuthoritySource;
  /**
   * Whether the rendered source is the OLD CHILD's or the SUCCESSOR's. A
   * replacement inheriting the successor's source rather than the old child's is
   * an explicitly rendered and committed change (@spec #carryover-manifest).
   */
  authority_source_origin: "old_child" | "successor";
  expires_at: string;
  derivation_limit: number | null;
  derivation_count: number;
  /** Filled at the approval event; absent on a prepared, unapproved plan. */
  approval_event_id?: string;
}

/** @spec child-delegation#carryover-manifest — one rendered manifest entry. */
export interface CarryoverEntry {
  child_id: string;
  issuer: string;
  created_at: string;
  child_actor: { sub: string; iss?: string; sub_profile?: string };
  state: MissionState;
  version: number;
  authority_hash: string;
  intent_hash: string;
  effective_authority_hash: string;
  containment_version: number;
  discharged_digests: string[];
  parent: CarryoverRef;
  depth: number;
  derivation_limit: number | null;
  derivation_count: number;
  expires_at: string;
  /** The old child's own non-terminal child occupancy at rendering. */
  child_occupancy: number;
  /** The external meter/latch inputs used to decide or transfer eligibility. */
  external_state: CarryoverExternalState;
  outcome: "carry" | "cascade";
  /** REQUIRED for `cascade`. */
  reason?: string;
  /** REQUIRED for `carry`. */
  replacement?: CarryoverReplacementProposal;
}

/**
 * @spec child-delegation#carryover-no-reset — the external meter/latch facts a
 * row's eligibility and budget transfer rest on. `transferable` false renders
 * the child ineligible BEFORE approval: an absent adapter means "not
 * transferable", except where the deployment explicitly declares that no
 * external meter or latch applies.
 */
export interface CarryoverExternalState {
  transferable: boolean;
  /** The deployment declared that no external meter or latch applies. */
  declared_absent: boolean;
  /** The adapter that will participate in the completion transaction, if any. */
  adapter?: string;
  /** The adapter's committed state commitment, when it supplies one. */
  state_hash?: string;
}

/** @spec child-delegation#carryover-manifest — the manifest itself. */
export interface CarryoverManifest {
  format_version: 1;
  predecessor: CarryoverRef;
  successor: CarryoverRef;
  successor_intent_hash: string;
  successor_authority_hash: string;
  exclusion_policy: CarryoverExclusionPolicy;
  policy_version: string;
  entries: CarryoverEntry[];
}

/**
 * The prepared plan as the issuer retains it beside the pending approval: the
 * manifest (with per-child approval identifiers still unfilled), the reserved
 * identifiers, and the derivation inputs completion reproduces from.
 */
export interface CarryoverPlan {
  plan_id: string;
  manifest: CarryoverManifest;
  reserved_ids: string[];
}

/**
 * @spec child-delegation#carryover-no-reset — the atomic external transfer
 * seam. Only a transfer that PARTICIPATES in the completion transaction (or a
 * demonstrably atomic shared-state binding) can support a carried budget: a
 * callback that returns `ok`, or a compensating action after an external
 * failure, does not satisfy atomic transfer. `eligible` runs at rendering and
 * is read-only; `transferInCallerTx` runs inside the completion transaction and
 * throws to roll the whole batch back.
 */
export interface CarryoverExternalStateAdapter {
  id: string;
  /** Read-only rendering probe: the committed external facts, or ineligibility. */
  eligible: (child: MissionRecord) => CarryoverExternalState;
  /** Transaction-participating transfer. A throw rolls the completion back. */
  transferInCallerTx: (input: {
    child: MissionRecord;
    replacementId: string;
    committed: CarryoverExternalState;
  }) => void;
}

/**
 * The deployment's carryover configuration. `enabled` is the capability
 * on-switch; the whole module is inert without it.
 */
export interface CarryoverConfig {
  enabled: boolean;
  /**
   * The subtree-size/transaction-budget cap: the maximum rendered rows one
   * carryover plan may carry. Null means the deployment imposes none. An
   * oversized widening proposal is refused at INTAKE, before approval, so the
   * approval event never names a plan the kernel cannot commit in one
   * transaction.
   */
  maxRows: number | null;
  /** The committed exclusion policy this deployment renders plans under. */
  exclusionPolicy: CarryoverExclusionPolicy;
  /**
   * The deployment's declaration that no external meter or latch applies to
   * carried children. Absent, and with no adapter, every child is rendered
   * ineligible rather than claiming a transfer the deployment cannot make.
   */
  noApplicableExternalState?: boolean;
  externalState?: CarryoverExternalStateAdapter;
}

/**
 * A carryover refusal. Pre-decision at INTAKE (`carryover_plan_too_large`,
 * `carryover_id_collision`); at COMPLETION every code rolls the whole
 * completion transaction back, so no partial successor, surviving replacement
 * or cascade is left behind.
 */
export type CarryoverRefusalCode =
  | "carryover_plan_too_large"
  | "carryover_id_collision"
  | "manifest_mismatch"
  | "reserved_id_unusable"
  | "subtree_changed"
  | "snapshot_moved"
  | "undisclosed_change_class"
  | "external_transfer_unavailable"
  | "approval_basis_not_direct"
  | "authority_source_substituted";

export class CarryoverError extends Error {
  constructor(
    readonly code: CarryoverRefusalCode,
    message: string,
  ) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// Commitment construction (@spec child-delegation#carryover-manifest).
// ---------------------------------------------------------------------------

/**
 * @spec child-delegation#carryover-manifest — `manifest_hash`: the issuance
 * profile's default commitment construction over the JCS canonical manifest,
 * `exclusion_policy` included. The hash alone authenticates no approval; the
 * issuer retains the manifest with its authenticated approval.
 */
export function carryoverManifestHash(iss: string, manifest: CarryoverManifest): string {
  return computeAnchor(CARRYOVER_MANIFEST_TYP, iss, manifest as unknown as JsonValue);
}

/**
 * @spec child-delegation#carryover-manifest — the DETERMINISTIC child-specific
 * approval event identifier: the same construction over the committed expansion
 * approval event identifier plus the qualified old-child identity. Stable on
 * retry, which is what makes a replay a `findByApprovalEvent` lookup rather
 * than a second creation.
 */
export function carryoverApprovalEventId(
  iss: string,
  expansionApprovalEventId: string,
  oldChild: CarryoverRef,
): string {
  const anchor = computeAnchor(CARRYOVER_APPROVAL_EVENT_TYP, iss, {
    approval_event_id: expansionApprovalEventId,
    old_child: { issuer: oldChild.issuer, mission_id: oldChild.mission_id },
  } as unknown as JsonValue);
  return `cry_${anchor.slice("sha-256:".length)}`;
}

// ---------------------------------------------------------------------------
// Identifier reservation (@spec child-delegation#carryover-manifest).
// ---------------------------------------------------------------------------

const RESERVATION_SCHEMA = `
CREATE TABLE IF NOT EXISTS carryover_reservations (
  issuer TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  role TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (issuer, mission_id)
) STRICT;

CREATE TABLE IF NOT EXISTS carryover_results (
  plan_id TEXT PRIMARY KEY,
  issuer TEXT NOT NULL,
  predecessor_id TEXT NOT NULL,
  successor_id TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  map_json TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  evidence_jws TEXT NOT NULL,
  committed_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS carryover_replacements (
  issuer TEXT NOT NULL,
  replacement_id TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  old_child_id TEXT NOT NULL,
  approval_event_id TEXT NOT NULL,
  child_evidence_json TEXT NOT NULL,
  PRIMARY KEY (issuer, replacement_id)
) STRICT;
`;

/** Bounded minting budget: a reserved identifier that collides is re-drawn. */
const RESERVATION_MAX_ATTEMPTS = 16;

/**
 * @spec child-delegation#carryover-manifest, #carryover-commit — the
 * reservation, result and replacement stores. They live in the KERNEL's own
 * database so the reservation, the replacement records, the final map and the
 * authenticated evidence share ONE transaction with `kernel.insertRecord`
 * (nested `withTransaction` calls become savepoints).
 *
 * Reservation lifecycle:
 *  - COLLISION. An identifier already held by a live record, a tombstone or
 *    another plan is re-drawn, up to {@link RESERVATION_MAX_ATTEMPTS}; a
 *    persistent collision refuses preparation (`carryover_id_collision`) rather
 *    than proceeding with an identifier the completion could not use.
 *  - CANCELLED PLAN. A denied or expired plan is marked `cancelled`. Its
 *    identifiers stay HELD: they are never handed to another plan and never
 *    re-drawn as fresh identifiers, and the cancelled plan can never complete.
 *  - CHANGED PLAN. A changed widening request is a different creation
 *    operation: it opens a new deferral, prepares a NEW plan and reserves NEW
 *    identifiers. The old plan's manifest hash still binds its own approval, so
 *    a changed plan cannot complete against reservations it did not commit.
 *  - RETRY. The idempotent open/poll path returns the EXISTING plan and its
 *    existing reservations; nothing is re-minted. A rolled-back completion
 *    attempt leaves the reservations intact (and writes no tombstone), so the
 *    retry uses exactly the same identifiers.
 */
export class CarryoverStore {
  readonly db: Database;
  constructor(
    private readonly kernel: MissionKernel,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.db = kernel.db;
    this.db.exec(RESERVATION_SCHEMA);
  }

  /** True when this identifier is already a live record, a tombstone or a reservation. */
  private taken(issuer: string, missionId: string): boolean {
    if (this.kernel.get(missionId)) return true;
    if (this.kernel.tombstones.exists(issuer, missionId)) return true;
    return (
      this.db
        .prepare("SELECT 1 FROM carryover_reservations WHERE issuer = ? AND mission_id = ?")
        .get(issuer, missionId) !== undefined
    );
  }

  /**
   * Reserve `count` fresh identifiers for `planId`. Read-only with respect to
   * authority: a reservation grants nothing, and no record exists yet.
   */
  reserve(issuer: string, planId: string, roles: readonly string[]): string[] {
    return withTransaction(this.db, () => {
      const out: string[] = [];
      for (const role of roles) {
        let chosen: string | undefined;
        for (let attempt = 0; attempt < RESERVATION_MAX_ATTEMPTS; attempt++) {
          const candidate = newMissionId();
          if (this.taken(issuer, candidate)) continue;
          this.db
            .prepare(
              "INSERT INTO carryover_reservations (issuer, mission_id, plan_id, role, state, created_at) VALUES (?, ?, ?, ?, 'held', ?)",
            )
            .run(issuer, candidate, planId, role, this.now().getTime());
          chosen = candidate;
          break;
        }
        if (!chosen) {
          throw new CarryoverError(
            "carryover_id_collision",
            `could not reserve a fresh ${role} identifier within ${RESERVATION_MAX_ATTEMPTS} attempts`,
          );
        }
        out.push(chosen);
      }
      return out;
    });
  }

  /**
   * Assert every reserved identifier is still usable at completion. A reserved
   * identifier that has since become a live record or a tombstone REFUSES the
   * completion: an identity absent from the approved manifest is never
   * substituted for it.
   */
  assertReservedUsableInCallerTx(issuer: string, planId: string, ids: readonly string[]): void {
    for (const id of ids) {
      const row = this.db
        .prepare("SELECT plan_id, state FROM carryover_reservations WHERE issuer = ? AND mission_id = ?")
        .get(issuer, id) as { plan_id: string; state: string } | undefined;
      if (!row || row.plan_id !== planId || row.state !== "held") {
        throw new CarryoverError(
          "reserved_id_unusable",
          `reserved identifier ${id} is not held by plan ${planId}`,
        );
      }
      if (this.kernel.get(id) || this.kernel.tombstones.exists(issuer, id)) {
        throw new CarryoverError(
          "reserved_id_unusable",
          `reserved identifier ${id} is no longer usable and MUST NOT be substituted`,
        );
      }
    }
  }

  /**
   * Assert an identifier is reserved BY THIS PLAN, without requiring it to be
   * unused: the successor identifier is already a live record inside the
   * completion transaction that created it.
   */
  assertReservationOwnedInCallerTx(issuer: string, planId: string, id: string): void {
    const row = this.db
      .prepare("SELECT plan_id, state FROM carryover_reservations WHERE issuer = ? AND mission_id = ?")
      .get(issuer, id) as { plan_id: string; state: string } | undefined;
    if (!row || row.plan_id !== planId || row.state !== "held") {
      throw new CarryoverError(
        "reserved_id_unusable",
        `identifier ${id} is not reserved by plan ${planId}`,
      );
    }
  }

  /** Mark a denied or expired plan's reservations cancelled; the identifiers stay held. */
  cancel(planId: string): void {
    this.db
      .prepare("UPDATE carryover_reservations SET state = 'cancelled' WHERE plan_id = ? AND state = 'held'")
      .run(planId);
  }

  /** Consume the reservations a committed completion actually used. */
  consumeInCallerTx(planId: string, ids: readonly string[]): void {
    for (const id of ids) {
      this.db
        .prepare("UPDATE carryover_reservations SET state = 'used' WHERE plan_id = ? AND mission_id = ?")
        .run(planId, id);
    }
  }

  /** Retain the frozen manifest, the complete map and the authenticated evidence. */
  retainResultInCallerTx(row: {
    planId: string;
    issuer: string;
    predecessorId: string;
    successorId: string;
    manifestHash: string;
    manifest: CarryoverManifest;
    map: CarryoverMap;
    evidenceHash: string;
    evidenceJws: string;
    committedAt: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO carryover_results (plan_id, issuer, predecessor_id, successor_id, manifest_hash,
           manifest_json, map_json, evidence_hash, evidence_jws, committed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.planId,
        row.issuer,
        row.predecessorId,
        row.successorId,
        row.manifestHash,
        JSON.stringify(row.manifest),
        JSON.stringify(row.map),
        row.evidenceHash,
        row.evidenceJws,
        row.committedAt,
      );
  }

  /** Retain one replacement's ordinary Child Evidence linkage. */
  retainReplacementInCallerTx(row: {
    issuer: string;
    replacementId: string;
    planId: string;
    oldChildId: string;
    approvalEventId: string;
    childEvidence: ChildEvidence;
  }): void {
    this.db
      .prepare(
        `INSERT INTO carryover_replacements (issuer, replacement_id, plan_id, old_child_id, approval_event_id, child_evidence_json)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.issuer,
        row.replacementId,
        row.planId,
        row.oldChildId,
        row.approvalEventId,
        JSON.stringify(row.childEvidence),
      );
  }

  /** The committed batch result for a plan, or undefined. */
  result(planId: string): CarryoverCommittedResult | undefined {
    const row = this.db.prepare("SELECT * FROM carryover_results WHERE plan_id = ?").get(planId) as
      | Record<string, unknown>
      | undefined;
    return row ? rowToResult(row) : undefined;
  }

  /** The committed batch result that created a given replacement, or undefined. */
  resultForReplacement(
    issuer: string,
    replacementId: string,
  ): { result: CarryoverCommittedResult; replacement: CarryoverReplacementRow } | undefined {
    const link = this.db
      .prepare("SELECT * FROM carryover_replacements WHERE issuer = ? AND replacement_id = ?")
      .get(issuer, replacementId) as Record<string, unknown> | undefined;
    if (!link) return undefined;
    const result = this.result(link.plan_id as string);
    if (!result) return undefined;
    return {
      result,
      replacement: {
        issuer: link.issuer as string,
        replacement_id: link.replacement_id as string,
        plan_id: link.plan_id as string,
        old_child_id: link.old_child_id as string,
        approval_event_id: link.approval_event_id as string,
        child_evidence: JSON.parse(link.child_evidence_json as string) as ChildEvidence,
      },
    };
  }

  /**
   * @spec child-delegation#carryover-commit — IDEMPOTENT retrieval of the
   * committed replacement result, to the AUTHENTICATED and AUTHORIZED child
   * actor. Authorization is the replacement record's own `client_id` (the child
   * actor): the deterministic approval event identifier is a
   * correlation/idempotency key, NEVER a bearer credential and never retrieval
   * authorization. Retrieval repeats no approval, creates no duplicate
   * replacement, and still enforces current authorization and lifecycle checks
   * on any newly issued credential (minting stays with the caller).
   */
  retrieve(input: {
    replacementId: string;
    actor: { sub: string };
  }): { replacement: MissionRecord; link: CarryoverReplacementRow; result: CarryoverCommittedResult } {
    const record = this.kernel.get(input.replacementId);
    if (!record) throw new CarryoverRetrievalError("not_found", "no such replacement record");
    const found = this.resultForReplacement(record.issuer, input.replacementId);
    if (!found) {
      throw new CarryoverRetrievalError("not_found", "record is not a committed carryover replacement");
    }
    if (record.client_id !== input.actor.sub) {
      throw new CarryoverRetrievalError(
        "unauthorized",
        "only the replacement's own child actor may retrieve its result",
      );
    }
    return { replacement: record, link: found.replacement, result: found.result };
  }
}

/** A retrieval refusal. `unauthorized` is the actor-authorization failure. */
export class CarryoverRetrievalError extends Error {
  constructor(
    readonly code: "not_found" | "unauthorized",
    message: string,
  ) {
    super(message);
  }
}

export interface CarryoverReplacementRow {
  issuer: string;
  replacement_id: string;
  plan_id: string;
  old_child_id: string;
  approval_event_id: string;
  child_evidence: ChildEvidence;
}

export interface CarryoverCommittedResult {
  plan_id: string;
  issuer: string;
  predecessor_id: string;
  successor_id: string;
  manifest_hash: string;
  manifest: CarryoverManifest;
  map: CarryoverMap;
  evidence_hash: string;
  evidence_jws: string;
  committed_at: string;
}

function rowToResult(row: Record<string, unknown>): CarryoverCommittedResult {
  return {
    plan_id: row.plan_id as string,
    issuer: row.issuer as string,
    predecessor_id: row.predecessor_id as string,
    successor_id: row.successor_id as string,
    manifest_hash: row.manifest_hash as string,
    manifest: JSON.parse(row.manifest_json as string) as CarryoverManifest,
    map: JSON.parse(row.map_json as string) as CarryoverMap,
    evidence_hash: row.evidence_hash as string,
    evidence_jws: row.evidence_jws as string,
    committed_at: row.committed_at as string,
  };
}

// ---------------------------------------------------------------------------
// The final map and the Carryover Evidence (@spec #carryover-evidence).
// ---------------------------------------------------------------------------

/** One row of the complete final old-to-new map. */
export type CarryoverMapRow =
  | {
      old_child: CarryoverRef;
      outcome: "carried";
      replacement_id: string;
      approval_event_id: string;
    }
  | {
      old_child: CarryoverRef;
      outcome: "excluded";
      reason: string;
      /** The observed terminal state, or the committed cascade this row took. */
      terminal_state: MissionState;
      /** True when this row was never rendered in the manifest. */
      unrendered?: true;
    };

export type CarryoverMap = CarryoverMapRow[];

/** @spec child-delegation#carryover-evidence — the retained Carryover Evidence. */
export interface CarryoverEvidence {
  evidence_id: string;
  media_type: typeof CARRYOVER_EVIDENCE_MEDIA_TYPE;
  manifest_hash: string;
  predecessor: CarryoverRef;
  successor: CarryoverRef;
  exclusion_policy: CarryoverExclusionPolicy;
  map: CarryoverMap;
  created_at: string;
}

/** The commitment over one Carryover Evidence object. */
export function carryoverEvidenceHash(iss: string, evidence: CarryoverEvidence): string {
  return computeAnchor(CARRYOVER_EVIDENCE_TYP, iss, evidence as unknown as JsonValue);
}

/**
 * Sign the Carryover Evidence SYNCHRONOUSLY, inside the completion
 * transaction, with the issuer's Status signing key: the evidence is retained
 * ATOMICALLY with the records, the map and the outbox payloads, so there is no
 * post-commit signing window in which a committed batch has an unauthenticated
 * result. ES256 compact JWS, `typ`
 * {@link CARRYOVER_EVIDENCE_JWS_TYP}.
 */
function signCarryoverEvidence(kernel: MissionKernel, evidence: CarryoverEvidence): string {
  const signer = kernel.statusSigner();
  const header = { alg: "ES256", kid: signer.kid, typ: CARRYOVER_EVIDENCE_JWS_TYP };
  const b64 = (value: unknown): string =>
    Buffer.from(canonicalize(value as JsonValue), "utf8").toString("base64url");
  const signingInput = `${b64(header)}.${b64(evidence)}`;
  return `${signingInput}.${signer.sign(signingInput).toString("base64url")}`;
}

// ---------------------------------------------------------------------------
// Preparation: read-only rendering (@spec #carryover-manifest, #carryover-generations).
// ---------------------------------------------------------------------------

export interface PrepareCarryoverInput {
  predecessorId: string;
  /** The widened successor Intent, as submitted. */
  successorIntent: MissionIntent;
  successorProposal?: AuthorityEntry[];
  config: CarryoverConfig;
}

/** The old child's non-terminal child occupancy: a mutable eligibility input. */
function childOccupancy(kernel: MissionKernel, id: string): number {
  return kernel.findChildren(id).filter((c) => !TERMINAL_STATES.has(c.state)).length;
}

/** The committed external facts for one child under this deployment's declaration. */
function externalStateFor(child: MissionRecord, config: CarryoverConfig): CarryoverExternalState {
  if (config.externalState) return config.externalState.eligible(child);
  // @spec child-delegation#carryover-no-reset — an absent adapter means NOT
  // transferable, except where the deployment explicitly declares that no
  // external meter or latch applies.
  return config.noApplicableExternalState === true
    ? { transferable: true, declared_absent: true }
    : { transferable: false, declared_absent: false };
}

/**
 * The replacement Authority Set: the OLD CHILD's current effective set carried
 * under the ordinary child inheritance steps against the PROSPECTIVE parent's
 * effective set. Never a fresh derivation from the old child's Intent, which
 * would reset the containment and discharge the effective-set calculation
 * removed (@spec child-delegation#carryover-no-reset).
 */
function replacementAuthority(
  oldChildEffective: readonly AuthorityEntry[],
  parentEffective: readonly AuthorityEntry[],
): AuthorityEntry[] {
  return inheritCapabilitySources(
    inheritActionApprovalRequirement([...oldChildEffective], parentEffective),
    parentEffective,
  );
}

/**
 * The PRIMARY justifying entry's occupancy after this replacement's insert, for
 * the Child Evidence `fanout` member (the ordinary child path's convention).
 */
function primaryOccupancy(
  kernel: MissionKernel,
  parent: MissionRecord,
  authority: readonly AuthorityEntry[],
): number {
  const primary = justifyingIndex(authority[0] as AuthorityEntry, parent.authority_set);
  return countChildBuckets(kernel, parent).get(primary) ?? 0;
}

/** The ordinary child fan-out, actor and depth gates, as a rendered reason or undefined. */
function fanoutReason(
  kernel: MissionKernel,
  parentApproved: readonly AuthorityEntry[],
  parentOccupancy: Map<number, number>,
  childAuthority: readonly AuthorityEntry[],
  actor: { sub: string },
  depth: number,
): string | undefined {
  const justifying = childAuthority.map((ce) => justifyingIndex(ce, parentApproved as AuthorityEntry[]));
  if (justifying.some((i) => i < 0)) return "not_strict_subset";
  const drawnOn = [...new Set(justifying)];
  const entryAt = (pi: number): AuthorityEntry => parentApproved[pi] as AuthorityEntry;
  for (const pi of drawnOn) {
    if (!childrenOf(entryAt(pi))) return "delegation_not_permitted";
  }
  const candidate: DelegateCandidate = {
    sub: actor.sub,
    assertedProfile: kernel.actorProfile(actor.sub),
  };
  for (const pi of drawnOn) {
    if (!delegatePermitted(candidate, childrenOf(entryAt(pi))?.allowed_child_actors)) {
      return "child_actor_not_allowed";
    }
  }
  if (depth > MAX_CHILD_DEPTH) return "fanout_exceeded";
  for (const pi of drawnOn) {
    const maxChildDepth = asNum(childrenOf(entryAt(pi))?.max_child_depth) ?? 1;
    if (depth > maxChildDepth) return "fanout_exceeded";
  }
  for (const pi of drawnOn) {
    const maxChildren = asNum(childrenOf(entryAt(pi))?.max_children);
    const active = parentOccupancy.get(pi) ?? 0;
    if (maxChildren !== undefined && active + 1 > maxChildren) return "fanout_exceeded";
  }
  // Admitted: occupy the buckets so the NEXT row in generation order sees this
  // one, which is what makes the excess exclusion deterministic.
  for (const pi of drawnOn) parentOccupancy.set(pi, (parentOccupancy.get(pi) ?? 0) + 1);
  return undefined;
}

/**
 * @spec child-delegation#carryover-manifest, #carryover-generations — render a
 * carryover plan, READ-ONLY, and reserve its proposed identifiers.
 *
 * The manifest includes EVERY non-terminal descendant at rendering. Rows are
 * ordered by old `created_at` then old Mission identifier byte order, which is
 * a DISPLAY order distinct from the generation order eligibility and derivation
 * use. Eligibility is decided generation by generation against each prospective
 * parent's effective set.
 */
export function prepareCarryover(
  kernel: MissionKernel,
  store: CarryoverStore,
  input: PrepareCarryoverInput,
): CarryoverPlan | undefined {
  const predecessor = kernel.get(input.predecessorId);
  if (!predecessor) throw new Error("unknown predecessor mission");
  const issuer = predecessor.issuer;

  // The whole current subtree, every state, in generation order. The manifest
  // includes every NON-TERMINAL descendant at rendering.
  const descendants = kernel.descendantsOf(predecessor.id);
  const rendered = descendants.filter((d) => !TERMINAL_STATES.has(d.state));
  // Nothing to carry: no plan, no reserved identifier, no manifest. Ordinary
  // cascade remains the default, and a descendant created after this point is
  // absent from every manifest and so is never carried.
  if (rendered.length === 0) return undefined;
  if (input.config.maxRows !== null && rendered.length > input.config.maxRows) {
    throw new CarryoverError(
      "carryover_plan_too_large",
      `carryover plan renders ${rendered.length} rows, above this deployment's carryover_max_rows of ${input.config.maxRows}`,
    );
  }

  // The PROSPECTIVE successor: its Intent and derived authority as the
  // submission proposes them. Committed as commitments, so a derivation-policy
  // or catalog drift between rendering and completion refuses rather than
  // silently carrying children under a set nobody approved.
  const successorAuthority = kernel.resolveFreshCapabilities(
    inheritCapabilitySources(
      kernel.derive(input.successorIntent, input.successorProposal),
      predecessor.authority_set,
    ),
  );

  const planId = `cryp_${randomBytes(12).toString("base64url")}`;
  const reserved = store.reserve(issuer, planId, [
    "successor",
    ...rendered.map(() => "replacement"),
  ]);
  const successorId = reserved[0] as string;
  const replacementIds = new Map<string, string>();
  rendered.forEach((child, i) => replacementIds.set(child.id, reserved[i + 1] as string));

  // Generation-order rendering. `newParentOf` resolves a row's prospective
  // parent: the successor for a direct child, its own replacement parent for a
  // deeper one, and NEVER the root successor for a deeper generation.
  const carried = new Map<string, { authority: AuthorityEntry[]; depth: number; expiresAt: string }>();
  const occupancy = new Map<string, Map<number, number>>();
  const approvedSetOf = new Map<string, readonly AuthorityEntry[]>([[successorId, successorAuthority]]);
  const effectiveSetOf = new Map<string, readonly AuthorityEntry[]>([[successorId, successorAuthority]]);
  const expiryOf = new Map<string, string>([[successorId, predecessor.expires_at]]);
  const nowIso = kernel.nowDate().toISOString();
  const entries: CarryoverEntry[] = [];

  for (const child of rendered) {
    const parentOldId = child.parent?.id as string;
    const newParentId = parentOldId === predecessor.id ? successorId : replacementIds.get(parentOldId);
    const oldChildEffective = kernel.effectiveAuthoritySet(child);
    const external = externalStateFor(child, input.config);
    const base: Omit<CarryoverEntry, "outcome"> = {
      child_id: child.id,
      issuer: child.issuer,
      created_at: child.created_at,
      child_actor: { sub: child.client_id },
      state: child.state,
      version: child.version,
      authority_hash: child.authority_hash,
      intent_hash: child.intent_hash,
      effective_authority_hash: authorityHash(issuer, oldChildEffective as never),
      containment_version: child.containment?.containment_version ?? 0,
      discharged_digests: kernel.dischargedEntryDigests(child),
      parent: { issuer: child.parent?.issuer ?? issuer, mission_id: parentOldId },
      depth: child.parent?.depth ?? 1,
      derivation_limit: child.derivation_limit,
      derivation_count: child.derivation_count,
      expires_at: child.expires_at,
      child_occupancy: childOccupancy(kernel, child.id),
      external_state: external,
    };
    const cascade = (reason: string): void => {
      entries.push({ ...base, outcome: "cascade", reason });
    };

    // Excluding a prospective replacement parent excludes every dependent
    // descendant: no replacement attaches to a missing parent.
    if (!newParentId || (newParentId !== successorId && !carried.has(newParentId))) {
      cascade("dependent_parent_excluded");
      continue;
    }
    // @spec child-delegation#carryover-no-reset — only an effectively `active`
    // child is eligible; a `suspended` child is excluded, never resumed.
    if (kernel.applyExpiry(child).state !== "active") {
      cascade(child.state === "suspended" ? "suspended_not_resumed" : "not_effectively_active");
      continue;
    }
    if (!external.transferable) {
      cascade("external_state_not_transferable");
      continue;
    }
    const parentEffective = effectiveSetOf.get(newParentId) as readonly AuthorityEntry[];
    const parentApproved = approvedSetOf.get(newParentId) as readonly AuthorityEntry[];
    const candidateAuthority = replacementAuthority(oldChildEffective, parentEffective);
    if (!isSubsetSet(candidateAuthority, parentEffective as AuthorityEntry[])) {
      cascade("not_strict_subset");
      continue;
    }
    const depth = newParentId === successorId ? 1 : (carried.get(newParentId)?.depth ?? 1) + 1;
    if (!occupancy.has(newParentId)) occupancy.set(newParentId, new Map());
    const reason = fanoutReason(
      kernel,
      parentApproved,
      occupancy.get(newParentId) as Map<number, number>,
      candidateAuthority,
      { sub: child.client_id },
      depth,
    );
    if (reason) {
      cascade(reason);
      continue;
    }
    const replacementId = replacementIds.get(child.id) as string;
    // @spec child-delegation#carryover-no-reset — the replacement's expiry is no
    // later than the old child's OR its new parent's effective expiry; a
    // successor's approved extension never reaches a replacement.
    const expiresAt = kernel.resolveEffectiveExpiry({
      requested: child.intent.expires_at,
      createdAt: nowIso,
      ceilings: {
        parent: expiryOf.get(newParentId) as string,
        carriedFrom: child.expires_at,
      },
    });
    entries.push({
      ...base,
      outcome: "carry",
      replacement: {
        replacement_id: replacementId,
        intent_hash: child.intent_hash,
        authority_hash: authorityHash(issuer, candidateAuthority as never),
        actor: { sub: child.client_id },
        parent: { issuer, mission_id: newParentId },
        // @spec mission#authority-sources — the rendered source. This
        // deployment renders the OLD CHILD's source; a replacement inheriting
        // the successor's instead would be an explicitly rendered and committed
        // change, which this member is what records.
        authority_source: child.authority_source,
        authority_source_origin: "old_child",
        expires_at: expiresAt,
        derivation_limit: child.derivation_limit,
        derivation_count: child.derivation_count,
      },
    });
    carried.set(replacementId, { authority: candidateAuthority, depth, expiresAt });
    approvedSetOf.set(replacementId, candidateAuthority);
    effectiveSetOf.set(replacementId, candidateAuthority);
    expiryOf.set(replacementId, expiresAt);
  }

  // Display order: old `created_at`, then old Mission identifier byte order,
  // independently of the generation order used above for derivation.
  entries.sort((a, b) =>
    a.created_at === b.created_at
      ? a.child_id < b.child_id
        ? -1
        : 1
      : a.created_at < b.created_at
        ? -1
        : 1,
  );

  const manifest: CarryoverManifest = {
    format_version: 1,
    predecessor: { issuer, mission_id: predecessor.id },
    successor: { issuer, mission_id: successorId },
    successor_intent_hash: intentHash(issuer, input.successorIntent as never),
    successor_authority_hash: authorityHash(issuer, successorAuthority as never),
    exclusion_policy: input.config.exclusionPolicy,
    policy_version: predecessor.policy_version,
    entries,
  };
  return { plan_id: planId, manifest, reserved_ids: reserved };
}

/**
 * @spec child-delegation#carryover-manifest — COMMIT the manifest at the
 * expansion approval event: the deterministic child-specific approval event
 * identifiers are derived from the committed expansion approval event
 * identifier and the qualified old-child identity, and the `manifest_hash` is
 * taken over the finalized manifest. Approval authenticates exactly what
 * preparation rendered.
 */
export function commitCarryoverManifest(
  plan: CarryoverPlan,
  expansionApprovalEventId: string,
): { manifest: CarryoverManifest; manifestHash: string } {
  const issuer = plan.manifest.predecessor.issuer;
  const manifest: CarryoverManifest = {
    ...plan.manifest,
    entries: plan.manifest.entries.map((entry) =>
      entry.outcome === "carry" && entry.replacement
        ? {
            ...entry,
            replacement: {
              ...entry.replacement,
              approval_event_id: carryoverApprovalEventId(issuer, expansionApprovalEventId, {
                issuer: entry.issuer,
                mission_id: entry.child_id,
              }),
            },
          }
        : entry,
    ),
  };
  return { manifest, manifestHash: carryoverManifestHash(issuer, manifest) };
}

// ---------------------------------------------------------------------------
// Completion (@spec #carryover-cas, #carryover-records, #carryover-commit).
// ---------------------------------------------------------------------------

export interface ApplyCarryoverInput {
  planId: string;
  manifest: CarryoverManifest;
  manifestHash: string;
  /** The just-created successor record, in this same transaction. */
  successor: MissionRecord;
  /** The expansion Approver: `consent_principal` and `direct` activation actor. */
  approver: { iss: string; sub: string };
  /** The committed expansion approval event identifier. */
  expansionApprovalEventId: string;
  /**
   * @spec child-delegation#carryover — a policy-adjudicated progressive
   * drawdown MUST NOT perform carryover. True only on an AUTHENTICATED direct
   * approval completion path.
   */
  directApproval: boolean;
  config: CarryoverConfig;
}

export interface ApplyCarryoverResult {
  map: CarryoverMap;
  evidence: CarryoverEvidence;
  evidenceHash: string;
  evidenceJws: string;
  replacements: MissionRecord[];
  childEvidence: ChildEvidence[];
}

/** One detected divergence between the committed manifest and current state. */
interface Divergence {
  childId: string;
  class: CarryoverChangeClass;
  detail: string;
}

/**
 * @spec child-delegation#carryover-commit — apply the approved manifest inside
 * the CALLER's transaction. Successor activation, every replacement record, the
 * required old-child cascades, the complete final map, the authenticated
 * Carryover Evidence, every external transfer, the terminal tombstones and the
 * durable outbox payloads commit together; a failure anywhere rolls all of them
 * back, leaving no partial successor, surviving replacement or cascade.
 */
export function applyCarryoverInCallerTx(
  kernel: MissionKernel,
  store: CarryoverStore,
  input: ApplyCarryoverInput,
): ApplyCarryoverResult {
  if (!kernel.db.inTransaction) {
    throw new Error("carryover must be applied inside the expansion completion transaction");
  }
  const { manifest, successor } = input;
  const issuer = manifest.predecessor.issuer;

  // @spec child-delegation#carryover — carryover requires a child-specific
  // DIRECT approval for each replacement. Rechecked here, at the funnel, so a
  // policy-adjudicated drawdown cannot enable carryover by supplying an
  // approver-shaped object.
  if (!input.directApproval || successor.approval_basis.type !== "direct") {
    throw new CarryoverError(
      "approval_basis_not_direct",
      "carryover requires an authenticated direct approval; a policy-adjudicated drawdown MUST NOT perform carryover",
    );
  }
  if (carryoverManifestHash(issuer, manifest) !== input.manifestHash) {
    throw new CarryoverError("manifest_mismatch", "carryover manifest hash does not match the approved commitment");
  }
  if (
    successor.id !== manifest.successor.mission_id ||
    successor.intent_hash !== manifest.successor_intent_hash ||
    successor.authority_hash !== manifest.successor_authority_hash
  ) {
    throw new CarryoverError(
      "manifest_mismatch",
      "the created successor does not match the identity and commitments the manifest committed",
    );
  }
  // The successor identifier is already a live record by now (this transaction
  // created it), so only its plan OWNERSHIP is asserted; every replacement
  // identifier must still be unused as well.
  store.assertReservationOwnedInCallerTx(issuer, input.planId, manifest.successor.mission_id);
  store.assertReservedUsableInCallerTx(
    issuer,
    input.planId,
    manifest.entries.flatMap((e) => (e.replacement ? [e.replacement.replacement_id] : [])),
  );

  const policy = manifest.exclusion_policy;
  const disclosed =
    policy.mode === "disclosed_exclusions" ? new Set<CarryoverChangeClass>(policy.change_classes) : undefined;

  // 1. Enumerate the WHOLE current old subtree, every state included.
  const current = new Map<string, MissionRecord>();
  for (const record of kernel.descendantsOf(manifest.predecessor.mission_id)) current.set(record.id, record);
  const renderedIds = new Set(manifest.entries.map((e) => e.child_id));

  // 2. Descendant-set MEMBERSHIP, which per-row compare-and-set cannot see.
  const divergences: Divergence[] = [];
  const unrendered: MissionRecord[] = [];
  for (const [id, record] of current) {
    if (renderedIds.has(id)) continue;
    // A row that was already terminal at rendering was never rendered and needs
    // no cascade; anything else is a descendant created after approval.
    if (TERMINAL_STATES.has(record.state)) continue;
    unrendered.push(record);
    divergences.push({ childId: id, class: "unrendered_descendant", detail: "descendant absent from the manifest" });
  }
  for (const entry of manifest.entries) {
    const record = current.get(entry.child_id);
    if (!record) {
      divergences.push({ childId: entry.child_id, class: "record_missing", detail: "rendered row is gone" });
      continue;
    }
    if (record.state !== entry.state || record.version !== entry.version) {
      divergences.push({
        childId: entry.child_id,
        class: "state_changed",
        detail: `state/version moved from ${entry.state}/${entry.version} to ${record.state}/${record.version}`,
      });
    }
    if (record.derivation_count !== entry.derivation_count) {
      divergences.push({
        childId: entry.child_id,
        class: "derivation_consumed",
        detail: `derivation_count moved from ${entry.derivation_count} to ${record.derivation_count}`,
      });
    }
    if ((record.containment?.containment_version ?? 0) !== entry.containment_version) {
      divergences.push({ childId: entry.child_id, class: "authority_narrowed", detail: "containment advanced" });
    }
    const effectiveHash = authorityHash(issuer, kernel.effectiveAuthoritySet(record) as never);
    if (effectiveHash !== entry.effective_authority_hash) {
      divergences.push({
        childId: entry.child_id,
        class: "authority_narrowed",
        detail: "effective authority or discharge state moved",
      });
    }
    if (record.expires_at !== entry.expires_at) {
      divergences.push({ childId: entry.child_id, class: "expiry_changed", detail: "expires_at moved" });
    }
    if (childOccupancy(kernel, entry.child_id) !== entry.child_occupancy) {
      divergences.push({
        childId: entry.child_id,
        class: "fanout_occupancy_changed",
        detail: "non-terminal child occupancy moved",
      });
    }
    if (entry.outcome === "carry") {
      const external = externalStateFor(record, input.config);
      if (!external.transferable || canonicalize(external as unknown as JsonValue) !== canonicalize(entry.external_state as unknown as JsonValue)) {
        divergences.push({
          childId: entry.child_id,
          class: "external_transfer_unavailable",
          detail: "an external meter or latch input moved or cannot participate",
        });
      }
    }
  }

  // 3. Adjudicate the divergences under the COMMITTED policy.
  const excluded = new Map<string, string>();
  if (divergences.length > 0) {
    if (!disclosed) {
      // @spec child-delegation#carryover-manifest — all-or-nothing: ANY relevant
      // change, the disappearance or termination of a rendered row included,
      // requires a fresh render and approval. An already-terminal rendered row
      // is NOT an automatically acceptable exclusion.
      const first = divergences[0] as Divergence;
      throw new CarryoverError(
        "subtree_changed",
        `all-or-nothing carryover requires a fresh approval: ${first.childId} ${first.detail}`,
      );
    }
    for (const d of divergences) {
      if (!disclosed.has(d.class)) {
        throw new CarryoverError(
          "undisclosed_change_class",
          `change class ${d.class} on ${d.childId} is not committed by this plan's disclosed exclusions`,
        );
      }
      if (renderedIds.has(d.childId)) excluded.set(d.childId, d.class);
    }
  }

  // Excluding a prospective replacement parent excludes every dependent
  // descendant: no replacement attaches to a missing parent. Iterated to a
  // fixpoint so an exclusion propagates the whole way down.
  const byOldId = new Map(manifest.entries.map((e) => [e.child_id, e]));
  const isCarried = (childId: string): boolean =>
    byOldId.get(childId)?.outcome === "carry" && !excluded.has(childId);
  for (let grew = true; grew; ) {
    grew = false;
    for (const entry of manifest.entries) {
      if (entry.outcome !== "carry" || excluded.has(entry.child_id)) continue;
      const parentOld = entry.parent.mission_id;
      if (parentOld === manifest.predecessor.mission_id) continue;
      if (!isCarried(parentOld)) {
        excluded.set(entry.child_id, "dependent_parent_excluded");
        grew = true;
      }
    }
  }

  // 4. Per-row exhaustive compare-and-set over every committed mutable input,
  // one conditional UPDATE per rendered CARRY row, `changes === 1` each. A
  // subtree-wide guard would let one stale entry through.
  const carryEntries = manifest.entries.filter(
    (e) => e.outcome === "carry" && e.replacement && !excluded.has(e.child_id),
  );
  for (const entry of carryEntries) {
    const record = current.get(entry.child_id) as MissionRecord;
    const changed = kernel.db
      .prepare(
        `UPDATE missions SET version = version
           WHERE id = ? AND version = ? AND state = ? AND authority_hash = ? AND derivation_count = ?
             AND expires_at = ? AND IFNULL(containment_json, '') = ? AND IFNULL(discharged_json, '') = ?`,
      )
      .run(
        entry.child_id,
        entry.version,
        entry.state,
        entry.authority_hash,
        entry.derivation_count,
        entry.expires_at,
        record.containment ? JSON.stringify(record.containment) : "",
        record.discharged ? JSON.stringify(record.discharged) : "",
      );
    if (changed.changes !== 1) {
      throw new CarryoverError(
        "snapshot_moved",
        `a committed eligibility input of ${entry.child_id} moved after rendering`,
      );
    }
  }

  // 5. Derive and insert the replacements in GENERATION order (never the
  // manifest's display order), each against its prospective parent's effective
  // set, with the old child's current effective set independently retained as a
  // ceiling after inheritance and derivation.
  const replacements: MissionRecord[] = [];
  const childEvidence: ChildEvidence[] = [];
  const carriedTo = new Map<string, string>();
  const parentRecordOf = new Map<string, MissionRecord>([[manifest.predecessor.mission_id, successor]]);
  const generationOrder = [...carryEntries].sort((a, b) => a.depth - b.depth || (a.child_id < b.child_id ? -1 : 1));

  for (const entry of generationOrder) {
    const proposal = entry.replacement as CarryoverReplacementProposal;
    const oldChild = current.get(entry.child_id) as MissionRecord;
    const newParent = parentRecordOf.get(entry.parent.mission_id);
    if (!newParent) {
      throw new CarryoverError(
        "subtree_changed",
        `no committed replacement parent exists for ${entry.child_id}`,
      );
    }
    if (newParent.id !== proposal.parent.mission_id) {
      throw new CarryoverError(
        "manifest_mismatch",
        `the committed parent reference of ${entry.child_id} does not match the parent it would attach to`,
      );
    }
    const parentEffective = kernel.effectiveAuthoritySet(newParent);
    const oldChildEffective = kernel.effectiveAuthoritySet(oldChild);
    const authority = replacementAuthority(oldChildEffective, parentEffective);
    // Ordinary strict-subset against the prospective parent.
    if (!isSubsetSet(authority, parentEffective)) {
      throw new CarryoverError("snapshot_moved", `${entry.child_id} no longer derives under its prospective parent`);
    }
    // The INDEPENDENT old-child ceiling: containment and discharge removals and
    // changed capability bindings cannot be restored by inheritance.
    if (!isSubsetSetIgnoringCapabilitySources(authority, oldChildEffective)) {
      throw new CarryoverError(
        "snapshot_moved",
        `${entry.child_id} would restore authority its effective set had removed`,
      );
    }
    if (authorityHash(issuer, authority as never) !== proposal.authority_hash) {
      throw new CarryoverError(
        "manifest_mismatch",
        `the recomputed authority of ${entry.child_id} does not match the rendered commitment`,
      );
    }
    // @spec mission#authority-sources — no substitution: the rendered source is
    // exactly the one the manifest committed AND exactly the source of the
    // record the manifest says it came from.
    const originSource =
      proposal.authority_source_origin === "old_child" ? oldChild.authority_source : newParent.authority_source;
    const renderedBytes = canonicalize(proposal.authority_source as unknown as JsonValue);
    if (renderedBytes !== canonicalize(originSource as unknown as JsonValue)) {
      throw new CarryoverError(
        "authority_source_substituted",
        `the rendered authority_source of ${entry.child_id} is not the ${proposal.authority_source_origin} source it declares`,
      );
    }
    // Source ACTIVATION and source CEILING, both re-run: a `direct`-basis
    // replacement is an activation, not a bare drawdown.
    kernel.assertRenderedAuthoritySource({
      source: proposal.authority_source,
      subject: successor.subject,
      approver: input.approver,
      authoritySet: authority,
    });

    // The ordinary fan-out, actor, depth and children-control gates, recounted
    // against the NEW parent's justifying entries in this same serialization
    // domain, so concurrently non-terminal occupants and every already-inserted
    // carried generation count.
    const occupancy = countChildBuckets(kernel, newParent);
    const depth = (newParent.parent?.depth ?? 0) + 1;
    const reason = fanoutReason(kernel, newParent.authority_set, occupancy, authority, proposal.actor, depth);
    if (reason) {
      throw new CarryoverError(
        "snapshot_moved",
        `${entry.child_id} no longer passes the ${reason} gate under its prospective parent`,
      );
    }

    let childAct: ActObject;
    try {
      childAct = extendChain({ sub: proposal.actor.sub, iss: proposal.actor.iss ?? issuer }, undefined);
      validateActChain(childAct);
    } catch (e) {
      if (e instanceof ActorChainError) {
        throw new CarryoverError("snapshot_moved", `replacement actor for ${entry.child_id} is not valid`);
      }
      throw e;
    }

    const createdAt = kernel.nowDate().toISOString();
    // @spec child-delegation#carryover-no-reset — no later than the old child's
    // expiry OR the new parent's effective expiry, through the one
    // effective-expiry hook. A successor's approved extension moves `parent`
    // later and still cannot extend a replacement.
    const expiresAt = kernel.resolveEffectiveExpiry({
      requested: oldChild.intent.expires_at,
      createdAt,
      ceilings: { parent: newParent.expires_at, carriedFrom: oldChild.expires_at },
    });
    const approvalEventId = proposal.approval_event_id;
    if (!approvalEventId) {
      throw new CarryoverError(
        "manifest_mismatch",
        `the committed manifest carries no child-specific approval event for ${entry.child_id}`,
      );
    }
    if (
      approvalEventId !==
      carryoverApprovalEventId(issuer, input.expansionApprovalEventId, {
        issuer: entry.issuer,
        mission_id: entry.child_id,
      })
    ) {
      throw new CarryoverError(
        "manifest_mismatch",
        `the committed child approval event for ${entry.child_id} is not the deterministic identifier`,
      );
    }
    const replacementAuthorityHash = proposal.authority_hash;
    // @spec child-delegation#carryover-records — a FRESH record with a `direct`
    // basis and its own child-specific approval event. The old child's `parent`
    // and immutable approval anchors are never touched.
    const approvalBasis: ApprovalBasis = {
      type: "direct",
      consent_principal: input.approver,
      activation: { approval_event_id: approvalEventId },
      activation_actor: input.approver,
      root_commitment: replacementAuthorityHash,
    };
    const parentRef: ParentRef = {
      id: newParent.id,
      issuer,
      authority_hash: newParent.authority_hash,
      depth,
      cascade_mode: "immediate",
      created_at: createdAt,
    };
    const record: MissionRecord = {
      id: proposal.replacement_id,
      issuer,
      state: "active",
      intent: oldChild.intent,
      authority_set: authority,
      intent_hash: oldChild.intent_hash,
      authority_hash: replacementAuthorityHash,
      subject: oldChild.subject,
      approver: input.approver,
      approval_basis: approvalBasis,
      authority_source: proposal.authority_source,
      client_id: childAct.sub,
      policy_version: manifest.policy_version,
      approval_event_id: approvalEventId,
      created_at: createdAt,
      expires_at: expiresAt,
      version: 1,
      // @spec child-delegation#carryover-no-reset — the carryover-specific
      // exception to a fresh derivation counter: the replacement CONTINUES the
      // old child's remaining budget, despite a new record identifier. Repeated
      // expansion and carryover therefore cannot replenish it.
      derivation_limit: oldChild.derivation_limit,
      derivation_count: oldChild.derivation_count,
      grant_id: null,
      status_list_idx: null,
      parent: parentRef,
      related_to: oldChild.id,
    };
    if (record.derivation_limit !== proposal.derivation_limit || record.derivation_count !== proposal.derivation_count) {
      throw new CarryoverError(
        "manifest_mismatch",
        `the derivation budget of ${entry.child_id} does not match the rendered commitment`,
      );
    }
    // The rendered `expires_at` is the committed CEILING: the completion
    // instant is later than the rendering instant, so a deployment lifetime
    // measured from it can only land earlier. A recomputed value LATER than the
    // rendered one is a refusal.
    if (Date.parse(expiresAt) > Date.parse(proposal.expires_at)) {
      throw new CarryoverError(
        "manifest_mismatch",
        `the recomputed expiry of ${entry.child_id} exceeds the rendered ceiling`,
      );
    }
    kernel.insertRecord(record);
    // @spec child-delegation#carryover-no-reset — the transaction-participating
    // external transfer. A throw here rolls the whole batch back, records
    // included; nothing is compensated after the fact.
    if (input.config.externalState) {
      input.config.externalState.transferInCallerTx({
        child: oldChild,
        replacementId: record.id,
        committed: entry.external_state,
      });
    }
    const inserted = kernel.get(record.id) as MissionRecord;
    replacements.push(inserted);
    parentRecordOf.set(entry.child_id, inserted);
    carriedTo.set(entry.child_id, inserted.id);
    const evidence: ChildEvidence = {
      evidence_id: `chd_${randomBytes(9).toString("base64url")}`,
      parent: { id: newParent.id, issuer, authority_hash: newParent.authority_hash },
      child: { id: inserted.id, issuer, authority_hash: inserted.authority_hash },
      child_actor: { sub: proposal.actor.sub },
      attenuation: { result: "strict_subset" },
      fanout: { active_children: primaryOccupancy(kernel, newParent, authority) },
      cascade_mode: "immediate",
      decision: "created",
      creation_mode: "carryover",
      carried_from: { issuer: entry.issuer, mission_id: entry.child_id },
      manifest_hash: input.manifestHash,
      created_at: createdAt,
    };
    childEvidence.push(evidence);
  }

  // 6. Terminate the WHOLE old subtree in this same transaction, in generation
  // order, through the one carried-terminal funnel: rendered carries, rendered
  // exclusions, and unrendered descendants under carried or already-terminal
  // intermediate ancestors alike. Already-terminal rows keep their state and
  // get no second transition.
  const map: CarryoverMap = [];
  const subtreeOrder = kernel.descendantsOf(manifest.predecessor.mission_id);
  for (const record of subtreeOrder) {
    // A replacement is a child of the SUCCESSOR, never of the predecessor, so
    // this walk only ever visits old records.
    const fresh = kernel.get(record.id) as MissionRecord;
    const entry = byOldId.get(record.id);
    const replacementId = carriedTo.get(record.id);
    const outcome = replacementId ? { carriedTo: replacementId } : {};
    const transitioned = kernel.carryTerminalInCallerTx(fresh, outcome);
    const terminalState = (transitioned ?? fresh).state;
    if (replacementId && entry?.replacement) {
      map.push({
        old_child: { issuer: record.issuer, mission_id: record.id },
        outcome: "carried",
        replacement_id: replacementId,
        approval_event_id: entry.replacement.approval_event_id as string,
      });
    } else {
      const reason = excluded.get(record.id) ?? entry?.reason ?? "unrendered_descendant";
      map.push({
        old_child: { issuer: record.issuer, mission_id: record.id },
        outcome: "excluded",
        reason,
        terminal_state: terminalState,
        ...(entry ? {} : { unrendered: true as const }),
      });
    }
  }

  // The traversal owns the descent, so the post-supersession cascade has
  // nothing left. Asserted, not assumed: a descendant left non-terminal here
  // would transition later with no outcome and never reach the map.
  for (const record of kernel.descendantsOf(manifest.predecessor.mission_id)) {
    if (!TERMINAL_STATES.has(record.state)) {
      throw new CarryoverError(
        "subtree_changed",
        `descendant ${record.id} was not terminated inside the completion transaction`,
      );
    }
  }

  // 7. Retain the complete map and the authenticated Carryover Evidence,
  // atomically with everything above.
  const committedAt = kernel.nowDate().toISOString();
  const evidence: CarryoverEvidence = {
    evidence_id: `cry_${randomBytes(9).toString("base64url")}`,
    media_type: CARRYOVER_EVIDENCE_MEDIA_TYPE,
    manifest_hash: input.manifestHash,
    predecessor: manifest.predecessor,
    successor: manifest.successor,
    exclusion_policy: manifest.exclusion_policy,
    map,
    created_at: committedAt,
  };
  const evidenceHash = carryoverEvidenceHash(issuer, evidence);
  const evidenceJws = signCarryoverEvidence(kernel, evidence);
  // @spec child-delegation#carryover-evidence — the replacement's ordinary Child
  // Evidence carries an AUTHENTICATED REFERENCE to the retained batch map, never
  // the map itself: a batch map does not replace ordinary Child Evidence and
  // never becomes authority.
  const linked = childEvidence.map((e) => ({
    ...e,
    carryover_evidence: { batch_id: input.planId, evidence_hash: evidenceHash },
  }));
  store.retainResultInCallerTx({
    planId: input.planId,
    issuer,
    predecessorId: manifest.predecessor.mission_id,
    successorId: successor.id,
    manifestHash: input.manifestHash,
    manifest,
    map,
    evidenceHash,
    evidenceJws,
    committedAt,
  });
  for (const evidenceRecord of linked) {
    store.retainReplacementInCallerTx({
      issuer,
      replacementId: evidenceRecord.child.id,
      planId: input.planId,
      oldChildId: (evidenceRecord.carried_from as CarryoverRef).mission_id,
      approvalEventId: (replacements.find((r) => r.id === evidenceRecord.child.id) as MissionRecord)
        .approval_event_id,
      childEvidence: evidenceRecord,
    });
  }
  store.consumeInCallerTx(input.planId, [
    manifest.successor.mission_id,
    ...replacements.map((r) => r.id),
  ]);
  return { map, evidence, evidenceHash, evidenceJws, replacements, childEvidence: linked };
}

/**
 * DECODE a retained Carryover Evidence envelope: the `typ` gate plus the
 * evidence object. It does NOT verify the signature, deliberately: signature
 * and trust verification belong to the consumer holding the issuer's published
 * key ({@link CARRYOVER_EVIDENCE_JWS_TYP} is an ordinary ES256 compact JWS over
 * this payload, verifiable with the Status `kid`).
 */
export function decodeCarryoverEvidence(jws: string): CarryoverEvidence {
  const parts = jws.split(".");
  if (parts.length !== 3) throw new Error("malformed carryover evidence envelope");
  const header = JSON.parse(Buffer.from(parts[0] as string, "base64url").toString("utf8")) as {
    typ?: string;
  };
  if (header.typ !== CARRYOVER_EVIDENCE_JWS_TYP) {
    throw new Error(`unexpected carryover evidence typ: ${String(header.typ)}`);
  }
  return JSON.parse(Buffer.from(parts[1] as string, "base64url").toString("utf8")) as CarryoverEvidence;
}
