/**
 * @spec mission#record-content-members, mission#integrity-anchors (#1917,
 * D1061): the Mission Record's three integrity anchors, `intent_hash`,
 * `authority_hash` and `proposal_hash`, are OPTIONAL record members, each
 * with an implied value: the anchor over the retained object it commits.
 *
 * The owner's five boundaries, each enforced here or at the creation funnel:
 *
 * 1. Stable construction. The implied value is the specified `sha-256`
 *    anchor construction: `computeAnchor` (through `intentHash`,
 *    `authorityHash` and `proposalHash`) with the fixed `typ` values and
 *    `iss` = the record's `issuer`. Never a configurable or preferred
 *    algorithm.
 * 2. Authoritative inputs. Computed from the immutable approved record
 *    only: `intent`, `authority_set` in stored array order, and
 *    `proposed_authority` in stored order when present. Never a served
 *    projection, a contained remainder, the effective Authority Set, or a
 *    response object.
 * 3. Present values. A recorded anchor that differs from its implied value
 *    is refused ({@link AnchorMismatchError}), never replaced by a fresh
 *    computation.
 * 4. Creation-time binding. Every ceremony or artifact that needs an anchor
 *    at approval still computes it then; omission only means the value is
 *    not persisted on the record (`KernelOptions.recordAnchors: false`).
 * 5. Record bytes. Resolving reads only: it returns a new object and never
 *    writes into the record, so the approval event preimage
 *    ({@link approvalEventPreimage}) keeps the record's members exactly as
 *    recorded.
 */

import { authorityHash, canonicalize, intentHash, type JsonValue, proposalHash } from "@mission/core";
import type { MissionRecord } from "./types.js";

/** The three integrity-anchor record members. */
export type AnchorMember = "intent_hash" | "authority_hash" | "proposal_hash";

/** Each anchor of a Mission Record, recorded or implied. */
export interface ResolvedAnchors {
  intent_hash: string;
  authority_hash: string;
  /** Present exactly when the record carries `proposed_authority`. */
  proposal_hash?: string;
}

/** The record members an anchor is drawn from, and the anchors it may carry. */
export type AnchoredRecord = Pick<
  MissionRecord,
  "issuer" | "intent" | "authority_set" | "proposed_authority" | "intent_hash" | "authority_hash" | "proposal_hash"
>;

/**
 * A Mission Record carries an integrity anchor whose value differs from the
 * anchor over the retained object it commits. The record is refused, never
 * repaired: nothing replaces the recorded value with a fresh computation.
 */
export class AnchorMismatchError extends Error {
  readonly code = "anchor_mismatch";
  constructor(
    readonly member: AnchorMember,
    message: string,
  ) {
    super(message);
    this.name = "AnchorMismatchError";
  }
}

const MEMBERS: readonly AnchorMember[] = ["intent_hash", "authority_hash", "proposal_hash"];

/**
 * The record's three anchors. Each is computed over the retained object
 * (boundaries 1 and 2); where the record carries the member, the recorded
 * value must equal the computed one, else {@link AnchorMismatchError}
 * (boundary 3). A recorded `proposal_hash` on a record without
 * `proposed_authority` has no implied value to match and is refused too.
 * Returns a new object; the record is not changed (boundary 5).
 */
export function resolvedAnchors(record: AnchoredRecord): ResolvedAnchors {
  const implied: ResolvedAnchors = {
    intent_hash: intentHash(record.issuer, record.intent as unknown as JsonValue),
    authority_hash: authorityHash(record.issuer, record.authority_set as unknown as JsonValue[]),
    ...(record.proposed_authority !== undefined
      ? { proposal_hash: proposalHash(record.issuer, record.proposed_authority as unknown as JsonValue[]) }
      : {}),
  };
  for (const member of MEMBERS) {
    // Read as stored, not as typed: a stored member can hold any value.
    const recorded = (record as Record<string, unknown>)[member];
    if (recorded !== undefined && recorded !== implied[member]) {
      throw new AnchorMismatchError(
        member,
        implied[member] === undefined
          ? `the record carries ${member} but no proposed_authority it could commit`
          : `the recorded ${member} is not the anchor over the retained object`,
      );
    }
  }
  return implied;
}

/**
 * @spec mission-audit#evidence-types ("Approval event"): the approval event's
 * canonical bytes, the Mission Record at creation as recorded with its
 * mutable members `state` and `termination` excluded, JCS-canonicalized.
 * Every other member is taken exactly as the record holds it: an omitted
 * anchor stays absent and a recorded one stays present. This never calls
 * {@link resolvedAnchors}, so an implied value is never inserted.
 *
 * The record passed is the record at creation (the value the creation funnel
 * committed, or the stored record read back before any transition): the
 * in-memory record also carries authorization-server state such as
 * `version` and `derivation_count`, which change after creation.
 */
export function approvalEventPreimage(record: MissionRecord): string {
  const { state: _state, termination: _termination, ...committed } = record;
  return canonicalize(committed as unknown as JsonValue);
}
