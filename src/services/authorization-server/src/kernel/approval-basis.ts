/**
 * @spec mission#record-principal-members (#1912, D1047): the three
 * `approval_basis` members that are OPTIONAL for a `direct` basis, and the
 * value each implies when omitted:
 *
 * - `activation`: an object whose `approval_event_id` is the record's own
 *   `approval_event_id`;
 * - `activation_actor`: the basis's `consent_principal` (the Approver
 *   triggers their own approval);
 * - `root_commitment`: the record's own `authority_hash`.
 *
 * When present for `direct`, each MUST match its implied value. The implied
 * values are semantic defaults: these functions read them, and nothing here
 * writes one into a record. A reader never inserts an omitted member before
 * hashing or committing the record, so the store and the Approval Governance
 * manifest input keep the basis exactly as recorded.
 *
 * A standing-consent basis REQUIRES and defines all three members
 * (@spec mission#standing-consent-bases), so these functions accept a
 * `direct` basis only.
 */

import type { ApprovalBasisDirect, MissionRecord } from "./types.js";

/** The record members the three implied values are drawn from. */
export type DirectBasisRecord = Pick<MissionRecord, "approval_basis" | "approval_event_id" | "authority_hash">;

/** The three members of a `direct` basis, each explicit or implied. */
export interface DirectBasisMembers {
  activation: { approval_event_id: string };
  activation_actor: { iss: string; sub: string };
  root_commitment: string;
}

/** The member names {@link assertDirectBasisConsistent} checks. */
export type DirectBasisMember = keyof DirectBasisMembers;

/** A `direct` basis member present with a value other than its implied value. */
export class DirectBasisMismatchError extends Error {
  constructor(
    readonly member: DirectBasisMember,
    message: string,
  ) {
    super(message);
    this.name = "DirectBasisMismatchError";
  }
}

function directBasisOf(record: DirectBasisRecord): ApprovalBasisDirect {
  const basis = record.approval_basis;
  if (basis.type !== "direct") {
    throw new TypeError(`approval_basis.type is '${basis.type}', not 'direct': a standing-consent basis carries its own members`);
  }
  return basis;
}

/** The implied value of each of the three members, whether or not the basis carries it. */
export function impliedDirectBasisMembers(record: DirectBasisRecord): DirectBasisMembers {
  const basis = directBasisOf(record);
  return {
    activation: { approval_event_id: record.approval_event_id },
    activation_actor: basis.consent_principal,
    root_commitment: record.authority_hash,
  };
}

/**
 * Each of the three members as the record states it: the explicit value
 * when the basis carries the member, else its implied value. Reads only; the
 * record is not changed. Call {@link assertDirectBasisConsistent} first where
 * a present member must be trusted to match.
 */
export function directBasisMembers(record: DirectBasisRecord): DirectBasisMembers {
  const basis = directBasisOf(record);
  const implied = impliedDirectBasisMembers(record);
  return {
    activation: basis.activation ?? implied.activation,
    activation_actor: basis.activation_actor ?? implied.activation_actor,
    root_commitment: basis.root_commitment ?? implied.root_commitment,
  };
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * Throws {@link DirectBasisMismatchError} when a `direct` basis carries one of
 * the three members with a value other than its implied value; an omitted
 * member passes. `activation` matches when it is an object whose
 * `approval_event_id` is the record's own; `activation_actor` when its `iss`
 * and `sub` are `consent_principal`'s; `root_commitment` when it is the
 * record's `authority_hash`. A member this check does not recognize inside
 * `activation` or `activation_actor` is not interpreted.
 */
export function assertDirectBasisConsistent(record: DirectBasisRecord): void {
  const basis = directBasisOf(record);
  const implied = impliedDirectBasisMembers(record);
  // Read as stored, not as typed: a stored basis can carry any JSON value.
  const activation = basis.activation as unknown;
  if (activation !== undefined && !(isObject(activation) && activation.approval_event_id === implied.activation.approval_event_id)) {
    throw new DirectBasisMismatchError(
      "activation",
      "approval_basis.activation does not name the record's own approval_event_id",
    );
  }
  const actor = basis.activation_actor as unknown;
  if (
    actor !== undefined &&
    !(isObject(actor) && actor.iss === implied.activation_actor.iss && actor.sub === implied.activation_actor.sub)
  ) {
    throw new DirectBasisMismatchError(
      "activation_actor",
      "approval_basis.activation_actor is not the basis's consent_principal",
    );
  }
  const root = basis.root_commitment as unknown;
  if (root !== undefined && root !== implied.root_commitment) {
    throw new DirectBasisMismatchError(
      "root_commitment",
      "approval_basis.root_commitment is not the record's authority_hash",
    );
  }
}
