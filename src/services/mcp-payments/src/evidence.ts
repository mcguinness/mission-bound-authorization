/**
 * @spec authzen evidence objects (Decision Evidence, Refusal Record)
 * @spec D13 (trace_id extension member), D32 (producers retain their own)
 *
 * The PEP retains its own evidence (feed-driven distributed, D32). Signing
 * and SCITT registration land in M10; M4 records the retained objects and
 * the members the operation profile fixes.
 */

import { currentTraceId } from "@mission/telemetry";

/**
 * @spec authzen `emitter.role`: the coordinated set of enforcement-point roles
 * that emit records under these conventions. The three authzen roles
 * (pdp/pep/executor), the two companion runtime points (harness/egress), and
 * `issuer` for records the AUTHORIZATION SERVER retains itself (protected-event
 * ingestion; the issuer-held Containment Plane).
 */
export type EmitterRole = "pdp" | "pep" | "executor" | "harness" | "egress" | "issuer";

export interface EvidenceBase {
  decision_id?: string;
  mission_id: string;
  authority_hash: string;
  action: string;
  parameter_digest?: string;
  instance_epoch: string;
  trace_id?: string;
  at: string;
  /**
   * @spec continuation (hop attribution): when the action was taken under a
   * continued credential, the specific continuation hop that authorized it.
   * `jti` is the authorizing token's identifier and `mission_id` the Mission it
   * belongs to; `continuation_handle` is the hop's identity-continuation handle
   * when present. Absent for a non-continued (or non-JWT) credential.
   */
  hop_reference?: { jti: string; mission_id: string; continuation_handle?: string };
  /**
   * @spec authzen `emitter`: the identity and role of the component that
   * emitted this record. `role` covers the authzen roles (pdp/pep/executor)
   * plus the coordinated companion roles for records emitted under these
   * conventions at other enforcement points (harness, egress, issuer).
   */
  emitter?: { id: string; role: EmitterRole };
  /**
   * @spec runtime (Enforcement Scope Statement): the integrity-anchor encoded
   * digest of the scope statement the emitting component enforced under, so a
   * record can be joined to the published enforcement scope after the fact.
   */
  scope_statement_digest?: string;
}

export interface DecisionEvidence extends EvidenceBase {
  kind: "decision";
  decision: boolean;
  policy_view_id?: string;
  denial_reason?: string;
  /**
   * @spec authzen `entry_digest`: the integrity-anchor encoded digest of the
   * Authority Set entry the decision was evaluated against (the resolved-scope
   * anchor), copied from the PDP's decision context when present.
   */
  entry_digest?: string;
}

export interface RefusalRecord extends EvidenceBase {
  kind: "refusal";
  refusal_reason: string;
}

/** @spec authzen Execution Evidence: the outcome joined to the decision. */
export interface ExecutionEvidence extends EvidenceBase {
  kind: "execution";
  permit_id: string;
  op_key: string;
  outcome: "committed" | "deduped";
}

/**
 * @spec authzen (emitter role `egress`): the record an egress enforcement
 * point retains for an outbound channel use, on the same evidence base as
 * decision/refusal/execution so one verification path covers all of them.
 */
export interface EgressEvidence extends EvidenceBase {
  kind: "egress";
  channel_class: string;
  destination: string;
  outcome: "permitted" | "refused";
  /** Present when `outcome` is `refused`: the failure condition. */
  refusal_reason?: string;
}

/**
 * @spec containment#protected-events, containment#containment-plane — the
 * record the ISSUER retains for one protected-event report received at the
 * ingestion endpoint. First-class on the UNIFIED evidence contract (emitter
 * role `issuer`), NOT a kernel-local table, so it joins the same verification
 * and activity-log surface as the enforcement-point records.
 *
 * Recorded for BOTH outcomes: fail-closed means an unverifiable or untrusted
 * event is rejected AND recorded, never silently ignored. `outcome: "applied"`
 * carries the ContainmentPolicy `rule_id` that fired; `outcome: "rejected"`
 * carries a `rejection_reason` (e.g. `unknown_event_type`, `bad_signature`,
 * `unknown_source`, `source_not_trusted_for_type`, `mission_mismatch`,
 * `mission_terminal`, `malformed_jws`). `advisory` marks a LOW-TRUST report
 * (a harness-forwarded egress refusal): the in-process egress gate is not a
 * trusted signing source, so its refusals are advisory and the PEP/PDP remain
 * the backstop.
 *
 * Deliberately does NOT extend {@link EvidenceBase}: an issuer-side ingestion
 * record carries no `authority_hash`/`action`/`instance_epoch` (those are
 * enforcement-point members). It reuses the record-envelope conventions
 * (`emitter`, `scope_statement_digest`, `trace_id`, `at`) directly.
 */
export interface IngestionEvidence {
  kind: "ingestion";
  event_type: string;
  source: string;
  outcome: "applied" | "rejected";
  /** Present when `outcome` is `rejected`: why the event was refused. */
  rejection_reason?: string;
  /** The ContainmentPolicy `rule_id` that fired; present when `outcome` is `applied`. */
  rule_id?: string;
  mission_id: string;
  event_id: string;
  /** Low-trust provenance: a harness-forwarded egress report (advisory only). */
  advisory?: boolean;
  emitter?: { id: string; role: EmitterRole };
  scope_statement_digest?: string;
  trace_id?: string;
  at: string;
}

export type Evidence =
  | DecisionEvidence
  | RefusalRecord
  | ExecutionEvidence
  | EgressEvidence
  | IngestionEvidence;

/** Distributive omit so the union's discriminated shapes are preserved. */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
export type EvidenceInput = DistributiveOmit<Evidence, "trace_id" | "at">;

export class EvidenceStore {
  private readonly records: Evidence[] = [];

  record(e: EvidenceInput): Evidence {
    const full = { ...e, trace_id: currentTraceId(), at: new Date().toISOString() } as Evidence;
    this.records.push(full);
    return full;
  }

  forMission(missionId: string): Evidence[] {
    return this.records.filter((r) => r.mission_id === missionId);
  }

  all(): readonly Evidence[] {
    return this.records;
  }
}
