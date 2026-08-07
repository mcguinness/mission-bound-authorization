/**
 * @spec authzen evidence objects (Decision Evidence, Refusal Record)
 * @spec D13 (trace_id extension member), D32 (producers retain their own)
 *
 * The PEP retains its own evidence (feed-driven distributed, D32). Signing
 * and SCITT registration land in M10; M4 records the retained objects and
 * the members the operation profile fixes.
 */

import { currentTraceId } from "@mission/telemetry";

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
   * conventions at other enforcement points (harness, egress).
   */
  emitter?: { id: string; role: "pdp" | "pep" | "executor" | "harness" | "egress" };
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

export type Evidence = DecisionEvidence | RefusalRecord | ExecutionEvidence | EgressEvidence;

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
