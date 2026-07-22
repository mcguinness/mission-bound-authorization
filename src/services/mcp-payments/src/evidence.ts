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
}

export interface DecisionEvidence extends EvidenceBase {
  kind: "decision";
  decision: boolean;
  policy_view_id?: string;
  denial_reason?: string;
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

export type Evidence = DecisionEvidence | RefusalRecord | ExecutionEvidence;

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
