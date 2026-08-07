/**
 * @spec containment#protected-events, containment#containment-plane — the
 * ISSUER-side evidence retention surface for the Containment Plane. It composes
 * the UNIFIED evidence contract (one {@link EvidenceStore} from
 * `@mission/mcp-payments`, holding the `ingestion` records the AS emits at the
 * protected-event endpoint) with retention of the {@link ContainmentEvidence}
 * that a `contain`/`containOnEvent` transition returns.
 *
 * Two retention channels are needed because {@link ContainmentEvidence} is
 * DELIBERATELY not an authzen-union member: it has its own media type and JCS
 * bytes (mirroring Child Evidence), and folding its type into
 * `@mission/mcp-payments` would form a package reference cycle (the AS depends on
 * mcp-payments for the store). This thin wrapper keeps both on one issuer-side
 * object so the later activity-log PR can join ingestion records to the
 * containment transitions they drove, per Mission.
 */

import { EvidenceStore, type IngestionEvidence } from "@mission/mcp-payments";
import type { ContainmentEvidence } from "./containment.js";

/** The ingestion-record fields a caller supplies; the store stamps `trace_id`/`at`. */
export type IngestionEvidenceInput = Omit<IngestionEvidence, "trace_id" | "at">;

export class IssuerEvidenceStore {
  /** The unified evidence store: holds the `kind: "ingestion"` records. */
  private readonly ingestion = new EvidenceStore();
  /** Retained Containment Evidence (its own media type; not an authzen-union member). */
  private readonly containment: ContainmentEvidence[] = [];

  /** Record one protected-event ingestion (accepted or rejected) on the unified contract. */
  recordIngestion(input: IngestionEvidenceInput): IngestionEvidence {
    return this.ingestion.record(input) as IngestionEvidence;
  }

  /** Retain the Containment Evidence a contain transition returned (no longer discarded). */
  retainContainment(evidence: ContainmentEvidence): void {
    this.containment.push(evidence);
  }

  /** All retained ingestion records, in receipt order. */
  ingestionRecords(): readonly IngestionEvidence[] {
    return this.ingestion.all().filter((r): r is IngestionEvidence => r.kind === "ingestion");
  }

  /** All retained Containment Evidence records, in receipt order. */
  containmentRecords(): readonly ContainmentEvidence[] {
    return this.containment;
  }

  /** Both channels for one Mission, so a consumer can join them. */
  forMission(missionId: string): {
    ingestion: IngestionEvidence[];
    containment: ContainmentEvidence[];
  } {
    return {
      ingestion: this.ingestionRecords().filter((r) => r.mission_id === missionId),
      containment: this.containment.filter((r) => r.mission.id === missionId),
    };
  }
}
