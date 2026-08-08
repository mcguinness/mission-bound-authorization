/**
 * @spec D35 (console BFF), D32 (feed-driven evidence timeline),
 * mission-management (fleet surfaces), status#legal-transitions (lifecycle)
 *
 * The persona backend-for-frontend. The three SPAs (approver, operator,
 * agent-console) are thin views over these methods; this layer holds the
 * sessions, the role checks, and the downstream-service credentials, and
 * assembles the persona surfaces. Its methods are what the M11 headless tests
 * exercise in place of driving a browser.
 */

import type { AccessRequestService } from "@mission/access-request";
import type { ContainmentEvidence, MissionKernel, MissionRecord } from "@mission/authorization-server";
import type { Evidence, IngestionEvidence } from "@mission/mcp-payments";
import {
  type SignedStatement,
  type TransparencyService,
  verifyTransparentStatement,
} from "@mission/transparency";
import type { JWK } from "jose";
import {
  type ActivityEntry,
  type ActivityRun,
  activityByTrace,
  buildActivityLog,
  type MissionLineage,
} from "./activity-log.js";
import { requireRole, type Session, SessionStore } from "./sessions.js";

export { SessionStore, requireRole, AuthzError, type Session, type Role } from "./sessions.js";
export {
  type ActivityEntry,
  type ActivityKind,
  type ActivityLogInput,
  type ActivityRun,
  activityByTrace,
  buildActivityLog,
  type MissionLineage,
} from "./activity-log.js";

/** A read accessor over an enforcement-point EvidenceStore (D32: producers
 * retain their own; the Activity Log only READS). `EvidenceStore` satisfies it. */
export interface EvidenceReader {
  all(): readonly Evidence[];
}

/** A read accessor over the issuer-side store (ingestion + Containment
 * Evidence). `IssuerEvidenceStore` satisfies it. */
export interface IssuerEvidenceReader {
  ingestionRecords(): readonly IngestionEvidence[];
  containmentRecords(): readonly ContainmentEvidence[];
}

/** @spec activity-log — the injected producer read sources for the joined
 * Activity Log. Additive and OPTIONAL: absent on the surfaces that retain no
 * evidence (the no-auth-server demo path has no issuer store). No store moves;
 * each producer keeps writing its own (D32). */
export interface ActivityDeps {
  /** Enforcement-point readers (the PEP store, the egress gate store, ...). */
  evidence: readonly EvidenceReader[];
  /** Issuer-side reader; absent on the no-auth-server path. */
  issuerEvidence?: IssuerEvidenceReader;
}

export interface ConsoleDeps {
  kernel: MissionKernel;
  ars: AccessRequestService;
  transparency: TransparencyService;
  /** Retrieve retained evidence by digest for the timeline (feed-driven, D32). */
  retrieveEvidence: (missionId: string, digest: string) => unknown | undefined;
  producerJwks: { keys: JWK[] };
  serviceJwks: { keys: JWK[] };
  /** Receipt lookup by statement (M10 registration returns these). */
  receiptFor: (statement: SignedStatement) => { jws: string; index: number; treeSize: number } | undefined;
  /** @spec activity-log — OPTIONAL producer sources for the joined Activity Log
   * (see {@link ActivityDeps}). Absent leaves the surface working with empty
   * timelines (lineage still resolves from the kernel). */
  activity?: ActivityDeps;
}

export interface FleetRow {
  id: string;
  state: string;
  version: number;
  subject: string;
  approver: string;
  predecessor?: string;
}

export interface TimelineRow {
  producer: string;
  evidence_type: string;
  digest: string;
  verified: boolean;
  detail?: string;
}

export class ConsoleBff {
  readonly sessions = new SessionStore();
  constructor(private readonly deps: ConsoleDeps) {}

  // --- Approver console ---------------------------------------------------

  /** The approver's queue: pending ARAP tasks awaiting adjudication. */
  approverQueue(session: Session | undefined): Array<{ id: string; mission_id: string; action: string; subject: string }> {
    requireRole(session, "approver");
    return this.deps.ars.pending();
  }

  async adjudicateTask(
    session: Session | undefined,
    taskId: string,
    decision: "approve" | "deny",
    csrf: string,
  ): Promise<{ approved: boolean }> {
    const s = requireRole(session, "approver", { write: true, csrf });
    const approval = await this.deps.ars.adjudicate(taskId, decision, s.sub);
    return { approved: approval !== null };
  }

  // --- Operator console ---------------------------------------------------

  /** @spec mission-management: fleet enumeration. */
  fleet(session: Session | undefined): FleetRow[] {
    requireRole(session, "operator");
    return this.deps.kernel.allMissions().map((m: MissionRecord) => ({
      id: m.id,
      state: this.deps.kernel.applyExpiry(m).state,
      version: m.version,
      subject: m.subject.sub,
      approver: m.approver.sub,
      ...(m.predecessor ? { predecessor: m.predecessor } : {}),
    }));
  }

  /** @spec status#legal-transitions: operator lifecycle operations. */
  lifecycle(
    session: Session | undefined,
    missionId: string,
    op: "revoke" | "suspend" | "resume" | "complete",
    csrf: string,
  ): { id: string; state: string } {
    requireRole(session, "operator", { write: true, csrf });
    const r = this.deps.kernel.transition(missionId, op);
    return { id: r.id, state: r.state };
  }

  /**
   * @spec D32: the evidence timeline IS the verified transparency feed. Walk
   * the mission's feed, retrieve evidence, run the five-step verification, and
   * render each statement as a verified or failed row. Tampering shows as a
   * failed row rather than being hidden.
   */
  async timeline(session: Session | undefined, missionId: string): Promise<TimelineRow[]> {
    requireRole(session, "operator");
    const feed = this.deps.transparency.feed(missionId);
    const rows: TimelineRow[] = [];
    for (const statement of feed) {
      const receipt = this.deps.receiptFor(statement);
      const evidence = this.deps.retrieveEvidence(missionId, statement.digest);
      const typePayload = decodeType(statement.jws);
      if (!receipt || evidence === undefined) {
        rows.push({ producer: statement.producer, evidence_type: typePayload, digest: statement.digest, verified: false, detail: "evidence or receipt unavailable" });
        continue;
      }
      const res = await verifyTransparentStatement({
        statement,
        receipt,
        evidence: evidence as never,
        producerJwks: this.deps.producerJwks,
        serviceJwks: this.deps.serviceJwks,
        expectedMissionId: missionId,
      });
      rows.push({
        producer: statement.producer,
        evidence_type: typePayload,
        digest: statement.digest,
        verified: res.ok,
        ...(res.ok ? {} : { detail: `failed at step ${res.step}: ${res.reason}` }),
      });
    }
    return rows;
  }

  // --- Agent Activity Log (read-side join over the unified evidence) ---------

  /**
   * @spec activity-log (AAM Agent Activity Log) — the joined, per-task-run
   * timeline: read the producer-retained records (D32) through the injected
   * accessors and join them by Mission + lineage into the task-run graph rooted
   * at `missionId` (template -> dispatched Mission -> continued hops -> Child
   * Missions). Pure read; no evidence moves. Operator-facing.
   */
  activityLog(session: Session | undefined, missionId: string): ActivityRun {
    requireRole(session, "operator");
    return buildActivityLog(missionId, this.activitySources());
  }

  /**
   * @spec activity-log — the trace-grouped view: the whole task run as one flat
   * ordered sequence of records sharing `trace_id`, across producers.
   */
  activityByTrace(session: Session | undefined, traceId: string): ActivityEntry[] {
    requireRole(session, "operator");
    return activityByTrace(traceId, this.activitySources());
  }

  /** Gather the injected producer sources + kernel lineage into one join input.
   * `all()`/`ingestionRecords()` return every Mission's records; the join filters
   * per node, so a whole task-run graph (root + descendants) is covered. */
  private activitySources(): {
    evidence: Evidence[];
    containment: ContainmentEvidence[];
    missions: MissionLineage[];
  } {
    const a = this.deps.activity;
    const evidence: Evidence[] = [];
    for (const reader of a?.evidence ?? []) evidence.push(...reader.all());
    if (a?.issuerEvidence) evidence.push(...a.issuerEvidence.ingestionRecords());
    const containment: ContainmentEvidence[] = a?.issuerEvidence ? [...a.issuerEvidence.containmentRecords()] : [];
    const missions: MissionLineage[] = this.deps.kernel.allMissions().map((m: MissionRecord) => ({
      id: m.id,
      ...(m.parent ? { parent: m.parent } : {}),
      ...(m.template ? { template: m.template } : {}),
      ...(m.predecessor ? { predecessor: m.predecessor } : {}),
    }));
    return { evidence, containment, missions };
  }
}

function decodeType(jws: string): string {
  try {
    const payload = JSON.parse(Buffer.from(jws.split(".")[1] as string, "base64url").toString());
    return (payload.evidence_type as string) ?? "unknown";
  } catch {
    return "unknown";
  }
}
