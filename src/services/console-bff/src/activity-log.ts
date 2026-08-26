/**
 * @spec activity-log (AAM Agent Activity Log) — a READ-SIDE join over the
 * UNIFIED evidence contract. Cloudflare's Agent Access Model describes an "Agent
 * Activity Log": one record set spanning every enforcement point for a task run.
 * The family emits that base contract already (`emitter {id, role}` with roles
 * pdp/pep/executor/harness/egress/issuer, `entry_digest`, `hop_reference`, the
 * issuer-side `ingestion` kind), but records are PRODUCER-RETAINED (D32): the
 * PEP, the egress gate, and the issuer each keep their own. This module JOINS
 * them by Mission and correlation into the per-task-run timeline AAM describes,
 * WITHOUT moving any evidence: it is a pure read-model over injected producer
 * sources, never a new store of record.
 *
 * In a real deployment a SIEM/warehouse ingests the producer-retained records
 * and runs this join at query time; this module is the reference join. It is a
 * SIBLING of {@link ConsoleBff.timeline}, which is a digest-keyed VERIFIED
 * transparency-feed view (D32); this one joins the raw retained records across
 * producers. Neither writes.
 *
 * Join keys are the ones already on the contract (no new fields are invented):
 * `mission_id` (everywhere), `event_id` (ingestion <-> Containment Evidence),
 * `hop_reference.jti`/handle (continuation), `entry_digest` (which Authority Set
 * entry), `trace_id` (a task-run trace). Mission lineage (`parent`, `template`,
 * `predecessor`) threads a whole task-run graph (template -> dispatched Mission
 * -> continued hops -> child Missions) into one tree.
 */

import type { EmitterRole } from "@mission/mcp-payments";
import type {
  ArtifactEvidence,
  DecisionEvidence,
  EgressEvidence,
  Evidence,
  EvidenceBase,
  ExecutionEvidence,
  IngestionEvidence,
  RefusalRecord,
} from "@mission/mcp-payments";
import type { ContainmentEvidence, ParentRef, TemplateRef } from "@mission/authorization-server";

/** The discriminants a timeline entry can carry: the five unified-contract
 * kinds plus `containment` (Containment Evidence has its own media type and is
 * not an authzen-union member, so it is joined in as a read-model row). */
export type ActivityKind = Evidence["kind"] | "containment";

/**
 * One row in the joined timeline: the per-record projection the consoles/SIEM
 * render, flattened to the members AAM's activity log needs. Every field is
 * copied from a producer record; nothing is invented. `role` for a
 * `containment` row is SYNTHESIZED as `issuer` (Containment Evidence is
 * issuer-committed and carries no `emitter` on the contract).
 */
export interface ActivityEntry {
  mission_id: string;
  kind: ActivityKind;
  /** `emitter.role`; synthesized `issuer` for a `containment` row. */
  role?: EmitterRole;
  /** `emitter.id` (absent for a `containment` row). */
  emitter_id?: string;
  /** The operation/action; for ingestion/containment, the protected-event type. */
  action?: string;
  /** The requested resource, where the record carries one (an egress destination). */
  resource?: string;
  /** The PDP's resolved-scope anchor (Authority Set entry), on a `decision` row. */
  entry_digest?: string;
  /** The published Enforcement Scope Statement digest, joining a row to its claim. */
  scope_statement_digest?: string;
  /** Present on a `decision` row: the permit/deny verdict. */
  decision?: boolean;
  /** execution/egress/ingestion outcome (committed/deduped/permitted/refused/applied/rejected). */
  outcome?: string;
  /** Normalized failure reason (denial_reason / refusal_reason / rejection_reason). */
  denial_reason?: string;
  /** The Containment overlay version, from Containment Evidence (`new_containment_version`). */
  containment_version?: number;
  /**
   * @spec work-products#provenance — the producing MISSION's principal/agent on
   * an `artifact` row. DELIBERATELY DISTINCT from `emitter_id`/`role` (which name
   * the emitting COMPONENT): work-product attribution is never conflated with the
   * enforcement-point emitter, so `producer` provenance gets its own field.
   */
  artifact_producer?: string;
  /** The provenance-chain back-reference, on an `artifact` row. */
  parent_artifact?: string;
  // --- correlation ids (already on the contract; used, never invented) ---
  trace_id?: string;
  event_id?: string;
  decision_id?: string;
  hop_reference?: { jti: string; mission_id: string; continuation_handle?: string };
  /** Record timestamp; the primary ordering key. */
  at: string;
}

/** The lineage a Mission carries, so the join can thread the task-run graph. */
export interface MissionLineage {
  id: string;
  /** Set on a Child Mission (child-delegation): threads it under its parent. */
  parent?: ParentRef;
  /** Set on an instance dispatched from a Mission Template (lineage/audit only). */
  template?: TemplateRef;
  /** Set on an Expansion successor (metadata; a successor is its OWN run). */
  predecessor?: string;
}

/** The producer sources the join reads. All optional but `evidence`; absent
 * sources simply contribute no rows (the no-auth-server demo surface retains no
 * issuer records, so `containment` is absent there). */
export interface ActivityLogInput {
  /** UNIFIED-contract records from every producer (PEP decision/refusal/execution,
   * egress, and issuer `ingestion`). The union already covers all five kinds. */
  evidence: readonly Evidence[];
  /** Issuer-retained Containment Evidence (own media type; not an authzen-union member). */
  containment?: readonly ContainmentEvidence[];
  /** Mission lineage for the task-run graph. A flat list; the join builds the tree. */
  missions?: readonly MissionLineage[];
}

/** One node of the task-run graph: a Mission, its lineage, its ordered
 * timeline, and its Child Missions (built from `parent` only; an Expansion
 * successor is a separate run, so `predecessor` stays lineage metadata). */
export interface ActivityRun {
  mission_id: string;
  lineage: {
    parent?: ParentRef;
    template?: TemplateRef;
    predecessor?: string;
  };
  entries: ActivityEntry[];
  children: ActivityRun[];
}

function emitterFields(emitter?: { id: string; role: EmitterRole }): Partial<ActivityEntry> {
  return emitter ? { role: emitter.role, emitter_id: emitter.id } : {};
}

/** The correlation members shared by the EvidenceBase-derived kinds (ingestion
 * does NOT extend EvidenceBase and is projected separately). */
function correlation(e: EvidenceBase): Partial<ActivityEntry> {
  return {
    ...(e.decision_id !== undefined ? { decision_id: e.decision_id } : {}),
    ...(e.trace_id !== undefined ? { trace_id: e.trace_id } : {}),
    ...(e.hop_reference !== undefined ? { hop_reference: e.hop_reference } : {}),
    ...(e.scope_statement_digest !== undefined ? { scope_statement_digest: e.scope_statement_digest } : {}),
  };
}

/** Project one unified-contract record onto a timeline row. */
function toEntry(e: Evidence): ActivityEntry {
  switch (e.kind) {
    case "decision": {
      // @spec runtime-evidence#decision-evidence-object (issue #649): the
      // retained row's `content` IS the exact signed Decision Evidence
      // Object; every substantive field below is projected from it, never
      // from the wrapper (`mission_id`/`trace_id`/`at` are the only wrapper
      // members this row reads, per the file header note in `evidence.ts`).
      const d = e as DecisionEvidence;
      return {
        mission_id: d.mission_id,
        kind: "decision",
        at: d.at,
        ...emitterFields(d.content.emitter),
        action: d.content.action.name,
        decision: d.content.decision === "permit",
        ...(d.content.denial_reason !== undefined ? { denial_reason: d.content.denial_reason } : {}),
        ...(d.content.entry_digest !== undefined ? { entry_digest: d.content.entry_digest } : {}),
        decision_id: d.content.evaluation_id,
        ...(d.trace_id !== undefined ? { trace_id: d.trace_id } : {}),
      };
    }
    case "refusal": {
      const r = e as RefusalRecord;
      return {
        mission_id: r.mission_id,
        kind: "refusal",
        at: r.at,
        ...emitterFields(r.content.emitter),
        action: r.content.action.name,
        denial_reason: r.content.denial_reason,
        ...(r.content.hop_reference !== undefined ? { hop_reference: r.content.hop_reference } : {}),
        ...(r.trace_id !== undefined ? { trace_id: r.trace_id } : {}),
      };
    }
    case "execution": {
      const x = e as ExecutionEvidence;
      return {
        mission_id: x.mission_id,
        kind: "execution",
        at: x.at,
        ...emitterFields(x.content.emitter),
        // The activity log's `action` column has no Execution Evidence
        // analogue (the spec object carries no action name, only
        // `evaluation_id`, joined back to the Decision Evidence row for
        // that detail); `decision_id` below carries the join key instead.
        outcome: x.content.outcome,
        decision_id: x.content.evaluation_id,
        ...(x.content.hop_reference !== undefined ? { hop_reference: x.content.hop_reference } : {}),
        ...(x.trace_id !== undefined ? { trace_id: x.trace_id } : {}),
      };
    }
    case "egress": {
      const g = e as EgressEvidence;
      return {
        mission_id: g.mission_id,
        kind: "egress",
        at: g.at,
        ...emitterFields(g.emitter),
        action: g.action,
        resource: g.destination,
        outcome: g.outcome,
        ...(g.refusal_reason !== undefined ? { denial_reason: g.refusal_reason } : {}),
        ...correlation(g),
      };
    }
    case "ingestion": {
      const n = e as IngestionEvidence;
      return {
        mission_id: n.mission_id,
        kind: "ingestion",
        at: n.at,
        ...emitterFields(n.emitter),
        action: n.event_type,
        outcome: n.outcome,
        ...(n.rejection_reason !== undefined ? { denial_reason: n.rejection_reason } : {}),
        event_id: n.event_id,
        ...(n.trace_id !== undefined ? { trace_id: n.trace_id } : {}),
        ...(n.scope_statement_digest !== undefined ? { scope_statement_digest: n.scope_statement_digest } : {}),
      };
    }
    case "artifact": {
      // @spec work-products#provenance — the work-product provenance row. It
      // carries NO emitter (attribution is not an enforcement-point emit) and NO
      // authority member; `producer` (the producing principal) maps to the
      // distinct `artifact_producer`, never `emitter_id`. `at` is the artifact's
      // production time (`created_at`), the timeline ordering key.
      const a = e as ArtifactEvidence;
      return {
        mission_id: a.mission_id,
        kind: "artifact",
        at: a.created_at,
        artifact_producer: a.producer,
        ...(a.parent_artifact !== undefined ? { parent_artifact: a.parent_artifact } : {}),
      };
    }
  }
}

/** Project one Containment Evidence record onto a timeline row. The issuer
 * commits the transition, so `role` is synthesized as `issuer`; the join keys it
 * to the driving `ingestion` record by `event_id`. */
function containmentToEntry(c: ContainmentEvidence): ActivityEntry {
  return {
    mission_id: c.mission.id,
    kind: "containment",
    role: "issuer",
    action: c.event.type,
    outcome: "applied",
    event_id: c.event.event_id,
    containment_version: c.new_containment_version,
    at: c.created_at,
  };
}

/** Parse a timestamp to epoch ms; malformed values sort first (0) rather than
 * poisoning the comparator with NaN. Real records are `toISOString()`. */
function timeOf(at: string): number {
  const t = Date.parse(at);
  return Number.isNaN(t) ? 0 : t;
}

/**
 * Project + order every source record into one flat timeline. Ordering is by
 * timestamp ascending; the deterministic tiebreak on an exact-millisecond
 * collision is INPUT ORDER (each producer's store is insertion-ordered, i.e.
 * causal, and the concatenation `[...evidence, ...containment]` is fixed), so
 * the same inputs always yield the same ordered output.
 */
function collectEntries(input: ActivityLogInput): ActivityEntry[] {
  const withOrd: Array<{ e: ActivityEntry; ord: number }> = [];
  let ord = 0;
  for (const e of input.evidence) withOrd.push({ e: toEntry(e), ord: ord++ });
  for (const c of input.containment ?? []) withOrd.push({ e: containmentToEntry(c), ord: ord++ });
  withOrd.sort((a, b) => {
    const ta = timeOf(a.e.at);
    const tb = timeOf(b.e.at);
    return ta !== tb ? ta - tb : a.ord - b.ord;
  });
  return withOrd.map((x) => x.e);
}

/**
 * Join the producer sources into the task-run graph rooted at `rootMissionId`:
 * a tree of {@link ActivityRun} nodes (template -> dispatched Mission ->
 * continued hops [carried as `hop_reference` on the entries] -> Child Missions),
 * each node holding its Mission's ordered timeline. Pure: same inputs -> same
 * output. The tree is built from `parent` lineage only; child order is
 * id-sorted for determinism, and a cycle guard keeps a malformed lineage finite.
 */
export function buildActivityLog(rootMissionId: string, input: ActivityLogInput): ActivityRun {
  const entries = collectEntries(input);
  const byMission = new Map<string, ActivityEntry[]>();
  for (const e of entries) {
    const arr = byMission.get(e.mission_id);
    if (arr) arr.push(e);
    else byMission.set(e.mission_id, [e]);
  }

  const missions = input.missions ?? [];
  const lineageById = new Map<string, MissionLineage>(missions.map((m) => [m.id, m]));
  const childrenIndex = new Map<string, MissionLineage[]>();
  for (const m of missions) {
    if (m.parent) {
      const arr = childrenIndex.get(m.parent.id);
      if (arr) arr.push(m);
      else childrenIndex.set(m.parent.id, [m]);
    }
  }

  const buildNode = (id: string, seen: Set<string>): ActivityRun => {
    seen.add(id);
    const lin = lineageById.get(id);
    const kids = (childrenIndex.get(id) ?? [])
      .filter((k) => !seen.has(k.id))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return {
      mission_id: id,
      lineage: {
        ...(lin?.parent ? { parent: lin.parent } : {}),
        ...(lin?.template ? { template: lin.template } : {}),
        ...(lin?.predecessor ? { predecessor: lin.predecessor } : {}),
      },
      entries: byMission.get(id) ?? [],
      children: kids.map((k) => buildNode(k.id, seen)),
    };
  };

  return buildNode(rootMissionId, new Set<string>());
}

/**
 * The trace-grouped view: every timeline row carrying `trace_id`, ordered. A
 * task run shares one `trace_id` across producers, so this reads the whole run
 * as one flat sequence (cheaper than the tree when the caller has the trace).
 * Containment Evidence carries no `trace_id`, so it never appears here.
 */
export function activityByTrace(traceId: string, input: ActivityLogInput): ActivityEntry[] {
  return collectEntries(input).filter((e) => e.trace_id === traceId);
}
