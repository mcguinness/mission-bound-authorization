/**
 * @spec mission#authority-sources (#827): startup reconciliation for Mission
 * rows that predate committed-root bindings. A row acquires a binding ONLY
 * from trusted evidence of the root it was approved against:
 *
 * - an explicit reconciliation mapping (Mission ID to root ID), or
 * - a trusted historical catalog the operator declares was in force over an
 *   interval containing the row's APPROVAL instant, in which exactly one root
 *   selected the row's client and Subject with the row's provenance. The
 *   instant follows the approval basis: a direct approval's is its
 *   `created_at`; a template instance's is the consent instant of its
 *   template (`approval_basis.approved_at`), when the recipient pair's root
 *   was resolved, never its later dispatch. A template instance without a
 *   usable consent instant has no historical evidence.
 *
 * A unique match in the CURRENT catalog is not evidence: root A may have been
 * removed and root B added for the same Subject, client and provenance, and
 * binding the row to B would hand it authority it was never approved under.
 * A derived row takes its origin's binding: a child its parent's, a carryover
 * replacement its rendered origin's. A row without evidence stays unbound,
 * and every drawdown from it refuses until it is reconciled.
 *
 * A binding records the root, not that the root still holds: a reconciled
 * root that is no longer declared refuses at the drawdown that consults it.
 */

import { type Database, withTransaction } from "@mission/store";
import {
  type AuthoritySourceBinding,
  type AuthoritySourceCatalog,
  historicalRootFor,
  parseAuthoritySource,
  validateAuthoritySourceCatalog,
} from "./authority-source.js";
import type { SourceBindingStore } from "./source-binding-store.js";
import type { AuthoritySource } from "./types.js";

/** One trusted historical catalog and the interval `[from, until)` it was in force. */
export interface HistoricalAuthoritySourceCatalog {
  catalog: AuthoritySourceCatalog;
  from: string;
  until?: string;
}

/**
 * Trusted deployment configuration for reconciling pre-binding rows. Neither
 * member has a default: no history means no historical evidence, never "the
 * current catalog".
 */
export interface AuthoritySourceReconciliation {
  /** Mission ID to root ID, for rows without a parent. */
  mappings?: Readonly<Record<string, string>>;
  /** Non-overlapping intervals, each with the catalog in force over it. */
  history?: readonly HistoricalAuthoritySourceCatalog[];
}

interface Interval {
  catalog: AuthoritySourceCatalog;
  from: number;
  until: number;
}

/** Validate the evidence at construction: a malformed or overlapping history
 *  refuses, rather than reconciling against an ambiguous past. */
function intervalsOf(history: readonly HistoricalAuthoritySourceCatalog[]): Interval[] {
  const intervals = history.map((h, i) => {
    const from = Date.parse(h.from);
    const until = h.until === undefined ? Number.POSITIVE_INFINITY : Date.parse(h.until);
    if (!Number.isFinite(from) || Number.isNaN(until) || !(from < until)) {
      throw new Error(`authority-source reconciliation history[${i}]: from must precede until`);
    }
    validateAuthoritySourceCatalog(h.catalog);
    return { catalog: h.catalog, from, until };
  });
  intervals.sort((a, b) => a.from - b.from);
  for (let i = 1; i < intervals.length; i++) {
    if ((intervals[i] as Interval).from < (intervals[i - 1] as Interval).until) {
      throw new Error("authority-source reconciliation history: intervals overlap");
    }
  }
  return intervals;
}

interface Row {
  id: string;
  created_at: string;
  approval_basis_json: string;
  subject_iss: string;
  subject_sub: string;
  client_id: string;
  authority_source_json: string;
  parent_id: string | null;
  related_to: string | null;
}

/** The rendered origin of a carryover replacement, from the committed
 *  manifest; undefined when the carryover tables do not name it. */
function carryoverOriginOf(db: Database, row: Row): string | undefined {
  const tables = new Set(
    (db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>).map(
      (t) => t.name,
    ),
  );
  if (!tables.has("carryover_replacements") || !tables.has("carryover_results")) return undefined;
  const rep = db
    .prepare("SELECT plan_id, old_child_id FROM carryover_replacements WHERE replacement_id = ?")
    .get(row.id) as { plan_id: string; old_child_id: string } | undefined;
  if (!rep) return undefined;
  const result = db.prepare("SELECT manifest_json FROM carryover_results WHERE plan_id = ?").get(rep.plan_id) as
    | { manifest_json: string }
    | undefined;
  if (!result) return undefined;
  const manifest = JSON.parse(result.manifest_json) as {
    entries?: Array<{ replacement?: { replacement_id?: string; authority_source_origin?: string } }>;
  };
  const origin = manifest.entries?.find((e) => e.replacement?.replacement_id === row.id)?.replacement
    ?.authority_source_origin;
  if (origin === "old_child") return rep.old_child_id;
  if (origin === "successor") return row.parent_id ?? undefined;
  return undefined;
}

/**
 * Bind every row that has no binding and has evidence, in one transaction.
 * Passes repeat until one binds nothing, so a derived row binds once its
 * origin has, whatever order equal creation instants list them in. Returns
 * the number of rows bound.
 */
export function reconcileSourceBindings(
  db: Database,
  bindings: SourceBindingStore,
  context: { deployment: string; principalIssuer: string },
  evidence: AuthoritySourceReconciliation | undefined,
): number {
  const intervals = intervalsOf(evidence?.history ?? []);
  const mappings = evidence?.mappings ?? {};
  for (const [missionId, rootId] of Object.entries(mappings)) {
    if (typeof rootId !== "string" || rootId.length === 0) {
      throw new Error(`authority-source reconciliation mapping for ${missionId} must name a root`);
    }
  }
  const rows = db
    .prepare(
      `SELECT id, created_at, approval_basis_json, subject_iss, subject_sub, client_id, authority_source_json,
       parent_id, related_to
       FROM missions m
       WHERE NOT EXISTS (SELECT 1 FROM authority_source_bindings b WHERE b.mission_id = m.id)
       ORDER BY created_at, id`,
    )
    .all() as Row[];
  if (rows.length === 0) return 0;
  let bound = 0;
  withTransaction(db, () => {
    let pending = rows;
    for (;;) {
      const unbound: Row[] = [];
      for (const row of pending) {
        const binding = evidenceFor(db, row, bindings, context, mappings, intervals);
        if (!binding) {
          unbound.push(row);
          continue;
        }
        bindings.bindInCallerTx(row.id, binding, "reconciled");
        bound++;
      }
      if (unbound.length === pending.length) break;
      pending = unbound;
    }
  });
  return bound;
}

/**
 * The instant a root row's root was resolved, by its approval basis: a direct
 * approval (and an Expansion successor) at its own creation, a template
 * instance at its template's consent. Undefined when the basis names no
 * usable instant, which is no historical evidence.
 */
function approvalInstantOf(row: Row): number | undefined {
  let basis: { type?: unknown; approved_at?: unknown };
  try {
    basis = JSON.parse(row.approval_basis_json) as { type?: unknown; approved_at?: unknown };
  } catch {
    return undefined;
  }
  if (basis.type === "direct") return Date.parse(row.created_at);
  if (basis.type === "template") {
    const at = typeof basis.approved_at === "string" ? Date.parse(basis.approved_at) : Number.NaN;
    return Number.isFinite(at) ? at : undefined;
  }
  return undefined;
}

function evidenceFor(
  db: Database,
  row: Row,
  bindings: SourceBindingStore,
  context: { deployment: string; principalIssuer: string },
  mappings: Readonly<Record<string, string>>,
  intervals: readonly Interval[],
): AuthoritySourceBinding | undefined {
  const provenance: AuthoritySource = parseAuthoritySource(
    JSON.parse(row.authority_source_json),
    `mission ${row.id}`,
  );
  if (row.parent_id !== null) {
    // A derived row: its origin's root, verbatim, or nothing.
    const origin = row.related_to !== null ? carryoverOriginOf(db, row) : row.parent_id;
    return origin === undefined ? undefined : bindings.get(origin);
  }
  if (row.subject_iss !== context.principalIssuer) return undefined;
  const principal = { iss: row.subject_iss, sub: row.subject_sub };
  const mapped = mappings[row.id];
  if (mapped !== undefined) {
    return { rootId: mapped, deployment: context.deployment, principal, clientId: row.client_id, provenance };
  }
  const at = approvalInstantOf(row);
  if (at === undefined) return undefined;
  const interval = intervals.find((i) => i.from <= at && at < i.until);
  if (!interval) return undefined;
  const rootId = historicalRootFor(interval.catalog, { clientId: row.client_id, sub: row.subject_sub, provenance });
  if (rootId === undefined) return undefined;
  return { rootId, deployment: context.deployment, principal, clientId: row.client_id, provenance };
}
