/**
 * @spec mission#authority-sources (#827): the issuer-local record of the
 * authority-source ROOT each Mission committed: the stable root id, the
 * deployment, the root context (the Subject and client the root was resolved
 * for) and the provenance. A drawdown (child, template dispatch, carryover)
 * recovers its origin's root from here, never by re-resolving provenance,
 * which cannot say which of several roots of one mode a Mission drew on.
 *
 * Private and outside every anchor: no wire member carries a root id, and the
 * public record and its integrity anchors are untouched. Rows are written
 * inside `insertRecord`'s transaction (the single record-creation funnel), so
 * a Mission never exists without its binding. A row that predates this table
 * acquires one only through the startup reconciliation, from trusted evidence;
 * a drawdown from a Mission with no binding refuses.
 */

import type { Database } from "@mission/store";
import { type AuthoritySourceBinding, parseAuthoritySource } from "./authority-source.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS authority_source_bindings (
  mission_id TEXT PRIMARY KEY,
  root_id TEXT NOT NULL,
  deployment TEXT NOT NULL,
  principal_iss TEXT NOT NULL,
  principal_sub TEXT NOT NULL,
  client_id TEXT NOT NULL,
  provenance_json TEXT NOT NULL,
  basis TEXT NOT NULL
) STRICT;
`;

/**
 * How a binding was established: `resolved` at a fresh approval, `inherited`
 * from a drawdown's origin, or `reconciled` at startup from trusted evidence.
 */
export type SourceBindingBasis = "resolved" | "inherited" | "reconciled";

export class SourceBindingStore {
  constructor(private readonly db: Database) {
    this.db.exec(SCHEMA);
  }

  /**
   * Record one Mission's binding. NO OWN TRANSACTION: `insertRecord` and the
   * startup reconciliation run this inside their own, so the binding and the
   * record commit as one unit. A second binding for one Mission is refused
   * by the primary key, never overwritten.
   */
  bindInCallerTx(missionId: string, binding: AuthoritySourceBinding, basis: SourceBindingBasis): void {
    this.db
      .prepare(
        `INSERT INTO authority_source_bindings (mission_id, root_id, deployment,
         principal_iss, principal_sub, client_id, provenance_json, basis)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        missionId,
        binding.rootId,
        binding.deployment,
        binding.principal.iss,
        binding.principal.sub,
        binding.clientId,
        JSON.stringify(binding.provenance),
        basis,
      );
  }

  /** The committed binding, or undefined for a Mission that has none. */
  get(missionId: string): AuthoritySourceBinding | undefined {
    const row = this.db
      .prepare(
        `SELECT root_id, deployment, principal_iss, principal_sub, client_id, provenance_json
         FROM authority_source_bindings WHERE mission_id = ?`,
      )
      .get(missionId) as Record<string, string> | undefined;
    if (!row) return undefined;
    return Object.freeze({
      rootId: row.root_id as string,
      deployment: row.deployment as string,
      principal: { iss: row.principal_iss as string, sub: row.principal_sub as string },
      clientId: row.client_id as string,
      // @spec mission#lifecycle: fail closed on hydration, as the record's
      // own member does: an unrecognized type refuses rather than widens.
      provenance: parseAuthoritySource(
        JSON.parse(row.provenance_json as string),
        `authority-source binding of ${missionId}`,
      ),
    });
  }

  /** The basis a binding was recorded with (audit and tests). */
  basisOf(missionId: string): SourceBindingBasis | undefined {
    const row = this.db
      .prepare("SELECT basis FROM authority_source_bindings WHERE mission_id = ?")
      .get(missionId) as { basis: string } | undefined;
    return row?.basis as SourceBindingBasis | undefined;
  }
}
