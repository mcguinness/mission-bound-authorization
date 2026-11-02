/**
 * @spec progressive#sec-drawdown-policy (#1017, D1162): one committed content per
 * drawdown policy version. A drawdown policy MUST be reviewed and versioned
 * like approval policy, so every ceiling consent and re-consent pins its
 * policy's (issuer, id, version) to the digest it commits, in the consent's
 * own transaction. A later consent naming that version with other content is
 * refused and commits nothing: a changed policy takes a new version.
 *
 * Pins are never pruned. The activation policy snapshots are no substitute:
 * they are retained only when an activation is adjudicated, and are pruned
 * past their audit horizon. A store from before the pins backfills them from
 * the consents it retains (the committed Mission records' ceilings, then the
 * recorded re-consents), the earliest first; a version that earlier consents
 * already committed with two contents keeps the first.
 *
 * Progressive only: no other activation policy profile reads these pins.
 */
import type { ActivationPolicyRef } from "@mission/core";
import type { Database } from "@mission/store";
import { IntentError } from "./intent.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS drawdown_policy_pins (
  issuer TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  pinned_at TEXT NOT NULL,
  PRIMARY KEY (issuer, policy_id, version)
) STRICT;
`;

/**
 * A ceiling consent named a drawdown policy version whose content differs from
 * the content an earlier consent committed under it. An IntentError, never a
 * unique violation: a retried approval meets the record's uniqueness, never
 * this.
 */
export class DrawdownPolicyVersionReuseError extends IntentError {
  constructor(ref: ActivationPolicyRef) {
    super(
      "invalid_request",
      `drawdown_policy ${ref.id} version ${ref.version} is committed with other content; a changed policy takes a new version`,
    );
    this.name = "DrawdownPolicyVersionReuseError";
  }
}

export class DrawdownPolicyPinStore {
  constructor(private readonly db: Database) {
    this.db.exec(SCHEMA);
    this.backfill();
  }

  /**
   * Pin `ref`'s version to its digest for `issuer`, or confirm the pin it
   * already has. NO OWN TRANSACTION: the consent's transaction runs this, so
   * the pin and the consent commit as one unit, and a refusal commits neither.
   */
  pinInCallerTx(issuer: string, ref: ActivationPolicyRef, pinnedAt: string): void {
    if (!this.db.inTransaction) {
      throw new Error("a drawdown policy version is pinned only inside its consent's transaction");
    }
    this.db
      .prepare(
        `INSERT INTO drawdown_policy_pins (issuer, policy_id, version, digest, pinned_at)
         VALUES (?, ?, ?, ?, ?) ON CONFLICT (issuer, policy_id, version) DO NOTHING`,
      )
      .run(issuer, ref.id, ref.version, ref.digest, pinnedAt);
    if (this.pinned(issuer, ref.id, ref.version) !== ref.digest) throw new DrawdownPolicyVersionReuseError(ref);
  }

  /** The digest `issuer` pinned for a policy version, if any consent committed it. */
  pinned(issuer: string, policyId: string, version: string): string | undefined {
    const row = this.db
      .prepare("SELECT digest FROM drawdown_policy_pins WHERE issuer = ? AND policy_id = ? AND version = ?")
      .get(issuer, policyId, version) as { digest: string } | undefined;
    return row?.digest;
  }

  /**
   * Pin every retained consent's version that has no pin, the earliest first.
   * Reads first and writes only where a consent is unpinned, so an open over a
   * store whose consents are all pinned commits nothing.
   */
  private backfill(): void {
    this.pinUnpinned(
      `SELECT issuer, json_extract(ceiling_json, '$.drawdown_policy.id') AS policy_id,
              json_extract(ceiling_json, '$.drawdown_policy.version') AS version,
              json_extract(ceiling_json, '$.drawdown_policy.digest') AS digest,
              created_at AS pinned_at, rowid AS seq
       FROM missions
       WHERE json_extract(ceiling_json, '$.drawdown_policy.digest') IS NOT NULL`,
    );
    const columns = this.db.prepare("SELECT name FROM pragma_table_info('expansion_deferrals')").all() as Array<{
      name: string;
    }>;
    if (!columns.some((c) => c.name === "ceiling_reconsent_json")) return;
    this.pinUnpinned(
      `SELECT m.issuer, json_extract(d.ceiling_reconsent_json, '$.drawdown_policy.id') AS policy_id,
              json_extract(d.ceiling_reconsent_json, '$.drawdown_policy.version') AS version,
              json_extract(d.ceiling_reconsent_json, '$.drawdown_policy.digest') AS digest,
              json_extract(d.ceiling_reconsent_json, '$.ceiling_consented_at') AS pinned_at, d.rowid AS seq
       FROM expansion_deferrals d JOIN missions m ON m.id = d.predecessor_id
       WHERE json_extract(d.ceiling_reconsent_json, '$.drawdown_policy.digest') IS NOT NULL`,
    );
  }

  private pinUnpinned(consents: string): void {
    const unpinned = `SELECT c.* FROM (${consents}) c WHERE NOT EXISTS (
      SELECT 1 FROM drawdown_policy_pins p
      WHERE p.issuer = c.issuer AND p.policy_id = c.policy_id AND p.version = c.version)`;
    if (this.db.prepare(`${unpinned} LIMIT 1`).get() === undefined) return;
    this.db
      .prepare(
        `INSERT OR IGNORE INTO drawdown_policy_pins (issuer, policy_id, version, digest, pinned_at)
         SELECT issuer, policy_id, version, digest, pinned_at FROM (${unpinned}) ORDER BY pinned_at, seq`,
      )
      .run();
  }
}
