/**
 * @spec mission#standing-consent-bases, mission#mission-record: the retained
 * activation policy snapshots. For every activation policy `digest` this
 * issuer activated a Mission under, the exact bytes and media type behind it,
 * kept for that Mission's audit horizon so an auditor can recompute the
 * commitment after the current registry has moved on.
 *
 * Retrieval here is never activation eligibility. Only the current registry
 * (`verifiedActivationPolicy` over an `ActivationPolicyRegistry`) decides
 * whether a policy adjudicates an activation: a retained snapshot does not
 * authorize a replaced or retired policy, and no activation gate reads this
 * store.
 *
 * - Identity: a row is keyed by (issuer, policy id, version, digest). Every
 *   write recomputes `digest` over the bytes it is handed and refuses bytes
 *   that do not hash to the reference. Changed bytes under an unchanged
 *   version are a different digest, so a different row: they never replace
 *   the bytes behind a committed identity, and no write updates the content
 *   columns.
 * - Digest input: the integrity anchor with `typ` `mission-activation-policy`,
 *   `iss` the row's issuer, and `value` `{content_type, content}` over the
 *   exact bytes. The row keeps each member, so the anchor recomputes from the
 *   row alone.
 * - Retention: a row is kept until the latest `expires_at` of a Mission
 *   activated under it plus the deployment's declared post-expiry audit
 *   retention (`audit_retention_seconds`, the same declaration the terminal
 *   tombstones compose). A later activation only moves that horizon forward.
 * - Deletion: {@link ActivationPolicySnapshotStore.pruneExpired} deletes a
 *   row only once its horizon has passed, at boot recovery or when an
 *   operator calls it. Retiring or replacing a policy in the registry deletes
 *   nothing. Storage is not indefinite: past its horizon a snapshot is gone
 *   and verification reports it `unavailable`.
 * - Durability: the table is on the kernel database and is written in the
 *   activation's own record transaction (`insertRecord`), so a Mission never
 *   commits without its snapshot, and the snapshot is exactly as durable as
 *   the kernel store (the file-backed opt-in survives a restart; the
 *   in-memory default does not).
 */

import {
  ACTIVATION_POLICY_TYP,
  type ActivationPolicyRef,
  type ActivationPolicySnapshot,
  activationPolicyDigest,
} from "@mission/core";
import type { Database } from "@mission/store";
import type { MissionRecord } from "./types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS activation_policy_snapshots (
  issuer TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  version TEXT NOT NULL,
  digest TEXT NOT NULL,
  content_type TEXT NOT NULL,
  content BLOB NOT NULL,
  first_activated_at TEXT NOT NULL,
  activations INTEGER NOT NULL,
  retain_until INTEGER NOT NULL,
  PRIMARY KEY (issuer, policy_id, version, digest)
) STRICT;
`;

/** The identity a retained snapshot is keyed by. */
export interface ActivationPolicySnapshotKey {
  issuer: string;
  id: string;
  version: string;
  digest: string;
}

/**
 * One activation policy an activation was adjudicated under: the committed
 * reference and the held snapshot verified against it before the activation.
 */
export interface EvaluatedActivationPolicy {
  ref: ActivationPolicyRef;
  snapshot: ActivationPolicySnapshot;
}

/** A retained snapshot: its identity, the digest's envelope context, the exact bytes, and its horizon. */
export interface RetainedActivationPolicySnapshot extends ActivationPolicySnapshotKey {
  /** The integrity-anchor `typ` the digest was computed under. */
  typ: typeof ACTIVATION_POLICY_TYP;
  /** The snapshot's media type, the anchor value's `content_type`. */
  content_type: string;
  /** The snapshot's exact bytes, whose base64url encoding is the anchor value's `content`. */
  content: Uint8Array;
  /** The creation instant of the first Mission activated under this snapshot. */
  first_activated_at: string;
  /** How many Mission activations retained this snapshot. */
  activations: number;
  /** The instant this row may be pruned after: latest Mission expiry plus the audit retention. */
  retain_until: string;
}

/**
 * The auditor's check of one committed activation policy reference against
 * the retained evidence: `verified` when the retained bytes recompute the
 * committed digest, `mismatch` when a retained row no longer does, and
 * `unavailable` when no snapshot is retained under that identity (never
 * retained, or pruned past its horizon). `not_applicable` when the Mission
 * commits no activation policy.
 */
export type ActivationPolicyCommitmentCheck =
  | { status: "verified"; ref: ActivationPolicyRef; snapshot: RetainedActivationPolicySnapshot }
  | { status: "mismatch"; ref: ActivationPolicyRef; snapshot: RetainedActivationPolicySnapshot }
  | { status: "unavailable"; ref: ActivationPolicyRef }
  | { status: "not_applicable" };

/** Raised when a snapshot cannot be retained under the identity it claims; the activation does not commit. */
export class ActivationPolicyRetentionError extends Error {}

const bytesOf = (content: string | Uint8Array): Buffer =>
  typeof content === "string" ? Buffer.from(content, "utf8") : Buffer.from(content);

export class ActivationPolicySnapshotStore {
  constructor(
    private readonly db: Database,
    private readonly opts: { now: () => Date; auditRetentionSeconds: number },
  ) {
    if (!Number.isFinite(opts.auditRetentionSeconds) || opts.auditRetentionSeconds < 0) {
      throw new Error("activation policy audit retention must be a non-negative number of seconds");
    }
    this.db.exec(SCHEMA);
  }

  /**
   * Retain the snapshot an activation evaluated. NO OWN TRANSACTION, and
   * refused outside one: `insertRecord` runs this inside the record's
   * transaction, so the Mission and its snapshot commit as one unit and a
   * refusal here commits no Mission. The digest is recomputed over the bytes
   * handed in; bytes that do not hash to `ref.digest` are refused. A repeat
   * under an existing identity moves the horizon forward and counts the
   * activation; it never touches the retained bytes.
   */
  retainInCallerTx(
    activation: Pick<MissionRecord, "issuer" | "created_at" | "expires_at">,
    evaluated: EvaluatedActivationPolicy,
  ): void {
    if (!this.db.inTransaction) {
      throw new Error("an activation policy snapshot is retained only inside its activation's transaction");
    }
    const { ref, snapshot } = evaluated;
    if (activationPolicyDigest(activation.issuer, snapshot) !== ref.digest) {
      throw new ActivationPolicyRetentionError(
        `activation policy ${ref.id} version ${ref.version}: the snapshot does not reproduce its committed digest`,
      );
    }
    const retainUntil = Date.parse(activation.expires_at) + this.opts.auditRetentionSeconds * 1000;
    if (!Number.isFinite(retainUntil)) {
      throw new ActivationPolicyRetentionError(`activation expiry ${activation.expires_at} is not a date-time`);
    }
    this.db
      .prepare(
        `INSERT INTO activation_policy_snapshots (issuer, policy_id, version, digest, content_type,
           content, first_activated_at, activations, retain_until)
         VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
         ON CONFLICT (issuer, policy_id, version, digest) DO UPDATE SET
           retain_until = max(retain_until, excluded.retain_until),
           activations = activations + 1`,
      )
      .run(
        activation.issuer,
        ref.id,
        ref.version,
        ref.digest,
        snapshot.content_type,
        bytesOf(snapshot.content),
        activation.created_at,
        retainUntil,
      );
  }

  /** The snapshot retained under exactly this identity, or undefined. A read for audit, never for eligibility. */
  resolve(key: ActivationPolicySnapshotKey): RetainedActivationPolicySnapshot | undefined {
    const row = this.db
      .prepare(
        `SELECT * FROM activation_policy_snapshots
         WHERE issuer = ? AND policy_id = ? AND version = ? AND digest = ?`,
      )
      .get(key.issuer, key.id, key.version, key.digest) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return {
      issuer: row.issuer as string,
      id: row.policy_id as string,
      version: row.version as string,
      digest: row.digest as string,
      typ: ACTIVATION_POLICY_TYP,
      content_type: row.content_type as string,
      content: new Uint8Array(row.content as Buffer),
      first_activated_at: row.first_activated_at as string,
      activations: row.activations as number,
      retain_until: new Date(row.retain_until as number).toISOString(),
    };
  }

  /**
   * @spec mission#standing-consent-bases: recompute a committed reference's
   * digest from the snapshot retained under its identity, as an auditor would.
   */
  verify(issuer: string, ref: ActivationPolicyRef): ActivationPolicyCommitmentCheck {
    const snapshot = this.resolve({ issuer, id: ref.id, version: ref.version, digest: ref.digest });
    if (!snapshot) return { status: "unavailable", ref };
    const recomputed = activationPolicyDigest(snapshot.issuer, {
      content_type: snapshot.content_type,
      content: snapshot.content,
    });
    return { status: recomputed === ref.digest ? "verified" : "mismatch", ref, snapshot };
  }

  /** Delete every snapshot whose horizon has passed; returns how many. Nothing else deletes. */
  pruneExpired(): number {
    return this.db
      .prepare("DELETE FROM activation_policy_snapshots WHERE retain_until < ?")
      .run(this.opts.now().getTime()).changes;
  }
}

/**
 * The activation policy reference a Mission record commits for its own
 * activation: a template instance's `template.dispatch_policy`, a
 * policy-adjudicated child's `approval_basis.activation` policy members, a
 * policy-adjudicated Progressive successor's `drawdown_policy`, or a
 * `governed_policy` instance's separate evaluator. Undefined when the record
 * commits none.
 */
export function committedActivationPolicy(record: MissionRecord): ActivationPolicyRef | undefined {
  if (record.template) return record.template.dispatch_policy;
  const basis = record.approval_basis;
  // @spec progressive#in-ceiling-expansion: the activation names the policy's
  // id and version only; the digest is the one `ceiling_hash` commits on the
  // record's own `drawdown_policy`.
  if (basis.type === "ceiling_drawdown") {
    const ref = record.drawdown_policy;
    return ref && ref.id === basis.activation.policy_id && ref.version === basis.activation.policy_version
      ? ref
      : undefined;
  }
  // @spec approval-governance#governed-policy-root: only a separate
  // evaluator is an activation policy. When the root itself decides,
  // `activation.policy.digest` is the root's `mission-approval-policy` digest
  // (`root_commitment`), a different domain this store never verifies.
  if (basis.type === "governed_policy") {
    return basis.activation.policy.digest === basis.root_commitment ? undefined : basis.activation.policy;
  }
  if (basis.type === "policy_drawdown") {
    const { policy_id, policy_version, policy_digest } = basis.activation;
    if (policy_id && policy_version && policy_digest) {
      return { id: policy_id, version: policy_version, digest: policy_digest };
    }
  }
  return undefined;
}
