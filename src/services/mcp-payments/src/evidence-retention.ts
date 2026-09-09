/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#execution-evidence-object
 * (Retention), #receipt-retention, #evidence-integrity-signing-keys; issue
 * #594 (W4-8).
 *
 * The durable half of runtime-evidence retention. {@link EvidenceStore}'s own
 * array answers one process's reads; an audit retention window is a property
 * of the deployment's records, of its per-emitter sequences, and of its
 * published verification keys ACROSS process lifetimes, so all three live here
 * in one SQLite repository (D27, `@mission/store`, `:memory:` unless a
 * deployment names a file).
 *
 * What this owns:
 *
 *  - one immutable row per Decision Evidence, Execution Evidence, Refusal
 *    Record and Mission Receipt, keyed by `(kind, record_id)` because those
 *    identifier namespaces are distinct, carrying the exact retained object,
 *    its complete-object digest, and the instant the declared window releases
 *    it. Eviction inside the window is REFUSED, observably, rather than
 *    silently skipped, and a store at capacity fails closed rather than making
 *    room by dropping a record it still owes an auditor.
 *  - the per-(Mission, emitter, role) `sequence` counter, so a restart
 *    continues an emitter's stream instead of restarting it at zero.
 *  - the deployment's published verification key sets: which location
 *    publishes a `kid`, which emitter, role and audience it authenticates, and
 *    for a retired key the instant it stops being resolvable, measured from
 *    the LAST artifact it signed rather than from its creation or from its
 *    retirement.
 *
 * What this is NOT. It is not an audit service: the only ways out are the
 * resolvers verification already takes. The access-control and
 * encryption-at-rest halves of {{evidence-pii}} are the deployment's own
 * storage mechanism, disclosed here and not exercised: this store holds the
 * PII sink in the clear, and a deployment that needs those properties supplies
 * them at the storage layer. It also publishes nothing over a network: a
 * published key set here is the document at the declared location, resolved
 * in process, not an HTTP discovery surface.
 */

import { KeyObject } from "node:crypto";
import { canonicalDigest, type JsonValue } from "@mission/core";
import { type Database, openStore, type StoreOptions, withTransaction } from "@mission/store";
import {
  type EnforcementScopeStatement,
  retentionWindowSeconds,
} from "@mission/pdp";
import type { JWK } from "jose";
import {
  DECISION_EVIDENCE_MEDIA_TYPE,
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  type EvidenceKeyLike,
  type EvidenceKeyResolver,
  REFUSAL_RECORD_MEDIA_TYPE,
} from "./evidence.js";
import {
  createReceiptIssuerScope,
  type MissionReceiptObject,
  type PublishedReceiptKey,
  type ReceiptIssuerScope,
  type ReceiptPredecessorResolver,
  type ReceiptRecordResolver,
  type ReceiptResolvedRecord,
} from "./mission-receipt.js";
import { CANONICAL_RESOURCE } from "./pep.js";

/** The retained kind each evidence-reference media type names ({{receipt-evidence}}). */
const RETAINED_KIND_FOR_MEDIA_TYPE: Record<string, RetainedEvidenceKind | undefined> = {
  [DECISION_EVIDENCE_MEDIA_TYPE]: "decision",
  [EXECUTION_EVIDENCE_MEDIA_TYPE]: "execution",
  [REFUSAL_RECORD_MEDIA_TYPE]: "refusal",
};

/**
 * This deployment's own evidence key-set location: the identifier its
 * published sets are named by, and the value its Enforcement Scope Statement
 * declares in `signing_key_locations` if and when it claims the evidence
 * capability. Derived from the canonical resource so the location tracks the
 * deployment rather than being a second, independently drifting constant.
 */
export const EVIDENCE_KEY_SET_LOCATION = `${CANONICAL_RESOURCE}/evidence-keys`;

/** The record kinds this store retains; the three record types of the retention floor, plus the receipt that projects them. */
export type RetainedEvidenceKind = "decision" | "execution" | "refusal" | "receipt";

/** The roles a published evidence key may authenticate ({{decision-evidence-integrity}}). */
export type PublishedKeyRole = "pdp" | "pep" | "executor" | "receipt_issuer";

/** One published verification key, as the deployment publishes it. */
export interface PublishEvidenceKeyInput {
  /** The declared key-set location this key is published at. */
  location: string;
  kid: string;
  /** The exact `emitter.id` this key authenticates. */
  emitterId: string;
  role: PublishedKeyRole;
  /** REQUIRED for every enforcement-point role; a receipt issuer's key MAY stay audience-unbound. */
  audience?: string;
  /** The public half: a Node public key or its JWK. Private material is refused. */
  publicKey: unknown;
}

/** One retained row, as recovery and resolution read it back. */
export interface RetainedEvidenceRow {
  kind: RetainedEvidenceKind;
  record_id: string;
  mission_id: string;
  emitter_id: string;
  emitter_role: string;
  signing_kid: string;
  /** The complete-object digest of the retained record, `evidence_envelope` included. */
  digest: string;
  /** The store row as it was retained (for a receipt, the receipt itself). */
  row: JsonValue;
  retained_at: number;
  /** The instant the declared window releases this record; before it, eviction is refused. */
  retain_until: number;
}

export interface RetainEvidenceInput {
  kind: RetainedEvidenceKind;
  record_id: string;
  mission_id: string;
  emitter_id: string;
  emitter_role: string;
  signing_kid: string;
  /** The wrapper this deployment retains (kind, mission, trace, content). */
  row: JsonValue;
  /** The complete signed record inside `row`: what the digest commits to. */
  record: JsonValue;
}

export interface EvidenceRetentionOptions {
  /**
   * Seconds a record is retained: the deployment's declared
   * `extensions.evidence.retention_window` where it claims the evidence
   * capability, and otherwise the Mission audit horizon, which the retention
   * floor puts under both.
   */
  retentionWindowSeconds: number;
  /** Persistence (D27): `:memory:` unless a deployment names a file. */
  store?: StoreOptions;
  /** An already-open database (a test sharing one across a simulated restart supplies the same file instead). */
  db?: Database;
  /** Rows this store has room for. Absent means unbounded. */
  capacity?: number;
  now?: () => Date;
}

export const EVIDENCE_RETENTION_SCHEMA = `
CREATE TABLE IF NOT EXISTS retained_evidence (
  kind TEXT NOT NULL,
  record_id TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  emitter_id TEXT NOT NULL,
  emitter_role TEXT NOT NULL,
  signing_kid TEXT NOT NULL,
  digest TEXT NOT NULL,
  row_json TEXT NOT NULL,
  retained_at INTEGER NOT NULL,
  retain_until INTEGER NOT NULL,
  PRIMARY KEY (kind, record_id)
) STRICT;

CREATE INDEX IF NOT EXISTS retained_evidence_digest ON retained_evidence (digest);
CREATE INDEX IF NOT EXISTS retained_evidence_mission ON retained_evidence (mission_id);

CREATE TABLE IF NOT EXISTS published_evidence_keys (
  location TEXT NOT NULL,
  kid TEXT NOT NULL,
  emitter_id TEXT NOT NULL,
  role TEXT NOT NULL,
  audience TEXT,
  jwk_json TEXT NOT NULL,
  retired_at INTEGER,
  last_signed_at INTEGER,
  PRIMARY KEY (location, kid)
) STRICT;

CREATE TABLE IF NOT EXISTS evidence_sequences (
  scope TEXT PRIMARY KEY,
  next INTEGER NOT NULL
) STRICT;
`;

const positive = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * The JWK the deployment publishes for one key. Private material never
 * reaches a published set: a `d` member is refused here rather than served to
 * every verifier that reads the location.
 */
export function publishedEvidenceJwk(publicKey: unknown, kid: string): JWK {
  const exported =
    publicKey instanceof KeyObject
      ? (publicKey.export({ format: "jwk" }) as JWK)
      : isObject(publicKey) && typeof publicKey.kty === "string"
        ? ({ ...publicKey } as JWK)
        : undefined;
  if (!exported) throw new Error("a published evidence key requires an asymmetric public key or its JWK");
  if (exported.d !== undefined) throw new Error("a published evidence key set must not carry private key material");
  return { ...exported, kid, use: "sig", alg: "ES256" };
}

interface KeyRow {
  location: string;
  kid: string;
  emitter_id: string;
  role: string;
  audience: string | null;
  jwk_json: string;
  retired_at: number | null;
  last_signed_at: number | null;
}

export class EvidenceRetentionStore {
  /** The declared window, in seconds: what `retain_until` and key retirement are both measured with. */
  readonly retentionWindowSeconds: number;
  private readonly db: Database;
  private readonly now: () => Date;
  private readonly capacity: number | undefined;

  constructor(options: EvidenceRetentionOptions) {
    if (!positive(options.retentionWindowSeconds)) {
      throw new Error("EvidenceRetentionStore: retentionWindowSeconds must be a positive integer");
    }
    if (options.capacity !== undefined && !positive(options.capacity)) {
      throw new Error("EvidenceRetentionStore: capacity must be a positive integer when declared");
    }
    this.retentionWindowSeconds = options.retentionWindowSeconds;
    this.capacity = options.capacity;
    this.now = options.now ?? (() => new Date());
    this.db = options.db ?? openStore(EVIDENCE_RETENTION_SCHEMA, options.store);
    // A store handed an already-open database still needs its own tables: a
    // reopen of the same file re-applies the schema idempotently, which is
    // what makes recovery a plain read rather than a migration.
    this.db.exec(EVIDENCE_RETENTION_SCHEMA);
  }

  /** Seconds since the epoch on this store's clock. */
  private seconds(): number {
    return Math.floor(this.now().getTime() / 1000);
  }

  /**
   * @spec runtime-evidence#decision-evidence-object — "each emitter maintains
   * its own monotonically increasing per-Mission sequence." Durable, so a
   * restart continues the stream: an in-process counter would restart every
   * emitter at zero and re-issue sequence numbers already signed into
   * retained records.
   */
  nextSequence(missionId: string, emitterId: string, role: string): number {
    const scope = `${missionId} ${emitterId} ${role}`;
    return withTransaction(this.db, () => {
      const row = this.db.prepare("SELECT next FROM evidence_sequences WHERE scope = ?").get(scope) as
        | { next: number }
        | undefined;
      const next = row?.next ?? 0;
      this.db
        .prepare("INSERT INTO evidence_sequences (scope, next) VALUES (?, ?) ON CONFLICT(scope) DO UPDATE SET next = ?")
        .run(scope, next + 1, next + 1);
      return next;
    });
  }

  /**
   * Retain one record for the declared window. Idempotent on
   * `(kind, record_id)`: re-retaining the same identity returns the row
   * already held rather than a second copy or a replacement, since retention
   * is append-only and the identity is the record's own.
   */
  retain(input: RetainEvidenceInput): RetainedEvidenceRow {
    const retained_at = this.seconds();
    const digest = canonicalDigest(input.record);
    return withTransaction(this.db, () => {
      const held = this.get(input.kind, input.record_id);
      if (held) return held;
      this.reserve(retained_at);
      const row: RetainedEvidenceRow = {
        kind: input.kind,
        record_id: input.record_id,
        mission_id: input.mission_id,
        emitter_id: input.emitter_id,
        emitter_role: input.emitter_role,
        signing_kid: input.signing_kid,
        digest,
        row: input.row,
        retained_at,
        retain_until: retained_at + this.retentionWindowSeconds,
      };
      this.db
        .prepare(
          `INSERT INTO retained_evidence
             (kind, record_id, mission_id, emitter_id, emitter_role, signing_kid, digest, row_json, retained_at, retain_until)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          row.kind,
          row.record_id,
          row.mission_id,
          row.emitter_id,
          row.emitter_role,
          row.signing_kid,
          row.digest,
          JSON.stringify(row.row),
          row.retained_at,
          row.retain_until,
        );
      // The key's retirement anchor is the LAST artifact it signed, so it
      // moves here and never backwards.
      this.db
        .prepare(
          "UPDATE published_evidence_keys SET last_signed_at = MAX(COALESCE(last_signed_at, 0), ?) WHERE kid = ?",
        )
        .run(retained_at, row.signing_kid);
      return row;
    });
  }

  /**
   * @spec runtime-evidence#receipt-retention — "A receipt is retained at least
   * as long as the records it projects." Keyed by its own complete-object
   * digest, which is exactly how a successor's `chain.previous` names it.
   */
  retainReceipt(receipt: MissionReceiptObject, signingKid: string): RetainedEvidenceRow {
    const digest = canonicalDigest(receipt as unknown as JsonValue);
    return this.retain({
      kind: "receipt",
      record_id: digest,
      mission_id: receipt.mission.id,
      emitter_id: receipt.emitter.id,
      emitter_role: receipt.emitter.role,
      signing_kid: signingKid,
      row: receipt as unknown as JsonValue,
      record: receipt as unknown as JsonValue,
    });
  }

  /**
   * Fail closed at capacity. A record already released by the window is
   * pruned to make room; a store whose rows are all still inside the window
   * refuses the write rather than evicting one of them. The caller's own
   * fail-closed path then applies: an unretainable record is not a record
   * that quietly did not happen.
   */
  private reserve(now: number): void {
    if (this.capacity === undefined) return;
    if (this.count() < this.capacity) return;
    this.pruneAt(now);
    if (this.count() >= this.capacity) {
      throw new Error(
        `EvidenceRetentionStore: at capacity (${this.capacity}) with every retained record still inside the ${this.retentionWindowSeconds}s window (fail closed: retention is not made room for by eviction)`,
      );
    }
  }

  private hydrate(raw: unknown): RetainedEvidenceRow {
    const r = raw as Omit<RetainedEvidenceRow, "row"> & { row_json: string };
    return {
      kind: r.kind,
      record_id: r.record_id,
      mission_id: r.mission_id,
      emitter_id: r.emitter_id,
      emitter_role: r.emitter_role,
      signing_kid: r.signing_kid,
      digest: r.digest,
      row: JSON.parse(r.row_json) as JsonValue,
      retained_at: r.retained_at,
      retain_until: r.retain_until,
    };
  }

  get(kind: RetainedEvidenceKind, recordId: string): RetainedEvidenceRow | undefined {
    const raw = this.db
      .prepare("SELECT * FROM retained_evidence WHERE kind = ? AND record_id = ?")
      .get(kind, recordId);
    return raw ? this.hydrate(raw) : undefined;
  }

  /** Resolve a retained record by its complete-object digest (a receipt's `chain.previous`, and a receipt's own evidence references). */
  byDigest(digest: string): RetainedEvidenceRow | undefined {
    const raw = this.db.prepare("SELECT * FROM retained_evidence WHERE digest = ? ORDER BY rowid LIMIT 1").get(digest);
    return raw ? this.hydrate(raw) : undefined;
  }

  /** Every retained row, in retention order: the startup-recovery read. */
  retained(): RetainedEvidenceRow[] {
    return (this.db.prepare("SELECT * FROM retained_evidence ORDER BY rowid").all() as unknown[]).map((raw) =>
      this.hydrate(raw),
    );
  }

  forMission(missionId: string): RetainedEvidenceRow[] {
    return (
      this.db.prepare("SELECT * FROM retained_evidence WHERE mission_id = ? ORDER BY rowid").all(missionId) as unknown[]
    ).map((raw) => this.hydrate(raw));
  }

  count(): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM retained_evidence").get() as { n: number }).n;
  }

  /** Delete only what the window has released; returns the number released. */
  prune(): number {
    return this.pruneAt(this.seconds());
  }

  private pruneAt(now: number): number {
    return this.db.prepare("DELETE FROM retained_evidence WHERE retain_until <= ?").run(now).changes;
  }

  /**
   * @spec runtime-evidence#execution-evidence-object (Retention) — an
   * eviction attempt inside the window is refused, not ignored: the caller
   * learns that the record is still owed rather than believing a deletion it
   * asked for happened.
   */
  evict(kind: RetainedEvidenceKind, recordId: string): void {
    const held = this.get(kind, recordId);
    if (!held) return;
    const now = this.seconds();
    if (held.retain_until > now) {
      throw new Error(
        `EvidenceRetentionStore: ${kind} record "${recordId}" is retained until ${held.retain_until} and cannot be evicted at ${now} (audit retention window)`,
      );
    }
    this.db.prepare("DELETE FROM retained_evidence WHERE kind = ? AND record_id = ?").run(kind, recordId);
  }

  /** Publish one verification key at a declared key-set location. */
  publishKey(input: PublishEvidenceKeyInput): void {
    if (input.role !== "receipt_issuer" && !input.audience) {
      throw new Error(`a published ${input.role} key requires the audience it is published for`);
    }
    const jwk = publishedEvidenceJwk(input.publicKey, input.kid);
    this.db
      .prepare(
        `INSERT INTO published_evidence_keys (location, kid, emitter_id, role, audience, jwk_json, retired_at, last_signed_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
         ON CONFLICT(location, kid) DO UPDATE SET emitter_id = excluded.emitter_id, role = excluded.role,
           audience = excluded.audience, jwk_json = excluded.jwk_json`,
      )
      .run(input.location, input.kid, input.emitterId, input.role, input.audience ?? null, JSON.stringify(jwk));
  }

  /**
   * Retire a key: it signs nothing further and stays resolvable in the
   * published set for the retention window past the LAST artifact it signed
   * ({{evidence-integrity-signing-keys}}). Measuring from retirement, or from
   * the key's creation, would strand records the key signed shortly before it
   * was retired.
   */
  retireKey(kid: string, location?: string): void {
    const at = this.seconds();
    if (location === undefined) {
      this.db.prepare("UPDATE published_evidence_keys SET retired_at = ? WHERE kid = ? AND retired_at IS NULL").run(at, kid);
    } else {
      this.db
        .prepare("UPDATE published_evidence_keys SET retired_at = ? WHERE kid = ? AND location = ? AND retired_at IS NULL")
        .run(at, kid, location);
    }
  }

  /** The instant a retired key stops being resolvable, or `undefined` while it is still active. */
  keyResolvableUntil(kid: string, location = EVIDENCE_KEY_SET_LOCATION): number | undefined {
    const row = this.keyRow(location, kid);
    if (!row || row.retired_at === null) return undefined;
    return (row.last_signed_at ?? row.retired_at) + this.retentionWindowSeconds;
  }

  private keyRow(location: string, kid: string): KeyRow | undefined {
    return this.db.prepare("SELECT * FROM published_evidence_keys WHERE location = ? AND kid = ?").get(location, kid) as
      | KeyRow
      | undefined;
  }

  private resolvable(row: KeyRow, now: number): boolean {
    if (row.retired_at === null) return true;
    return now <= (row.last_signed_at ?? row.retired_at) + this.retentionWindowSeconds;
  }

  /** The key-set locations this deployment publishes at. */
  locations(): string[] {
    return (this.db.prepare("SELECT DISTINCT location FROM published_evidence_keys").all() as { location: string }[]).map(
      (r) => r.location,
    );
  }

  /**
   * The published document at one location: the key sets a verifier reads a
   * `kid` out of. An active key is in it; a retired key stays in it for the
   * retention window past its last artifact and then leaves it.
   */
  publishedKeySet(location: string): { keys: JWK[] } {
    const now = this.seconds();
    const rows = this.db
      .prepare("SELECT * FROM published_evidence_keys WHERE location = ? ORDER BY kid")
      .all(location) as KeyRow[];
    return {
      keys: rows.filter((row) => this.resolvable(row, now)).map((row) => JSON.parse(row.jwk_json) as JWK),
    };
  }

  /**
   * The resolvable keys at one location, in the shape a receipt-issuer scope
   * takes ({@link createReceiptIssuerScope} keeps only the `receipt_issuer`
   * entries bound to each designated emitter).
   */
  publishedVerificationKeys(location: string): PublishedReceiptKey[] {
    const now = this.seconds();
    const rows = this.db
      .prepare("SELECT * FROM published_evidence_keys WHERE location = ? ORDER BY kid")
      .all(location) as KeyRow[];
    const keys: PublishedReceiptKey[] = [];
    for (const row of rows) {
      if (!this.resolvable(row, now)) continue;
      const publicKey = JSON.parse(row.jwk_json) as EvidenceKeyLike;
      if (row.role === "receipt_issuer") {
        keys.push({
          kid: row.kid,
          publicKey,
          role: "receipt_issuer",
          emitterId: row.emitter_id,
          ...(row.audience !== null ? { audience: row.audience } : {}),
        });
      } else if (row.audience !== null && (row.role === "pdp" || row.role === "pep" || row.role === "executor")) {
        keys.push({ kid: row.kid, publicKey, role: row.role, emitterId: row.emitter_id, audience: row.audience });
      }
    }
    return keys;
  }

  /**
   * @spec runtime-evidence#evidence-integrity-signing-keys — resolution goes
   * declared location, then the published document at it, then the `kid` in
   * that document, then the binding that document's publisher registered for
   * it. A `kid` the document no longer carries (a retired key past its
   * window) resolves to nothing even though the deployment still remembers
   * it, and a `kid` at a location the statement does not declare is not
   * reachable at all.
   *
   * The binding rules are {@link buildEvidenceKeyResolver}'s: exact `kid`,
   * `emitter.id` and `role`, plus an exact `audience` for every enforcement
   * role. Only a `receipt_issuer` key may stay audience-unbound.
   */
  resolver(options: { locations?: readonly string[] } = {}): EvidenceKeyResolver {
    return ({ kid, emitter, audience }) => {
      for (const location of options.locations ?? this.locations()) {
        const published = this.publishedKeySet(location).keys.find((key) => key.kid === kid);
        if (!published) continue;
        const binding = this.keyRow(location, kid);
        if (!binding || binding.emitter_id !== emitter.id || binding.role !== emitter.role) continue;
        if (binding.role === "receipt_issuer") {
          if (binding.audience !== null && binding.audience !== audience) continue;
        } else if (binding.audience === null || binding.audience !== audience) {
          continue;
        }
        return { key: published as EvidenceKeyLike };
      }
      return undefined;
    };
  }

  /**
   * @spec runtime-evidence#receipt-verification step 3, #receipt-retention —
   * resolve one of a receipt's evidence references out of retained storage.
   * Both the reference's digest and its `evidence_id` must name the retained
   * record: a digest collision on one of them is not a resolution.
   */
  recordResolver(): ReceiptRecordResolver {
    return (ref) => {
      const kind = RETAINED_KIND_FOR_MEDIA_TYPE[ref.type];
      if (kind === undefined) return undefined;
      const held = this.byDigest(ref.digest);
      if (!held || held.kind !== kind || held.record_id !== ref.evidence_id) return undefined;
      const content = (held.row as { content?: unknown }).content;
      return content === undefined ? undefined : ({ type: kind, record: content } as ReceiptResolvedRecord);
    };
  }

  /**
   * @spec runtime-evidence#receipt-chaining, #receipt-retention — resolve a
   * chain predecessor by the complete-object digest its successor committed
   * to. A predecessor already released by the window resolves to nothing, and
   * chain verification then fails rather than treating it as absent.
   */
  receiptResolver(): ReceiptPredecessorResolver {
    return (digest) => {
      const held = this.get("receipt", digest);
      return held ? (held.row as unknown as MissionReceiptObject) : undefined;
    };
  }

  close(): void {
    this.db.close();
  }
}

/**
 * @spec runtime#runtime-conformance, runtime-evidence#receipt-verification —
 * the deployment's OWN receipt-issuer scope: its published key sets, at the
 * locations its own Enforcement Scope Statement declares, for the issuers that
 * statement designates.
 *
 * `undefined` when the statement claims no evidence capability or designates
 * no receipt issuer, which is the fail-closed answer rather than an error: a
 * deployment that claims nothing designates nobody, so receipt verification is
 * unreachable for it. A statement that DOES claim the capability but declares
 * it incoherently throws, from {@link createReceiptIssuerScope}.
 */
export function deploymentReceiptIssuerScope(
  statement: unknown,
  retention: EvidenceRetentionStore,
): ReceiptIssuerScope | undefined {
  if (!isObject(statement)) return undefined;
  const declaring = statement as unknown as EnforcementScopeStatement;
  const declaration = declaring.extensions?.evidence;
  if (!declaring.claims?.includes("evidence") || !declaration?.receipt_issuers?.length) return undefined;
  const published = new Map<string, readonly PublishedReceiptKey[]>();
  for (const location of declaration.signing_key_locations ?? []) {
    published.set(location, retention.publishedVerificationKeys(location));
  }
  return createReceiptIssuerScope(declaring, published);
}

/**
 * The retention window this deployment runs with: its declared
 * `extensions.evidence.retention_window` where it claims the evidence
 * capability, and otherwise the Mission audit horizon. The retention floor
 * binds every runtime-enforced deployment, claim or no claim, so an
 * unclaiming deployment retains for the horizon rather than for nothing
 * (@spec runtime-evidence#execution-evidence-object).
 */
export function deploymentRetentionWindowSeconds(statement: unknown, auditHorizonSeconds: number): number {
  const declared = isObject(statement)
    ? retentionWindowSeconds((statement as unknown as EnforcementScopeStatement).extensions?.evidence?.retention_window)
    : undefined;
  return Math.max(declared ?? 0, auditHorizonSeconds);
}
