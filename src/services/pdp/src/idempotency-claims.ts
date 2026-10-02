/**
 * @spec runtime#idempotency, authzen#parameter-digest (#917, D223): the
 * PDP-owned Exact idempotency claim domain: local, durable, single writer.
 *
 * "Before issuing a permit for a keyed action in the irreversible-action,
 * external-commitment, or privileged-administration classes, the PDP MUST
 * atomically claim the pair (idempotency scope, `idempotency_key`) together
 * with the request's operation identity". This module is that claim: one
 * SQLite file named in configuration, opened by exactly one PDP process
 * (`locking_mode=EXCLUSIVE`), so the Exact enforcement profile holds by the
 * "single serializing PDP" construction. Nothing here is in memory only: a
 * file that cannot be opened safely refuses the PDP at startup, and a domain
 * that becomes unreachable throws, so the PDP issues no decision at all
 * rather than a permit without the claim.
 *
 * D28 keeps execution-side ownership. The PDP never redeems a permit, holds
 * no execution lease and owns no effect: the PEP's single-use redemption
 * store stays where it is. Under the owner's 2026-10-02 ruling the PDP is
 * told what happened: authenticated, PEP-signed Execution Evidence settles a
 * claim (`settle`), the declared reconciler resolves what never settled
 * (`listUnresolved`, `reconcile`), and a retransmission additionally needs
 * the PEP's explicit `unconsumed` answer for the stored `evaluation_id`.
 * Unknown always suppresses: no state here is ever inferred unused from
 * silence.
 *
 * States: `claimed` (inserted when a request would otherwise permit, the
 * linearization point), `permit_issued` (the full decision persisted before
 * it is returned), `unresolved`, and the terminal `completed`, `failed` and
 * `indeterminate`. `tombstoned` is not a state: it is a terminal row whose
 * stored decision was compacted away after the reconciliation window, with
 * its commitments kept and its refusal unchanged.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  canonicalIdempotencyScope,
  canonicalize,
  IDEMPOTENCY_SCOPE_DIMENSIONS,
  type IdempotencyScope,
  isScopeDimension,
  isVolatileScopeMember,
} from "@mission/core";
import { type Database, DurableStoreError, openDurableStore, withTransaction } from "@mission/store";
import {
  type EnforcementScopeStatement,
  retentionWindowSeconds,
  type TransactionAssuranceDeclaration,
  validateEnforcementScopeStatement,
} from "./enforcement-scope.js";
import type { Decision } from "./evaluate.js";
import {
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  type EvidenceKeyResolver,
  verifyEvidenceEnvelope,
} from "./runtime-evidence-integrity.js";

/**
 * @spec runtime#classification: the three high-consequence classes, the
 * only classes whose keyed actions the PDP claims.
 */
export const CLAIMED_ACTION_CLASSES = ["irreversible_action", "external_commitment", "privileged_administration"] as const;

/** The one topology this domain implements: one PDP process, one file. */
export const LOCAL_SINGLE_WRITER = "local-single-writer";

export type ClaimState = "claimed" | "permit_issued" | "unresolved" | "completed" | "failed" | "indeterminate";

/**
 * The authenticated party a decision was issued to: the PEP's registered
 * identity and the epoch of its redemption store. Bound by the decision
 * channel (co-resident: the trusted assembly; remote: the per-PEP MAC and a
 * MAC-covered epoch header), never by a member of the evaluation request.
 */
export interface ClaimRequester {
  pep_id: string;
  pep_epoch: string;
}

/**
 * @spec runtime#idempotency, retransmission condition 6: the PEP's answer
 * from its D28 redemption store for one `evaluation_id`. `unknown` covers a
 * store of another epoch, which cannot speak for redemptions it never held.
 */
export type ConsumptionStatus = "unconsumed" | "consumed" | "unknown";

/** Read-only; answered by the PEP, asked by the PDP only for a retransmission candidate. */
export type ConsumptionStatusFn = (
  evaluationId: string,
  pepEpoch: string,
) => ConsumptionStatus | Promise<ConsumptionStatus>;

/** A startup refusal: the configured domain is not one this PDP can run as Exact. */
export class ClaimDomainConfigError extends Error {
  constructor(why: string) {
    super(`idempotency claim domain refused: ${why}`);
    this.name = "ClaimDomainConfigError";
  }
}

/**
 * The domain cannot be reached (closed, locked, or failing). The PDP issues
 * no decision on it: co-resident, the decision call throws; remote, the
 * channel answers 503. Either way the PEP records `pdp_unreachable` and
 * nothing executes (@spec runtime#idempotency: "MUST fail closed rather than
 * issue a permit").
 */
export class ClaimDomainUnavailableError extends Error {
  constructor(cause: unknown) {
    super(`idempotency claim domain unavailable: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "ClaimDomainUnavailableError";
  }
}

export interface ClaimDomainOptions {
  /** The durable file, from configuration (`topology.json` `stores.pdpIdempotencyClaims.file`). */
  file: string | undefined;
  /** This PDP's identity: the ESS `idempotency_claim_owner` and its only `pdps` entry. */
  owner: string;
  /** The deployment's Enforcement Scope Statement; the domain is read from it, never from a request. */
  statement: EnforcementScopeStatement;
  /** The domain's clock for sweeps, settlement and reconciliation. Decisions pass their own instant. */
  now?: () => Date;
  /**
   * The executing PEP's PUBLISHED Execution Evidence keys. Settlement is
   * accepted only from a record that verifies under them; absent, nothing
   * settles and every unsettled claim stays suppressed.
   */
  settlementKeys?: EvidenceKeyResolver;
  /** Bound on a consumption-status query; expiry is `unknown`. Default 1000 ms. */
  consumptionStatusTimeoutMs?: number;
}

interface ClassDomain {
  actionClass: string;
  horizonMs: number;
  leaseMaxMs: number;
}

interface ClaimRow {
  scope_digest: string;
  idempotency_key: string;
  scope_json: string;
  action_class: string;
  operation_identity: string;
  cache_key: string;
  evaluation_id: string;
  pdp_boot: string;
  pep_id: string;
  pep_epoch: string;
  state: ClaimState;
  valid_until_ms: number;
  decision_json: string | null;
  execution_id: string | null;
  outcome: string | null;
  outcome_ref: string | null;
  claimed_at_ms: number;
  terminal_at_ms: number | null;
  retain_until_ms: number | null;
}

export interface ClaimInput {
  actionClass: string;
  scope: IdempotencyScope;
  scopeDigest: string;
  key: string;
  operationIdentity: string;
  cacheKey: string;
  evaluationId: string;
  validUntilMs: number;
  requester: ClaimRequester;
  /**
   * The decision's clock, epoch milliseconds. Read inside each transaction
   * that decides, once, and that one reading serves both state advancement
   * and the expiry comparison: a reading taken before an await (the
   * consumption-status query) is never the one a decision rests on.
   */
  clock: () => number;
}

/** What the claim step tells the decision it is part of. */
export type ClaimOutcome =
  /** This evaluation holds the claim: it persists its permit, or releases on abort. */
  | { kind: "claimed"; ticket: ClaimTicket }
  /** Same key, different operation identity: terminal in every state. */
  | { kind: "conflict" }
  /** Same key and identity, and no permit may issue. */
  | { kind: "suppressed"; state: ClaimState; transient: boolean; retryAfterSeconds?: number }
  /** Conditions 1 to 5 of a retransmission hold; condition 6 is asked next. */
  | { kind: "retransmission_candidate"; evaluationId: string; pepEpoch: string };

export interface ClaimTicket {
  readonly evaluationId: string;
  /** Persist the full decision, signed Decision Evidence included, BEFORE it is returned. */
  persist(decision: Decision): void;
  /** The evaluation ended without returning its permit: the row is adoptable. */
  release(): void;
}

export type SettlementResult =
  | { accepted: true; state: "completed" | "failed"; duplicate: boolean }
  | { accepted: false; reason: string };

/** A claim the declared reconciler is asked to resolve. */
export interface UnresolvedClaim {
  evaluation_id: string;
  action_class: string;
  valid_until: string;
  window_closes_at: string;
}

/** How the reconciler resolves an unresolved claim. */
export type ClaimResolution =
  /** The redeeming attempt's PEP-signed Execution Evidence, exactly as settlement takes it. */
  | { kind: "execution_evidence"; record: unknown }
  /**
   * Proof of no effect from the redemption owner: in the same epoch, no
   * redemption of the `evaluation_id`, asserted once the permit and its
   * longest lease have both elapsed, over the authenticated channel.
   */
  | { kind: "unredeemed" };

/**
 * An Execution Evidence `error` that by definition marks an attempt which
 * never held the redemption: a re-presentation of an evaluation identifier
 * already consumed. Such a record is not a settlement, since the redeeming
 * attempt may still be completing. (`operation_already_claimed` and
 * `operation_identity_conflict` are not listed: the executing PEP also
 * records them after a redemption it did hold, and only redeeming attempts
 * settle at all.)
 */
const NON_REDEEMING_ERRORS = new Set(["permit_consumed"]);

const MIGRATIONS = [
  `CREATE TABLE claims (
    scope_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    action_class TEXT NOT NULL,
    operation_identity TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    evaluation_id TEXT NOT NULL UNIQUE,
    pdp_boot TEXT NOT NULL,
    pep_id TEXT NOT NULL,
    pep_epoch TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('claimed', 'permit_issued', 'unresolved', 'completed', 'failed', 'indeterminate')),
    valid_until_ms INTEGER NOT NULL,
    decision_json TEXT,
    execution_id TEXT,
    outcome TEXT,
    outcome_ref TEXT,
    claimed_at_ms INTEGER NOT NULL,
    terminal_at_ms INTEGER,
    retain_until_ms INTEGER,
    PRIMARY KEY (scope_digest, idempotency_key)
  ) STRICT;
  CREATE TABLE claim_transitions (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    evaluation_id TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    cause TEXT NOT NULL,
    at_ms INTEGER NOT NULL
  ) STRICT;`,
];

const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * The startup checks on the statement, all refusals fatal. One owner, which
 * is the only PDP the statement declares: two PDP processes holding private
 * files under identical configuration are unobservable from either one, so
 * the statement may not describe that topology at all. Each mediated
 * high-consequence class names its domain (per class, never per key) under
 * the Exact profile, the supported topology, a scope holding every required
 * dimension and nothing volatile, and a horizon; and the reconciliation
 * window the transient and indeterminate transitions run on is declared.
 */
function readClassDomains(statement: EnforcementScopeStatement, owner: string): { classes: Map<string, ClassDomain>; windowMs: number } {
  const findings = validateEnforcementScopeStatement(statement);
  if (findings.length) throw new ClaimDomainConfigError(JSON.stringify(findings));
  const pdps = statement.pdps;
  if (pdps.length !== 1 || pdps[0] !== owner) {
    throw new ClaimDomainConfigError(`the claim owner ${owner} must be the statement's only PDP (declared: ${pdps.join(", ")})`);
  }
  const reconciliation = statement.extensions?.outcome_reconciliation;
  const windowSeconds = object(reconciliation) ? retentionWindowSeconds(reconciliation.window) : undefined;
  if (windowSeconds === undefined) {
    throw new ClaimDomainConfigError("no outcome_reconciliation window is declared for unresolved claims");
  }
  const declarations = statement.extensions?.transaction_assurance ?? [];
  const classes = new Map<string, ClassDomain>();
  for (const decl of declarations) {
    if (!(CLAIMED_ACTION_CLASSES as readonly string[]).includes(decl.mediated_class_or_scope)) continue;
    classes.set(decl.mediated_class_or_scope, readClassDomain(decl, owner));
  }
  for (const actionClass of CLAIMED_ACTION_CLASSES) {
    if (statement.mediated_scope.action_classes.includes(actionClass) && !classes.has(actionClass)) {
      throw new ClaimDomainConfigError(`mediated class ${actionClass} names no Exact claim domain`);
    }
  }
  return { classes, windowMs: windowSeconds * 1000 };
}

function readClassDomain(decl: TransactionAssuranceDeclaration, owner: string): ClassDomain {
  const name = decl.mediated_class_or_scope;
  if (decl.idempotency_claim_owner !== owner) {
    throw new ClaimDomainConfigError(`${name}: claim owner ${String(decl.idempotency_claim_owner)} is not this PDP (${owner})`);
  }
  if (decl.idempotency_enforcement_profile !== "exact") {
    throw new ClaimDomainConfigError(
      `${name}: the idempotency claim runs under the Exact profile only, not ${String(decl.idempotency_enforcement_profile)}`,
    );
  }
  if (decl.idempotency_claim_topology !== LOCAL_SINGLE_WRITER) {
    throw new ClaimDomainConfigError(`${name}: unsupported claim topology ${String(decl.idempotency_claim_topology)}`);
  }
  const scope = decl.idempotency_scope ?? [];
  for (const member of scope) {
    if (isVolatileScopeMember(member)) throw new ClaimDomainConfigError(`${name}: volatile member ${member} in the idempotency scope`);
    if (!isScopeDimension(member)) throw new ClaimDomainConfigError(`${name}: unknown idempotency scope dimension ${member}`);
  }
  for (const dimension of IDEMPOTENCY_SCOPE_DIMENSIONS) {
    if (!scope.includes(dimension)) throw new ClaimDomainConfigError(`${name}: the idempotency scope omits ${dimension}`);
  }
  const horizon = decl.idempotency_horizon_seconds;
  if (typeof horizon !== "number" || !Number.isSafeInteger(horizon) || horizon <= 0) {
    throw new ClaimDomainConfigError(`${name}: no idempotency horizon is declared`);
  }
  return { actionClass: name, horizonMs: horizon * 1000, leaseMaxMs: decl.execution_lease_max_seconds * 1000 };
}

/**
 * Open the claim domain. Every refusal is fatal: an absent, empty or
 * in-memory file, a file another handle or process holds, a newer schema, a
 * file recorded for another owner, or a statement this domain cannot run.
 * The recovery sweep runs before the domain is returned, so no decision is
 * ever taken against a prior boot's unswept state.
 */
export function openIdempotencyClaimDomain(options: ClaimDomainOptions): IdempotencyClaimDomain {
  const { classes, windowMs } = readClassDomains(options.statement, options.owner);
  let db: Database;
  try {
    db = openDurableStore({ file: options.file, migrations: MIGRATIONS, owner: options.owner });
  } catch (e) {
    if (e instanceof DurableStoreError) throw new ClaimDomainConfigError(e.message);
    throw e;
  }
  const domain = new IdempotencyClaimDomain(db, classes, windowMs, options);
  domain.sweep();
  return domain;
}

/**
 * A claim domain on a fresh file in a new temporary directory, for a demo,
 * eval, or test process with no configured store of its own: the claim
 * counterpart of an ephemeral evidence key. It is the same durable,
 * single-writer domain on a real file, never `:memory:`; what it lacks is a
 * file that outlives the process, so a deployment configures its own
 * (`topology.json` `stores.pdpIdempotencyClaims.file`) and never this.
 */
export function openEphemeralClaimDomain(
  options: Omit<ClaimDomainOptions, "file"> & { directory?: string },
): IdempotencyClaimDomain {
  const directory = mkdtempSync(join(options.directory ?? tmpdir(), "pdp-claims-"));
  return openIdempotencyClaimDomain({ ...options, file: join(directory, "claims.sqlite") });
}

export class IdempotencyClaimDomain {
  /** This process's boot of the domain: a row claimed under another boot issued no permit from here. */
  readonly boot = randomUUID();
  private readonly inFlight = new Set<string>();
  private readonly now: () => Date;
  private closed = false;

  constructor(
    private readonly db: Database,
    private readonly classes: ReadonlyMap<string, ClassDomain>,
    private readonly windowMs: number,
    private readonly options: ClaimDomainOptions,
  ) {
    this.now = options.now ?? (() => new Date());
  }

  /** Whether the statement names a claim domain for this class. */
  declares(actionClass: string | undefined): boolean {
    return actionClass !== undefined && this.classes.has(actionClass);
  }

  /** Release the file. A closed domain is unreachable: every later call throws. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.db.close();
  }

  /**
   * The claim step, taken when a request would otherwise permit. One
   * transaction: look the pair up, apply what time alone has decided, then
   * either insert the claim (the linearization point) or resolve against the
   * row found. The whole lookup-and-insert runs with no await inside it, so
   * of two concurrent requests for one pair exactly one inserts and the other
   * observes the claim.
   */
  async claim(input: ClaimInput): Promise<ClaimOutcome> {
    return this.tx(() => this.claimNow(input));
  }

  private claimNow(input: ClaimInput): ClaimOutcome {
    // One clock reading, inside the transaction, for every decision below.
    const nowMs = input.clock();
    const found = this.select(input.scopeDigest, input.key);
    const row = found ? this.advance(found, nowMs) : undefined;
    if (!row) {
      this.insert(input, nowMs);
      return { kind: "claimed", ticket: this.ticket(input.evaluationId) };
    }
    if (row.operation_identity !== input.operationIdentity) return { kind: "conflict" };
    switch (row.state) {
      case "claimed":
        // Adoptable only with proof no permit left this PDP: no decision was
        // ever persisted, and no evaluation in this boot is still holding it.
        if (row.decision_json === null && (row.pdp_boot !== this.boot || !this.inFlight.has(row.evaluation_id))) {
          this.adopt(row, input, nowMs);
          return { kind: "claimed", ticket: this.ticket(input.evaluationId) };
        }
        return { kind: "suppressed", state: "claimed", transient: true, retryAfterSeconds: 1 };
      case "permit_issued":
        if (
          row.execution_id === null &&
          row.cache_key === input.cacheKey &&
          nowMs < row.valid_until_ms &&
          row.pep_id === input.requester.pep_id &&
          row.pep_epoch === input.requester.pep_epoch &&
          row.decision_json !== null
        ) {
          return { kind: "retransmission_candidate", evaluationId: row.evaluation_id, pepEpoch: row.pep_epoch };
        }
        return { kind: "suppressed", state: "permit_issued", transient: true, retryAfterSeconds: 1 };
      case "unresolved":
        return {
          kind: "suppressed",
          state: "unresolved",
          transient: true,
          retryAfterSeconds: Math.max(1, Math.ceil((this.windowCloseMs(row) - nowMs) / 1000)),
        };
      default:
        // completed, failed, indeterminate: terminal. A failed key is retried
        // as a NEW operation under a new key (deployment policy).
        return { kind: "suppressed", state: row.state, transient: false };
    }
  }

  /**
   * Retransmission condition 6, then a recheck of 1 to 5 against the row as
   * it stands after the query: a settlement, a sweep or the clock may have
   * moved it while the PEP was answering, so the recheck reads the clock
   * again, inside its transaction, after the await. Returns the stored decision byte for byte,
   * or `undefined` to suppress. The stored Decision Evidence is returned
   * with it and never re-emitted: a second emission would be a second signed
   * record for one `evaluation_id`.
   */
  async retransmit(
    input: ClaimInput,
    candidate: { evaluationId: string; pepEpoch: string },
    consumptionStatus: ConsumptionStatusFn | undefined,
  ): Promise<Decision | undefined> {
    const status = await this.askConsumption(candidate, consumptionStatus);
    if (status !== "unconsumed") return undefined;
    return this.tx(() => {
      const nowMs = input.clock();
      const found = this.select(input.scopeDigest, input.key);
      const row = found ? this.advance(found, nowMs) : undefined;
      if (
        !row ||
        row.state !== "permit_issued" ||
        row.evaluation_id !== candidate.evaluationId ||
        row.execution_id !== null ||
        row.operation_identity !== input.operationIdentity ||
        row.cache_key !== input.cacheKey ||
        nowMs >= row.valid_until_ms ||
        row.pep_id !== input.requester.pep_id ||
        row.pep_epoch !== input.requester.pep_epoch ||
        row.decision_json === null
      ) {
        return undefined;
      }
      this.log(row, row.state, row.state, "retransmitted", nowMs);
      return JSON.parse(row.decision_json) as Decision;
    });
  }

  private async askConsumption(
    candidate: { evaluationId: string; pepEpoch: string },
    consumptionStatus: ConsumptionStatusFn | undefined,
  ): Promise<ConsumptionStatus> {
    if (!consumptionStatus) return "unknown";
    const timeoutMs = this.options.consumptionStatusTimeoutMs ?? 1000;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const answer = await Promise.race([
        Promise.resolve(consumptionStatus(candidate.evaluationId, candidate.pepEpoch)),
        new Promise<ConsumptionStatus>((resolve) => {
          timer = setTimeout(() => resolve("unknown"), timeoutMs);
        }),
      ]);
      return answer === "unconsumed" || answer === "consumed" ? answer : "unknown";
    } catch {
      return "unknown";
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * @spec runtime-evidence#execution-evidence-object (owner ruling,
   * 2026-10-02): accept the redeeming attempt's PEP-signed Execution
   * Evidence as the outcome of the claim its `evaluation_id` names.
   * Authenticated (it verifies under the PEP's published key), bound (only
   * the PEP the permit was issued to settles it), and idempotent on
   * `execution_id`: a resent record is acknowledged, never applied twice.
   */
  async settle(requester: ClaimRequester, record: unknown): Promise<SettlementResult> {
    const keys = this.options.settlementKeys;
    if (!keys) return { accepted: false, reason: "no_verification_keys" };
    const verified = await verifyEvidenceEnvelope(record, EXECUTION_EVIDENCE_MEDIA_TYPE, keys);
    if (!verified.valid) return { accepted: false, reason: verified.reason };
    const content = record as Record<string, unknown>;
    const emitter = content.emitter as { role?: unknown } | undefined;
    if (emitter?.role !== "executor" && emitter?.role !== "pep") return { accepted: false, reason: "not_an_execution_record" };
    const evaluationId = content.evaluation_id;
    const executionId = content.execution_id;
    const outcome = content.outcome;
    if (typeof evaluationId !== "string" || typeof executionId !== "string") return { accepted: false, reason: "malformed_record" };
    let next: "completed" | "failed";
    if (outcome === "completed") next = "completed";
    else if (outcome === "failed") next = "failed";
    else if (outcome === "suppressed" && !NON_REDEEMING_ERRORS.has(String(content.error))) next = "failed";
    else return { accepted: false, reason: "not_a_settling_outcome" };
    const outcomeRef = typeof content.evidence_id === "string" ? content.evidence_id : executionId;
    return this.tx(() => this.applySettlement(requester, evaluationId, executionId, next, String(outcome), outcomeRef, "settled"));
  }

  private applySettlement(
    requester: ClaimRequester,
    evaluationId: string,
    executionId: string,
    next: "completed" | "failed",
    outcome: string,
    outcomeRef: string,
    cause: string,
  ): SettlementResult {
    const nowMs = this.now().getTime();
    const found = this.db.prepare("SELECT * FROM claims WHERE evaluation_id = ?").get(evaluationId) as ClaimRow | undefined;
    const row = found ? this.advance(found, nowMs) : undefined;
    if (!row) return { accepted: false, reason: "unknown_evaluation" };
    if (row.pep_id !== requester.pep_id) return { accepted: false, reason: "not_the_permit_holder" };
    if (row.execution_id !== null) {
      return row.execution_id === executionId && (row.state === "completed" || row.state === "failed")
        ? { accepted: true, state: row.state, duplicate: true }
        : { accepted: false, reason: "already_settled" };
    }
    if (row.state !== "permit_issued" && row.state !== "unresolved") return { accepted: false, reason: `not_settleable_${row.state}` };
    const horizonMs = this.classes.get(row.action_class)?.horizonMs;
    if (horizonMs === undefined) return { accepted: false, reason: "undeclared_class" };
    this.db
      .prepare(
        `UPDATE claims SET state = ?, execution_id = ?, outcome = ?, outcome_ref = ?, terminal_at_ms = ?, retain_until_ms = ?
         WHERE evaluation_id = ?`,
      )
      .run(next, executionId, outcome, outcomeRef, nowMs, nowMs + horizonMs, evaluationId);
    this.log(row, row.state, next, cause, nowMs);
    return { accepted: true, state: next, duplicate: false };
  }

  /**
   * The unresolved claims of one PEP epoch, for the declared reconciler
   * (`outcome_reconciliation.responsible_component`). A permit still inside
   * its validity and lease is not listed: it may still be redeemed.
   */
  listUnresolved(requester: ClaimRequester): UnresolvedClaim[] {
    return this.tx(() => {
      this.sweepNow(this.now().getTime());
      const rows = this.db
        .prepare("SELECT * FROM claims WHERE state = 'unresolved' AND pep_id = ? AND pep_epoch = ? ORDER BY claimed_at_ms")
        .all(requester.pep_id, requester.pep_epoch) as ClaimRow[];
      return rows.map((row) => ({
        evaluation_id: row.evaluation_id,
        action_class: row.action_class,
        valid_until: new Date(row.valid_until_ms).toISOString(),
        window_closes_at: new Date(this.windowCloseMs(row)).toISOString(),
      }));
    });
  }

  /**
   * Resolve one unresolved claim: from the redeeming attempt's evidence
   * (exactly the settlement path), or from the redemption owner's proof of
   * no effect, which holds only within the epoch the permit was issued to
   * and only once the permit and its longest lease have both elapsed.
   */
  async reconcile(requester: ClaimRequester, evaluationId: string, resolution: ClaimResolution): Promise<SettlementResult> {
    if (resolution.kind === "execution_evidence") {
      const content = object(resolution.record) ? resolution.record : undefined;
      if (content?.evaluation_id !== evaluationId) return { accepted: false, reason: "evaluation_mismatch" };
      return this.settle(requester, resolution.record);
    }
    return this.tx(() => {
      const nowMs = this.now().getTime();
      const found = this.db.prepare("SELECT * FROM claims WHERE evaluation_id = ?").get(evaluationId) as ClaimRow | undefined;
      const row = found ? this.advance(found, nowMs) : undefined;
      if (!row) return { accepted: false, reason: "unknown_evaluation" };
      if (row.state !== "unresolved") return { accepted: false, reason: `not_unresolved_${row.state}` };
      if (row.pep_id !== requester.pep_id || row.pep_epoch !== requester.pep_epoch) {
        return { accepted: false, reason: "other_epoch" };
      }
      if (nowMs <= row.valid_until_ms + this.leaseMaxMs(row)) return { accepted: false, reason: "lease_not_elapsed" };
      return this.applySettlement(requester, evaluationId, `unredeemed:${evaluationId}`, "failed", "unredeemed", "unredeemed-in-epoch", "reconciled");
    });
  }

  /**
   * The recovery sweep: run at open and before every listing. A prior
   * boot's permit is unknown (never inferred unused); an elapsed permit is
   * unresolved; an unresolved claim closes indeterminate at its window's
   * end; terminal rows compact past the window; completed and failed rows
   * are purged past their horizon. Indeterminate rows carry no horizon and
   * are never purged by time.
   */
  sweep(): void {
    this.tx(() => this.sweepNow(this.now().getTime()));
  }

  private sweepNow(nowMs: number): void {
    const rows = this.db
      .prepare("SELECT * FROM claims WHERE state != 'claimed' OR pdp_boot != ?")
      .all(this.boot) as ClaimRow[];
    for (const row of rows) this.advance(row, nowMs);
  }

  /** Apply what time and restart alone decide for one row; `undefined` when it was purged. */
  private advance(row: ClaimRow, nowMs: number): ClaimRow | undefined {
    let current = row;
    if (
      (current.state === "completed" || current.state === "failed") &&
      current.retain_until_ms !== null &&
      nowMs >= current.retain_until_ms
    ) {
      this.db
        .prepare("DELETE FROM claims WHERE scope_digest = ? AND idempotency_key = ?")
        .run(current.scope_digest, current.idempotency_key);
      this.log(current, current.state, "purged", "horizon_elapsed", nowMs);
      return undefined;
    }
    if (current.state === "permit_issued") {
      const restarted = current.pdp_boot !== this.boot;
      if (restarted || nowMs > current.valid_until_ms + this.leaseMaxMs(current)) {
        current = this.move(current, "unresolved", restarted ? "restart_unknown" : "lease_elapsed", nowMs);
      }
    }
    if (current.state === "unresolved" && nowMs >= this.windowCloseMs(current)) {
      this.db
        .prepare("UPDATE claims SET state = 'indeterminate', terminal_at_ms = ?, retain_until_ms = NULL WHERE evaluation_id = ?")
        .run(nowMs, current.evaluation_id);
      this.log(current, "unresolved", "indeterminate", "window_closed", nowMs);
      current = { ...current, state: "indeterminate", terminal_at_ms: nowMs, retain_until_ms: null };
    }
    if (
      (current.state === "completed" || current.state === "failed" || current.state === "indeterminate") &&
      current.decision_json !== null &&
      nowMs >= this.windowCloseMs(current)
    ) {
      this.db.prepare("UPDATE claims SET decision_json = NULL WHERE evaluation_id = ?").run(current.evaluation_id);
      this.log(current, current.state, current.state, "tombstoned", nowMs);
      current = { ...current, decision_json: null };
    }
    return current;
  }

  private move(row: ClaimRow, to: ClaimState, cause: string, nowMs: number): ClaimRow {
    this.db.prepare("UPDATE claims SET state = ? WHERE evaluation_id = ?").run(to, row.evaluation_id);
    this.log(row, row.state, to, cause, nowMs);
    return { ...row, state: to };
  }

  private leaseMaxMs(row: ClaimRow): number {
    return this.classes.get(row.action_class)?.leaseMaxMs ?? 0;
  }

  private windowCloseMs(row: ClaimRow): number {
    return row.valid_until_ms + this.leaseMaxMs(row) + this.windowMs;
  }

  private select(scopeDigest: string, key: string): ClaimRow | undefined {
    return this.db
      .prepare("SELECT * FROM claims WHERE scope_digest = ? AND idempotency_key = ?")
      .get(scopeDigest, key) as ClaimRow | undefined;
  }

  private insert(input: ClaimInput, nowMs: number): void {
    this.db
      .prepare(
        `INSERT INTO claims (scope_digest, idempotency_key, scope_json, action_class, operation_identity, cache_key,
           evaluation_id, pdp_boot, pep_id, pep_epoch, state, valid_until_ms, claimed_at_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'claimed', ?, ?)`,
      )
      .run(
        input.scopeDigest,
        input.key,
        canonicalize(canonicalIdempotencyScope(input.scope)),
        input.actionClass,
        input.operationIdentity,
        input.cacheKey,
        input.evaluationId,
        this.boot,
        input.requester.pep_id,
        input.requester.pep_epoch,
        input.validUntilMs,
        nowMs,
      );
    this.inFlight.add(input.evaluationId);
    this.logKeys(input.scopeDigest, input.key, input.evaluationId, null, "claimed", "claimed", nowMs);
  }

  private adopt(row: ClaimRow, input: ClaimInput, nowMs: number): void {
    this.db
      .prepare(
        `UPDATE claims SET evaluation_id = ?, cache_key = ?, pdp_boot = ?, pep_id = ?, pep_epoch = ?, valid_until_ms = ?, claimed_at_ms = ?
         WHERE scope_digest = ? AND idempotency_key = ? AND state = 'claimed' AND decision_json IS NULL`,
      )
      .run(
        input.evaluationId,
        input.cacheKey,
        this.boot,
        input.requester.pep_id,
        input.requester.pep_epoch,
        input.validUntilMs,
        nowMs,
        row.scope_digest,
        row.idempotency_key,
      );
    this.inFlight.add(input.evaluationId);
    this.logKeys(row.scope_digest, row.idempotency_key, input.evaluationId, "claimed", "claimed", `adopted:${row.evaluation_id}`, nowMs);
  }

  private ticket(evaluationId: string): ClaimTicket {
    return {
      evaluationId,
      persist: (decision: Decision) => {
        this.tx(() => {
          const changed = this.db
            .prepare(
              `UPDATE claims SET state = 'permit_issued', decision_json = ?
               WHERE evaluation_id = ? AND state = 'claimed' AND decision_json IS NULL AND pdp_boot = ?`,
            )
            .run(JSON.stringify(decision), evaluationId, this.boot).changes;
          if (changed !== 1) throw new Error(`claim for ${evaluationId} was not held at persist`);
          const row = this.db.prepare("SELECT * FROM claims WHERE evaluation_id = ?").get(evaluationId) as ClaimRow;
          this.log(row, "claimed", "permit_issued", "persisted", this.now().getTime());
        });
      },
      release: () => {
        this.inFlight.delete(evaluationId);
      },
    };
  }

  private log(row: ClaimRow, from: string | null, to: string, cause: string, atMs: number): void {
    this.logKeys(row.scope_digest, row.idempotency_key, row.evaluation_id, from, to, cause, atMs);
  }

  private logKeys(
    scopeDigest: string,
    key: string,
    evaluationId: string,
    from: string | null,
    to: string,
    cause: string,
    atMs: number,
  ): void {
    this.db
      .prepare(
        "INSERT INTO claim_transitions (scope_digest, idempotency_key, evaluation_id, from_state, to_state, cause, at_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
      )
      .run(scopeDigest, key, evaluationId, from, to, cause, atMs);
  }

  /** Every store access goes through here: any failure is the domain being unreachable. */
  private tx<T>(fn: () => T): T {
    if (this.closed) throw new ClaimDomainUnavailableError("the domain is closed");
    try {
      return withTransaction(this.db, fn);
    } catch (e) {
      if (e instanceof ClaimDomainUnavailableError) throw e;
      throw new ClaimDomainUnavailableError(e);
    }
  }
}
