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
 *
 * @spec metering#retry, metering#settlement-states, metering#aggregate-bounds
 * (#816, D830): where the statement claims `budget_metering`, the same file
 * holds the exact budget counters, and a metered claim reserves on both of
 * its counters in the claim's own transaction, so of two concurrent requests
 * against one counter neither can pass on headroom the other took. A
 * reservation is `reserved`, `committed`, `released` or `held`, and is never
 * deleted when its claim is purged: committed spend persists. It is released
 * only where no permit left the PDP, or on affirmative non-execution before
 * redemption (`suppressed`); `completed` commits it; anything uncertain
 * (`failed`, a lease that elapsed, a restart) holds it, raising the declared
 * operator alert, and nothing but {@link IdempotencyClaimDomain.reconcileHeldReservation}
 * moves a reservation out of `held`.
 */

import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type ActionPhase,
  canonicalIdempotencyScope,
  canonicalize,
  IDEMPOTENCY_SCOPE_DIMENSIONS,
  type IdempotencyScope,
  isScopeDimension,
  isVolatileScopeMember,
  type JsonValue,
} from "@mission/core";
import { afterCommit, type Database, DurableStoreError, openDurableStore, withTransaction } from "@mission/store";
import {
  BUDGET_METERING_EXTENSION,
  type BudgetAmount,
  type BudgetMeteringDeclaration,
  decimalOf,
  metersAction,
  type MissionBudgetBinding,
  resolveBudgetCharge,
} from "./budget-metering.js";
import type { DecisionMeteringEntry } from "./decision-evidence.js";
import { type BoundaryConsumer, lineageScopeDigests, versionInForceAt } from "./enforcement-boundary.js";
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

/**
 * #1016 review round 2: the PEP's read-only answer, from its D28 redemption
 * record, to "which attempt took the single use of this `evaluation_id`?":
 * that attempt's `execution_id`, or `undefined` when the record names none
 * (never redeemed, or another epoch). Asked only to settle a failed or
 * suppressed outcome; never cached.
 */
export type RedeemingExecutionFn = (
  evaluationId: string,
  pepEpoch: string,
) => string | undefined | Promise<string | undefined>;

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
  /**
   * @spec runtime#evidence (outcome reconciliation), runtime#runtime-conformance
   * (#1103): told of every claim that moves `unresolved` to `indeterminate`,
   * once, after the transaction that moved it commits, on whichever path
   * moved it (the open-time sweep, a listing, a reconciliation, a decision).
   * The sweep is epoch-agnostic, so this sees a prior process's claim that
   * no current PEP epoch can list. The deployment wires it to the alerting
   * obligation its statement declares. A hook that throws is ignored: it
   * never reaches the decision or the transaction.
   */
  onIndeterminate?: (claim: IndeterminateClaim) => void;
  /**
   * @spec metering#settlement-states (#816, D830 rulings 7 and 10): told of
   * every budget reservation that becomes `held`, once, after the
   * transaction that held it commits, on whichever path held it (a `failed`
   * settlement, a lease that elapsed, the open-time sweep after a restart).
   * A held reservation stays charged until an operator reconciles it, so the
   * deployment wires this to the alerting obligation its statement declares.
   * A hook that throws is ignored, as `onIndeterminate` is.
   */
  onReservationHeld?: (reservation: HeldReservation) => void;
}

/**
 * A budget reservation that became `held`, as the operator alert reports
 * it: identifiers, counters and amounts, never the stored decision or the
 * request's parameters.
 */
export interface HeldReservation {
  evaluation_id: string;
  mission_id: string;
  /** What held it: `failed`, `lease_elapsed`, `restart_unknown`, `window_closed`. */
  cause: string;
  held_at: string;
  counters: Array<{ counter_scope: string; counter_id: string; amount: BudgetAmount }>;
}

/** A budget reservation's state. Only `reserved` and `held` still count as open. */
export type ReservationState = "reserved" | "committed" | "released" | "held";

/** One counter's charge for one evaluation, as the operator reads it. */
export interface ReservationRecord {
  evaluation_id: string;
  counter_scope: string;
  counter_id: string;
  mission_id: string;
  amount: BudgetAmount;
  state: ReservationState;
  cause: string;
}

/** One counter's totals, as the operator reads it. */
export interface BudgetCounterState {
  counter_scope: string;
  counter_id: string;
  reserved: BudgetAmount;
  held: BudgetAmount;
  committed: BudgetAmount;
}

/**
 * @spec metering#settlement-states (#816, D830 ruling 7): the authoritative
 * reconciliation an operator records for a held reservation. `not_executed`
 * releases it (the permit was never redeemed, or the effect is established
 * not to have happened); `executed` commits it. `reference` names the
 * evidence the operator relied on and is logged with the transition.
 */
export interface HeldReservationResolution {
  kind: "not_executed" | "executed";
  reference: string;
}

export type HeldReservationResult =
  | { accepted: true; state: "released" | "committed" }
  | { accepted: false; reason: string };

/**
 * @spec metering#metering (#816): the charge a metered request asks the claim
 * step to make. Built by `evaluate` from the PDP-local view and the request's
 * amount; resolved against this domain's own declaration inside the claim
 * transaction.
 */
export interface BudgetChargeRequest {
  /** The loaded view's budget binding (`MissionView.budget`). */
  binding: MissionBudgetBinding;
  /** The view's issuer, which qualifies the instance counter's Mission. */
  issuer: string;
  /** The Mission the decision is for; recorded on each reservation. */
  missionId: string;
  /** The request's amount: the same `context.amount` the `max_amount` step reads. */
  amount: BudgetAmount;
}

/**
 * @spec metering#metering, #816 (decision f): this domain's budget store as
 * a decision point binds it. Only the co-resident decision point
 * (`createDecisionPoint`) binds one; it exists only where the statement
 * claims `budget_metering`.
 */
export interface BudgetMetering {
  /** The claim domain the reservations share a transaction with. */
  readonly domain: IdempotencyClaimDomain;
  /** Whether the declaration meters this action at this phase. */
  meters(action: string, phase: ActionPhase | undefined): boolean;
}

/**
 * A claim that closed `indeterminate` at its window's end, as the operator
 * alert reports it: identifiers and instants only, never the stored decision
 * or the request's parameters.
 */
export interface IndeterminateClaim {
  evaluation_id: string;
  /** The `mission.id` of the claim's idempotency scope. */
  mission_id: string | undefined;
  action_class: string;
  pep_id: string;
  pep_epoch: string;
  valid_until: string;
  closed_at: string;
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
  /** The statement generation the claim was made under (`generationAt`); `null` on a row from before the column. */
  statement_version: string | null;
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
  /**
   * @spec metering#metering (#816): present for a metered request. The claim
   * then reserves on both of the charge's counters in the same transaction,
   * or claims nothing at all.
   */
  budget?: BudgetChargeRequest;
}

/** What the claim step tells the decision it is part of. */
export type ClaimOutcome =
  /**
   * This evaluation holds the claim: it persists its permit, or releases on
   * abort. A metered claim also holds its reservations, described by
   * `metering` for the decision's evidence.
   */
  | { kind: "claimed"; ticket: ClaimTicket; metering?: DecisionMeteringEntry[] }
  /**
   * @spec metering#aggregate-bounds, metering#authzen-binding (#816): a
   * counter would be exceeded. Nothing was claimed or reserved; `metering`
   * shows the requested quantity and each counter's unchanged remainder.
   */
  | { kind: "quota_exceeded"; metering: DecisionMeteringEntry[] }
  /** #816 (decision b): the binding names a budget this domain does not meter as bound. Nothing claimed. */
  | { kind: "budget_unsupported" }
  /** #816: the request's amount is not one the declared unit counts exactly. Nothing claimed. */
  | { kind: "budget_amount_invalid" }
  /** Same key, different operation identity: terminal in every state. */
  | { kind: "conflict" }
  /** Same key and identity, and no permit may issue. */
  | { kind: "suppressed"; state: ClaimState; transient: boolean; retryAfterSeconds?: number }
  /** Conditions 1 to 5 of a retransmission hold, in the generation the claim was made under; condition 6 is asked next. */
  | { kind: "retransmission_candidate"; evaluationId: string; pepEpoch: string };

/**
 * @spec metering#lease-renewal (#1464): the outcome of a claim the PDP settles
 * itself. A duration-lease renewal's only effect is the lease extension the
 * PDP commits, so its claim settles `completed` when the decision is
 * persisted, under this outcome, and no Execution Evidence is expected for it.
 */
export const LEASE_EXTENSION_OUTCOME = "lease_extended";

export interface ClaimTicket {
  readonly evaluationId: string;
  /**
   * Persist the full decision, signed Decision Evidence included, BEFORE it
   * is returned. `settled` names an outcome the PDP observed itself (a
   * committed lease extension): the claim is then settled `completed` in the
   * same transaction, and its stored permit stays retransmittable while it is
   * valid.
   */
  persist(decision: Decision, settled?: typeof LEASE_EXTENSION_OUTCOME): void;
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
  // @spec runtime#boundary-identifier-change (#1327 re-review): the statement
  // generation each claim was made under. A row from before this column
  // holds NULL, and a NULL row never retransmits.
  "ALTER TABLE claims ADD COLUMN statement_version TEXT;",
  // @spec metering#retry, metering#settlement-states, metering#aggregate-bounds
  // (#816, D830): the exact budget counters and their reservations. Neither
  // is ever deleted when a claim is purged at its horizon: committed spend
  // persists, and a held reservation stays charged until reconciled.
  `CREATE TABLE budget_counters (
    counter_id TEXT PRIMARY KEY,
    counter_scope TEXT NOT NULL CHECK (counter_scope IN ('mission', 'standing_consent')),
    counter_key TEXT NOT NULL,
    currency TEXT NOT NULL,
    exponent INTEGER NOT NULL,
    reserved_minor INTEGER NOT NULL DEFAULT 0,
    held_minor INTEGER NOT NULL DEFAULT 0,
    committed_minor INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL
  ) STRICT;
  CREATE TABLE budget_reservations (
    evaluation_id TEXT NOT NULL,
    counter_id TEXT NOT NULL,
    scope_digest TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    amount_minor INTEGER NOT NULL CHECK (amount_minor >= 0),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'committed', 'released', 'held')),
    reserved_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    cause TEXT NOT NULL,
    PRIMARY KEY (evaluation_id, counter_id)
  ) STRICT;
  CREATE TABLE budget_transitions (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    evaluation_id TEXT NOT NULL,
    counter_id TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    cause TEXT NOT NULL,
    at_ms INTEGER NOT NULL
  ) STRICT;`,
];

/**
 * The claim file's schema version this build writes: the number of
 * migrations. A test reading the file through a raw opener names it.
 */
export const CLAIM_SCHEMA_VERSION = MIGRATIONS.length;

interface ReservationRow {
  evaluation_id: string;
  counter_id: string;
  scope_digest: string;
  idempotency_key: string;
  mission_id: string;
  amount_minor: number;
  state: ReservationState;
  reserved_at_ms: number;
  updated_at_ms: number;
  cause: string;
}

interface CounterRow {
  counter_id: string;
  counter_scope: string;
  counter_key: string;
  currency: string;
  exponent: number;
  reserved_minor: number;
  held_minor: number;
  committed_minor: number;
}

/** The counter column an open or settled reservation state is totalled in; `released` counts nowhere. */
const STATE_COLUMN: Record<ReservationState, "reserved_minor" | "held_minor" | "committed_minor" | undefined> = {
  reserved: "reserved_minor",
  held: "held_minor",
  committed: "committed_minor",
  released: undefined,
};

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
  // @spec metering#topology (#816): the declaration was validated with the
  // statement above; it is in force only where the statement claims it.
  const budgets = options.statement.claims?.includes(BUDGET_METERING_EXTENSION)
    ? options.statement.extensions?.budget_metering
    : undefined;
  let db: Database;
  try {
    db = openDurableStore({ file: options.file, migrations: MIGRATIONS, owner: options.owner });
  } catch (e) {
    if (e instanceof DurableStoreError) throw new ClaimDomainConfigError(e.message);
    throw e;
  }
  const domain = new IdempotencyClaimDomain(db, classes, windowMs, options, budgets);
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
    private readonly budgets?: BudgetMeteringDeclaration,
  ) {
    this.now = options.now ?? (() => new Date());
  }

  /** Whether the statement names a claim domain for this class. */
  declares(actionClass: string | undefined): boolean {
    return actionClass !== undefined && this.classes.has(actionClass);
  }

  /**
   * @spec metering#metering, metering#topology (#816): this domain's budget
   * store, for the co-resident decision point to bind; `undefined` where the
   * statement does not claim `budget_metering`.
   */
  budgetMetering(): BudgetMetering | undefined {
    const declaration = this.budgets;
    if (!declaration) return undefined;
    return { domain: this, meters: (action, phase) => metersAction(declaration, action, phase) };
  }

  /**
   * @spec runtime#boundary-identifier-change step 1 (#853 review): this
   * domain as a consumer of the boundary identifier. It reads the
   * `replaces` lineage a key is looked up across from its own statement
   * ({@link heldRow}), so it is provisioned for a version only when that
   * statement declares the same version, byte for byte. A PDP still loaded
   * with an earlier statement would treat every key as fresh after the
   * change; bound to the PEP's boundary context, it holds the cutover until
   * it is reloaded.
   */
  boundaryConsumer(): BoundaryConsumer {
    const declared = this.options.statement.enforcement_boundaries?.versions ?? [];
    return {
      name: `pdp-claim-domain:${this.options.owner}`,
      provisionedFor: (version) => {
        const own = declared.find((v) => v.version === version.version);
        return own !== undefined && canonicalize(own as unknown as JsonValue) === canonicalize(version as unknown as JsonValue);
      },
    };
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
    const row = this.heldRow(input, nowMs);
    if (!row) {
      // @spec metering#retry (#816): a fresh key reserves on both counters
      // or claims nothing; a retry or replay under the key finds the row
      // below and reserves nothing more.
      const reserved = input.budget ? this.reserve(input, input.budget, nowMs) : undefined;
      if (reserved && reserved.kind !== "reserved") return reserved;
      this.insert(input, nowMs);
      return { kind: "claimed", ticket: this.ticket(input.evaluationId), ...(reserved ? { metering: reserved.metering } : {}) };
    }
    if (row.operation_identity !== input.operationIdentity) return { kind: "conflict" };
    switch (row.state) {
      case "claimed":
        // Adoptable only with proof no permit left this PDP: no decision was
        // ever persisted, and no evaluation in this boot is still holding it.
        if (row.decision_json === null && (row.pdp_boot !== this.boot || !this.inFlight.has(row.evaluation_id))) {
          // @spec metering#settlement-states (#816): the abandoned evaluation
          // issued no permit, so its reservations are released before this
          // one reserves afresh.
          this.transitionReservations(row.evaluation_id, ["reserved"], "released", "abandoned_unpersisted", nowMs);
          const reserved = input.budget ? this.reserve(input, input.budget, nowMs) : undefined;
          if (reserved && reserved.kind !== "reserved") return reserved;
          this.adopt(row, input, nowMs);
          return { kind: "claimed", ticket: this.ticket(input.evaluationId), ...(reserved ? { metering: reserved.metering } : {}) };
        }
        return { kind: "suppressed", state: "claimed", transient: true, retryAfterSeconds: 1 };
      case "permit_issued":
        if (this.retransmittable(row, input, nowMs)) {
          return { kind: "retransmission_candidate", evaluationId: row.evaluation_id, pepEpoch: row.pep_epoch };
        }
        return { kind: "suppressed", state: "permit_issued", transient: true, retryAfterSeconds: 1 };
      case "completed":
        // A lease extension the PDP settled itself: its stored permit is
        // returned to a retransmission while valid, as an issued one is.
        if (this.retransmittable(row, input, nowMs)) {
          return { kind: "retransmission_candidate", evaluationId: row.evaluation_id, pepEpoch: row.pep_epoch };
        }
        return { kind: "suppressed", state: "completed", transient: false };
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
   * @spec metering#metering, metering#aggregate-bounds,
   * metering#capacity-across-missions (#816, D830 rulings 1, 2 and 8):
   * reserve one charge on both of its counters, inside the claim's
   * transaction and with no await in it, so the check and the debit are one
   * step against the authoritative balance (the Exact profile, by the single
   * serializing PDP). Both counters are checked before either is debited:
   * either one refuses, and a refusal leaves both unchanged. Every open or
   * settled quantity, reserved, held or committed, counts against a limit.
   * The binding is resolved against this domain's own declaration here, so a
   * statement reloaded with another policy version refuses a binding to the
   * old one.
   */
  private reserve(
    input: ClaimInput,
    request: BudgetChargeRequest,
    nowMs: number,
  ):
    | { kind: "reserved"; metering: DecisionMeteringEntry[] }
    | { kind: "quota_exceeded"; metering: DecisionMeteringEntry[] }
    | { kind: "budget_unsupported" }
    | { kind: "budget_amount_invalid" } {
    if (!this.budgets) return { kind: "budget_unsupported" };
    const charge = resolveBudgetCharge(this.budgets, request.binding, request.issuer, request.amount);
    if (charge.kind === "unsupported") return { kind: "budget_unsupported" };
    if (charge.kind === "amount_invalid") return { kind: "budget_amount_invalid" };
    const { amountMinor, currency, exponent } = charge;
    const quantity = (minor: number): BudgetAmount => ({ amount: decimalOf(minor, exponent), currency });
    const counters: Array<{ counter: (typeof charge.counters)[number]; remainingMinor: number }> = [];
    for (const counter of charge.counters) {
      const row = this.counterRow(counter.id);
      // A counter kept in another unit is one this declaration cannot meter.
      if (row && (row.currency !== currency || row.exponent !== exponent)) return { kind: "budget_unsupported" };
      const used = row ? row.reserved_minor + row.held_minor + row.committed_minor : 0;
      counters.push({ counter, remainingMinor: Math.max(0, counter.limitMinor - used) });
    }
    if (counters.some((c) => amountMinor > c.remainingMinor)) {
      return {
        kind: "quota_exceeded",
        metering: counters.map((c) => ({
          bound: "max_budget",
          counter_scope: c.counter.scope,
          counter_id: c.counter.id,
          requested: quantity(amountMinor),
          remaining: quantity(c.remainingMinor),
        })),
      };
    }
    for (const { counter } of counters) {
      this.db
        .prepare(
          `INSERT INTO budget_counters (counter_id, counter_scope, counter_key, currency, exponent, created_at_ms)
           VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(counter_id) DO NOTHING`,
        )
        .run(counter.id, counter.scope, canonicalize(counter.key), currency, exponent, nowMs);
      this.db
        .prepare(
          `INSERT INTO budget_reservations (evaluation_id, counter_id, scope_digest, idempotency_key, mission_id, amount_minor, state,
             reserved_at_ms, updated_at_ms, cause)
           VALUES (?, ?, ?, ?, ?, ?, 'reserved', ?, ?, 'reserved')`,
        )
        .run(input.evaluationId, counter.id, input.scopeDigest, input.key, request.missionId, amountMinor, nowMs, nowMs);
      this.db.prepare("UPDATE budget_counters SET reserved_minor = reserved_minor + ? WHERE counter_id = ?").run(amountMinor, counter.id);
      this.logReservation(input.evaluationId, counter.id, null, "reserved", "reserved", nowMs);
    }
    return {
      kind: "reserved",
      metering: counters.map((c) => ({
        bound: "max_budget",
        counter_scope: c.counter.scope,
        counter_id: c.counter.id,
        requested: quantity(amountMinor),
        reserved: quantity(amountMinor),
        remaining: quantity(c.remainingMinor - amountMinor),
        settlement_state: "reserved" as const,
      })),
    };
  }

  private counterRow(counterId: string): CounterRow | undefined {
    return this.db.prepare("SELECT * FROM budget_counters WHERE counter_id = ?").get(counterId) as CounterRow | undefined;
  }

  /**
   * Move one evaluation's reservations that are in one of `from` to `to`,
   * keeping each counter's totals in the same transaction, and log each move.
   * A move into `held` queues the operator alert. Reservations in any other
   * state are untouched, so every caller is idempotent: a duplicate
   * settlement, a second sweep or a second listing changes nothing.
   */
  private transitionReservations(
    evaluationId: string,
    from: readonly ReservationState[],
    to: ReservationState,
    cause: string,
    nowMs: number,
  ): ReservationRow[] {
    const rows = (
      this.db.prepare("SELECT * FROM budget_reservations WHERE evaluation_id = ?").all(evaluationId) as ReservationRow[]
    ).filter((r) => from.includes(r.state));
    for (const r of rows) {
      this.db
        .prepare("UPDATE budget_reservations SET state = ?, cause = ?, updated_at_ms = ? WHERE evaluation_id = ? AND counter_id = ?")
        .run(to, cause, nowMs, r.evaluation_id, r.counter_id);
      const out = STATE_COLUMN[r.state];
      const into = STATE_COLUMN[to];
      if (out) this.db.prepare(`UPDATE budget_counters SET ${out} = ${out} - ? WHERE counter_id = ?`).run(r.amount_minor, r.counter_id);
      if (into) this.db.prepare(`UPDATE budget_counters SET ${into} = ${into} + ? WHERE counter_id = ?`).run(r.amount_minor, r.counter_id);
      this.logReservation(r.evaluation_id, r.counter_id, r.state, to, cause, nowMs);
    }
    if (to === "held" && rows.length > 0) this.notifyHeld(evaluationId, rows, cause, nowMs);
    return rows;
  }

  /**
   * @spec metering#settlement-states (#816, D830 ruling 7): queue
   * {@link ClaimDomainOptions.onReservationHeld} for after the enclosing
   * transaction commits, as {@link notifyIndeterminate} does.
   */
  private notifyHeld(evaluationId: string, rows: readonly ReservationRow[], cause: string, nowMs: number): void {
    const hook = this.options.onReservationHeld;
    if (!hook) return;
    const held: HeldReservation = {
      evaluation_id: evaluationId,
      mission_id: rows[0]?.mission_id ?? "unknown",
      cause,
      held_at: new Date(nowMs).toISOString(),
      counters: rows.map((r) => {
        const counter = this.counterRow(r.counter_id);
        return {
          counter_scope: counter?.counter_scope ?? "unknown",
          counter_id: r.counter_id,
          amount: { amount: decimalOf(r.amount_minor, counter?.exponent ?? 0), currency: counter?.currency ?? "" },
        };
      }),
    };
    afterCommit(this.db, () => {
      try {
        hook(held);
      } catch {
        /* the alert sink's failure never reaches the claim domain */
      }
    });
  }

  private logReservation(evaluationId: string, counterId: string, from: string | null, to: string, cause: string, atMs: number): void {
    this.db
      .prepare(
        "INSERT INTO budget_transitions (evaluation_id, counter_id, from_state, to_state, cause, at_ms) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(evaluationId, counterId, from, to, cause, atMs);
  }

  /**
   * @spec metering#settlement-states (#816, D830 rulings 7 and 10): the
   * operator's authoritative reconciliation of a held reservation, and the
   * only way out of `held`. Fresh consent, a new policy version, a restart,
   * a timeout, an elapsed lease and the executing PEP's own settlement or
   * reconciliation never release one. A reservation in any other state is
   * refused unchanged.
   */
  reconcileHeldReservation(evaluationId: string, resolution: HeldReservationResolution): HeldReservationResult {
    return this.tx(() => {
      const nowMs = this.now().getTime();
      const rows = this.db.prepare("SELECT * FROM budget_reservations WHERE evaluation_id = ?").all(evaluationId) as ReservationRow[];
      if (rows.length === 0) return { accepted: false, reason: "unknown_evaluation" };
      if (resolution.kind !== "not_executed" && resolution.kind !== "executed") return { accepted: false, reason: "unknown_resolution" };
      if (typeof resolution.reference !== "string" || resolution.reference.length === 0) return { accepted: false, reason: "no_reference" };
      if (!rows.some((r) => r.state === "held")) return { accepted: false, reason: `not_held_${rows[0]?.state}` };
      const to = resolution.kind === "not_executed" ? "released" : "committed";
      this.transitionReservations(evaluationId, ["held"], to, `operator_reconciled:${resolution.kind}:${resolution.reference}`, nowMs);
      return { accepted: true, state: to };
    });
  }

  /** @spec metering#settlement-states (#816): every held reservation, oldest first, for the operator reconciling them. */
  listHeldReservations(): ReservationRecord[] {
    return this.tx(() =>
      (this.db.prepare("SELECT * FROM budget_reservations WHERE state = 'held' ORDER BY reserved_at_ms, evaluation_id").all() as ReservationRow[]).map(
        (r) => this.recordOf(r),
      ),
    );
  }

  /** @spec metering#metering-evidence (#816): one evaluation's reservations, one per counter it charged. */
  reservationsFor(evaluationId: string): ReservationRecord[] {
    return this.tx(() =>
      (this.db.prepare("SELECT * FROM budget_reservations WHERE evaluation_id = ? ORDER BY counter_id").all(evaluationId) as ReservationRow[]).map(
        (r) => this.recordOf(r),
      ),
    );
  }

  /** @spec metering#aggregate-bounds (#816): one counter's totals, or `undefined` before its first reservation. */
  budgetCounter(counterId: string): BudgetCounterState | undefined {
    return this.tx(() => {
      const row = this.counterRow(counterId);
      if (!row) return undefined;
      const q = (minor: number): BudgetAmount => ({ amount: decimalOf(minor, row.exponent), currency: row.currency });
      return {
        counter_scope: row.counter_scope,
        counter_id: row.counter_id,
        reserved: q(row.reserved_minor),
        held: q(row.held_minor),
        committed: q(row.committed_minor),
      };
    });
  }

  private recordOf(r: ReservationRow): ReservationRecord {
    const counter = this.counterRow(r.counter_id);
    return {
      evaluation_id: r.evaluation_id,
      counter_scope: counter?.counter_scope ?? "unknown",
      counter_id: r.counter_id,
      mission_id: r.mission_id,
      amount: { amount: decimalOf(r.amount_minor, counter?.exponent ?? 0), currency: counter?.currency ?? "" },
      state: r.state,
      cause: r.cause,
    };
  }

  /**
   * Retransmission condition 6, then a recheck of 1 to 5 and the claim's
   * generation against the row as it stands after the query: a settlement,
   * a sweep or the clock (a cutover included) may have moved it while the
   * PEP was answering, so the recheck reads the clock again, inside its
   * transaction, after the await. Returns the stored decision byte for byte,
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
        row.evaluation_id !== candidate.evaluationId ||
        row.operation_identity !== input.operationIdentity ||
        row.decision_json === null ||
        !this.retransmittable(row, input, nowMs)
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
  async settle(
    requester: ClaimRequester,
    record: unknown,
    redeemingExecution?: RedeemingExecutionFn,
  ): Promise<SettlementResult> {
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
    // #1016 review round 2: a completed record proves an effect whatever
    // attempt wrote it. A failed or suppressed one proves no effect only for
    // the attempt that held the single use: a replay of the same permit that
    // was refused before redemption (`permit_expired` at admission, say)
    // says nothing about the redeeming attempt, which may have committed.
    // So a non-completed record settles only when the redemption owner's
    // own record names its `execution_id` as the redeeming attempt. The
    // record's members are never taken as that proof.
    if (next === "failed") {
      const row = this.tx(
        () => this.db.prepare("SELECT * FROM claims WHERE evaluation_id = ?").get(evaluationId) as ClaimRow | undefined,
      );
      if (!row) return { accepted: false, reason: "unknown_evaluation" };
      if (row.pep_id !== requester.pep_id) return { accepted: false, reason: "not_the_permit_holder" };
      const redeemer = await this.askRedeemer(evaluationId, row.pep_epoch, redeemingExecution);
      if (redeemer === undefined) return { accepted: false, reason: "redeeming_attempt_unknown" };
      if (redeemer !== executionId) return { accepted: false, reason: "not_the_redeeming_attempt" };
    }
    const outcomeRef = typeof content.evidence_id === "string" ? content.evidence_id : executionId;
    return this.tx(() => this.applySettlement(requester, evaluationId, executionId, next, String(outcome), outcomeRef, "settled"));
  }

  /** The redemption owner's answer; `undefined` for none, a failure, or no answer in time. */
  private async askRedeemer(
    evaluationId: string,
    pepEpoch: string,
    redeemingExecution: RedeemingExecutionFn | undefined,
  ): Promise<string | undefined> {
    if (!redeemingExecution) return undefined;
    const timeoutMs = this.options.consumptionStatusTimeoutMs ?? 1000;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const answer = await Promise.race([
        Promise.resolve(redeemingExecution(evaluationId, pepEpoch)),
        new Promise<undefined>((resolve) => {
          timer = setTimeout(() => resolve(undefined), timeoutMs);
        }),
      ]);
      return typeof answer === "string" && answer.length > 0 ? answer : undefined;
    } catch {
      return undefined;
    } finally {
      if (timer) clearTimeout(timer);
    }
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
    this.settleReservations(evaluationId, next, outcome, nowMs);
    return { accepted: true, state: next, duplicate: false };
  }

  /**
   * @spec metering#settlement-states (#816, D830 ruling 10): settle the
   * claim's reservations on the evidence state, never on a generic failure
   * signal, in the settling transaction. `completed` commits the reserved
   * quantity (the payment's amount is the quantity: no actual measure is
   * conveyed). `suppressed`, affirmative non-execution before redemption,
   * releases a reservation that is still `reserved`. Anything else, a
   * `failed` attempt or the redemption owner's `unredeemed` answer, holds
   * it. A reservation already `held` leaves `held` only by operator
   * reconciliation ({@link reconcileHeldReservation}), or by `completed`,
   * which keeps it charged. A duplicate settlement never reaches here.
   */
  private settleReservations(evaluationId: string, next: "completed" | "failed", outcome: string, nowMs: number): void {
    if (next === "completed") {
      this.transitionReservations(evaluationId, ["reserved", "held"], "committed", `settled_${outcome}`, nowMs);
    } else if (outcome === "suppressed") {
      this.transitionReservations(evaluationId, ["reserved"], "released", "settled_suppressed", nowMs);
    } else {
      this.transitionReservations(evaluationId, ["reserved"], "held", outcome === "failed" ? "failed" : outcome, nowMs);
    }
  }

  /**
   * @spec metering#lease-renewal (#1464): settle a just-persisted claim on an
   * outcome the PDP observed itself, in the persisting transaction. The row
   * takes the terminal `completed` state and its horizon as Execution
   * Evidence settlement would, so it never ages to `unresolved` or
   * `indeterminate`, raises no operator alert, and keeps conflicting with any
   * other operation identity under its key. Its `execution_id` names the PDP,
   * never a PEP attempt, so no Execution Evidence settles it again.
   */
  private settleObserved(row: ClaimRow, outcome: typeof LEASE_EXTENSION_OUTCOME, nowMs: number): void {
    const horizonMs = this.classes.get(row.action_class)?.horizonMs;
    if (horizonMs === undefined) throw new Error(`claim for ${row.evaluation_id} names an undeclared class`);
    this.db
      .prepare(
        `UPDATE claims SET state = 'completed', execution_id = ?, outcome = ?, outcome_ref = ?, terminal_at_ms = ?, retain_until_ms = ?
         WHERE evaluation_id = ? AND state = 'permit_issued' AND execution_id IS NULL`,
      )
      .run(`pdp:${row.evaluation_id}`, outcome, row.evaluation_id, nowMs, nowMs + horizonMs, row.evaluation_id);
    this.log(row, "permit_issued", "completed", outcome, nowMs);
    this.settleReservations(row.evaluation_id, "completed", outcome, nowMs);
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
  async reconcile(
    requester: ClaimRequester,
    evaluationId: string,
    resolution: ClaimResolution,
    redeemingExecution?: RedeemingExecutionFn,
  ): Promise<SettlementResult> {
    if (resolution.kind === "execution_evidence") {
      const content = object(resolution.record) ? resolution.record : undefined;
      if (content?.evaluation_id !== evaluationId) return { accepted: false, reason: "evaluation_mismatch" };
      // The settlement rule applies unchanged, the redeeming-attempt linkage included.
      return this.settle(requester, resolution.record, redeemingExecution);
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
      // @spec metering#settlement-states (#816): the claim's reservations
      // are kept: committed spend persists, and a held one stays charged.
      return undefined;
    }
    // @spec metering#settlement-states (#816): a prior boot's claim that
    // never persisted a decision issued no permit, so its reservations are
    // released (the claim itself stays adoptable, as before).
    if (current.state === "claimed" && current.decision_json === null && current.pdp_boot !== this.boot) {
      this.transitionReservations(current.evaluation_id, ["reserved"], "released", "prior_boot_unpersisted", nowMs);
    }
    if (current.state === "permit_issued") {
      const restarted = current.pdp_boot !== this.boot;
      if (restarted || nowMs > current.valid_until_ms + this.leaseMaxMs(current)) {
        const cause = restarted ? "restart_unknown" : "lease_elapsed";
        current = this.move(current, "unresolved", cause, nowMs);
        // @spec metering#settlement-states (#816, D830 rulings 7 and 10): an
        // issued permit whose outcome is now unknown may have been redeemed.
        // Its reservation is held, never released, by a restart or an
        // elapsed lease alike.
        this.transitionReservations(current.evaluation_id, ["reserved"], "held", cause, nowMs);
      }
    }
    if (current.state === "unresolved" && nowMs >= this.windowCloseMs(current)) {
      this.db
        .prepare("UPDATE claims SET state = 'indeterminate', terminal_at_ms = ?, retain_until_ms = NULL WHERE evaluation_id = ?")
        .run(nowMs, current.evaluation_id);
      this.log(current, "unresolved", "indeterminate", "window_closed", nowMs);
      this.notifyIndeterminate(current, nowMs);
      this.transitionReservations(current.evaluation_id, ["reserved"], "held", "window_closed", nowMs);
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

  /**
   * Queue {@link ClaimDomainOptions.onIndeterminate} for after the enclosing
   * transaction commits, so a rolled-back transition alerts nothing. The
   * catch is inside the callback: a commit callback runs outside the
   * transaction's own error handling, so a throwing hook would otherwise read
   * as an unreachable domain.
   */
  private notifyIndeterminate(row: ClaimRow, nowMs: number): void {
    const hook = this.options.onIndeterminate;
    if (!hook) return;
    let missionId: string | undefined;
    try {
      const id = (JSON.parse(row.scope_json) as { mission?: { id?: unknown } }).mission?.id;
      missionId = typeof id === "string" ? id : undefined;
    } catch {
      missionId = undefined;
    }
    const claim: IndeterminateClaim = {
      evaluation_id: row.evaluation_id,
      mission_id: missionId,
      action_class: row.action_class,
      pep_id: row.pep_id,
      pep_epoch: row.pep_epoch,
      valid_until: new Date(row.valid_until_ms).toISOString(),
      closed_at: new Date(nowMs).toISOString(),
    };
    afterCommit(this.db, () => {
      try {
        hook(claim);
      } catch {
        /* the alert sink's failure never reaches the claim domain */
      }
    });
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

  /**
   * @spec runtime#idempotency, runtime#boundary-identifier-change (#853
   * review): the row that holds the pair, after time has been applied: the
   * one under the request's own scope, or else one under the scope of a
   * boundary its audience replaces, per this domain's statement
   * ({@link lineageScopeDigests}). A declared change of identifier therefore
   * never makes a claimed key fresh: a retry after it meets the original
   * claim, which suppresses or conflicts exactly as it would have, and never
   * retransmits (its cache key names the old audience, and the statement
   * version it was claimed under is no longer in force). The row stays
   * under the scope it was claimed in.
   */
  private heldRow(input: ClaimInput, nowMs: number): ClaimRow | undefined {
    const lineage = lineageScopeDigests(this.options.statement.enforcement_boundaries, input.scope);
    for (const digest of [input.scopeDigest, ...lineage]) {
      const found = this.select(digest, input.key);
      const row = found ? this.advance(found, nowMs) : undefined;
      if (row) return row;
    }
    return undefined;
  }

  /**
   * @spec runtime#boundary-identifier-change, runtime#idempotency (#1327
   * re-review): the statement generation in force at `nowMs` under this
   * domain's own statement: the declared version whose cutover was reached
   * last, or `""` where none is in force. A claim records the generation it
   * is made under, and its stored permit is a retransmission candidate only
   * while that generation is still in force. The reference invalidates
   * every permit at a new statement version, so a permit decided before a
   * cutover is never returned after it, even when the boundary identifier,
   * and with it the cache key, is unchanged: the retry is suppressed under
   * the original claim and never claims afresh.
   */
  private generationAt(nowMs: number): string {
    return versionInForceAt(this.options.statement.enforcement_boundaries, nowMs)?.version ?? "";
  }

  /**
   * Retransmission conditions 1 to 5 against a row holding a stored permit:
   * an issued permit no attempt has settled, or a lease extension the PDP
   * settled itself ({@link LEASE_EXTENSION_OUTCOME}), whose permit no
   * Execution Evidence ever settles. Condition 6 is asked separately.
   */
  private retransmittable(row: ClaimRow, input: ClaimInput, nowMs: number): boolean {
    const holdsPermit =
      (row.state === "permit_issued" && row.execution_id === null) ||
      (row.state === "completed" && row.outcome === LEASE_EXTENSION_OUTCOME);
    return (
      holdsPermit &&
      !this.metered(row, input) &&
      row.cache_key === input.cacheKey &&
      row.statement_version === this.generationAt(nowMs) &&
      nowMs < row.valid_until_ms &&
      row.pep_id === input.requester.pep_id &&
      row.pep_epoch === input.requester.pep_epoch &&
      row.decision_json !== null
    );
  }

  /**
   * @spec metering#retry, authzen#projections (#816, decision d): a metered
   * decision is never answered from a stored one. The budget binding it was
   * charged under is PDP-local and absent from the cache key, so a stored
   * permit could be returned under a binding it was never charged against.
   * A metered retry is suppressed instead, and reserves nothing more.
   */
  private metered(row: ClaimRow, input: ClaimInput): boolean {
    return (
      input.budget !== undefined ||
      this.db.prepare("SELECT 1 FROM budget_reservations WHERE evaluation_id = ? LIMIT 1").get(row.evaluation_id) !== undefined
    );
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
           evaluation_id, pdp_boot, pep_id, pep_epoch, state, valid_until_ms, claimed_at_ms, statement_version)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'claimed', ?, ?, ?)`,
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
        this.generationAt(nowMs),
      );
    this.inFlight.add(input.evaluationId);
    this.logKeys(input.scopeDigest, input.key, input.evaluationId, null, "claimed", "claimed", nowMs);
  }

  private adopt(row: ClaimRow, input: ClaimInput, nowMs: number): void {
    this.db
      .prepare(
        `UPDATE claims SET evaluation_id = ?, cache_key = ?, pdp_boot = ?, pep_id = ?, pep_epoch = ?, valid_until_ms = ?, claimed_at_ms = ?,
           statement_version = ?
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
        this.generationAt(nowMs),
        row.scope_digest,
        row.idempotency_key,
      );
    this.inFlight.add(input.evaluationId);
    this.logKeys(row.scope_digest, row.idempotency_key, input.evaluationId, "claimed", "claimed", `adopted:${row.evaluation_id}`, nowMs);
  }

  private ticket(evaluationId: string): ClaimTicket {
    let persisted = false;
    return {
      evaluationId,
      persist: (decision: Decision, settled?: typeof LEASE_EXTENSION_OUTCOME) => {
        this.tx(() => {
          const changed = this.db
            .prepare(
              `UPDATE claims SET state = 'permit_issued', decision_json = ?
               WHERE evaluation_id = ? AND state = 'claimed' AND decision_json IS NULL AND pdp_boot = ?`,
            )
            .run(JSON.stringify(decision), evaluationId, this.boot).changes;
          if (changed !== 1) throw new Error(`claim for ${evaluationId} was not held at persist`);
          const row = this.db.prepare("SELECT * FROM claims WHERE evaluation_id = ?").get(evaluationId) as ClaimRow;
          const nowMs = this.now().getTime();
          this.log(row, "claimed", "permit_issued", "persisted", nowMs);
          if (settled === LEASE_EXTENSION_OUTCOME) this.settleObserved(row, settled, nowMs);
        });
        persisted = true;
      },
      release: () => {
        this.inFlight.delete(evaluationId);
        if (!persisted) this.releaseUnpersisted(evaluationId);
      },
    };
  }

  /**
   * @spec metering#settlement-states (#816): an evaluation that ended
   * without persisting its permit issued none, so its reservations are
   * released. Best effort, never thrown into the evaluation's own unwinding:
   * a release that cannot run now runs when a retry adopts the claim, or at
   * the next boot's sweep, and until then the reservation stays charged.
   */
  private releaseUnpersisted(evaluationId: string): void {
    if (this.closed) return;
    try {
      this.tx(() => {
        const row = this.db.prepare("SELECT * FROM claims WHERE evaluation_id = ?").get(evaluationId) as ClaimRow | undefined;
        if (row?.state === "claimed" && row.decision_json === null && row.pdp_boot === this.boot) {
          this.transitionReservations(evaluationId, ["reserved"], "released", "not_persisted", this.now().getTime());
        }
      });
    } catch {
      /* the reservation stays charged until adoption or the next sweep releases it */
    }
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
