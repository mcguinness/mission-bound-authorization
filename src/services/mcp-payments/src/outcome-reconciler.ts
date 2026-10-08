/**
 * @spec runtime#evidence (outcome reconciliation), runtime#runtime-conformance,
 * runtime#idempotency (#1103): the declared reconciler, running.
 *
 * The Enforcement Scope Statement's `outcome_reconciliation` names a window,
 * the responsible component and an alerting obligation. This is that
 * component's loop, built from the declaration and refused at construction
 * unless the declaration names this PEP. Each run takes these steps in order,
 * each caught on its own: a step that throws raises `reconciliation_failed`
 * and the others still run.
 *
 * a. Claims: the PDP's unresolved claims of this epoch, settled over the claim
 *    channel from what the execution side observed (`reconcileClaims`).
 * b. Orphans: per Mission, `completed` Execution Evidence joined to the
 *    connectors' committed effects (`reconcile`). What remains unmatched after
 *    step a is alerted once: evidence of an effect that never committed at
 *    once, and an effect with no evidence once it is older than the window
 *    (step a settles such an effect's claim only after the permit and its
 *    lease elapse, and an attempt between its commit and its evidence write is
 *    no orphan).
 * c. Sweeps: the write-reservation store's retention sweeps.
 * d. Reserved rows: a `reserved` write reservation, whose effect is not known
 *    to have committed, is escalated once and never resolved by executing.
 *
 * Evidence, never the deadline, decides an outcome. A claim nothing here can
 * establish stays unresolved, and the PDP closes it `indeterminate` when its
 * window closes. That alert is raised where the transition happens, by the
 * claim domain's `onIndeterminate` hook ({@link indeterminateClaimAlert}),
 * which also sees a prior process's claims that this epoch cannot list.
 * Nothing here alerts from a run's `open` list.
 *
 * A run comes every third of the window, so each unresolved claim gets at
 * least two attempts before its window closes. Nothing here re-executes an
 * effect: step a records evidence of an effect the ledger already holds, and
 * steps b to d only read and alert.
 */

import { type ClaimChannel, type EnforcementScopeStatement, type IndeterminateClaim, retentionWindowSeconds } from "@mission/pdp";
import { type ClaimReconciliationReport, reconcileClaims } from "./claim-reconciliation.js";
import type { Connectors } from "./connectors.js";
import type { EvidenceStore } from "./evidence.js";
import { type ReconciliationReport, reconcile } from "./reconcile.js";
import type { RedemptionStatus } from "./redemption-status.js";
import type { WriteReservationStore } from "./write-reservations.js";

export type OperatorAlertKind =
  /** A claim closed `indeterminate` at its window's end (the declared alert). */
  | "claim_indeterminate"
  /** A reconciliation step threw. */
  | "reconciliation_failed"
  /** A committed effect still has no `completed` Execution Evidence after the window. */
  | "orphaned_effect"
  /** `completed` Execution Evidence names an effect no connector committed. */
  | "orphaned_evidence"
  /** A `reserved` write reservation has no recorded outcome. */
  | "reservation_unresolved";

/**
 * One operator alert: a structured event carrying identifiers and a fixed
 * cause only, never a request's arguments, parameters, credentials or an
 * error's message.
 */
export interface OperatorAlert {
  kind: OperatorAlertKind;
  evaluation_id?: string;
  mission_id?: string;
  cause: string;
  at: string;
}

export interface OperatorAlertSink {
  alert(event: OperatorAlert): void;
}

/** The reference sink: one JSON line per alert on stderr. */
export function stderrAlertSink(write: (line: string) => void = (line) => process.stderr.write(line)): OperatorAlertSink {
  return { alert: (event) => write(`${JSON.stringify({ type: "operator_alert", ...event })}\n`) };
}

/** A sink that keeps every alert, for tests and in-process inspection. */
export class CollectingAlertSink implements OperatorAlertSink {
  readonly alerts: OperatorAlert[] = [];
  alert(event: OperatorAlert): void {
    this.alerts.push(event);
  }
}

/** The declared alert for a claim the PDP closed `indeterminate`. */
export function indeterminateClaimAlert(claim: IndeterminateClaim): OperatorAlert {
  return {
    kind: "claim_indeterminate",
    evaluation_id: claim.evaluation_id,
    ...(claim.mission_id !== undefined ? { mission_id: claim.mission_id } : {}),
    cause: "window_closed",
    at: claim.closed_at,
  };
}

/** The statement does not declare this component as the reconciler. */
export class OutcomeReconcilerConfigError extends Error {
  constructor(why: string) {
    super(`outcome reconciler refused: ${why}`);
    this.name = "OutcomeReconcilerConfigError";
  }
}

export interface OutcomeReconcilerOptions {
  statement: EnforcementScopeStatement;
  /** This PEP's identity: the statement must name it `responsible_component`. */
  component: string;
  claims: ClaimChannel;
  evidence: EvidenceStore;
  redemption: RedemptionStatus;
  connectors: Connectors;
  writeReservations: WriteReservationStore;
  alerts: OperatorAlertSink;
  now?: () => Date;
  /** TEST ONLY: replaces the interval derived from the window. */
  intervalMs?: number;
}

export type OutcomeReconcilerStep = "claims" | "orphans" | "reservation_sweep" | "consumed_permit_sweep" | "reserved_rows";

export interface OutcomeReconciliationRun {
  /** Another run was in flight, so this one ran nothing. */
  skipped: boolean;
  /** Step a's report; absent when the step threw. */
  claims?: ClaimReconciliationReport;
  /** Step b's per-Mission joins. */
  ledger: ReconciliationReport[];
  /** Operation keys step b alerted in this run. */
  orphaned: { effects: string[]; evidence: string[] };
  /** Rows each sweep removed; absent when that sweep threw. */
  swept: { reservations?: number; consumedPermits?: number };
  /** The `evaluation_id` of every `reserved` row, escalated and never executed. */
  reserved: string[];
  /** The steps that threw. */
  failed: OutcomeReconcilerStep[];
}

const emptyRun = (skipped: boolean): OutcomeReconciliationRun => ({
  skipped,
  ledger: [],
  orphaned: { effects: [], evidence: [] },
  swept: {},
  reserved: [],
  failed: [],
});

export class OutcomeReconciler {
  /** The declared window, in milliseconds. */
  readonly windowMs: number;
  /** The interval between runs: a third of the window unless a test overrides it. */
  readonly intervalMs: number;
  private readonly now: () => Date;
  private readonly alerted = new Set<string>();
  private inFlight: Promise<OutcomeReconciliationRun> | undefined;
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor(private readonly options: OutcomeReconcilerOptions) {
    const declared = options.statement.extensions?.outcome_reconciliation;
    if (!declared) throw new OutcomeReconcilerConfigError("the statement declares no outcome_reconciliation");
    if (declared.responsible_component !== options.component) {
      throw new OutcomeReconcilerConfigError(
        `outcome_reconciliation names ${String(declared.responsible_component)}, not this component (${options.component})`,
      );
    }
    const windowSeconds = retentionWindowSeconds(declared.window);
    if (windowSeconds === undefined) throw new OutcomeReconcilerConfigError("the outcome_reconciliation window is not a duration");
    if (options.intervalMs !== undefined && !(Number.isSafeInteger(options.intervalMs) && options.intervalMs > 0)) {
      throw new OutcomeReconcilerConfigError("the interval override must be a positive whole number of milliseconds");
    }
    this.windowMs = windowSeconds * 1000;
    this.intervalMs = options.intervalMs ?? Math.floor(this.windowMs / 3);
    this.now = options.now ?? (() => new Date());
  }

  /** Whether the interval is running. */
  get started(): boolean {
    return this.timer !== undefined;
  }

  /** Run once now, then every interval, on a timer that keeps no process alive. Idempotent. */
  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.runOnce(), this.intervalMs);
    this.timer.unref();
    void this.runOnce();
  }

  /** Stop the interval and wait for a run in flight. Idempotent. */
  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.inFlight;
  }

  /**
   * One run. Never throws. A call while another run is in flight is skipped,
   * so a slow run never overlaps the next tick.
   */
  async runOnce(): Promise<OutcomeReconciliationRun> {
    if (this.inFlight) return emptyRun(true);
    const run = this.run();
    this.inFlight = run;
    try {
      return await run;
    } finally {
      this.inFlight = undefined;
    }
  }

  private async run(): Promise<OutcomeReconciliationRun> {
    const o = this.options;
    const report = emptyRun(false);
    const step = async (name: OutcomeReconcilerStep, fn: () => unknown): Promise<void> => {
      try {
        await fn();
      } catch (e) {
        report.failed.push(name);
        this.raise({ kind: "reconciliation_failed", cause: `${name}: ${e instanceof Error ? e.name : "non-error throw"}` });
      }
    };
    await step("claims", async () => {
      report.claims = await reconcileClaims({
        claims: o.claims,
        evidence: o.evidence,
        redemption: o.redemption,
        connectors: o.connectors,
      });
    });
    await step("orphans", () => this.detectOrphans(report));
    await step("reservation_sweep", () => {
      report.swept.reservations = o.writeReservations.sweep();
    });
    await step("consumed_permit_sweep", () => {
      report.swept.consumedPermits = o.writeReservations.sweepConsumedPermits();
    });
    await step("reserved_rows", () => {
      for (const row of o.writeReservations.reservations()) {
        if (row.state !== "reserved") continue;
        report.reserved.push(row.evaluationId);
        this.raiseOnce(`reserved:${row.scopeDigest}:${row.idempotencyKey}`, {
          kind: "reservation_unresolved",
          evaluation_id: row.evaluationId,
          cause: "reserved_without_outcome",
        });
      }
    });
    return report;
  }

  /** Step b: what remains unmatched after step a, each alerted once. */
  private detectOrphans(report: OutcomeReconciliationRun): void {
    const { evidence, connectors } = this.options;
    const effects = connectors.committedEffects();
    const executions = evidence.all().flatMap((e) => (e.kind === "execution" ? [e] : []));
    const missions = new Set([...effects.map((e) => e.missionId), ...executions.map((e) => e.mission_id)]);
    const nowMs = this.now().getTime();
    for (const missionId of missions) {
      const joined = reconcile(missionId, evidence, connectors);
      report.ledger.push(joined);
      for (const opKey of joined.ledgerWithoutEvidence) {
        const effect = effects.find((e) => e.opKey === opKey);
        // Inside the window the effect may still find its evidence.
        if (!effect || nowMs < effect.committedAtMs + this.windowMs) continue;
        if (this.raiseOnce(`effect:${opKey}`, { kind: "orphaned_effect", evaluation_id: effect.permitId, mission_id: missionId, cause: "effect_without_execution_evidence" })) {
          report.orphaned.effects.push(opKey);
        }
      }
      for (const opKey of joined.evidenceWithoutLedger) {
        const record = executions.find((e) => e.op_key === opKey && e.content.outcome === "completed");
        if (this.raiseOnce(`evidence:${opKey}`, { kind: "orphaned_evidence", ...(record ? { evaluation_id: record.content.evaluation_id } : {}), mission_id: missionId, cause: "execution_evidence_without_effect" })) {
          report.orphaned.evidence.push(opKey);
        }
      }
    }
  }

  private raiseOnce(identity: string, event: Omit<OperatorAlert, "at">): boolean {
    if (this.alerted.has(identity)) return false;
    this.alerted.add(identity);
    this.raise(event);
    return true;
  }

  private raise(event: Omit<OperatorAlert, "at">): void {
    try {
      this.options.alerts.alert({ ...event, at: this.now().toISOString() });
    } catch {
      /* a failing sink never stops a run */
    }
  }
}
