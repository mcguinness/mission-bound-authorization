/**
 * @spec runtime#input-authority-dependency, runtime#state-freshness,
 * mission#revocation (#830 Q-d and Q-e, D798): lifecycle-mediated enforcement
 * of a declared authority dependency.
 *
 * A trusted reconciler translates a relevant change at the identity source
 * into a Mission restriction through the existing lifecycle operations: the
 * declaration names the operation for each invalidating change it acts on,
 * `suspend` for a recoverable one (the Subject disabled, the delegation
 * withdrawn) and `revoke` for the Subject's deprovisioning (Q-e).
 *
 * - One pass reads the source (asynchronously, outside any store
 *   transaction), then commits each needed transition through
 *   {@link MissionKernel.transition}, one at a time: `suspend` only for an
 *   `active` Mission, `revoke` for any non-terminal one, a suspended one
 *   included. A pass that finds nothing to do commits nothing, so passes are
 *   idempotent, and a pass after a restart reconciles from the source and the
 *   kernel alone: the reconciler keeps no state a restart could lose except
 *   its progress stamp, and a lost stamp fails closed.
 * - Only the Mission's recorded Subject is evaluated: an approver's, owner's
 *   or client's departure changes nothing here unless that principal is the
 *   Subject. A source that cannot be read, a principal the source holds no
 *   record of, and a disabled Subject never revoke.
 * - Re-enablement is never reconciled into a resumption: a suspended Mission
 *   resumes only through an authorized lifecycle operation, after which every
 *   remaining check (the issuance gates' dependency check included) still
 *   applies, and a terminated Mission stays terminated. Authority removed
 *   through Containment is not touched.
 * - Progress is the time the observation the last complete pass acted on
 *   represents. A pass whose read fails, or whose transitions do not all
 *   commit, does not advance it, so an enforcing component refuses once it
 *   exceeds the declared lag bound ({@link lag}).
 */

import {
  type AuthorityDependencyDeclaration,
  type AuthorityDependencyResolver,
  type InvalidatingChange,
  type ReconcilerOperation,
} from "@mission/core";
import type { MissionKernel } from "../kernel/kernel.js";
import type { MissionRecord } from "../kernel/types.js";

/** One pass's result. */
export interface ReconcileOutcome {
  /** Whether the pass read the source and committed every transition it needed. */
  ok: boolean;
  /** The time the observation the pass acted on represents, where the read succeeded. */
  observedAt?: string;
  transitions: { mission: string; operation: ReconcilerOperation; change: InvalidatingChange }[];
  failures: { mission?: string; error: string }[];
}

export interface AuthorityReconcilerOptions {
  kernel: MissionKernel;
  declaration: AuthorityDependencyDeclaration;
  resolver: AuthorityDependencyResolver;
  /** The lifecycle commit, defaulting to {@link MissionKernel.transition}. */
  transition?: (missionId: string, operation: ReconcilerOperation) => MissionRecord;
}

export class AuthorityReconciler {
  private lastReconciledAtMs: number | undefined;
  private lastOutcome: ReconcileOutcome | undefined;

  constructor(private readonly opts: AuthorityReconcilerOptions) {
    if (!opts.declaration.enforcement.lifecycle) {
      throw new Error(`authority dependency ${opts.declaration.id} declares no lifecycle-mediated enforcement`);
    }
  }

  /** The time the observation the last complete pass acted on represents; absent before the first. */
  lag(): { lastReconciledAtMs?: number } {
    return this.lastReconciledAtMs !== undefined ? { lastReconciledAtMs: this.lastReconciledAtMs } : {};
  }

  /** The last pass's outcome, for monitoring. */
  last(): ReconcileOutcome | undefined {
    return this.lastOutcome;
  }

  /** One pass: read the source, then commit each restriction its changes call for. */
  async reconcile(): Promise<ReconcileOutcome> {
    const { kernel, declaration, resolver } = this.opts;
    const transition = this.opts.transition ?? ((id: string, op: ReconcilerOperation) => kernel.transition(id, op));
    const read = await resolver.refresh();
    const observedAtMs = resolver.observedAtMs();
    if (!read || observedAtMs === undefined) {
      this.lastOutcome = { ok: false, transitions: [], failures: [{ error: "the identity source could not be read" }] };
      return this.lastOutcome;
    }
    const transitions: ReconcileOutcome["transitions"] = [];
    const failures: ReconcileOutcome["failures"] = [];
    let missions: MissionRecord[];
    try {
      missions = kernel.allMissions();
    } catch (e) {
      this.lastOutcome = { ok: false, transitions, failures: [{ error: e instanceof Error ? e.message : String(e) }] };
      return this.lastOutcome;
    }
    for (const record of missions) {
      if (record.state === "terminated") continue;
      if (!(declaration.governs.authority_sources as readonly string[]).includes(record.authority_source.type)) continue;
      const change = this.changeFor(record);
      if (change === undefined) continue;
      const operation = declaration.enforcement.lifecycle_operations?.[change];
      if (operation === undefined) continue;
      if (operation === "suspend" && record.state !== "active") continue;
      try {
        transition(record.id, operation);
        transitions.push({ mission: record.id, operation, change });
      } catch (e) {
        failures.push({ mission: record.id, error: e instanceof Error ? e.message : String(e) });
      }
    }
    const ok = failures.length === 0;
    if (ok) this.lastReconciledAtMs = observedAtMs;
    this.lastOutcome = { ok, observedAt: new Date(observedAtMs).toISOString(), transitions, failures };
    return this.lastOutcome;
  }

  /**
   * The invalidating change the current observation shows for the Mission's
   * recorded Subject and client, if the declaration names it: deprovisioning
   * first, then disablement, then a withdrawn delegation. A principal the
   * source holds no record of shows none: an unavailable lookup does not
   * establish deprovisioning.
   */
  private changeFor(record: MissionRecord): InvalidatingChange | undefined {
    const observation = this.opts.resolver.view(record.subject).observation;
    if (!observation?.known) return undefined;
    const changes = this.opts.declaration.invalidating_changes;
    if (observation.status === "deprovisioned" && changes.includes("subject_deprovisioned")) return "subject_deprovisioned";
    if (observation.status === "disabled" && changes.includes("subject_disabled")) return "subject_disabled";
    if (changes.includes("delegation_withdrawn") && observation.withdrawnDelegations.includes(record.client_id)) {
      return "delegation_withdrawn";
    }
    return undefined;
  }
}
