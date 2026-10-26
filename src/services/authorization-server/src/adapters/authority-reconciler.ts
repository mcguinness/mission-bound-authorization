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
 *   record of, and a disabled Subject never revoke. A governed Mission whose
 *   Subject the source holds no record of is recorded as unresolved with the
 *   pass's progress, so the PDP refuses its actions: fresh progress never
 *   authorizes reliance on a dependency the pass could not resolve. Likewise
 *   each pass records the governed Missions whose Subject shows an applicable
 *   invalidation (disabled, withdrawn, deprovisioned; mapped to an operation
 *   or not), so a Mission resumed while it holds is still refused.
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
  classifyObservedInvalidation,
  type InvalidatingChange,
  type ReconciledInvalidation,
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
  /** The governed, non-terminal Missions whose Subject the observation holds no record of. */
  unresolved: string[];
  /** The governed, non-terminal Missions whose Subject the observation shows an applicable invalidation for. */
  invalidated: string[];
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
  private lastUnresolved: ReadonlySet<string> = new Set();
  private lastInvalidated: ReadonlyMap<string, ReconciledInvalidation> = new Map();
  private lastOutcome: ReconcileOutcome | undefined;

  constructor(private readonly opts: AuthorityReconcilerOptions) {
    if (!opts.declaration.enforcement.lifecycle) {
      throw new Error(`authority dependency ${opts.declaration.id} declares no lifecycle-mediated enforcement`);
    }
  }

  /**
   * The time the observation the last complete pass acted on represents
   * (absent before the first), with the Missions that pass could not resolve.
   */
  lag(): {
    lastReconciledAtMs?: number;
    unresolved?: ReadonlySet<string>;
    invalidated?: ReadonlyMap<string, ReconciledInvalidation>;
  } {
    return this.lastReconciledAtMs !== undefined
      ? { lastReconciledAtMs: this.lastReconciledAtMs, unresolved: this.lastUnresolved, invalidated: this.lastInvalidated }
      : {};
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
      this.lastOutcome = { ok: false, transitions: [], failures: [{ error: "the identity source could not be read" }], unresolved: [], invalidated: [] };
      return this.lastOutcome;
    }
    const transitions: ReconcileOutcome["transitions"] = [];
    const failures: ReconcileOutcome["failures"] = [];
    // @spec control-plane#rollback (#250 step 3): a kernel whose durable state
    // is uncertain loads no Mission for a decision, so a pass over it neither
    // commits nor counts as current: the PDP's lag refusal applies until the
    // kernel is reconciled. (Read where the kernel reports it.)
    const uncertainty = (kernel as { recoveryUncertainty?: () => unknown }).recoveryUncertainty?.();
    if (uncertainty) {
      this.lastOutcome = { ok: false, transitions, failures: [{ error: "the kernel's durable state is uncertain" }], unresolved: [], invalidated: [] };
      return this.lastOutcome;
    }
    let missions: MissionRecord[];
    try {
      missions = kernel.allMissions();
    } catch (e) {
      this.lastOutcome = { ok: false, transitions, failures: [{ error: e instanceof Error ? e.message : String(e) }], unresolved: [], invalidated: [] };
      return this.lastOutcome;
    }
    const unresolved: string[] = [];
    const invalidated = new Map<string, ReconciledInvalidation>();
    for (const record of missions) {
      if (record.state === "terminated") continue;
      if (!(declaration.governs.authority_sources as readonly string[]).includes(record.authority_source.type)) continue;
      // What the observation this pass acts on shows for the recorded Subject,
      // classified as direct evaluation classifies it but from the observation
      // alone: the source's current availability and the observation's age are
      // not evidence that an invalidation disappeared. A Mission the pass
      // cannot classify (no observation of its Subject) keeps the pass from
      // publishing, as a failed pass.
      const observation = resolver.view(record.subject).observation;
      if (observation === undefined) {
        failures.push({ mission: record.id, error: "no observation of the recorded Subject" });
        continue;
      }
      const shown = classifyObservedInvalidation(declaration, observation, record.client_id);
      if (shown?.failure === "unresolved") unresolved.push(record.id);
      if (shown !== undefined && shown.failure !== "unresolved") {
        // An applicable invalidation, mapped to a lifecycle operation or not.
        invalidated.set(record.id, { failure: shown.failure, observedAt: observation.observedAt });
      }
      const change = shown !== undefined && shown.failure !== "unresolved" ? shown.change : undefined;
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
    // Published together, recomputed from this pass alone: a Mission leaves a
    // set only when a later complete pass observes the condition gone, and a
    // failed or partial pass leaves the previous sets standing.
    if (ok) {
      this.lastReconciledAtMs = observedAtMs;
      this.lastUnresolved = new Set(unresolved);
      this.lastInvalidated = invalidated;
    }
    this.lastOutcome = {
      ok,
      observedAt: new Date(observedAtMs).toISOString(),
      transitions,
      failures,
      unresolved,
      invalidated: [...invalidated.keys()],
    };
    return this.lastOutcome;
  }
}
