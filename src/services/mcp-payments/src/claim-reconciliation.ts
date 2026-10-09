/**
 * @spec runtime#idempotency, runtime#runtime-conformance (outcome
 * reconciliation) (#917, owner ruling 2026-10-02): the declared reconciler
 * (`outcome_reconciliation.responsible_component`, this PEP) for the PDP's
 * idempotency claims its permits hold.
 *
 * Each unresolved claim of this PEP's epoch is resolved from what the
 * execution side actually observed, in this order:
 *
 * 1. a completed Execution Evidence record for the permit: an effect
 *    committed, whatever else was recorded;
 * 2. for a consumed permit, the connector ledger by operation key: a
 *    committed effect is an effect, so it takes precedence over any failed
 *    or suppressed record, and a completed record is emitted for it now;
 * 3. for a consumed permit with no committed effect, a failed or suppressed
 *    record from the attempt the redemption store names as the one that
 *    took the single use (#1016 review round 2). A record from any other
 *    attempt (a replay of the same permit refused before redemption) says
 *    nothing about the effect and is never offered;
 * 4. for an unconsumed permit (no redemption in this epoch), the redemption
 *    owner's proof of no effect, which the PDP accepts only once the permit
 *    and its longest lease have both elapsed.
 *
 * Anything else stays unresolved, and the PDP closes it `indeterminate` at
 * the end of the declared window: never fresh by time, never inferred
 * unused, never a purgeable `failed`. Redemption, the lease and the effect
 * stay here (D28).
 */

import { type ClaimChannel, newRecordId } from "@mission/pdp";
import type { Connectors } from "./connectors.js";
import type { EvidenceStore, ExecutionEvidenceObject } from "./evidence.js";
import { CANONICAL_RESOURCE } from "./pep.js";
import type { RedemptionStatus } from "./redemption-status.js";

export interface ClaimReconciliationReport {
  /** Settled from Execution Evidence, retained or recovered from the ledger. */
  settled: string[];
  /** Proven unredeemed within the epoch: settled `failed`. */
  unredeemed: string[];
  /** Left unresolved: they close indeterminate at the window's end. */
  open: string[];
  /** The state each resolved claim settled to. */
  states: Record<string, "completed" | "failed">;
  /**
   * Claims whose reconciliation threw, each with the error's name and never
   * its message. Each stays unresolved for a later run; the claims after it
   * are still reconciled (#1161 review).
   */
  errors: Array<{ evaluation_id: string; error: string }>;
}

export async function reconcileClaims(input: {
  claims: ClaimChannel;
  evidence: EvidenceStore;
  redemption: RedemptionStatus;
  connectors?: Connectors;
}): Promise<ClaimReconciliationReport> {
  const report: ClaimReconciliationReport = { settled: [], unredeemed: [], open: [], states: {}, errors: [] };
  for (const claim of await input.claims.listUnresolved()) {
    // One claim's failure (an evidence write that throws, a settlement the
    // channel cannot deliver) is isolated: it is recorded, the claim stays
    // unresolved for a later run, and the claims after it are still
    // reconciled, so the progress already made is kept (#1161 review).
    try {
      await reconcileClaim(input, claim.evaluation_id, report);
    } catch (e) {
      report.errors.push({ evaluation_id: claim.evaluation_id, error: e instanceof Error ? e.name : "non-error throw" });
    }
  }
  return report;
}

/** Resolve one unresolved claim into `report`, in the order the module header gives. */
async function reconcileClaim(
  input: { claims: ClaimChannel; evidence: EvidenceStore; redemption: RedemptionStatus; connectors?: Connectors },
  id: string,
  report: ClaimReconciliationReport,
): Promise<void> {
  const records = input.evidence
    .all()
    .flatMap((e) => (e.kind === "execution" && e.content.evaluation_id === id ? [e.content] : []));
  const settled = (state: "completed" | "failed" | undefined, into: string[]): boolean => {
    if (!state) return false;
    into.push(id);
    report.states[id] = state;
    return true;
  };
  // 1. A completed record: the effect committed.
  if (settled(await offer(input.claims, id, records.filter((r) => r.outcome === "completed")), report.settled)) return;
  const status = input.redemption.status(id, input.redemption.epoch);
  if (status === "consumed") {
    // 2. The ledger's committed effect before any non-completed record.
    if (settled(await fromLedger(input, id), report.settled)) return;
    // 3. Only the redeeming attempt's own failure or suppression.
    const redeemer = input.redemption.redeemer(id, input.redemption.epoch);
    const linked = redeemer === undefined ? [] : records.filter((r) => r.execution_id === redeemer && r.outcome !== "completed");
    if (settled(await offer(input.claims, id, linked), report.settled)) return;
  } else if (status === "unconsumed") {
    // 4. Proof of no effect from the redemption owner.
    const resolved = await input.claims.reconcile(id, { kind: "unredeemed" });
    if (resolved.accepted && settled(resolved.state, report.unredeemed)) return;
  }
  report.open.push(id);
}

/** Offer records in turn; the state the first accepted one settled to. */
async function offer(
  claims: ClaimChannel,
  evaluationId: string,
  records: readonly ExecutionEvidenceObject[],
): Promise<"completed" | "failed" | undefined> {
  for (const record of records) {
    const resolved = await claims.reconcile(evaluationId, { kind: "execution_evidence", record });
    if (resolved.accepted) return resolved.state;
  }
  return undefined;
}

async function fromLedger(
  input: { claims: ClaimChannel; evidence: EvidenceStore; connectors?: Connectors },
  evaluationId: string,
): Promise<"completed" | "failed" | undefined> {
  const opKey = input.connectors?.committedFor(evaluationId);
  if (opKey === undefined) return undefined;
  const decision = input.evidence
    .all()
    .find((e) => e.kind === "decision" && e.content.evaluation_id === evaluationId);
  if (!decision || decision.kind !== "decision") return undefined;
  const digest = decision.content.parameter_digest;
  const executed = await input.evidence.recordExecution(CANONICAL_RESOURCE, "executor", {
    permitId: evaluationId,
    opKey,
    execution_id: newRecordId("exe"),
    evaluation_id: evaluationId,
    mission_id: decision.content.mission.id,
    audience: CANONICAL_RESOURCE,
    ...(digest !== undefined ? { authorized_parameter_digest: digest, effective_parameter_digest: digest } : {}),
    outcome: "completed",
  });
  return offer(input.claims, evaluationId, [executed.content]);
}
