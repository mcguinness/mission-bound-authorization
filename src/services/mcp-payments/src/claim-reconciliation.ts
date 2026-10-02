/**
 * @spec runtime#idempotency, runtime#runtime-conformance (outcome
 * reconciliation) (#917, owner ruling 2026-10-02): the declared reconciler
 * (`outcome_reconciliation.responsible_component`, this PEP) for the PDP's
 * idempotency claims its permits hold.
 *
 * Each unresolved claim of this PEP's epoch is resolved from what the
 * execution side actually observed, in order:
 *
 * 1. the redeeming attempt's own retained Execution Evidence, exactly as
 *    settlement would have carried it;
 * 2. the connector ledger by operation key: an effect committed for the
 *    permit is an effect, so a completed record is emitted for it now and
 *    settles the claim;
 * 3. within the same epoch, no redemption of the `evaluation_id` at all: the
 *    redemption owner's proof of no effect, which the PDP accepts only once
 *    the permit and its longest lease have both elapsed.
 *
 * Anything else stays unresolved, and the PDP closes it `indeterminate` at
 * the end of the declared window: never fresh by time, never inferred
 * unused. Redemption, the lease and the effect stay here (D28).
 */

import { type ClaimChannel, newRecordId } from "@mission/pdp";
import type { Connectors } from "./connectors.js";
import type { EvidenceStore } from "./evidence.js";
import { CANONICAL_RESOURCE } from "./pep.js";
import type { RedemptionStatus } from "./redemption-status.js";

export interface ClaimReconciliationReport {
  /** Settled from Execution Evidence, retained or recovered from the ledger. */
  settled: string[];
  /** Proven unredeemed within the epoch: settled `failed`. */
  unredeemed: string[];
  /** Left unresolved: they close indeterminate at the window's end. */
  open: string[];
}

const SETTLING_ORDER = ["completed", "failed", "suppressed"] as const;

export async function reconcileClaims(input: {
  claims: ClaimChannel;
  evidence: EvidenceStore;
  redemption: RedemptionStatus;
  connectors?: Connectors;
}): Promise<ClaimReconciliationReport> {
  const report: ClaimReconciliationReport = { settled: [], unredeemed: [], open: [] };
  for (const claim of await input.claims.listUnresolved()) {
    const id = claim.evaluation_id;
    if (await fromEvidence(input, id)) {
      report.settled.push(id);
      continue;
    }
    const status = input.redemption.status(id, input.redemption.epoch);
    if (status === "unconsumed") {
      const resolved = await input.claims.reconcile(id, { kind: "unredeemed" });
      (resolved.accepted ? report.unredeemed : report.open).push(id);
      continue;
    }
    if (status === "consumed" && (await fromLedger(input, id))) {
      report.settled.push(id);
      continue;
    }
    report.open.push(id);
  }
  return report;
}

async function fromEvidence(input: { claims: ClaimChannel; evidence: EvidenceStore }, evaluationId: string): Promise<boolean> {
  const records = input.evidence
    .all()
    .flatMap((e) => (e.kind === "execution" && e.content.evaluation_id === evaluationId ? [e.content] : []));
  for (const outcome of SETTLING_ORDER) {
    for (const record of records.filter((r) => r.outcome === outcome)) {
      const resolved = await input.claims.reconcile(evaluationId, { kind: "execution_evidence", record });
      if (resolved.accepted) return true;
    }
  }
  return false;
}

async function fromLedger(
  input: { claims: ClaimChannel; evidence: EvidenceStore; connectors?: Connectors },
  evaluationId: string,
): Promise<boolean> {
  const opKey = input.connectors?.committedFor(evaluationId);
  if (opKey === undefined) return false;
  const decision = input.evidence
    .all()
    .find((e) => e.kind === "decision" && e.content.evaluation_id === evaluationId);
  if (!decision || decision.kind !== "decision") return false;
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
  const resolved = await input.claims.reconcile(evaluationId, { kind: "execution_evidence", record: executed.content });
  return resolved.accepted;
}
