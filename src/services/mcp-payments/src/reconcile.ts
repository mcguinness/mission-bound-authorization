/**
 * @spec runtime (outcome reconciliation)
 *
 * Reconciliation joins Execution Evidence to the connectors' committed
 * effects (the wire ledger and the email outbox) by the operation key: every
 * committed effect MUST have matching `completed` Execution Evidence and vice
 * versa. Unmatched entries on either side are anomalies (a side effect
 * without evidence, or evidence of an effect that never committed). A
 * `failed` or `suppressed` record asserts no effect, so it has no ledger
 * counterpart and is never an anomaly (#1103).
 */

import type { Connectors } from "./connectors.js";
import type { EvidenceStore } from "./evidence.js";

export interface ReconciliationReport {
  missionId: string;
  /** `amount` is a wire's; an email carries none. */
  matched: Array<{ op_key: string; permit_id: string; amount?: string }>;
  evidenceWithoutLedger: string[];
  ledgerWithoutEvidence: string[];
  ok: boolean;
}

export function reconcile(missionId: string, evidence: EvidenceStore, connectors: Connectors): ReconciliationReport {
  const execEvidence = evidence
    .forMission(missionId)
    .flatMap((e) => (e.kind === "execution" && e.content.outcome === "completed" ? [e] : []));
  const ledger = connectors.committedEffects(missionId);

  const ledgerByKey = new Map(ledger.map((l) => [l.opKey, l]));
  const evidenceKeys = new Set(execEvidence.map((e) => e.op_key));

  const matched: ReconciliationReport["matched"] = [];
  const evidenceWithoutLedger: string[] = [];
  for (const e of execEvidence) {
    const key = e.op_key;
    const entry = ledgerByKey.get(key);
    if (entry) {
      matched.push({ op_key: key, permit_id: entry.permitId, ...(entry.amount !== undefined ? { amount: entry.amount } : {}) });
    } else {
      evidenceWithoutLedger.push(key);
    }
  }
  const ledgerWithoutEvidence = ledger.map((l) => l.opKey).filter((k) => !evidenceKeys.has(k));

  return {
    missionId,
    matched,
    evidenceWithoutLedger,
    ledgerWithoutEvidence,
    ok: evidenceWithoutLedger.length === 0 && ledgerWithoutEvidence.length === 0,
  };
}
