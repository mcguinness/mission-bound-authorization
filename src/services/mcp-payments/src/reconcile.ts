/**
 * @spec runtime (outcome reconciliation)
 *
 * Reconciliation joins Execution Evidence to the connector's ledger by the
 * operation key: every committed ledger entry MUST have matching Execution
 * Evidence and vice versa. Unmatched entries on either side are anomalies
 * (a side effect without evidence, or evidence without a side effect).
 */

import type { Connectors } from "./connectors.js";
import type { EvidenceStore } from "./evidence.js";

export interface ReconciliationReport {
  missionId: string;
  matched: Array<{ op_key: string; permit_id: string; amount: string }>;
  evidenceWithoutLedger: string[];
  ledgerWithoutEvidence: string[];
  ok: boolean;
}

export function reconcile(missionId: string, evidence: EvidenceStore, connectors: Connectors): ReconciliationReport {
  const execEvidence = evidence.forMission(missionId).filter((e) => e.kind === "execution");
  const ledger = connectors.ledgerEntries(missionId);

  const ledgerByKey = new Map(ledger.map((l) => [l.op_key as string, l]));
  const evidenceKeys = new Set(execEvidence.map((e) => (e as { op_key: string }).op_key));

  const matched: ReconciliationReport["matched"] = [];
  const evidenceWithoutLedger: string[] = [];
  for (const e of execEvidence) {
    const key = (e as { op_key: string }).op_key;
    const entry = ledgerByKey.get(key);
    if (entry) {
      matched.push({ op_key: key, permit_id: entry.permit_id as string, amount: entry.amount as string });
    } else {
      evidenceWithoutLedger.push(key);
    }
  }
  const ledgerWithoutEvidence = ledger.map((l) => l.op_key as string).filter((k) => !evidenceKeys.has(k));

  return {
    missionId,
    matched,
    evidenceWithoutLedger,
    ledgerWithoutEvidence,
    ok: evidenceWithoutLedger.length === 0 && ledgerWithoutEvidence.length === 0,
  };
}
