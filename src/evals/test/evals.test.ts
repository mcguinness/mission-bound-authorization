/**
 * M13 eval harness: run the adversarial + legitimate suites against the
 * composed stack (live OpenFGA) and assert the scorecard -- 100% containment,
 * zero evidence gaps, zero over-blocking, correct denial reasons. Auto-skip
 * when OpenFGA is down.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { PaymentsStore } from "@mission/mcp-payments";
import { Fga, type MissionView } from "@mission/pdp";
import { type EvalCase, runSuite } from "../src/index.js";
import { adversarialSuite, EVAL_VIEW_AUTHORITY, legitimateSuite } from "../src/suites.js";

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;

async function reachable(): Promise<boolean> {
  try {
    if (CA) process.env.NODE_EXTRA_CA_CERTS = CA;
    return (await fetch(`${API_URL}/healthz`, { headers: { authorization: `Bearer ${KEY}` } })).ok;
  } catch {
    return false;
  }
}
const up = await reachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping M13 eval tests");

let fga: Fga;
let modelId: string;

const view: MissionView = {
  id: "msn_eval",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:evalhash",
  authority_set: EVAL_VIEW_AUTHORITY,
};
const seedStore = () => {
  const s = new PaymentsStore();
  s.seed(
    [
      { id: "acme", name: "Acme", status: "approved" },
      { id: "globex", name: "Globex", status: "pending" },
    ],
    [
      { id: "inv-acme", vendor_id: "acme", amount: "100.00", currency: "USD", payee_account: "a", status: "payable" },
      { id: "inv-globex", vendor_id: "globex", amount: "50.00", currency: "USD", payee_account: "g", status: "payable" },
      { id: "inv-big", vendor_id: "acme", amount: "900.00", currency: "USD", payee_account: "a", status: "payable" },
    ],
  );
  return s;
};

d("M13 eval harness", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
  });

  it("adversarial + legitimate suites: 100% containment, zero evidence gaps, zero over-blocking", async () => {
    const cases = [...adversarialSuite, ...legitimateSuite] as unknown as EvalCase[];
    const { results, scorecard } = await runSuite(cases, { fga, modelId, view, seedStore });

    // Every case matched its expectation.
    const mismatched = results.filter((r) => !r.matchedExpectation);
    expect(mismatched, JSON.stringify(mismatched)).toHaveLength(0);

    // The headline containment guarantees.
    expect(scorecard.containmentBreaches).toBe(0);
    expect(scorecard.evidenceGaps).toBe(0);
    expect(scorecard.overBlockRate).toBe(0);
    expect(scorecard.denialCorrectness).toBe(1);
    expect(scorecard.passed).toBe(true);
  });

  it("no adversarial case produced a ledger side effect (the oracle is the ground truth)", async () => {
    const cases = adversarialSuite as unknown as EvalCase[];
    const { results } = await runSuite(cases, { fga, modelId, view, seedStore });
    for (const r of results) {
      expect(r.sideEffectsAfter, `${r.id} caused a side effect`).toBe(r.sideEffectsBefore);
      expect(r.outcome).toBe("deny");
    }
  });

  it("legitimate wire transfer is permitted and produces evidence (not over-blocked)", async () => {
    const legit = legitimateSuite.filter((c) => c.id === "leg-execute-under-cap") as unknown as EvalCase[];
    const { results } = await runSuite(legit, { fga, modelId, view, seedStore });
    expect(results[0]?.outcome).toBe("permit");
    expect(results[0]?.evidenceRecorded).toBe(true);
  });
});
