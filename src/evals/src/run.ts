/**
 * `pnpm evals` entrypoint: compose the stack against live OpenFGA, run the
 * adversarial + legitimate suites, print the scorecard, and exit non-zero on
 * any containment breach / evidence gap / over-block (CI gate, D24).
 */

import { PaymentsStore } from "@mission/mcp-payments";
import { Fga, type MissionView } from "@mission/pdp";
import { adversarialSuite, EVAL_VIEW_AUTHORITY, legitimateSuite } from "./suites.js";
import { type EvalCase, runSuite } from "./index.js";

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";

async function main() {
  const ca = process.env.OPENFGA_CA_CERT;
  const { fga, modelId } = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, ...(ca ? { caCertPath: ca } : {}) });
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
  const cases = [...adversarialSuite, ...legitimateSuite] as unknown as EvalCase[];
  const { results, scorecard } = await runSuite(cases, { fga, modelId, view, seedStore });

  for (const r of results) {
    const flag = r.matchedExpectation ? "PASS" : "FAIL";
    console.log(`${flag}  ${r.suite.padEnd(11)} ${r.id.padEnd(28)} -> ${r.outcome}${r.reason ? ` (${r.reason})` : ""}`);
  }
  console.log("\nScorecard:", JSON.stringify(scorecard, null, 2));
  if (!scorecard.passed) {
    console.error("\n✗ evals FAILED (containment breach / evidence gap / over-block / wrong denial reason)");
    process.exit(1);
  }
  console.log("\n✓ evals passed: 100% containment, zero evidence gaps, zero over-blocking.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
