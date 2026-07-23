/**
 * `pnpm demo:vendor-test`: the four valid-token-but-denied cases, one per
 * axis (state, bounds, parameters, delegation chain). Exits non-zero unless
 * all four deny.
 */

import { PaymentsStore } from "@mission/mcp-payments";
import { Fga, type MissionView } from "@mission/pdp";
import { EVAL_VIEW_AUTHORITY } from "./suites.js";
import { runVendorTest } from "./vendor-test.js";

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
      [{ id: "acme", name: "Acme", status: "approved" }],
      [
        { id: "inv-acme", vendor_id: "acme", amount: "100.00", currency: "USD", payee_account: "a", status: "payable" },
        { id: "inv-big", vendor_id: "acme", amount: "900.00", currency: "USD", payee_account: "a", status: "payable" },
      ],
    );
    return s;
  };
  const { rows, passed } = await runVendorTest({ fga, modelId, view, seedStore, revokedInstances: new Set() });

  console.log("Vendor test: one denied action per axis, each with a VALID token.\n");
  for (const r of rows) {
    console.log(`${r.denied ? "DENIED " : "PERMIT "} axis=${r.axis.padEnd(16)} tool=${r.tool.padEnd(22)} reason=${r.reason ?? "-"}`);
  }
  if (!passed) {
    console.error("\n✗ vendor test FAILED: a valid-token action that should have been denied was permitted.");
    process.exit(1);
  }
  console.log("\n✓ vendor test passed: every axis (state, bounds, parameters, delegation) denied a valid token.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
