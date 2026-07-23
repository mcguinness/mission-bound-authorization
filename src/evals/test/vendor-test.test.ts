/**
 * M14: the vendor-test demonstration. Each of the four axes (state, bounds,
 * parameters, delegation chain) denies an action presented with a VALID
 * token, with the axis-appropriate reason. Live OpenFGA; auto-skip when down.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { PaymentsStore } from "@mission/mcp-payments";
import { Fga, type MissionView } from "@mission/pdp";
import { EVAL_VIEW_AUTHORITY } from "../src/suites.js";
import { runVendorTest } from "../src/vendor-test.js";

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
if (!up) console.warn("OpenFGA unreachable; skipping M14 vendor-test");

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
    [{ id: "acme", name: "Acme", status: "approved" }],
    [
      { id: "inv-acme", vendor_id: "acme", amount: "100.00", currency: "USD", payee_account: "a", status: "payable" },
      { id: "inv-big", vendor_id: "acme", amount: "900.00", currency: "USD", payee_account: "a", status: "payable" },
    ],
  );
  return s;
};

d("M14 vendor-test demonstration", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
  });

  it("denies a valid-token action on every axis with the axis-appropriate reason", async () => {
    const { rows, passed } = await runVendorTest({ fga, modelId, view, seedStore, revokedInstances: new Set() });
    expect(passed, JSON.stringify(rows)).toBe(true);
    const byAxis = Object.fromEntries(rows.map((r) => [r.axis, r]));
    expect(byAxis.state?.reason).toBe("mission_inactive");
    expect(byAxis.bounds?.reason).toBe("constraint_exceeded");
    expect(byAxis.parameters?.reason).toBe("parameter_mismatch");
    expect(byAxis["delegation chain"]?.reason).toBe("instance_revoked");
    for (const r of rows) expect(r.tokenWasValid).toBe(true);
  });
});
