/**
 * M12 scenario 13: sub-agent delegation end to end. An orchestrator holds a
 * mission-bound token; it spawns a sub-agent whose token carries a two-hop
 * `act` chain (orchestrator -> sub-agent). Both act within the mission. Then
 * the operator revokes the sub-agent's instance at the PEP: only the
 * sub-agent is denied; the orchestrator keeps working. In-process, live
 * OpenFGA, auto-skip when down.
 */

import { beforeAll, describe, expect, it } from "vitest";
import type { ActObject } from "@mission/actor-chain";
import { Fga, type MissionView } from "@mission/pdp";
import { CANONICAL_RESOURCE, EvidenceStore, PaymentsStore, Pep, sourceDigestOf, type TokenFacts } from "../src/index.js";

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
if (!up) console.warn("OpenFGA unreachable; skipping M12 sub-agent tests");

const VIEW: MissionView = {
  id: "msn_m12",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:m12hash",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read"],
      constraints: { vendors: ["acme"] },
    },
  ],
};

const AS = "https://as.test";
// Orchestrator instance (leaf when acting alone).
const ORCH = { iss: AS, sub: "inst-orchestrator", sub_profile: "ai_agent client_instance" };
// Sub-agent token: two-hop chain, orchestrator inner, sub-agent outer (leaf).
const SUBAGENT_ACT: ActObject = {
  iss: AS,
  sub: "inst-subagent",
  sub_profile: "ai_agent client_instance",
  act: { iss: AS, sub: "inst-orchestrator", sub_profile: "ai_agent client_instance" },
};

const orchestratorToken = (): TokenFacts => ({
  sub: "alice",
  clientId: "ap-agent",
  clientInstanceId: "inst-orchestrator",
  act: ORCH,
  mission: { id: "msn_m12", authority_hash: "sha-256:m12hash" },
  cnfJkt: "jkt-orch",
});
const subAgentToken = (): TokenFacts => ({
  sub: "alice",
  clientId: "ap-agent",
  clientInstanceId: "inst-subagent",
  act: SUBAGENT_ACT,
  mission: { id: "msn_m12", authority_hash: "sha-256:m12hash" },
  cnfJkt: "jkt-sub",
});

let fga: Fga;
let modelId: string;
const revoked = new Set<string>();

function pep(): Pep {
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "100.00", currency: "USD", payee_account: "acct", status: "payable" }],
  );
  return new Pep({
    payments,
    evidence: new EvidenceStore(),
    fga,
    modelId,
    loadView: (id) => (id === VIEW.id ? VIEW : undefined),
    instanceEpoch: "epoch-1",
    sourceDigest: sourceDigestOf({ name: "payments" }),
    revokedInstances: revoked,
  });
}

d("M12 scenario 13: sub-agent delegation + per-instance revocation", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
  });

  it("both orchestrator and sub-agent act within the mission (two-hop chain permitted)", async () => {
    const p = pep();
    const orch = await p.enforce("get_invoice", { invoice_id: "inv-1" }, orchestratorToken());
    expect(orch.permitted, JSON.stringify(orch)).toBe(true);
    const sub = await p.enforce("get_invoice", { invoice_id: "inv-1" }, subAgentToken());
    expect(sub.permitted, JSON.stringify(sub)).toBe(true);
  });

  it("revoking the sub-agent instance kills only the sub-agent; the orchestrator keeps working", async () => {
    revoked.add(`${AS} inst-subagent`);
    const p = pep();
    const sub = await p.enforce("get_invoice", { invoice_id: "inv-1" }, subAgentToken());
    expect(sub.permitted).toBe(false);
    expect(sub.refusal_reason).toBe("instance_revoked");
    // The orchestrator (a different instance, present in the sub-agent's chain
    // too) is NOT revoked and still acts on its own token.
    const orch = await p.enforce("get_invoice", { invoice_id: "inv-1" }, orchestratorToken());
    expect(orch.permitted, JSON.stringify(orch)).toBe(true);
    revoked.clear();
  });
});
