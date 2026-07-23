/**
 * M6 scenario 5: ARAP reevaluate mode end to end.
 *
 * An action_approval_required denial at the PEP is marked requestable; the
 * PEP submits an ARAP access request bound to the PDP-signed denial; Bob
 * adjudicates at the ARS; the PEP re-evaluates with context.action_approval
 * and the PDP now permits. Proves the reevaluate property: approval is input
 * context, the PDP stays authoritative, and NO new token is issued.
 * In-process, live OpenFGA, auto-skip when down.
 */

import { generateKeyPair, exportJWK } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { Fga, type MissionView } from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  EvidenceStore,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type TokenFacts,
} from "@mission/mcp-payments";
import { AccessRequestService } from "../src/index.js";

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
if (!up) console.warn("OpenFGA unreachable; skipping M6 reevaluate tests");

const VIEW: MissionView = {
  id: "msn_m6",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:m6hash",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
};
const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: "msn_m6", authority_hash: "sha-256:m6hash" },
  cnfJkt: "jkt-1",
};

let fga: Fga;
let modelId: string;

d("M6 ARAP reevaluate (scenario 5)", () => {
  let pep: Pep;
  let ars: AccessRequestService;

  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;

    const pdpKeys = await generateKeyPair("ES256", { extractable: true });
    const pdpPubJwk = { ...(await exportJWK(pdpKeys.publicKey)), kid: "pdp-evidence", alg: "ES256" };

    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
    );
    pep = new Pep({
      payments,
      evidence: new EvidenceStore(),
      fga,
      modelId,
      loadView: (id) => (id === VIEW.id ? VIEW : undefined),
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf({ name: "payments" }),
      // Deployment policy: irreversible execute requires an action-bound approval.
      requiresActionApproval: (_action, cls) => cls === "irreversible_action",
      maxApprovalAgeSeconds: 300,
      requestable: { sign: pdpKeys.privateKey, kid: "pdp-evidence", endpoint: "https://ars.test/access-requests" },
    });
    ars = new AccessRequestService({
      pdpJwks: { keys: [pdpPubJwk as never] },
      approvalKey: (await generateKeyPair("ES256", { extractable: true })).privateKey,
      approvalKid: "ars-approval",
    });
  });

  it("denies requestable, resolves via ARS approval, re-evaluates to a permit -- no token issued", async () => {
    // 1. First attempt: no approval -> action_approval_required, requestable.
    const denied = await pep.enforce("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    expect(denied.permitted).toBe(false);
    expect(denied.denial_reason).toBe("action_approval_required");
    expect(denied.access_request?.binding_token).toBeDefined();
    const digest = denied.decision?.context.parameter_digest as string;

    // 2. PEP submits the ARAP access request bound to the PDP-signed denial.
    const { taskId, state } = await ars.submit({
      binding_token: denied.access_request?.binding_token as string,
      requested: { action: "payments:payment.execute", mission_id: "msn_m6", parameter_digest: digest, subject: "alice" },
    });
    expect(state).toBe("pending");
    expect(ars.pending().map((t) => t.id)).toContain(taskId);

    // 3. Bob adjudicates.
    const approval = await ars.adjudicate(taskId, "approve", "bob");
    expect(approval?.parameter_digest).toBe(digest);

    // 4. PEP re-evaluates with context.action_approval -> permit.
    const permitted = await pep.enforce("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN, {
      id: approval?.id as string,
      approved_at: approval?.approved_at as string,
      parameter_digest: approval?.parameter_digest as string,
    });
    expect(permitted.permitted, JSON.stringify(permitted)).toBe(true);
    expect(permitted.decision?.decision).toBe(true);
    // Reevaluate mode: the result is a fresh PDP decision, not a new token.
    expect(permitted.decision?.context.permit_expires_at).toBeDefined();
  });

  it("rejects an approval bound to a different parameter_digest", async () => {
    const denied = await pep.enforce("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    const badApproval = await pep.enforce("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN, {
      id: "apr_forged",
      approved_at: new Date().toISOString(),
      parameter_digest: "sha-256:WRONG",
    });
    expect(denied.denial_reason).toBe("action_approval_required");
    expect(badApproval.permitted).toBe(false);
    expect(badApproval.denial_reason).toBe("action_approval_required");
  });

  it("ARS rejects a submission that does not match its signed binding", async () => {
    const denied = await pep.enforce("execute_wire_transfer", { invoice_id: "inv-1" }, TOKEN);
    await expect(
      ars.submit({
        binding_token: denied.access_request?.binding_token as string,
        requested: { action: "payments:payment.execute", mission_id: "msn_m6", parameter_digest: "sha-256:TAMPERED", subject: "alice" },
      }),
    ).rejects.toThrow(/does not match/);
  });
});
