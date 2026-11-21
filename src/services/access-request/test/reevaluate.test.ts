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

import { randomUUID } from "node:crypto";
import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { ARAP_APPROVAL_TYP, Fga, type MissionView } from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  PaymentsStore,
  Pep,
  type TokenFacts,
  credentialAuthorityFrom
} from "@mission/mcp-payments";
import { AccessRequestService } from "../src/index.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { pinnedToCurrentContract } from "@mission/demo-data";

/** @spec runtime#idempotency (#917): one fresh `idempotency_key` per intended execution. */
const idem = (): string => `idem_${randomUUID()}`;

// ARAP: the ARS's identity as approval-state issuer, audienced to the PDP.
const ARS_ISS = "https://ars.test";
const APPROVAL_AUD = "https://pdp.test";
const arsApprovalKeys = await generateKeyPair("ES256", { extractable: true });
const arsApprovalPubJwk = { ...(await exportJWK(arsApprovalKeys.publicKey)), kid: "ars-approval", alg: "ES256" };

// @spec runtime-evidence#decision-evidence-object (#741): one bundle per
// test module. `signing`/`resolver` wire the PEP's store; `decide` is the
// decision point's entry point, which closes over the PDP's emission path.
// @spec authzen#context-approval (#2067): the decision point holds the ARS's
// approval-state trust anchor, from which it establishes the Mission binding.
const EVIDENCE_KEYS = createEphemeralEvidenceKeys({
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  approvalVerification: {
    issuers: [{ typ: ARAP_APPROVAL_TYP, issuer: ARS_ISS, audience: APPROVAL_AUD, keys: { keys: [arsApprovalPubJwk] } }],
  },
});

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
    pinnedToCurrentContract({
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    }),
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
};
const TOKEN: TokenFacts = {
  sub: "alice",
  clientId: "ap-agent",
  mission: { id: "msn_m6", issuer: "https://as.test", authority_hash: "sha-256:m6hash" },
  cnfJkt: "jkt-1",
  // @spec runtime#input-authority (#825) — as issued for this Mission.
  credentialAuthority: credentialAuthorityFrom(VIEW.authority_set),
};

let fga: Fga;
let modelId: string;

d("M6 ARAP reevaluate (scenario 5)", () => {
  let pep: Pep;
  let ars: AccessRequestService;

  beforeAll(async () => {
    const conn = await Fga.bootstrap({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
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
      decide: EVIDENCE_KEYS.decide,
      payments,
      evidence: new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver),
      fga,
      modelId,
      // @spec runtime#state-freshness: a synchronous live read, freshness-
      // stamped at this read (Finding 1), under the published `pep` placement.
      // Implements the canonical (issuer, id) tuple contract (@spec
      // authority-server#reference-tuple, #685 review).
      loadView: (ref) =>
        ref.id === VIEW.id && ref.issuer === VIEW.issuer
          ? { view: VIEW, observation: { state: VIEW.state, version: VIEW.version, mode: "fresh", freshness_at: new Date().toISOString() } }
          : undefined,
      instanceEpoch: "epoch-1",
      // Deployment policy: irreversible execute requires an action-bound approval.
      requiresActionApproval: (_action, cls) => cls === "irreversible_action",
      maxApprovalAgeSeconds: 300,
      requestable: { sign: pdpKeys.privateKey, kid: "pdp-evidence", endpoint: "https://ars.test/access-requests" },
    });
    ars = new AccessRequestService({
      pdpJwks: { keys: [pdpPubJwk as never] },
      approvalKey: arsApprovalKeys.privateKey,
      approvalKid: "ars-approval",
      issuer: ARS_ISS,
      approvalAudience: APPROVAL_AUD,
    });
  });

  it("denies requestable, resolves via ARS approval, re-evaluates to a permit -- no token issued", async () => {
    // 1. First attempt: no approval -> action_approval_required, requestable.
    const denied = await pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, TOKEN);
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

    // ARAP: the signed approval state carries iss (the ARS) and aud (the PDP).
    const stateJws = ars.getTask(taskId)?.approval?.state as string;
    expect(stateJws).toBeDefined();
    const { payload: stateClaims } = await jwtVerify(
      stateJws,
      createLocalJWKSet({ keys: [arsApprovalPubJwk] } as never),
      { issuer: ARS_ISS, audience: APPROVAL_AUD, typ: "arap-approval+jwt" },
    );
    expect(stateClaims.iss).toBe(ARS_ISS);
    expect(stateClaims.aud).toBe(APPROVAL_AUD);

    // @spec authzen#context-approval (#2067): the state binds the qualified
    // Mission identity the PDP-signed denial binding named.
    expect(stateClaims.mission).toEqual({ issuer: VIEW.issuer, id: VIEW.id });

    // 4. PEP re-evaluates with context.action_approval: the approval object
    // the ARS issued, unchanged (approved_until, the approved Resource with
    // the denied request's contract reference, #249, D865, and the signed
    // state carried) -> permit.
    expect(approval?.state).toBe(stateJws);
    const permitted = await pep.enforce(
      "execute_wire_transfer",
      { invoice_id: "inv-1", idempotency_key: idem() },
      TOKEN,
      approval ?? undefined,
    );
    expect(permitted.permitted, JSON.stringify(permitted)).toBe(true);
    expect(permitted.decision?.decision).toBe(true);
    // Reevaluate mode: the result is a fresh PDP decision, not a new token.
    expect((permitted.decision?.context.conditions as { valid_until?: string } | undefined)?.valid_until).toBeDefined();
  });

  it("rejects an approval bound to a different parameter_digest", async () => {
    const denied = await pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, TOKEN);
    // A genuine ARS approval for this Mission and the right Resource, contract
    // reference included (#249, D865), so only the digest is wrong.
    const members = {
      id: "apr_other_parameters",
      approved_at: new Date().toISOString(),
      approved_until: new Date(Date.now() + 300_000).toISOString(),
      parameter_digest: "sha-256:WRONG",
      resource: { properties: { resource_contract: VIEW.authority_set[0]?.resource_contract } },
    };
    const state = await new SignJWT({ ...members, mission: { issuer: VIEW.issuer, id: VIEW.id }, approver: "bob" })
      .setProtectedHeader({ alg: "ES256", kid: "ars-approval", typ: ARAP_APPROVAL_TYP })
      .setIssuer(ARS_ISS)
      .setAudience(APPROVAL_AUD)
      .setIssuedAt()
      .sign(arsApprovalKeys.privateKey);
    const badApproval = await pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, TOKEN, {
      ...members,
      state,
    });
    expect(denied.denial_reason).toBe("action_approval_required");
    expect(badApproval.permitted).toBe(false);
    // @spec authzen#context-approval: a presented approval that does not cover
    // these parameters is ARAP's `out_of_scope`, never `action_approval_required`.
    expect(badApproval.denial_reason).toBe("out_of_scope");
  });

  it("ARS rejects a submission that does not match its signed binding", async () => {
    const denied = await pep.enforce("execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: idem() }, TOKEN);
    await expect(
      ars.submit({
        binding_token: denied.access_request?.binding_token as string,
        requested: { action: "payments:payment.execute", mission_id: "msn_m6", parameter_digest: "sha-256:TAMPERED", subject: "alice" },
      }),
    ).rejects.toThrow(/does not match/);
  });
});
