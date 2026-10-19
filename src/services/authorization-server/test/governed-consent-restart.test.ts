/**
 * @spec approval-governance#governed-policy-activation (step 2), #831: a
 * standing governed-policy consent is the issuer's attestation, signed with
 * its status key, and every activation verifies it against that key. With a
 * key ring and a file-backed kernel, a consent recorded before a restart
 * still verifies after it, and activates. With keys generated at each boot,
 * the same kept consent no longer verifies and activation refuses
 * `consent_unauthenticated`: the ring is what carries the consent across.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DERIVATION_POLICY, TOPOLOGY } from "@mission/demo-data";
import { afterAll, describe, expect, it } from "vitest";
import {
  activateGovernedPolicy,
  type BuiltAs,
  buildAuthorizationServer,
  type GovernedPolicyRoot,
  initSigningKeyRing,
  recordGovernedPolicyConsent,
  type RegisteredActivationPolicy,
  type SigningKeySource,
  validateMissionIntent,
} from "../src/index.js";

const ISSUER = "http://localhost:14846";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
/** The shipped `service_owned` source's agent and workload. */
const AGENT = "ledger-reconciler";
const WORKLOAD = "agt_ledger_reconciler";
const ROOT_ID = "urn:root:ledger-restart";
const READ = ["payments:invoice.list", "payments:invoice.read", "payments:vendor.read"];
const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
const dirs: string[] = [];

afterAll(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

const rootDoc: GovernedPolicyRoot = {
  admits: { clients: [AGENT], subjects: [WORKLOAD], authority_sources: ["service_owned"] },
  authority_ceiling: [{ type: "mission_resource_access", resource: RESOURCE, actions: READ, constraints: { vendors: ["acme"] } }] as never,
  lifetime: { max_lifetime_s: 3600 },
  rules: { max_entries: 3 },
  recency: { ceilings: { default: 30 * 86400 }, clock_skew_s: 60 },
  classification: {
    standard: [...READ, "payments:payment.schedule", "payments:payment.schedule.cancel", "ledger:vendor.read"],
    irreversible_action: ["payments:payment.execute"],
    external_commitment: ["payments:remittance.send"],
  },
};
const held: RegisteredActivationPolicy = { version: "1", content_type: "application/json", content: JSON.stringify(rootDoc) };
const governance = { roots: { [ROOT_ID]: held }, approvers: { [ROOT_ID]: ["dana"] } };

const boot = (signingKeys: SigningKeySource, file: string): Promise<BuiltAs> =>
  buildAuthorizationServer({ issuer: ISSUER, signingKeys, kernelStore: { file }, governedPolicyApproval: governance });

/** Record dana's consent on one boot, restart on the same kernel file, and activate under it. */
async function consentAcrossRestart(keys: () => Promise<SigningKeySource>): Promise<() => unknown> {
  const dir = mkdtempSync(join(tmpdir(), "governed-consent-"));
  dirs.push(dir);
  const file = join(dir, "kernel.db");
  const first = await boot(await keys(), file);
  const consent = recordGovernedPolicyConsent(first.kernel, {
    root: { id: ROOT_ID, version: "1" },
    approver: { iss: ISSUER, sub: "dana" },
    consentEventId: `gpce-${crypto.randomUUID()}`,
  });
  first.kernel.close();

  const second = await boot(await keys(), file);
  const now = second.kernel.nowDate();
  return () => {
    try {
      return activateGovernedPolicy(second.kernel, {
        consentId: consent.consent_id,
        approvalEventId: `ape-${crypto.randomUUID()}`,
        intent: validateMissionIntent(
          JSON.stringify({
            goal: "Reconcile Acme invoices",
            target_resources: [RESOURCE],
            expires_at: new Date(now.getTime() + 30 * 60_000).toISOString(),
          }),
          { now },
        ),
        clientId: AGENT,
      });
    } finally {
      second.kernel.close();
    }
  };
}

describe("a governed-policy consent across a restart (@spec approval-governance#governed-policy-activation, #831)", () => {
  it("still verifies and activates after a restart from the same key ring and kernel file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "governed-ring-"));
    dirs.push(dir);
    const ring = join(dir, "keys", "ring.json");
    await initSigningKeyRing(ring, ISSUER, { asToken, asStatus, asTxn, asContinuation });
    const activate = await consentAcrossRestart(async () => ({ ring }));
    const activation = activate() as { mission: { state: string; approval_basis: { type: string } } };
    expect(activation.mission.state).toBe("active");
    expect(activation.mission.approval_basis.type).toBe("governed_policy");
  });

  it("no longer verifies after a restart with keys generated at each boot: activation refuses consent_unauthenticated", async () => {
    const activate = await consentAcrossRestart(async () => ({ ephemeral: true }));
    expect(activate).toThrow(expect.objectContaining({ code: "consent_unauthenticated" }));
  });
});
