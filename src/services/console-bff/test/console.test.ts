/**
 * M11 console-bff: the persona surfaces the three SPAs render, exercised
 * headlessly (standing in for "scenarios runnable from the UIs"). Covers
 * session/role/CSRF enforcement, the approver queue + adjudication, the
 * operator fleet + lifecycle, and the feed-driven evidence timeline (D32)
 * including a tamper row that surfaces as failed rather than hidden.
 */

import { exportJWK, generateKeyPair, type JWK } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { AccessRequestService } from "@mission/access-request";
import { MissionKernel, validateMissionIntent } from "@mission/authorization-server";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { type Receipt, signStatement, type SignedStatement, TransparencyService } from "@mission/transparency";
import { AuthzError, ConsoleBff } from "../src/index.js";

const ISS = "https://as.test";

let kernel: MissionKernel;
let ars: AccessRequestService;
let transparency: TransparencyService;
let bff: ConsoleBff;
const evidenceById = new Map<string, unknown>();
const receiptByJws = new Map<string, Receipt>();
let producerJwks: { keys: JWK[] };
let serviceJwks: { keys: JWK[] };
let pdpKey: { iss: string; key: CryptoKey; kid: string };

const approveMission = (n: number) =>
  kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Pay", resources: [DERIVATION_POLICY.ceiling[0].resource], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-${n}`,
  });

beforeAll(async () => {
  const asKeys = await generateKeyPair("ES256", { extractable: true });
  kernel = new MissionKernel({ issuer: ISS, policy: DERIVATION_POLICY as never, statusKey: asKeys.privateKey, statusKid: "as-status" });

  const pdp = await generateKeyPair("ES256", { extractable: true });
  const pdpPub = { ...(await exportJWK(pdp.publicKey)), kid: "pdp-evidence", alg: "ES256" };
  pdpKey = { iss: "https://pdp.test", key: pdp.privateKey, kid: "pdp-evidence" };
  producerJwks = { keys: [pdpPub] };

  const arsKeys = await generateKeyPair("ES256", { extractable: true });
  const pdpDenialKeys = await generateKeyPair("ES256", { extractable: true });
  ars = new AccessRequestService({
    pdpJwks: { keys: [{ ...(await exportJWK(pdpDenialKeys.publicKey)), kid: "pdp", alg: "ES256" } as never] },
    approvalKey: arsKeys.privateKey,
    approvalKid: "ars",
  });

  const svc = await generateKeyPair("ES256", { extractable: true });
  serviceJwks = { keys: [{ ...(await exportJWK(svc.publicKey)), kid: "transparency", alg: "ES256" }] };
  transparency = new TransparencyService({ key: svc.privateKey, kid: "transparency", issuer: "https://transparency.test" });

  bff = new ConsoleBff({
    kernel,
    ars,
    transparency,
    retrieveEvidence: (_m, digest) => evidenceById.get(digest),
    producerJwks,
    serviceJwks,
    receiptFor: (s: SignedStatement) => receiptByJws.get(s.jws),
  });
});

describe("M11 session, role, and CSRF enforcement (D35)", () => {
  it("rejects missing session, wrong role, and bad CSRF", async () => {
    expect(() => bff.fleet(undefined)).toThrow(AuthzError);
    const approverOnly = bff.sessions.create("bob", ["approver"]);
    expect(() => bff.fleet(approverOnly)).toThrow(/operator required/);
    const op = bff.sessions.create("olivia", ["operator"]);
    const m = approveMission(1);
    await expect(async () => bff.lifecycle(op, m.id, "revoke", "wrong-csrf")).rejects.toThrow(/CSRF/);
  });
});

describe("M11 operator console: fleet + lifecycle", () => {
  it("enumerates the fleet and drives lifecycle with CSRF", () => {
    const op = bff.sessions.create("olivia", ["operator"]);
    approveMission(2);
    const fleet = bff.fleet(op);
    expect(fleet.length).toBeGreaterThanOrEqual(2);
    const target = fleet[0] as { id: string };
    const res = bff.lifecycle(op, target.id, "revoke", op.csrf);
    expect(res.state).toBe("revoked");
    expect(bff.fleet(op).find((r) => r.id === target.id)?.state).toBe("revoked");
  });
});

describe("M11 approver console: queue + adjudication", () => {
  it("shows pending ARAP tasks and adjudicates them", async () => {
    // Seed a pending ARAP task via a PDP-signed binding.
    const { SignJWT } = await import("jose");
    const pdpDenialKeys = await generateKeyPair("ES256", { extractable: true });
    // Rebuild ARS with a known denial key so we can mint a valid binding_token.
    const localArs = new AccessRequestService({
      pdpJwks: { keys: [{ ...(await exportJWK(pdpDenialKeys.publicKey)), kid: "pdp", alg: "ES256" } as never] },
      approvalKey: (await generateKeyPair("ES256", { extractable: true })).privateKey,
      approvalKid: "ars",
    });
    const localBff = new ConsoleBff({
      kernel, ars: localArs, transparency,
      retrieveEvidence: () => undefined, producerJwks, serviceJwks, receiptFor: () => undefined,
    });
    const binding = await new SignJWT({ decision_id: "dec_1", mission_id: "msn_x", action: "payments:payment.execute", parameter_digest: "sha-256:pd" })
      .setProtectedHeader({ alg: "ES256", kid: "pdp", typ: "pdp-denial-binding+jwt" })
      .setIssuedAt()
      .sign(pdpDenialKeys.privateKey);
    await localArs.submit({ binding_token: binding, requested: { action: "payments:payment.execute", mission_id: "msn_x", parameter_digest: "sha-256:pd", subject: "alice" } });

    const approver = localBff.sessions.create("bob", ["approver"]);
    const queue = localBff.approverQueue(approver);
    expect(queue).toHaveLength(1);
    const taskId = (queue[0] as { id: string }).id;
    const res = await localBff.adjudicateTask(approver, taskId, "approve", approver.csrf);
    expect(res.approved).toBe(true);
    expect(localBff.approverQueue(approver)).toHaveLength(0);
  });
});

describe("M11 evidence timeline is the verified feed (D32)", () => {
  it("renders verified rows and surfaces a tampered record as failed", async () => {
    const mission = approveMission(3);
    // Register two evidence records; retain the evidence for retrieval.
    const good = { kind: "decision", decision: true, mission_id: mission.id };
    const stmtGood = await signStatement(pdpKey, { missionId: mission.id, evidenceType: "decision-evidence", evidence: good });
    receiptByJws.set(stmtGood.jws, await transparency.register(stmtGood));
    evidenceById.set(stmtGood.digest, good);

    const exec = { kind: "execution", op_key: "op:9", mission_id: mission.id };
    const stmtExec = await signStatement(pdpKey, { missionId: mission.id, evidenceType: "execution-evidence", evidence: exec });
    receiptByJws.set(stmtExec.jws, await transparency.register(stmtExec));
    // Tamper: store MUTATED evidence under the committed digest.
    evidenceById.set(stmtExec.digest, { ...exec, op_key: "op:TAMPERED" });

    const op = bff.sessions.create("olivia", ["operator"]);
    const timeline = await bff.timeline(op, mission.id);
    expect(timeline).toHaveLength(2);
    const goodRow = timeline.find((r) => r.evidence_type === "decision-evidence");
    const badRow = timeline.find((r) => r.evidence_type === "execution-evidence");
    expect(goodRow?.verified).toBe(true);
    expect(badRow?.verified).toBe(false);
    expect(badRow?.detail).toContain("step 5");
  });
});
