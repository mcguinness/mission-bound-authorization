/**
 * M10 scenario 11: transparent audit. Producers register Mission evidence as
 * Signed Statements committing by hash; the Transparency Service returns
 * Receipts; the operator assembles the mission feed and runs the five-step
 * offline verification. Tamper demo: mutated evidence fails the digest check;
 * a dropped/forged record fails the inclusion proof.
 */

import { exportJWK, generateKeyPair, type JWK } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  MerkleLog,
  leafHash,
  signStatement,
  TransparencyService,
  verifyInclusion,
  verifyTransparentStatement,
  type ProducerKey,
  type Receipt,
  type SignedStatement,
} from "../src/index.js";

const MISSION = "msn_audit_1";

let pdp: ProducerKey;
let pep: ProducerKey;
let producerJwks: { keys: JWK[] };
let service: TransparencyService;
let serviceJwks: { keys: JWK[] };

async function producer(iss: string, kid: string): Promise<{ pk: ProducerKey; pub: JWK }> {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const pub = { ...(await exportJWK(publicKey)), kid, alg: "ES256" };
  return { pk: { iss, key: privateKey, kid }, pub };
}

beforeAll(async () => {
  const p1 = await producer("https://pdp.test", "pdp-evidence");
  const p2 = await producer("https://pep.test", "pep-evidence");
  pdp = p1.pk;
  pep = p2.pk;
  producerJwks = { keys: [p1.pub, p2.pub] };
  const svcKeys = await generateKeyPair("ES256", { extractable: true });
  const svcPub = { ...(await exportJWK(svcKeys.publicKey)), kid: "transparency", alg: "ES256" };
  serviceJwks = { keys: [svcPub] };
  service = new TransparencyService({ key: svcKeys.privateKey, kid: "transparency", issuer: "https://transparency.test" });
});

describe("M10 Merkle log", () => {
  it("produces verifiable inclusion proofs for every leaf", () => {
    const log = new MerkleLog();
    const leaves = Array.from({ length: 7 }, (_, i) => leafHash(Buffer.from(`e${i}`)));
    leaves.forEach((l) => log.append(l));
    const root = log.root();
    for (let i = 0; i < leaves.length; i += 1) {
      expect(verifyInclusion(leaves[i] as Buffer, i, 7, log.proof(i), root)).toBe(true);
    }
    // A wrong leaf does not verify.
    expect(verifyInclusion(leafHash(Buffer.from("nope")), 0, 7, log.proof(0), root)).toBe(false);
  });
});

describe("M10 scenario 11: transparent audit + tamper demo", () => {
  const decisionEvidence = { kind: "decision", decision: true, action: "payments:payment.execute", parameter_digest: "sha-256:pd", mission_id: MISSION };
  const executionEvidence = { kind: "execution", op_key: "op:1", outcome: "committed", mission_id: MISSION };
  let stmtD: SignedStatement;
  let rcptD: Receipt;
  let stmtE: SignedStatement;
  let rcptE: Receipt;

  it("registers Decision and Execution Evidence and returns Receipts", async () => {
    stmtD = await signStatement(pdp, { missionId: MISSION, evidenceType: "decision-evidence", evidence: decisionEvidence });
    rcptD = await service.register(stmtD);
    stmtE = await signStatement(pep, { missionId: MISSION, evidenceType: "execution-evidence", evidence: executionEvidence });
    rcptE = await service.register(stmtE);
    expect(rcptD.index).toBe(0);
    expect(rcptE.index).toBe(1);
    expect(service.treeHead().size).toBe(2);
  });

  it("the mission feed collects both statements", () => {
    const feed = service.feed(MISSION);
    expect(feed).toHaveLength(2);
    expect(feed.map((s) => s.producer).sort()).toEqual(["https://pdp.test", "https://pep.test"]);
  });

  it("five-step offline verification passes for a genuine record", async () => {
    const res = await verifyTransparentStatement({
      statement: stmtD,
      receipt: rcptD,
      evidence: decisionEvidence,
      producerJwks,
      serviceJwks,
      expectedMissionId: MISSION,
    });
    expect(res).toEqual({ ok: true });
  });

  it("tamper: mutated evidence fails at step 5 (digest mismatch)", async () => {
    const mutated = { ...decisionEvidence, decision: false }; // flip the decision
    const res = await verifyTransparentStatement({
      statement: stmtD,
      receipt: rcptD,
      evidence: mutated,
      producerJwks,
      serviceJwks,
      expectedMissionId: MISSION,
    });
    expect(res).toEqual({ ok: false, step: 5, reason: expect.stringContaining("digest") });
  });

  it("tamper: a forged statement not in the log fails at step 3 (inclusion)", async () => {
    const forged = await signStatement(pdp, {
      missionId: MISSION,
      evidenceType: "decision-evidence",
      evidence: { kind: "decision", decision: true, forged: true, mission_id: MISSION },
    });
    // Present it with a real receipt (for the genuine statement) -- inclusion fails.
    const res = await verifyTransparentStatement({
      statement: forged,
      receipt: rcptD,
      evidence: { kind: "decision", decision: true, forged: true, mission_id: MISSION },
      producerJwks,
      serviceJwks,
      expectedMissionId: MISSION,
    });
    expect(res).toEqual({ ok: false, step: 3, reason: expect.stringContaining("inclusion") });
  });

  it("wrong mission subject fails at step 4", async () => {
    const res = await verifyTransparentStatement({
      statement: stmtE,
      receipt: rcptE,
      evidence: executionEvidence,
      producerJwks,
      serviceJwks,
      expectedMissionId: "msn_other",
    });
    expect(res).toEqual({ ok: false, step: 4, reason: expect.stringContaining("Mission") });
  });

  it("an untrusted producer key fails at step 1", async () => {
    const stranger = await producer("https://evil.test", "evil");
    const stmt = await signStatement(stranger.pk, { missionId: MISSION, evidenceType: "decision-evidence", evidence: decisionEvidence });
    const rcpt = await service.register(stmt);
    const res = await verifyTransparentStatement({
      statement: stmt,
      receipt: rcpt,
      evidence: decisionEvidence,
      producerJwks, // does not include the stranger's key
      serviceJwks,
      expectedMissionId: MISSION,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.step).toBe(1);
  });
});
