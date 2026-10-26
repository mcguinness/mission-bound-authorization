/**
 * @spec runtime-evidence#decision-evidence-object, runtime#record-integrity
 * (#821, D814): "each emitter maintains its own monotonically increasing
 * per-Mission sequence", and the local minimum keeps that sequence
 * recoverable in durable, producer-owned storage. The PDP is the producer:
 * its counters live in its own durable claim file
 * (`IdempotencyClaimDomain.evidenceSequences`), so a restarted PDP continues
 * each stream instead of re-issuing a number already signed into a record
 * the claim store and the PEP retain.
 *
 * Every claim domain here is a real file in a fresh temporary directory, so
 * this file never skips.
 */

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalDigest } from "@mission/core";
import { describe, expect, it } from "vitest";
import {
  ClaimDomainUnavailableError,
  createDecisionEvidenceEmitter,
  DECISION_EVIDENCE_MEDIA_TYPE,
  type DecisionEvidenceEmissionInput,
  type DecisionEvidenceSequences,
  type IdempotencyClaimDomain,
  newRecordId,
  openIdempotencyClaimDomain,
  verifyEvidenceEnvelope,
} from "../src/index.js";
import { CLAIM_OWNER, statementWithPrivilegedAdministration } from "./claim-fixture.js";

const RESOURCE = "http://localhost:4403/mcp";
const ISSUER = "https://as.test";
const NOW = new Date("2026-10-25T12:00:00Z");

/** The PDP's claim domain on `file`: the same file across a restart. */
function openClaims(file: string): IdempotencyClaimDomain {
  return openIdempotencyClaimDomain({
    file,
    owner: CLAIM_OWNER,
    statement: statementWithPrivilegedAdministration(),
    now: () => NOW,
  });
}

const claimFile = (): string => join(mkdtempSync(join(tmpdir(), "pdp-evidence-sequence-")), "claims.sqlite");

/** One emitter: a fresh key per process, as the shipped PDP generates one per boot. */
function emitter(options: { emitterId?: string; sequences?: DecisionEvidenceSequences } = {}) {
  const emitterId = options.emitterId ?? RESOURCE;
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const kid = `pdp-821-${newRecordId("k")}`;
  const emit = createDecisionEvidenceEmitter({
    signer: { kid, key: privateKey },
    emitterId,
    audience: RESOURCE,
    ...(options.sequences ? { sequences: options.sequences } : {}),
  });
  const resolve = (params: { kid: string; emitter: { id: string; role: string }; audience?: string }) =>
    params.kid === kid && params.emitter.id === emitterId && params.emitter.role === "pdp" && params.audience === RESOURCE
      ? { key: publicKey }
      : undefined;
  return { emit: emit.emit, resolve };
}

/** A denial the PDP reached for `missionId`: no permit conditions to bind, so the record is minimal. */
const denial = (missionId: string): DecisionEvidenceEmissionInput => {
  const evaluation_id = newRecordId("evl");
  return {
    mission: { id: missionId, issuer: ISSUER, policy_view_id: `pv_${missionId}` },
    subject: { id: "alice" },
    resource: { type: "invoice", id: "inv-1" },
    action: { name: "payments:invoice.read" },
    action_class: "consequential_read",
    audience: RESOURCE,
    evaluation_id,
    decision: "deny",
    denial_reason: "out_of_authority",
    evaluated_at: NOW.toISOString(),
    evaluation_request_digest: canonicalDigest({ evaluation_id }),
  };
};

async function sequencesOf(
  emit: (input: DecisionEvidenceEmissionInput) => Promise<{ sequence: number }>,
  missionId: string,
  count: number,
): Promise<number[]> {
  const out: number[] = [];
  for (let i = 0; i < count; i += 1) out.push((await emit(denial(missionId))).sequence);
  return out;
}

describe("the PDP's Decision Evidence sequence is durable and producer-owned (@spec runtime-evidence#decision-evidence-object, runtime#record-integrity, #821)", () => {
  it("continues a Mission's sequence across a PDP restart on the same claim file, re-issuing no number", async () => {
    const file = claimFile();
    const first = openClaims(file);
    const before = emitter({ sequences: first.evidenceSequences() });
    const issuedBefore = await sequencesOf(before.emit, "msn_821", 3);
    first.close();

    // A new process: a new key, a new emitter, the same file.
    const reopened = openClaims(file);
    try {
      const after = emitter({ sequences: reopened.evidenceSequences() });
      const records = [await after.emit(denial("msn_821")), await after.emit(denial("msn_821"))];
      const issued = [...issuedBefore, ...records.map((r) => r.sequence)];
      expect(issued).toEqual([0, 1, 2, 3, 4]);
      expect(new Set(issued).size).toBe(issued.length);
      // The continued records are signed as before: the record format is unchanged.
      for (const record of records) {
        expect(await verifyEvidenceEnvelope(record, DECISION_EVIDENCE_MEDIA_TYPE, after.resolve)).toEqual({ valid: true });
        expect(record.emitter).toEqual({ id: RESOURCE, role: "pdp" });
      }
    } finally {
      reopened.close();
    }
  });

  it("keeps a distinct counter for each Mission and each emitter, across a restart", async () => {
    const file = claimFile();
    const first = openClaims(file);
    const pdpA = emitter({ sequences: first.evidenceSequences() });
    const pdpB = emitter({ emitterId: "https://pdp-b.example/mcp", sequences: first.evidenceSequences() });
    expect(await sequencesOf(pdpA.emit, "msn_a", 2)).toEqual([0, 1]);
    expect(await sequencesOf(pdpA.emit, "msn_b", 1)).toEqual([0]);
    expect(await sequencesOf(pdpB.emit, "msn_a", 3)).toEqual([0, 1, 2]);
    first.close();

    const reopened = openClaims(file);
    try {
      const againA = emitter({ sequences: reopened.evidenceSequences() });
      const againB = emitter({ emitterId: "https://pdp-b.example/mcp", sequences: reopened.evidenceSequences() });
      expect(await sequencesOf(againA.emit, "msn_a", 1)).toEqual([2]);
      expect(await sequencesOf(againA.emit, "msn_b", 1)).toEqual([1]);
      expect(await sequencesOf(againB.emit, "msn_a", 1)).toEqual([3]);
      // A Mission of the same id under another issuer is another Mission.
      const otherIssuer = { ...denial("msn_a"), mission: { id: "msn_a", issuer: "https://other-as.test", policy_view_id: "pv_x" } };
      expect((await againA.emit(otherIssuer)).sequence).toBe(0);
    } finally {
      reopened.close();
    }
  });

  it("fails the emission closed when the durable source is unreachable: no record is signed", async () => {
    const claims = openClaims(claimFile());
    const pdp = emitter({ sequences: claims.evidenceSequences() });
    expect((await pdp.emit(denial("msn_821"))).sequence).toBe(0);
    claims.close();
    await expect(pdp.emit(denial("msn_821"))).rejects.toBeInstanceOf(ClaimDomainUnavailableError);
  });

  it("without a configured source the counter stays in process memory and a new emitter starts at zero", async () => {
    const first = emitter();
    expect(await sequencesOf(first.emit, "msn_821", 3)).toEqual([0, 1, 2]);
    expect(await sequencesOf(first.emit, "msn_other", 1)).toEqual([0]);
    const restarted = emitter();
    expect(await sequencesOf(restarted.emit, "msn_821", 1)).toEqual([0]);
  });
});
