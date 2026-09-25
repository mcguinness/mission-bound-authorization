/**
 * @spec runtime-evidence#execution-evidence-object
 *
 * "Exactly one Execution Evidence Object exists per final disposition of a
 * permit, and delivery of that record is at-least-once, so a consumer MUST
 * deduplicate on `execution_id`."
 *
 * Issue #786 made one execution identity cover one disposition attempt and
 * every emission retry of it. PR #808's review found the identity was only
 * checked against RETAINED rows, which leaves the whole signing await open:
 * two emissions of the same disposition, exactly what an at-least-once retry
 * produces, both miss the lookup and both retain. These tests drive both
 * interleavings through a gated signer, so neither the emission that resolves
 * first nor the one that resolves second can leave a second row behind.
 *
 * The guarantee the same review established stays under test here too: a
 * DIFFERENT disposition under one identity is refused in the in-flight window
 * as well as against a retained row, so no rejected replay can take a
 * completed record's identity while its signature is still outstanding.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The signer gate. `signEvidenceEnvelope` is the one await inside
 * `EvidenceStore.recordExecution`, so holding it holds an emission exactly
 * where the race lives. Each held call parks a resolver in `waiting`, and the
 * test releases them in the order the interleaving under test requires.
 */
const gate = vi.hoisted(() => ({ held: false, waiting: [] as Array<() => void> }));

vi.mock("@mission/pdp", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@mission/pdp")>();
  return {
    ...actual,
    signEvidenceEnvelope: vi.fn(async (...args: Parameters<typeof actual.signEvidenceEnvelope>) => {
      if (gate.held) {
        await new Promise<void>((resolve) => {
          gate.waiting.push(resolve);
        });
      }
      return actual.signEvidenceEnvelope(...args);
    }),
  };
});

import { signEvidenceEnvelope } from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  type ExecutionEvidence,
} from "../src/index.js";

const EVIDENCE_KEYS = createEphemeralEvidenceKeys();
const MISSION_ID = "msn_concurrent";

/** One disposition attempt, reused verbatim by every emission of it. */
function completedEmission(execution_id: string) {
  return {
    permitId: "dec_concurrent",
    opKey: "op:msn_concurrent:payments:payment.execute:sha-256:d",
    execution_id,
    evaluation_id: "dec_concurrent",
    mission_id: MISSION_ID,
    audience: CANONICAL_RESOURCE,
    authorized_parameter_digest: "sha-256:d",
    effective_parameter_digest: "sha-256:d",
    outcome: "completed" as const,
  };
}

/**
 * Release the gated signatures in `order`, by arrival index. An index with no
 * held call is skipped: coalescing means the second emission never signs, so
 * there is then nothing left to interleave.
 */
function release(order: readonly number[]): void {
  const held = gate.waiting.splice(0, gate.waiting.length);
  for (const index of order) {
    held[index]?.();
  }
}

/**
 * Two concurrent emissions of ONE disposition under one execution identity,
 * with their signatures released in `order`. Returns what each caller got
 * back, plus the store, so each interleaving asserts the same invariants.
 */
async function raceOneDisposition(order: readonly number[]): Promise<{
  evidence: EvidenceStore;
  first: ExecutionEvidence;
  second: ExecutionEvidence;
}> {
  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  gate.held = true;
  // Both callers enter before either signature returns: the at-least-once
  // retry of a pending emission, overlapping its own first attempt.
  const a = evidence.recordExecution(CANONICAL_RESOURCE, "executor", completedEmission("exe_concurrent"));
  const b = evidence.recordExecution(CANONICAL_RESOURCE, "executor", completedEmission("exe_concurrent"));
  await Promise.resolve();
  release(order);
  const [first, second] = await Promise.all([a, b]);
  gate.held = false;
  return { evidence, first, second };
}

/** The invariants both interleavings owe: one signature, one row, one result. */
async function expectOneRecord(raced: {
  evidence: EvidenceStore;
  first: ExecutionEvidence;
  second: ExecutionEvidence;
}): Promise<void> {
  expect(signEvidenceEnvelope).toHaveBeenCalledTimes(1);
  expect(raced.evidence.forMission(MISSION_ID)).toHaveLength(1);
  expect(raced.first).toBe(raced.second);
  expect(raced.first.content.execution_id).toBe("exe_concurrent");
  // The coalesced caller consumed no sequence number either: a burned number
  // would leave a gap no emitted record accounts for.
  const next = await raced.evidence.recordExecution(
    CANONICAL_RESOURCE,
    "executor",
    completedEmission("exe_next"),
  );
  expect(next.content.sequence).toBe(raced.first.content.sequence + 1);
}

describe("one execution identity survives concurrent emission", () => {
  beforeEach(() => {
    gate.held = false;
    gate.waiting.length = 0;
    vi.mocked(signEvidenceEnvelope).mockClear();
  });

  it("collapses two concurrent emissions of one disposition to one record when the first signature returns first", async () => {
    await expectOneRecord(await raceOneDisposition([0, 1]));
  });

  it("collapses two concurrent emissions of one disposition to one record when the second signature returns first", async () => {
    await expectOneRecord(await raceOneDisposition([1, 0]));
  });

  it("refuses a different disposition presented under an identity whose signature is still in flight", async () => {
    const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
    gate.held = true;

    const completed = evidence.recordExecution(CANONICAL_RESOURCE, "executor", completedEmission("exe_inflight"));
    // A rejected replay taking the completed attempt's identity, arriving
    // while that attempt's signature is outstanding rather than after it.
    const replay = evidence.recordExecution(CANONICAL_RESOURCE, "pep", {
      permitId: "dec_replay",
      opKey: "op:msn_concurrent:payments:payment.execute:sha-256:d",
      execution_id: "exe_inflight",
      evaluation_id: "dec_replay",
      mission_id: MISSION_ID,
      audience: CANONICAL_RESOURCE,
      outcome: "suppressed" as const,
      error: "operation_already_claimed",
    });
    const replayOutcome = replay.then(
      () => undefined,
      (error: unknown) => error as Error,
    );
    release([0, 1]);

    const refusal = await replayOutcome;
    expect(refusal).toBeInstanceOf(Error);
    expect(refusal?.message).toMatch(/different disposition/);

    const record = await completed;
    expect(record.content.outcome).toBe("completed");
    const retained = evidence.forMission(MISSION_ID);
    expect(retained).toHaveLength(1);
    expect((retained[0] as ExecutionEvidence).content.outcome).toBe("completed");
    expect(signEvidenceEnvelope).toHaveBeenCalledTimes(1);
  });
});
