/**
 * @spec mission#submission-via-par, mission#intent-submission-evidence,
 * expansion#creation-fingerprint — issue #506.
 *
 * The Mission Intent Submission envelope: the `mission_intent` parameter VALUE
 * is `{intent, evidence?}` with its OWN closed top level. Covered here:
 *  - the envelope is accepted and yields the SAME semantic intent (and the
 *    SAME `intent_hash`) as the pre-envelope bare shape — anchors and vectors
 *    are stable across the carriage change;
 *  - the retired bare-Intent parameter shape is refused (invalid_request);
 *  - the envelope top level is closed and strict-parsed;
 *  - the semantic-intent rules are enforced unchanged on the inner `intent`;
 *  - Intent Submission Evidence intake: entries typed (REQUIRED `type`),
 *    unknown type refused (the registry is EMPTY today, so EVERY presented
 *    type is unknown — the correct shipped state), malformed entries refused,
 *    count/size bounds enforced, nothing silently ignored;
 *  - verified-fact record plumbing: `submission_evidence` lands on the Mission
 *    Record OUTSIDE all integrity anchors and round-trips through the store;
 *  - the D69 creation fingerprint includes presented `evidence`: the same
 *    inputs with different evidence produce a MISMATCH, never a silent replay.
 */

import { intentHash } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  creationFingerprint,
  type MissionCreationFingerprintInput,
} from "../src/kernel/creation-idempotency.js";
import {
  DEFAULT_MAX_EVIDENCE_ENTRIES,
  INTENT_SUBMISSION_EVIDENCE_TYPES,
  IntentError,
  MissionKernel,
  validateIntentSubmissionEvidence,
  validateMissionIntent,
  validateMissionIntentSubmission,
} from "../src/index.js";

const ISS = "https://as.example.com";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;

const TASK_INTENT = {
  goal: "Reconcile Q3 invoices",
  resources: [RESOURCE],
  expires_at: "2027-01-01T00:00:00Z",
};

const EVIDENCE_ENTRY = {
  type: "urn:ietf:params:oauth:mission:intent-evidence:intent-admission",
  assertion: "eyJhbGciOiJFUzI1NiJ9..sig",
};

function refusal(fn: () => unknown): IntentError {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(IntentError);
    return e as IntentError;
  }
  expect.unreachable("expected an IntentError refusal");
}

describe("Submission envelope parse (@spec mission#submission-via-par)", () => {
  it("accepts {intent} and returns the semantic intent unchanged", () => {
    const submission = validateMissionIntentSubmission(JSON.stringify({ intent: TASK_INTENT }));
    expect(submission.intent).toEqual(validateMissionIntent(JSON.stringify(TASK_INTENT)));
    expect(submission.evidence).toBeUndefined();
  });

  it("intent_hash commits exactly the inner semantic intent (anchor-stable across the carriage change)", () => {
    const submission = validateMissionIntentSubmission(JSON.stringify({ intent: TASK_INTENT }));
    const bare = validateMissionIntent(JSON.stringify(TASK_INTENT));
    // The envelope never enters the commitment: hashing the envelope-parsed
    // intent equals hashing the pre-envelope bare intent, byte for byte.
    expect(intentHash(ISS, submission.intent as never)).toBe(intentHash(ISS, bare as never));
  });

  it("refuses the retired bare-Intent parameter shape explicitly", () => {
    const e = refusal(() => validateMissionIntentSubmission(JSON.stringify(TASK_INTENT)));
    expect(e.code).toBe("invalid_request");
    expect(e.message).toContain("bare Mission Intent shape");
  });

  it("closed envelope top level: an unknown submission member is refused", () => {
    const e = refusal(() =>
      validateMissionIntentSubmission(
        JSON.stringify({ intent: TASK_INTENT, controls: { max_derivations: 3 } }),
      ),
    );
    expect(e.code).toBe("invalid_request");
    expect(e.message).toContain("unknown submission member: controls");
  });

  it("strict parse: duplicate member names in the envelope are refused", () => {
    expect(() =>
      validateMissionIntentSubmission(
        `{"intent":${JSON.stringify(TASK_INTENT)},"intent":${JSON.stringify(TASK_INTENT)}}`,
      ),
    ).toThrow(/duplicate/i);
  });

  it("intent must be a JSON object", () => {
    const e = refusal(() => validateMissionIntentSubmission(JSON.stringify({ intent: "goal" })));
    expect(e.message).toContain("intent must be a JSON object");
  });

  it("the semantic-intent rules apply unchanged to the inner intent", () => {
    // Missing required members.
    expect(() => validateMissionIntentSubmission(JSON.stringify({ intent: { goal: "x" } }))).toThrow(
      IntentError,
    );
    // The retired proposed_authority member fails the INNER closed top level.
    const e = refusal(() =>
      validateMissionIntentSubmission(
        JSON.stringify({ intent: { ...TASK_INTENT, proposed_authority: [] } }),
      ),
    );
    expect(e.message).toContain("unknown top-level member: proposed_authority");
  });
});

describe("Intent Submission Evidence intake (@spec mission#intent-submission-evidence)", () => {
  it("the registry is EMPTY: no evidence types are implemented", () => {
    expect(INTENT_SUBMISSION_EVIDENCE_TYPES.size).toBe(0);
  });

  it("refuses an unknown evidence type (every presented type today)", () => {
    const e = refusal(() =>
      validateMissionIntentSubmission(
        JSON.stringify({ intent: TASK_INTENT, evidence: [EVIDENCE_ENTRY] }),
      ),
    );
    expect(e.code).toBe("invalid_request");
    expect(e.message).toContain(`unknown evidence type: ${EVIDENCE_ENTRY.type}`);
  });

  it("refuses an entry without a type (and an empty-string type)", () => {
    for (const entry of [{ assertion: "eyJ" }, { type: "", assertion: "eyJ" }]) {
      const e = refusal(() =>
        validateMissionIntentSubmission(JSON.stringify({ intent: TASK_INTENT, evidence: [entry] })),
      );
      expect(e.code).toBe("invalid_request");
      expect(e.message).toContain("evidence entries require a type");
    }
  });

  it("refuses a non-object entry and a non-array evidence member", () => {
    expect(
      refusal(() =>
        validateMissionIntentSubmission(JSON.stringify({ intent: TASK_INTENT, evidence: ["eyJ"] })),
      ).message,
    ).toContain("evidence entries must be objects");
    expect(
      refusal(() =>
        validateMissionIntentSubmission(
          JSON.stringify({ intent: TASK_INTENT, evidence: { type: "x" } }),
        ),
      ).message,
    ).toContain("evidence must be a JSON array");
  });

  it("normalizes an empty evidence array to absent (mirrors the proposal rule)", () => {
    const submission = validateMissionIntentSubmission(
      JSON.stringify({ intent: TASK_INTENT, evidence: [] }),
    );
    expect(submission.evidence).toBeUndefined();
  });

  it("bounds the entry COUNT (config default, overridable)", () => {
    const tooMany = Array.from({ length: DEFAULT_MAX_EVIDENCE_ENTRIES + 1 }, () => EVIDENCE_ENTRY);
    const e = refusal(() =>
      validateMissionIntentSubmission(JSON.stringify({ intent: TASK_INTENT, evidence: tooMany })),
    );
    expect(e.message).toContain("entry-count bound");
    // A narrowed deployment bound refuses earlier.
    const e2 = refusal(() =>
      validateMissionIntentSubmission(
        JSON.stringify({ intent: TASK_INTENT, evidence: [EVIDENCE_ENTRY, EVIDENCE_ENTRY] }),
        { maxEvidenceEntries: 1 },
      ),
    );
    expect(e2.message).toContain("entry-count bound (1)");
  });

  it("bounds the per-entry SIZE (config default, overridable)", () => {
    const big = { type: "x", blob: "A".repeat(128) };
    const e = refusal(() =>
      validateMissionIntentSubmission(
        JSON.stringify({ intent: TASK_INTENT, evidence: [big] }),
        { maxEvidenceEntryBytes: 64 },
      ),
    );
    expect(e.message).toContain("size bound");
  });

  it("the standalone evidence validator applies the same rules", () => {
    expect(validateIntentSubmissionEvidence(undefined)).toBeUndefined();
    expect(validateIntentSubmissionEvidence([])).toBeUndefined();
    const e = refusal(() => validateIntentSubmissionEvidence([EVIDENCE_ENTRY as never]));
    expect(e.message).toContain("unknown evidence type");
  });
});

describe("verified-fact record plumbing (@spec mission#intent-submission-evidence)", () => {
  let kernel: MissionKernel;
  beforeAll(async () => {
    const { privateKey } = await generateKeyPair("ES256");
    kernel = new MissionKernel({
      issuer: ISS,
      policy: DERIVATION_POLICY as never,
      statusKey: privateKey,
      statusKid: "as-status",
    });
  });

  const approve = (n: number, facts?: { type: string; artifact_hash: string; verified_at: string }[]) =>
    kernel.approve({
      intent: validateMissionIntent(JSON.stringify(TASK_INTENT)),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: `apev-sub-${n}`,
      ...(facts ? { submissionEvidence: facts } : {}),
    });

  it("records verified facts on the Mission and round-trips through the store", () => {
    const fact = {
      type: "intent_admission",
      artifact_hash: "sha-256:0000000000000000000000000000000000000000000",
      verified_at: "2026-08-12T18:00:00Z",
    };
    const record = approve(1, [fact]);
    expect(record.submission_evidence).toEqual([fact]);
    expect(kernel.get(record.id)?.submission_evidence).toEqual([fact]);
  });

  it("verified facts stay OUTSIDE the integrity anchors", () => {
    const withFacts = approve(2, [
      { type: "intent_admission", artifact_hash: "sha-256:aaa", verified_at: "2026-08-12T18:00:00Z" },
    ]);
    const without = approve(3);
    expect(without.submission_evidence).toBeUndefined();
    // Same intent, same derivation: identical anchors regardless of recorded facts.
    expect(withFacts.intent_hash).toBe(without.intent_hash);
    expect(withFacts.authority_hash).toBe(without.authority_hash);
  });
});

describe("creation fingerprint includes evidence (@spec expansion#creation-fingerprint)", () => {
  const base: MissionCreationFingerprintInput = {
    op: "child-creation",
    iss: ISS,
    client: "ap-agent",
    source: "msn_parent",
    cnf: { jkt: "jkt-1" },
    actor: { iss: ISS, sub: "ap-agent" },
    intent: validateMissionIntent(JSON.stringify(TASK_INTENT)),
    child_actor: { sub: "subagent-a" },
    requested_token_type: "urn:ietf:params:oauth:token-type:jwt",
  };

  it("same creation inputs + different evidence => fingerprint MISMATCH (both exchanges)", () => {
    for (const op of ["child-creation", "expansion"] as const) {
      const input = { ...base, op };
      const noEvidence = creationFingerprint(input);
      const evidenceA = creationFingerprint({ ...input, evidence: [EVIDENCE_ENTRY as never] });
      const evidenceB = creationFingerprint({
        ...input,
        evidence: [{ ...EVIDENCE_ENTRY, assertion: "eyJhbGciOiJFUzI1NiJ9..other" } as never],
      });
      expect(evidenceA).not.toBe(noEvidence);
      expect(evidenceB).not.toBe(noEvidence);
      expect(evidenceA).not.toBe(evidenceB);
      // Determinism: the same presented evidence reproduces the fingerprint.
      expect(creationFingerprint({ ...input, evidence: [EVIDENCE_ENTRY as never] })).toBe(evidenceA);
    }
  });
});
