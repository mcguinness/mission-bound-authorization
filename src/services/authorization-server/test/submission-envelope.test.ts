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
 *  - the envelope top level is closed and strict-parsed; the semantic-intent
 *    rules are enforced unchanged on the inner `intent`;
 *  - Intent Submission Evidence intake, TWO-STAGE: stage-1 synchronous
 *    structural validation at parse (typed entries, unknown type refused —
 *    the SHIPPED registry is empty, so every presented type is unknown —
 *    non-empty array, count/size bounds, nothing silently ignored); stage-2
 *    ASYNC per-type verification (provisional intent_hash + issuer +
 *    presenter + now in; normalized recordable facts out; every failure
 *    invalid_mission_intent_evidence);
 *  - the anti-downgrade hook: a policy-REQUIRED evidence type absent from the
 *    submission refuses it; success without evidence never satisfies a
 *    requirement;
 *  - END-TO-END fact propagation: a test evidence type (registered by THIS
 *    file only) submitted through PAR is verified, rendered to the Approver
 *    ("Verified intent provenance"), and lands request-derived on the Mission
 *    Record's `submission_evidence` — outside all integrity anchors;
 *  - the D69 creation fingerprint includes presented `evidence`: the same
 *    inputs with different evidence produce a MISMATCH, never a silent replay.
 */

import { TEST_APPROVAL_PRINCIPALS, trustedApprovalHeaders } from "./approval-fixture.js";

import { type Server } from "node:http";
import { computeAnchor, intentHash, MISSION_INTENT_EVIDENCE_TYP } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { generateKeyPair, importJWK, SignJWT, type CryptoKey } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  creationFingerprint,
  type MissionCreationFingerprintInput,
} from "../src/kernel/creation-idempotency.js";
import {
  buildAuthorizationServer,
  DEFAULT_MAX_EVIDENCE_ENTRIES,
  INTENT_SUBMISSION_EVIDENCE_TYPES,
  IntentError,
  type BuiltAs,
  type IntentSubmissionEvidenceVerifyInput,
  registerIntentSubmissionEvidenceType,
  unregisterIntentSubmissionEvidenceType,
  validateIntentSubmissionEvidence,
  validateMissionIntent,
  validateMissionIntentSubmission,
  verifyIntentSubmissionEvidence,
} from "../src/index.js";

const ISS = "https://as.example.com";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;

const TASK_INTENT = {
  goal: "Reconcile Q3 invoices",
  target_resources: [RESOURCE],
  expires_at: "2027-01-01T00:00:00Z",
};

/** An UNREGISTERED type: every use below must be refused as unknown. */
const EVIDENCE_ENTRY = {
  type: "urn:ietf:params:oauth:mission:intent-evidence:intent-admission",
  assertion: "eyJhbGciOiJFUzI1NiJ9..sig",
};

// The SHIPPED registry size, captured BEFORE this file registers its test
// fixture: the implementation ships with NO evidence types (lock decision 3).
const SHIPPED_REGISTRY_SIZE = INTENT_SUBMISSION_EVIDENCE_TYPES.size;

// ---------------------------------------------------------------------------
// The TEST evidence type (registered by THIS FILE ONLY; the shipped registry
// stays empty). Two-stage: closed {type, assertion} schema at stage 1; the
// stage-2 verifier records its input and returns normalized facts, and can be
// flipped to fail (freshness-lapse simulation).
// ---------------------------------------------------------------------------
const TEST_TYPE = "urn:test:intent-evidence:stub";
let verifierMode: "ok" | "fail" = "ok";
let lastVerifyInput: IntentSubmissionEvidenceVerifyInput | undefined;
registerIntentSubmissionEvidenceType(TEST_TYPE, {
  validate(entry) {
    if (typeof entry.assertion !== "string" || entry.assertion.length === 0) {
      throw new IntentError("invalid_mission_intent_evidence", "stub: assertion (string) required");
    }
    for (const k of Object.keys(entry)) {
      if (k !== "type" && k !== "assertion") {
        throw new IntentError("invalid_mission_intent_evidence", `stub: unknown member: ${k}`);
      }
    }
  },
  async verify(input) {
    lastVerifyInput = input;
    if (verifierMode === "fail") throw new Error("stub artifact expired");
    return {
      admission_issuer: "https://admission.example",
      presenter_client: input.presenter.clientId,
      bound_intent_hash: input.intentHash,
    };
  },
});
afterAll(() => unregisterIntentSubmissionEvidenceType(TEST_TYPE));

const TEST_ENTRY = { type: TEST_TYPE, assertion: "stub-assertion-artifact" };

function refusal(fn: () => unknown): IntentError {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(IntentError);
    return e as IntentError;
  }
  expect.unreachable("expected an IntentError refusal");
}

async function asyncRefusal(fn: () => Promise<unknown>): Promise<IntentError> {
  try {
    await fn();
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

describe("Intent Submission Evidence intake, stage 1 (@spec mission#intent-submission-evidence)", () => {
  it("the SHIPPED registry is EMPTY: no evidence types are implemented", () => {
    expect(SHIPPED_REGISTRY_SIZE).toBe(0);
  });

  it("refuses an unknown evidence type with the registered error code", () => {
    const e = refusal(() =>
      validateMissionIntentSubmission(
        JSON.stringify({ intent: TASK_INTENT, evidence: [EVIDENCE_ENTRY] }),
      ),
    );
    // @spec mission#intent-submission-evidence — type-dispatch failures carry
    // the core-registered invalid_mission_intent_evidence; STRUCTURAL envelope
    // failures (bare shape, missing type, bounds) stay invalid_request.
    expect(e.code).toBe("invalid_mission_intent_evidence");
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

  it("refuses an EMPTY evidence array (evidence, when present, is non-empty)", () => {
    const e = refusal(() =>
      validateMissionIntentSubmission(JSON.stringify({ intent: TASK_INTENT, evidence: [] })),
    );
    expect(e.code).toBe("invalid_request");
    expect(e.message).toContain("evidence must be a non-empty array");
  });

  it("bounds the entry COUNT (config default, overridable)", () => {
    const tooMany = Array.from({ length: DEFAULT_MAX_EVIDENCE_ENTRIES + 1 }, () => EVIDENCE_ENTRY);
    const e = refusal(() =>
      validateMissionIntentSubmission(JSON.stringify({ intent: TASK_INTENT, evidence: tooMany })),
    );
    expect(e.code).toBe("invalid_request");
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
    expect(e.code).toBe("invalid_request");
    expect(e.message).toContain("size bound");
  });

  it("a REGISTERED type passes stage 1 at parse; its OWN closed schema is enforced there", () => {
    // Stage 1 passes: the parsed submission carries the entry (verification is
    // stage 2, not the parser's job).
    const submission = validateMissionIntentSubmission(
      JSON.stringify({ intent: TASK_INTENT, evidence: [TEST_ENTRY] }),
    );
    expect(submission.evidence).toEqual([TEST_ENTRY]);
    // The type owns its members: a member outside {type, assertion} refuses.
    const e = refusal(() =>
      validateMissionIntentSubmission(
        JSON.stringify({ intent: TASK_INTENT, evidence: [{ ...TEST_ENTRY, extra: 1 }] }),
      ),
    );
    expect(e.code).toBe("invalid_mission_intent_evidence");
    expect(e.message).toContain("unknown member: extra");
    // ...and a structurally bad entry of the registered type refuses too.
    const e2 = refusal(() =>
      validateMissionIntentSubmission(
        JSON.stringify({ intent: TASK_INTENT, evidence: [{ type: TEST_TYPE, assertion: 5 }] }),
      ),
    );
    expect(e2.message).toContain("assertion (string) required");
  });

  it("the standalone stage-1 validator applies the same rules", () => {
    expect(validateIntentSubmissionEvidence(undefined)).toBeUndefined();
    expect(refusal(() => validateIntentSubmissionEvidence([])).message).toContain("non-empty");
    const e = refusal(() => validateIntentSubmissionEvidence([EVIDENCE_ENTRY as never]));
    expect(e.message).toContain("unknown evidence type");
  });
});

describe("stage-2 verification (@spec mission#intent-submission-evidence)", () => {
  const NOW = new Date("2026-08-13T12:00:00Z");
  const CTX = {
    intentHash: intentHash(ISS, TASK_INTENT as never),
    issuer: ISS,
    presenter: { clientId: "ap-agent", cnf: { jkt: "jkt-abc" } },
    now: NOW,
  };

  it("hands the verifier the provisional intent_hash, issuer, presenter, and now; lands normalized facts", async () => {
    verifierMode = "ok";
    lastVerifyInput = undefined;
    const facts = await verifyIntentSubmissionEvidence([TEST_ENTRY as never], CTX);
    // The verifier received the full verification context.
    expect(lastVerifyInput?.entry).toEqual(TEST_ENTRY);
    expect(lastVerifyInput?.intentHash).toBe(CTX.intentHash);
    expect(lastVerifyInput?.issuer).toBe(ISS);
    expect(lastVerifyInput?.presenter).toEqual(CTX.presenter);
    expect(lastVerifyInput?.now).toBe(NOW);
    // The normalized recordable fact: type + artifact digest (anchor idiom
    // over the entry AS PRESENTED) + verification time + verifier facts.
    expect(facts).toEqual([
      {
        type: TEST_TYPE,
        artifact_hash: computeAnchor(MISSION_INTENT_EVIDENCE_TYP, ISS, TEST_ENTRY as never),
        verified_at: NOW.toISOString(),
        facts: {
          admission_issuer: "https://admission.example",
          presenter_client: "ap-agent",
          bound_intent_hash: CTX.intentHash,
        },
      },
    ]);
  });

  it("maps EVERY verification failure to invalid_mission_intent_evidence", async () => {
    verifierMode = "fail";
    const e = await asyncRefusal(() => verifyIntentSubmissionEvidence([TEST_ENTRY as never], CTX));
    verifierMode = "ok";
    expect(e.code).toBe("invalid_mission_intent_evidence");
    expect(e.message).toContain("stub artifact expired");
  });

  it("anti-downgrade: a policy-REQUIRED type absent from the submission refuses", async () => {
    // Absent entirely: successful processing WITHOUT evidence never satisfies
    // an evidence requirement.
    const e = await asyncRefusal(() => verifyIntentSubmissionEvidence(undefined, CTX, [TEST_TYPE]));
    expect(e.code).toBe("invalid_mission_intent_evidence");
    expect(e.message).toContain(`required evidence type absent: ${TEST_TYPE}`);
    // Presenting OTHER evidence does not satisfy the requirement either.
    const e2 = await asyncRefusal(() =>
      verifyIntentSubmissionEvidence([TEST_ENTRY as never], CTX, ["urn:test:other-required"]),
    );
    expect(e2.message).toContain("required evidence type absent: urn:test:other-required");
    // The requirement satisfied verifies normally.
    const facts = await verifyIntentSubmissionEvidence([TEST_ENTRY as never], CTX, [TEST_TYPE]);
    expect(facts?.[0]?.type).toBe(TEST_TYPE);
  });

  it("no evidence and no requirement verifies to no facts", async () => {
    expect(await verifyIntentSubmissionEvidence(undefined, CTX)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// END-TO-END: PAR -> approval render -> decide -> Mission Record, with the
// test evidence type on the wire. The record's submission_evidence is
// REQUEST-DERIVED (verifier output), never fabricated.
// ---------------------------------------------------------------------------

const PORT = 14531;
const ISSUER_E2E = `http://localhost:${PORT}`;
const REQUIRED_PORT = 14532;
const REQUIRED_ISSUER = `http://localhost:${REQUIRED_PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";

let e2eAs: BuiltAs;
let e2eServer: Server;
let requiredAs: BuiltAs;
let requiredServer: Server;
let agentKey: CryptoKey;
let requiredAgentKey: CryptoKey;

const PKCE_VERIFIER = "submission-envelope-verifier-0123456789-0123456789";
async function pkceChallenge(): Promise<string> {
  return Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER)),
  ).toString("base64url");
}

async function clientAssertion(issuer: string, key: CryptoKey): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(issuer)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(key);
}

async function pushPar(issuer: string, key: CryptoKey, params: Record<string, string>): Promise<Response> {
  return fetch(`${issuer}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "payments",
      resource: RESOURCE,
      code_challenge: await pkceChallenge(),
      code_challenge_method: "S256",
      ...params,
      client_assertion: await clientAssertion(issuer, key),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
}

beforeAll(async () => {
  e2eAs = await buildAuthorizationServer({ issuer: ISSUER_E2E, allowHeadlessAdjudication: true, serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS });
  e2eServer = e2eAs.provider.listen(PORT);
  agentKey = (await importJWK(e2eAs.agentClientJwk as never, "ES256")) as CryptoKey;
  // A second AS whose GLOBAL policy REQUIRES the test evidence type (the
  // config-driven anti-downgrade hook).
  requiredAs = await buildAuthorizationServer({
    issuer: REQUIRED_ISSUER,
    allowHeadlessAdjudication: true, serviceTokenPrincipals: TEST_APPROVAL_PRINCIPALS,
    requiredIntentEvidenceTypes: [TEST_TYPE],
  });
  requiredServer = requiredAs.provider.listen(REQUIRED_PORT);
  requiredAgentKey = (await importJWK(requiredAs.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  e2eServer?.close();
  requiredServer?.close();
});

describe("end-to-end verified facts on the Mission Record (@spec mission#intent-submission-evidence)", () => {
  it("PAR-submitted evidence is verified, RENDERED to the Approver, and landed request-derived on submission_evidence — outside all anchors", async () => {
    verifierMode = "ok";
    const cookies = new Map<string, string>();
    const cookieHeader = () => [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    const storeCookies = (res: Response) => {
      for (const line of res.headers.getSetCookie()) {
        const [pair] = line.split(";");
        const eq = (pair as string).indexOf("=");
        cookies.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
      }
    };

    const par = await pushPar(ISSUER_E2E, agentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT, evidence: [TEST_ENTRY] }),
    });
    expect(par.status, await par.clone().text()).toBe(201);
    const { request_uri } = (await par.json()) as { request_uri: string };

    let res = await fetch(
      `${ISSUER_E2E}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`,
      { redirect: "manual" },
    );
    storeCookies(res);
    const location = res.headers.get("location") as string;
    const uid = location.split("/interaction/")[1] as string;

    // The approval RENDERING covers the verified provenance facts (material
    // verified provenance is INPUT to approval).
    const page = await fetch(`${ISSUER_E2E}/interaction/${uid}`, {
      headers: { cookie: cookieHeader() },
    });
    const html = await page.text();
    expect(html).toContain("Verified intent provenance");
    expect(html).toContain("admission.example");

    res = await fetch(`${ISSUER_E2E}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { ...trustedApprovalHeaders(), "content-type": "application/json", cookie: cookieHeader() },
      body: JSON.stringify({ decision: "approve" }),
    });
    expect(res.status, await res.clone().text()).toBe(303);

    // The record exists (decide() ran kernel.approve) with REQUEST-DERIVED facts.
    const record = e2eAs.kernel.findByApprovalEvent(`apev_${uid}`);
    expect(record).toBeDefined();
    const facts = record?.submission_evidence;
    expect(facts).toHaveLength(1);
    expect(facts?.[0]?.type).toBe(TEST_TYPE);
    expect(facts?.[0]?.artifact_hash).toBe(
      computeAnchor(MISSION_INTENT_EVIDENCE_TYP, ISSUER_E2E, TEST_ENTRY as never),
    );
    expect(Number.isNaN(Date.parse(facts?.[0]?.verified_at ?? ""))).toBe(false);
    // The verifier's facts landed verbatim, and the provisional hash the
    // verifier was bound to IS the recorded intent_hash commitment.
    expect(facts?.[0]?.facts).toEqual({
      admission_issuer: "https://admission.example",
      presenter_client: "ap-agent",
      bound_intent_hash: record?.intent_hash,
    });
    // Facts stay OUTSIDE the anchors: intent_hash commits exactly the
    // semantic intent, identical to an evidence-free submission of it.
    expect(record?.intent_hash).toBe(intentHash(ISSUER_E2E, TASK_INTENT as never));
    // Round-trips through the store.
    expect(e2eAs.kernel.get(record?.id ?? "")?.submission_evidence).toEqual(facts);
  });

  it("anti-downgrade on the wire: a required type absent refuses the PAR submission; presenting it proceeds", async () => {
    verifierMode = "ok";
    const absent = await pushPar(REQUIRED_ISSUER, requiredAgentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
    });
    expect(absent.status).toBe(400);
    const body = (await absent.json()) as { error: string; error_description?: string };
    expect(body.error).toBe("invalid_mission_intent_evidence");
    expect(body.error_description).toContain(`required evidence type absent: ${TEST_TYPE}`);

    const present = await pushPar(REQUIRED_ISSUER, requiredAgentKey, {
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT, evidence: [TEST_ENTRY] }),
    });
    expect(present.status, await present.clone().text()).toBe(201);
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
