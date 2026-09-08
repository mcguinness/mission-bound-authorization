/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#mission-receipt (lines
 * 1236-1662 at 41f66a4a), #receipt-verification (1482-1537). Covers build +
 * sign, positive end-to-end verification, and each of steps 1-5 and 7's
 * failure modes. Step 6 (chain) is not implemented (see mission-receipt.ts's
 * file header); a receipt carrying `chain` is rejected as unsupported.
 */

import { generateKeyPairSync, webcrypto } from "node:crypto";
import { canonicalDigest } from "@mission/core";
import { describe, expect, it, vi } from "vitest";
import {
  DECISION_EVIDENCE_MEDIA_TYPE,
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  REFUSAL_RECORD_MEDIA_TYPE,
  type EvidenceSigningKey,
  type EnforcementScopeStatement,
  signEvidenceEnvelope,
} from "@mission/pdp";
import type { DecisionEvidenceObject, ExecutionEvidenceObject, RefusalRecordObject } from "../src/evidence.js";
import { buildEvidenceKeyResolver, type EvidenceVerificationKey } from "../src/evidence.js";
import {
  buildAndSignMissionReceipt,
  createReceiptIssuerScope,
  type MissionReceiptEvidenceRef,
  type PublishedReceiptKey,
  type ReceiptIssuerBinding,
  type ReceiptIssuerScope,
  type ReceiptResolvedRecord,
  verifyMissionReceipt,
} from "../src/mission-receipt.js";

const pdpKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const executorKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const pepKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
const receiptKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });

const PDP_SIGNER: EvidenceSigningKey = { kid: "pdp-1", key: pdpKeys.privateKey };
const EXECUTOR_SIGNER: EvidenceSigningKey = { kid: "exec-1", key: executorKeys.privateKey };
const PEP_SIGNER: EvidenceSigningKey = { kid: "pep-1", key: pepKeys.privateKey };
const RECEIPT_SIGNER: EvidenceSigningKey = { kid: "receipt-1", key: receiptKeys.privateKey };

const MISSION = { id: "msn_1", issuer: "https://as.example.com", authority_hash: "sha-256:ah" };

async function signedDecision(overrides: Partial<DecisionEvidenceObject> = {}): Promise<DecisionEvidenceObject> {
  const unsigned = {
    evidence_id: "evd_1",
    evaluation_id: "dec_1",
    mission: { id: MISSION.id, issuer: MISSION.issuer, policy_view_id: "pv-1", authority_hash: MISSION.authority_hash },
    subject: { id: "alice" },
    resource: { type: "invoice", id: "inv-1" },
    action: { name: "payments:invoice.read" },
    audience: "https://erp.example.com",
    action_class: "consequential_read" as const,
    class_source: "default" as const,
    parameter_digest: "sha-256:paramdigest",
    decision: "permit" as const,
    entry_digest: "sha-256:entrydigest",
    conditions: { valid_until: "2026-01-01T00:05:00.000Z" },
    ...(Object.hasOwn(overrides, "parameter_digest") && overrides.parameter_digest === undefined ? { evaluation_request_digest: canonicalDigest({ request: "fixture" }) } : {}),
    sequence: 0,
    emitter: { id: "pdp.example.com", role: "pdp" as const },
    evaluated_at: "2026-01-01T00:00:01.000Z",
    ...overrides,
  };
  const evidence_envelope = await signEvidenceEnvelope(unsigned, DECISION_EVIDENCE_MEDIA_TYPE, PDP_SIGNER);
  return { ...unsigned, evidence_envelope };
}

async function signedExecution(overrides: Partial<ExecutionEvidenceObject> = {}): Promise<ExecutionEvidenceObject> {
  const unsigned = {
    execution_id: "exe_1",
    evaluation_id: "dec_1",
    mission_id: MISSION.id,
    audience: "https://erp.example.com",
    authorized_parameter_digest: "sha-256:paramdigest",
    effective_parameter_digest: "sha-256:paramdigest",
    outcome: "completed" as const,
    outcome_at: "2026-01-01T00:00:02.000Z",
    sequence: 0,
    emitter: { id: "pep.example.com", role: "executor" as const },
    ...overrides,
  };
  const evidence_envelope = await signEvidenceEnvelope(unsigned, EXECUTION_EVIDENCE_MEDIA_TYPE, EXECUTOR_SIGNER);
  return { ...unsigned, evidence_envelope };
}

async function signedRefusal(overrides: Partial<RefusalRecordObject> = {}): Promise<RefusalRecordObject> {
  const unsigned = {
    refusal_id: "ref_1",
    audience: "https://erp.example.com",
    action: { name: "payments:invoice.read" },
    decision: "deny" as const,
    denial_reason: "out_of_authority",
    evaluation_request_digest: canonicalDigest({ request: "fixture" }),
    sequence: 0,
    evaluated_at: "2026-01-01T00:00:01.000Z",
    mission: { ...MISSION },
    emitter: { id: "pep.example.com", role: "pep" as const },
    ...overrides,
  };
  const evidence_envelope = await signEvidenceEnvelope(unsigned, REFUSAL_RECORD_MEDIA_TYPE, PEP_SIGNER);
  return { ...unsigned, evidence_envelope };
}

function resolverFor(records: {
  decision?: DecisionEvidenceObject;
  execution?: ExecutionEvidenceObject;
  refusal?: RefusalRecordObject;
}) {
  return (ref: MissionReceiptEvidenceRef): ReceiptResolvedRecord | undefined => {
    if (ref.type === DECISION_EVIDENCE_MEDIA_TYPE && records.decision) return { type: "decision", record: records.decision };
    if (ref.type === EXECUTION_EVIDENCE_MEDIA_TYPE && records.execution) return { type: "execution", record: records.execution };
    if (records.refusal) return { type: "refusal", record: records.refusal };
    return undefined;
  };
}

const resolveEvidenceKey = buildEvidenceKeyResolver([
  { kid: "pdp-1", publicKey: pdpKeys.publicKey, emitterId: "pdp.example.com", role: "pdp", audience: "https://erp.example.com" },
  { kid: "exec-1", publicKey: executorKeys.publicKey, emitterId: "pep.example.com", role: "executor", audience: "https://erp.example.com" },
  { kid: "pep-1", publicKey: pepKeys.publicKey, emitterId: "pep.example.com", role: "pep", audience: "https://erp.example.com" },
]);
const KEY_SET = "https://deployment.example.com/receipt-jwks";
const receiptScope = (): EnforcementScopeStatement => ({
  mediated_scope: { resources: ["https://erp.example.com"], action_classes: ["consequential_read"], execution_paths: ["tools"], pep_locations: ["pep.example.com", "receipts.example.com"], excluded_paths: [], mission_establishment_mode: "token-claim" },
  authority_entry_types: [{ type: "mission_resource_access", evaluator: "fixture" }], pdps: ["pdp.example.com"],
  state_source: { source: "status", max_staleness_seconds: 30, pdp_unavailability_posture: "deny" },
  remote_decision_channels: [], record_integrity_mechanism: "signed-records", claims: ["evidence"],
  extensions: { evidence: { mechanism: "signed-records", retention_window: "test-only", signing_key_locations: [KEY_SET], receipt_issuers: [{ emitter: "receipts.example.com", key_set: KEY_SET }] } },
});
const receiptKey: EvidenceVerificationKey = { kid: "receipt-1", publicKey: receiptKeys.publicKey, emitterId: "receipts.example.com", role: "receipt_issuer" };
const receiptIssuers = createReceiptIssuerScope(receiptScope(), new Map([[KEY_SET, [receiptKey]]]));
/** A frozen snapshot rejects a write: strict mode throws, and either way the snapshot is unchanged. */
const tamper = (mutate: () => void): void => {
  try {
    mutate();
  } catch {
    /* frozen */
  }
};

async function resigned(receipt: object, changes: Record<string, unknown>) {
  const { evidence_envelope: _drop, ...base } = receipt as Record<string, unknown>;
  const unsigned = { ...base, ...changes };
  return { ...unsigned, evidence_envelope: await signEvidenceEnvelope(unsigned as never, "application/mission-receipt+json", RECEIPT_SIGNER) };
}

describe("Mission Receipt digest vector (spec worked example)", () => {
  it("reproduces the exact digest the spec computes over its Execution Evidence stand-in", () => {
    // @spec runtime-evidence.md#mission-receipt-digest-worked (lines 1613-1661).
    const value = {
      audience: "https://erp.example.com",
      emitter: { id: "pep.example.com", role: "executor" },
      evaluation_id: "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
      evidence_envelope: {
        format: "jws-compact",
        value:
          "eyJhbGciOiJFUzI1NiIsImtpZCI6InBlcC1rZXktMSJ9.dGhlLXNpZ25lZC1wYXlsb2FkLWJ5dGVzLWFib3Zl.RVMyNTZfc2lnbmF0dXJlX2J5dGVzX2lsbHVzdHJhdGl2ZQ",
      },
      execution_id: "exe_4r9SqLm8tY2pXkV3nR0eF7jB1zN6cQ5w",
      mission_id: "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      outcome: "completed",
      outcome_at: "2026-11-02T08:14:05Z",
      sequence: 43,
    };
    expect(canonicalDigest(value)).toBe("sha-256:Ims1Xx5FAPYfFB6c6Y2gbqybB-Z2PxCi93yWPcIHmC8");
  });
});

describe("Mission Receipt build + verify", () => {
  it("resolver mutation cannot replace the receipt's authenticated evidence reference", async () => {
    const decision = await signedDecision();
    const replacement = await signedDecision({ parameter_digest: "sha-256:replacement" });
    const receipt = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    const committedDigest = receipt.evidence[0]!.digest;
    expect(await verifyMissionReceipt(receipt, resolverFor({ decision: replacement }), receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "digest_mismatch" });
    expect(await verifyMissionReceipt(receipt, async (ref) => {
      await Promise.resolve();
      ref.digest = canonicalDigest(replacement as never);
      return { type: "decision", record: replacement };
    }, receiptIssuers, resolveEvidenceKey)).toEqual({ valid: false, reason: "digest_mismatch" });
    expect(receipt.evidence[0]!.digest).toBe(committedDigest);
  });

  it("resolver-owned reference mutations leave all authenticated comparison fields intact", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    expect(await verifyMissionReceipt(receipt, (ref) => {
      ref.type = REFUSAL_RECORD_MEDIA_TYPE;
      ref.digest = "sha-256:resolver-cache-marker";
      ref.evidence_id = "resolver-cache-id";
      ref.emitter.id = "resolver-cache-emitter";
      ref.emitter.role = "pep";
      return { type: "decision", record: decision };
    }, receiptIssuers, resolveEvidenceKey)).toEqual({ valid: true });
  });

  it("a selected receipt authority hash must equal its verified source for every receipt kind", async () => {
    const identity = { id: MISSION.id, issuer: MISSION.issuer };
    for (const kind of ["decision", "execution", "refusal"] as const) {
      for (const sourceHasHash of [true, false]) {
        const sourceMission = sourceHasHash ? MISSION : identity;
        const decision = await signedDecision({ mission: { ...sourceMission, policy_view_id: "pv-1" } });
        const execution = await signedExecution();
        const refusal = await signedRefusal({ mission: sourceMission });
        const receipt = await buildAndSignMissionReceipt({
          kind, mission: identity,
          ...(kind === "refusal" ? { refusalRecord: refusal } : { decisionEvidence: decision }),
          ...(kind === "execution" ? { executionEvidence: execution } : {}),
        }, "receipts.example.com", RECEIPT_SIGNER);
        const resolve = resolverFor({ decision, execution, refusal });
        // Selection is optional even when the verified source has the hash.
        expect(await verifyMissionReceipt(receipt, resolve, receiptIssuers, resolveEvidenceKey))
          .toEqual({ valid: true });
        for (const authority_hash of [MISSION.authority_hash, "sha-256:another-authority"]) {
          const selected = await resigned(receipt, { mission: { ...identity, authority_hash } });
          expect(await verifyMissionReceipt(selected, resolve, receiptIssuers, resolveEvidenceKey))
            .toEqual(sourceHasHash && authority_hash === MISSION.authority_hash
              ? { valid: true } : { valid: false, reason: "copied_member_mismatch" });
        }
      }
    }
  });

  it("retains immutable CryptoKey verification material and rejects symmetric byte keys", async () => {
    const publicKey = await webcrypto.subtle.importKey("jwk", receiptKeys.publicKey.export({ format: "jwk" }), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const scope = createReceiptIssuerScope(receiptScope(), new Map([[KEY_SET, [{ ...receiptKey, publicKey }]]]));
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    expect(await verifyMissionReceipt(receipt, resolverFor({ decision }), scope, resolveEvidenceKey)).toEqual({ valid: true });
    expect(() => createReceiptIssuerScope(receiptScope(), new Map([[KEY_SET, [{ ...receiptKey, publicKey: new Uint8Array(32) }]]]))).toThrow("asymmetric verification key");
  });

  it("mutation of a caller-owned JWK cannot replace a snapshotted issuer key", async () => {
    const jwk = receiptKeys.publicKey.export({ format: "jwk" });
    const frozen = createReceiptIssuerScope(receiptScope(), new Map([[KEY_SET, [{ ...receiptKey, publicKey: jwk }]]]));
    const replacement = generateKeyPairSync("ec", { namedCurve: "P-256" });
    Object.assign(jwk, replacement.publicKey.export({ format: "jwk" }));
    const decision = await signedDecision();
    const substituted = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com", { ...RECEIPT_SIGNER, key: replacement.privateKey },
    );
    expect(await verifyMissionReceipt(substituted, resolverFor({ decision }), frozen, resolveEvidenceKey)).toMatchObject({ valid: false });
    const original = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    expect(await verifyMissionReceipt(original, resolverFor({ decision }), frozen, resolveEvidenceKey)).toEqual({ valid: true });
    const held = frozen.issuers[0]!.keys[0]!.publicKey;
    expect(held).not.toBe(jwk);
    expect(Object.isFrozen(held)).toBe(true);
    expect(() => Object.assign(held, jwk)).toThrow();
  });
  it("totally refuses malformed authenticated receipt members and references before resolving source records", async () => {
    const decision = await signedDecision();
    const base = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    const resolve = vi.fn(resolverFor({ decision }));
    for (const input of [null, undefined, [], true, "receipt", {}, { evidence_envelope: null }]) {
      expect(await verifyMissionReceipt(input, resolve, receiptIssuers, resolveEvidenceKey)).toEqual({ valid: false, reason: "envelope_invalid" });
    }
    const changes = [
      { kind: null }, { kind: "unknown" }, { mission: MISSION.id }, { mission: [] }, { mission: { id: MISSION.id } },
      { mission: { ...MISSION, grant: "a grant beside the receipt is not this member" } },
      { issued_at: undefined }, { issued_at: "2026-01-01" }, { issued_at: "2026-02-31T00:00:00Z" }, { issued_at: 1 }, { outcome: "completed" },
      { evidence: null }, { evidence: [{}] }, { decision: { id: 1, result: "permit" } },
      ...["type", "digest", "evidence_id", "emitter"].map((key) => ({ evidence: [{ ...base.evidence[0], [key]: null }] })),
    ];
    for (const change of changes) {
      expect(await verifyMissionReceipt(await resigned(base, change), resolve, receiptIssuers, resolveEvidenceKey), JSON.stringify(change))
        .toEqual({ valid: false, reason: "malformed" });
    }
    expect(resolve).not.toHaveBeenCalled();
  });

  it("an unknown receipt kind cannot fall through into a valid refusal combination", async () => {
    const refusal = await signedRefusal();
    const base = await buildAndSignMissionReceipt({ kind: "refusal", mission: MISSION, refusalRecord: refusal }, "receipts.example.com", RECEIPT_SIGNER);
    expect(await verifyMissionReceipt(await resigned(base, { kind: "another-kind" }), resolverFor({ refusal }), receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "malformed" });
    await expect(buildAndSignMissionReceipt({ kind: "another-kind" as never, mission: MISSION, refusalRecord: refusal }, "receipts.example.com", RECEIPT_SIGNER))
      .rejects.toThrow("unknown Mission Receipt kind");
  });

  it("an issuer the trusted scope does not designate refuses as issuer_not_authorized, before any key lookup", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    const resolve = vi.fn(resolverFor({ decision }));
    const removed = receiptScope(); removed.extensions!.evidence!.receipt_issuers = [];
    expect(await verifyMissionReceipt(receipt, resolve, createReceiptIssuerScope(removed, new Map([[KEY_SET, [receiptKey]]])), resolveEvidenceKey))
      .toEqual({ valid: false, reason: "issuer_not_authorized" });
    const elsewhere = receiptScope(); elsewhere.extensions!.evidence!.receipt_issuers = [{ emitter: "pep.example.com", key_set: KEY_SET }];
    expect(await verifyMissionReceipt(receipt, resolve, createReceiptIssuerScope(elsewhere, new Map([[KEY_SET, [receiptKey]]])), resolveEvidenceKey))
      .toEqual({ valid: false, reason: "issuer_not_authorized" });
    // A public key alone cannot designate a receipt issuer. The trusted scope is an
    // explicit parameter, so a bare key resolver is a compile error wherever the
    // build type-checks it, and designates nothing at runtime.
    const keyAlone = (() => ({ key: receiptKeys.publicKey })) as unknown as ReceiptIssuerScope;
    expect(await verifyMissionReceipt(receipt, resolve, keyAlone, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "issuer_not_authorized" });
    expect(resolve).not.toHaveBeenCalled();
  });

  it("an authorized issuer refuses a key bound to another issuer or published outside the scope", async () => {
    const decision = await signedDecision();
    const both = receiptScope();
    both.mediated_scope.pep_locations = [...both.mediated_scope.pep_locations, "other-receipts.example.com"];
    both.extensions!.evidence!.receipt_issuers = [
      { emitter: "receipts.example.com", key_set: KEY_SET },
      { emitter: "other-receipts.example.com", key_set: KEY_SET },
    ];
    // One key set, one published key, one kid, bound to the OTHER designated issuer.
    const boundElsewhere = createReceiptIssuerScope(both, new Map([[KEY_SET, [{ ...receiptKey, emitterId: "other-receipts.example.com" }]]]));
    const receipt = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    expect(await verifyMissionReceipt(receipt, resolverFor({ decision }), boundElsewhere, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "envelope_invalid" });
    const ownIssuer = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "other-receipts.example.com", RECEIPT_SIGNER);
    expect(await verifyMissionReceipt(ownIssuer, resolverFor({ decision }), boundElsewhere, resolveEvidenceKey)).toEqual({ valid: true });
    const outside = createReceiptIssuerScope(receiptScope(), new Map([["https://other.test/keys", [receiptKey]]]));
    expect(await verifyMissionReceipt(receipt, resolverFor({ decision }), outside, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "envelope_invalid" });
  });

  it("a scope snapshot cannot be broadened after it is created, and the declaration limits component and resource scope", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    const unknownComponent = receiptScope(); unknownComponent.mediated_scope.pep_locations = ["pep.example.com"];
    expect(() => createReceiptIssuerScope(unknownComponent, new Map([[KEY_SET, [receiptKey]]]))).toThrow("not named by the scope");
    const wrongLocation = receiptScope(); wrongLocation.extensions!.evidence!.signing_key_locations = ["https://other.test/keys"];
    expect(() => createReceiptIssuerScope(wrongLocation, new Map([[KEY_SET, [receiptKey]]]))).toThrow("not named by the scope");
    const statement = receiptScope(); statement.mediated_scope.resources = ["https://other.test"];
    const published: PublishedReceiptKey[] = [receiptKey];
    const narrow = createReceiptIssuerScope(statement, new Map([[KEY_SET, published]]));
    statement.mediated_scope.resources = ["https://erp.example.com"]; // The caller's own statement.
    published.push({ ...receiptKey, kid: "receipt-2" }); // The caller's own key set.
    tamper(() => { (narrow.issuers as ReceiptIssuerBinding[]).push({ emitter: "attacker.example.com", key_set: KEY_SET, keys: [receiptKey] }); });
    tamper(() => { (narrow.issuers[0]!.keys as PublishedReceiptKey[]).push({ ...receiptKey, kid: "receipt-3" }); });
    tamper(() => { (narrow.statement.mediated_scope.resources as string[]).push("https://erp.example.com"); });
    expect(narrow.issuers).toHaveLength(1);
    expect(narrow.issuers[0]!.keys).toHaveLength(1);
    expect(await verifyMissionReceipt(receipt, resolverFor({ decision }), narrow, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "referenced_record_invalid" });
    const pushedIssuer = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "attacker.example.com", RECEIPT_SIGNER);
    expect(await verifyMissionReceipt(pushedIssuer, resolverFor({ decision }), narrow, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "issuer_not_authorized" });
    const differentMission = await resigned(receipt, { mission: { ...MISSION, id: "another-mission" } });
    expect(await verifyMissionReceipt(differentMission, resolverFor({ decision }), receiptIssuers, resolveEvidenceKey)).toEqual({ valid: false, reason: "join_failure" });
  });

  it("an execution receipt requires a terminal outcome and a permit, while a decision receipt makes no execution claim", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution();
    const receipt = await buildAndSignMissionReceipt({ kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: execution }, "receipts.example.com", RECEIPT_SIGNER);
    for (const outcome of [undefined, null, "pending", "running"]) {
      expect(await verifyMissionReceipt(await resigned(receipt, { outcome }), resolverFor({ decision, execution }), receiptIssuers, resolveEvidenceKey))
        .toEqual({ valid: false, reason: "malformed" });
      await expect(buildAndSignMissionReceipt({ kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: { ...execution, outcome: outcome as never } }, "receipts.example.com", RECEIPT_SIGNER))
        .rejects.toThrow("final outcome");
    }
    const decisionOnly = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    expect(decisionOnly).not.toHaveProperty("outcome");
    expect(await verifyMissionReceipt(await resigned(decisionOnly, { outcome: "completed" }), resolverFor({ decision }), receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "malformed" });
    const denied = await signedDecision({ decision: "deny", denial_reason: "out_of_authority" });
    const malicious = await resigned(receipt, { evidence: [
      { ...receipt.evidence[0], digest: canonicalDigest(denied as never) }, receipt.evidence[1],
    ], decision: { id: denied.evidence_id, result: "deny" } });
    expect(await verifyMissionReceipt(malicious, resolverFor({ decision: denied, execution }), receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "join_failure" });
  });

  it("rejects signed but structurally invalid referenced records rather than treating integrity as content validation", async () => {
    const decision = await signedDecision({ subject: null as never });
    const receipt = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    expect(await verifyMissionReceipt(receipt, resolverFor({ decision }), receiptIssuers, resolveEvidenceKey)).toEqual({ valid: false, reason: "referenced_record_invalid" });
    const good = await signedDecision();
    const goodReceipt = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: good }, "receipts.example.com", RECEIPT_SIGNER);
    expect(await verifyMissionReceipt(goodReceipt, () => { throw new Error("store unavailable"); }, receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "reference_unresolvable" });
    expect(await verifyMissionReceipt(goodReceipt, () => ({ type: "unknown", record: good }) as never, receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "reference_type_mismatch" });
  });

  it("compares each reference's identifier, emitter and complete canonical digest after source verification", async () => {
    const decision = await signedDecision();
    const base = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    expect(base.evidence[0]!.digest).toBe(canonicalDigest(decision as never));
    const { evidence_envelope: _envelope, ...unsignedDecision } = decision;
    expect(base.evidence[0]!.digest).not.toBe(canonicalDigest(unsignedDecision as never));
    for (const [change, reason] of [
      [{ evidence_id: "another-id" }, "identifier_mismatch"],
      [{ emitter: { id: "another-emitter", role: "pdp" } }, "emitter_mismatch"],
      [{ digest: "sha-512:unsupported" }, "digest_mismatch"],
    ] as const) {
      expect(await verifyMissionReceipt(await resigned(base, { evidence: [{ ...base.evidence[0], ...change }] }), resolverFor({ decision }), receiptIssuers, resolveEvidenceKey))
        .toEqual({ valid: false, reason });
    }
  });

  it("compares selected policy and executor projections exactly and refuses issuer assertions on this verification path", async () => {
    const actor = { client_id: "ap-agent", act: [{ iss: "https://as.example.com", sub: "worker" }] };
    const decision = await signedDecision({ actor });
    const base = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    const policy = { pdp_policy_view: decision.mission.policy_view_id };
    const selected = await resigned(base, { policy, executor: actor });
    expect(await verifyMissionReceipt(selected, resolverFor({ decision }), receiptIssuers, resolveEvidenceKey)).toEqual({ valid: true });
    for (const changed of [{ policy: { ...policy, mission_policy_version: "invented" } }, { executor: { ...actor, client_id: "other" } }]) {
      expect(await verifyMissionReceipt(await resigned(selected, changed), resolverFor({ decision }), receiptIssuers, resolveEvidenceKey))
        .toEqual({ valid: false, reason: "copied_member_mismatch" });
    }
    expect(await verifyMissionReceipt(await resigned(base, { issuer_assertions: { custody: "asserted" } }), resolverFor({ decision }), receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "malformed" });
    expect(await verifyMissionReceipt(await resigned(base, { profile: "https://example.com/other-profile", issuer_assertions: { custody: "asserted" } }), resolverFor({ decision }), receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "unimplemented_projection" });
  });

  it("performs envelope, combination and source verification before joins or copied-field reliance", async () => {
    const decision = await signedDecision();
    const base = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    const resolve = vi.fn(resolverFor({ decision }));
    expect(await verifyMissionReceipt({ ...base, evidence: [] }, resolve, receiptIssuers, resolveEvidenceKey)).toEqual({ valid: false, reason: "envelope_invalid" });
    expect(resolve).not.toHaveBeenCalled();
    expect(await verifyMissionReceipt(await resigned(base, { evidence: [], decision: { id: "bad", result: "deny" } }), resolve, receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "combination_invalid" });
    expect(resolve).not.toHaveBeenCalled();
    const wrongCopy = await resigned(base, { decision: { id: "bad", result: "deny" } });
    expect(await verifyMissionReceipt(wrongCopy, resolverFor({ decision: { ...decision, subject: { id: "changed" } } }), receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "referenced_record_invalid" });
  });

  it("an unimplemented chain refuses at its own step, after the steps before it and never as a pass", async () => {
    const decision = await signedDecision();
    const base = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    const chain = { stream: "https://receipts.example.com/stream", sequence: 1, previous: [{ digest: canonicalDigest({ predecessor: true }) }] };
    expect(await verifyMissionReceipt(await resigned(base, { chain }), resolverFor({ decision }), receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "chain_not_supported" });
    // An earlier step still owns its own reason: the chain refusal never masks it.
    expect(await verifyMissionReceipt(await resigned(base, { chain, evidence: [{ ...base.evidence[0], evidence_id: "another-id" }] }), resolverFor({ decision }), receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "identifier_mismatch" });
  });

  it("joins issuer-qualified Mission identity and reports an unauthorized completed parameter deviation without discarding evidence", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution({ effective_parameter_digest: "sha-256:changed" });
    const receipt = await buildAndSignMissionReceipt({ kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: execution }, "receipts.example.com", RECEIPT_SIGNER);
    expect(await verifyMissionReceipt(receipt, resolverFor({ decision, execution }), receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: true, unauthorized_execution: true });
    const foreignMission = await resigned(receipt, { mission: { ...MISSION, issuer: "https://other-issuer.test" } });
    expect(await verifyMissionReceipt(foreignMission, resolverFor({ decision, execution }), receiptIssuers, resolveEvidenceKey))
      .toEqual({ valid: false, reason: "join_failure" });
  });

  it("a compromised receipt issuer key cannot bypass the boundary rule through scope publication", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt({ kind: "decision", mission: MISSION, decisionEvidence: decision }, "receipts.example.com", RECEIPT_SIGNER);
    const status = { compromised: true, boundary: "2026-01-01T00:00:00Z" };
    const keys = createReceiptIssuerScope(receiptScope(), new Map([[KEY_SET, [{ ...receiptKey, status }]]]));
    status.compromised = false; // Frozen policy snapshot, not a mutable caller back door.
    const resolve = vi.fn(resolverFor({ decision }));
    expect(await verifyMissionReceipt(receipt, resolve, keys, resolveEvidenceKey)).toEqual({ valid: false, reason: "envelope_invalid" });
    expect(resolve).not.toHaveBeenCalled();
    expect(await verifyMissionReceipt(receipt, resolve, keys, resolveEvidenceKey, {
      presented: true, valid: true, commits: "complete-artifact", authenticatedTime: "2026-01-01T00:00:00Z", proofKey: { compromised: false },
    })).toEqual({ valid: false, reason: "envelope_invalid" });
    expect(resolve).not.toHaveBeenCalled();
  });

  it("builds and verifies a 'decision' receipt", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    expect(receipt.kind).toBe("decision");
    expect(receipt.evidence).toHaveLength(1);
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: true });
  });

  it("builds and verifies an 'execution' receipt, joined on evaluation_id", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: execution },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    expect(receipt.evidence).toHaveLength(2);
    expect(receipt.outcome).toBe("completed");
    expect(receipt.decision).toEqual({ id: decision.evidence_id, result: "permit" });
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision, execution }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: true });
  });

  it("rejects an 'execution' receipt whose evidence combination is missing the Execution Evidence reference", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: execution },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const truncated = { ...receipt, evidence: receipt.evidence.slice(0, 1) };
    const result = await verifyMissionReceipt(
      truncated,
      resolverFor({ decision, execution }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    // The envelope no longer matches the truncated evidence array either, but
    // step 2's combination check is reached only if step 1 somehow passed; a
    // real attacker who also re-signed would be caught by step 2.
    expect(result.valid).toBe(false);
  });

  it("rejects a genuinely mis-signed 'decision' receipt that carries an Execution Evidence reference too (evidence-combination-per-kind)", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution();
    // A malicious/buggy issuer that signs a `kind: "decision"` object but
    // attaches both references anyway: the builder itself never produces
    // this (it enforces the combination), so this constructs it directly to
    // exercise step 2 on a receipt that otherwise DOES verify (its envelope
    // is genuinely signed over exactly these bytes).
    const unsigned = {
      kind: "decision" as const,
      mission: MISSION,
      emitter: { id: "receipts.example.com", role: "receipt_issuer" as const },
      evidence: [
        { type: DECISION_EVIDENCE_MEDIA_TYPE, digest: canonicalDigest(decision as never), evidence_id: decision.evidence_id, emitter: decision.emitter },
        { type: EXECUTION_EVIDENCE_MEDIA_TYPE, digest: canonicalDigest(execution as never), evidence_id: execution.execution_id, emitter: execution.emitter },
      ],
      issued_at: "2026-01-01T00:00:03.000Z",
      decision: { id: decision.evidence_id, result: "permit" as const },
    };
    const evidence_envelope = await signEvidenceEnvelope(unsigned, "application/mission-receipt+json", RECEIPT_SIGNER);
    const badReceipt = { ...unsigned, evidence_envelope };
    const result = await verifyMissionReceipt(
      badReceipt,
      resolverFor({ decision, execution }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "combination_invalid" });
  });

  it("rejects a copied member mismatch: the receipt's own embedded decision.result disagrees with the resolved Decision Evidence it references (step 5)", async () => {
    const decision = await signedDecision(); // decision: "permit"
    // A malicious/buggy issuer that copies the WRONG result into the
    // receipt's own `decision` member while still referencing (and
    // correctly digesting) the real, unmodified permit Decision Evidence:
    // the builder never produces this (it derives `decision` from the same
    // object it references), so this constructs it directly to exercise
    // step 5 on a receipt whose envelope, combination, digest, identifier,
    // emitter, and mission join all otherwise pass.
    const unsigned = {
      kind: "decision" as const,
      mission: MISSION,
      emitter: { id: "receipts.example.com", role: "receipt_issuer" as const },
      evidence: [
        {
          type: DECISION_EVIDENCE_MEDIA_TYPE,
          digest: canonicalDigest(decision as never),
          evidence_id: decision.evidence_id,
          emitter: decision.emitter,
        },
      ],
      issued_at: "2026-01-01T00:00:03.000Z",
      decision: { id: decision.evidence_id, result: "deny" as const },
    };
    const evidence_envelope = await signEvidenceEnvelope(unsigned, "application/mission-receipt+json", RECEIPT_SIGNER);
    const badReceipt = { ...unsigned, evidence_envelope };
    const result = await verifyMissionReceipt(
      badReceipt,
      resolverFor({ decision }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "copied_member_mismatch" });
  });

  it("rejects when a referenced record is unresolvable", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const result = await verifyMissionReceipt(receipt, () => undefined, receiptIssuers, resolveEvidenceKey);
    expect(result).toEqual({ valid: false, reason: "reference_unresolvable" });
  });

  it("rejects when the referenced record's own signature does not verify", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const tamperedDecision = { ...decision, decision: "deny" as const };
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision: tamperedDecision }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "referenced_record_invalid" });
  });

  it("rejects a digest mismatch: the resolved record verifies on its own but does not match the receipt's committed digest", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    // A second, independently-signed but genuinely different Decision Evidence
    // record: it verifies (own signature valid) but is not the one this
    // receipt committed to.
    const otherDecision = await signedDecision({ evidence_id: "evd_1", sequence: 1 });
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision: otherDecision }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "digest_mismatch" });
  });

  it("rejects a join failure: Execution Evidence's evaluation_id does not match the Decision Evidence it is paired with", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution({ evaluation_id: "dec_DIFFERENT" });
    const receipt = await buildAndSignMissionReceipt(
      { kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: execution },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision, execution }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "join_failure" });
  });

  it("rejects the receipt's own envelope tampering (byte-mismatch, ordered-total-verification)", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const tampered = { ...receipt, mission: { ...receipt.mission, id: "msn_evil" } };
    const result = await verifyMissionReceipt(
      tampered,
      resolverFor({ decision }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "envelope_invalid" });
  });

  it("rejects an unresolvable receipt-issuer key", async () => {
    const decision = await signedDecision();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const result = await verifyMissionReceipt(receipt, resolverFor({ decision }), createReceiptIssuerScope(receiptScope(), new Map()), resolveEvidenceKey);
    expect(result).toEqual({ valid: false, reason: "envelope_invalid" });
  });

  it("builds and verifies a 'refusal' receipt", async () => {
    const refusal = await signedRefusal();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "refusal", mission: MISSION, refusalRecord: refusal },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    expect(receipt.kind).toBe("refusal");
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ refusal }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: true });
  });

  it("rejects a reference declared as Decision Evidence that resolves to a genuinely-verifying Execution record instead (#739 review point 2, step 3, before record verification)", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution();
    const receipt = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    // The resolver ignores the reference's declared `type` and returns a
    // DIFFERENT, independently well-signed record kind instead. The
    // Execution record verifies fine under its OWN `cty`, so if the
    // verifier checked only the resolver's claimed kind (`r.type`) rather
    // than requiring it to equal the reference's OWN declared `type`, this
    // substitution would slip past record verification entirely.
    const result = await verifyMissionReceipt(
      receipt,
      () => ({ type: "execution", record: execution }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "reference_type_mismatch" });
  });

  it("rejects a join failure: Execution Evidence's mission_id does not match the receipt's mission (#739 review point 3)", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution({ mission_id: "msn_DIFFERENT" });
    const receipt = await buildAndSignMissionReceipt(
      { kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: execution },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision, execution }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "join_failure" });
  });

  it("rejects a 'refusal' receipt whose Refusal Record carries no established Mission (#739 review point 3)", async () => {
    const refusal = await signedRefusal({ mission: undefined });
    const receipt = await buildAndSignMissionReceipt(
      { kind: "refusal", mission: MISSION, refusalRecord: refusal },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ refusal }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "join_failure" });
  });

  it("rejects a join failure: Execution Evidence carries no authorized_parameter_digest while the Decision Evidence carries a parameter_digest (#739 review point 3, exact mirror)", async () => {
    const decision = await signedDecision(); // parameter_digest: "sha-256:paramdigest"
    const execution = await signedExecution({ authorized_parameter_digest: undefined, effective_parameter_digest: undefined });
    const receipt = await buildAndSignMissionReceipt(
      { kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: execution },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision, execution }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "join_failure" });
  });

  it("rejects a join failure: Execution Evidence carries authorized_parameter_digest while the Decision Evidence carries no parameter_digest (#739 review point 3, exact mirror, reverse direction)", async () => {
    const decision = await signedDecision({ parameter_digest: undefined });
    const execution = await signedExecution(); // still carries authorized_parameter_digest
    const receipt = await buildAndSignMissionReceipt(
      { kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: execution },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision, execution }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "join_failure" });
  });

  it("rejects an Execution Evidence record missing effective_parameter_digest while authorized_parameter_digest is present (#739 review point 3)", async () => {
    const decision = await signedDecision();
    const execution = await signedExecution({ effective_parameter_digest: undefined });
    const receipt = await buildAndSignMissionReceipt(
      { kind: "execution", mission: MISSION, decisionEvidence: decision, executionEvidence: execution },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    const result = await verifyMissionReceipt(
      receipt,
      resolverFor({ decision, execution }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: false, reason: "join_failure" });
  });

  it("verifies a selected target projection against the source record (#739 review point 4)", async () => {
    const decision = await signedDecision();
    const receiptBase = await buildAndSignMissionReceipt(
      { kind: "decision", mission: MISSION, decisionEvidence: decision },
      "receipts.example.com",
      RECEIPT_SIGNER,
    );
    // Re-sign with an explicitly selected target projection. Acceptance
    // requires equality against the verified source, never the issuer key alone.
    const { evidence_envelope: _drop, ...unsignedBase } = receiptBase;
    const unsigned = { ...unsignedBase, target: { resource: decision.resource, audience: decision.audience } };
    const evidence_envelope = await signEvidenceEnvelope(unsigned, "application/mission-receipt+json", RECEIPT_SIGNER);
    const receiptWithTarget = { ...unsigned, evidence_envelope };
    const result = await verifyMissionReceipt(
      receiptWithTarget,
      resolverFor({ decision }),
      receiptIssuers,
      resolveEvidenceKey,
    );
    expect(result).toEqual({ valid: true });
    const wrong = await resigned(receiptWithTarget, { target: { resource: { ...decision.resource, id: "inv-other" }, audience: decision.audience } });
    expect(await verifyMissionReceipt(wrong, resolverFor({ decision }), receiptIssuers, resolveEvidenceKey)).toEqual({ valid: false, reason: "copied_member_mismatch" });
  });
});
