/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-integrity
 * (lines 775-872 at 41f66a4a). The primitive under test is the ONE algorithm
 * that section fixes for Decision Evidence, Execution Evidence, Refusal
 * Records, and (reused) the Mission Receipt: JWS Compact over the JCS
 * canonical bytes of the record with `evidence_envelope` removed, ordered
 * verification that never treats a record as verified if any step fails.
 *
 * Every negative case here asserts the SPECIFIC rejection reason, not just
 * `valid: false`: that is what makes "ordered-total-verification" (the outer
 * object is rejected on byte mismatch even when the embedded JWS itself
 * would still verify) an honestly-tested claim rather than a coincidence.
 */

import { generateKeyPairSync } from "node:crypto";
import { canonicalize, evaluateCompromiseBoundary } from "@mission/core";
import { CompactSign } from "jose";
import { describe, expect, it } from "vitest";
import {
  DECISION_EVIDENCE_MEDIA_TYPE,
  EXECUTION_EVIDENCE_MEDIA_TYPE,
  RUNTIME_EVIDENCE_JWS_TYP,
  signEvidenceEnvelope,
  verifyEvidenceEnvelope,
} from "../src/runtime-evidence-integrity.js";

const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const otherKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });

const RECORD = {
  evidence_id: "evd_9Nq3TmR6xL2vP8kY4sD1eB7jH0wC5uA",
  evaluation_id: "dec_8K2nP4qV9rL3tY6sB1zN0eF7jB",
  mission: { id: "msn_1", issuer: "https://as.example.com", policy_view_id: "sha-256:abc" },
  audience: "https://erp.example.com",
  action_class: "irreversible_action",
  class_source: "deployment",
  decision: "permit",
  sequence: 42,
  emitter: { id: "pdp.example.com", role: "pdp" },
  evaluated_at: "2026-11-02T08:14:03Z",
};

async function sign() {
  const envelope = await signEvidenceEnvelope(RECORD, DECISION_EVIDENCE_MEDIA_TYPE, {
    kid: "pdp-key-1",
    key: privateKey,
  });
  return { ...RECORD, evidence_envelope: envelope };
}

const resolvePdpKey = ({ kid, emitter, audience }: { kid: string; emitter: { id: string; role: string }; audience?: string }) => {
  if (kid !== "pdp-key-1" || emitter.role !== "pdp" || audience !== "https://erp.example.com") return undefined;
  return { key: publicKey };
};

describe("runtime-evidence-integrity: sign/verify", () => {
  it("verifies a genuinely signed record (positive vector)", async () => {
    const signed = await sign();
    const result = await verifyEvidenceEnvelope(signed, DECISION_EVIDENCE_MEDIA_TYPE, resolvePdpKey);
    expect(result).toEqual({ valid: true });
  });

  it("embeds the mandatory-to-implement alg, typ, and cty in the protected header", async () => {
    const signed = await sign();
    const [protectedB64] = signed.evidence_envelope.value.split(".");
    const header = JSON.parse(Buffer.from(protectedB64, "base64url").toString("utf8"));
    expect(header).toEqual({
      alg: "ES256",
      kid: "pdp-key-1",
      typ: RUNTIME_EVIDENCE_JWS_TYP,
      cty: DECISION_EVIDENCE_MEDIA_TYPE,
    });
  });

  it("rejects an unsupported envelope format before touching the signature", async () => {
    const signed = await sign();
    const tampered = { ...signed, evidence_envelope: { format: "other-format" as never, value: "x" } };
    const result = await verifyEvidenceEnvelope(tampered, DECISION_EVIDENCE_MEDIA_TYPE, resolvePdpKey);
    expect(result).toEqual({ valid: false, reason: "unsupported_format" });
  });

  it("rejects a malformed compact serialization", async () => {
    const signed = await sign();
    const tampered = { ...signed, evidence_envelope: { format: "jws-compact" as const, value: "not-a-jws" } };
    const result = await verifyEvidenceEnvelope(tampered, DECISION_EVIDENCE_MEDIA_TYPE, resolvePdpKey);
    expect(result).toEqual({ valid: false, reason: "malformed" });
  });

  it("rejects an unresolvable kid", async () => {
    const signed = await sign();
    const result = await verifyEvidenceEnvelope(signed, DECISION_EVIDENCE_MEDIA_TYPE, () => undefined);
    expect(result).toEqual({ valid: false, reason: "key_not_resolvable" });
  });

  it("rejects a key not bound to this record's emitter role / scope / audience", async () => {
    const signed = await sign();
    // The resolver only publishes the key for role "pep" / a different
    // audience: the record's own "pdp" role + audience never match, so no
    // key is resolvable for THIS record even though the kid exists.
    const result = await verifyEvidenceEnvelope(
      signed,
      DECISION_EVIDENCE_MEDIA_TYPE,
      ({ kid, emitter, audience }) =>
        kid === "pdp-key-1" && emitter.role === "pep" && audience === "https://wrong.example.com"
          ? { key: publicKey }
          : undefined,
    );
    expect(result).toEqual({ valid: false, reason: "key_not_resolvable" });
  });

  it("rejects a modified outer object even though the embedded JWS is still independently valid (ordered-total-verification: byte-mismatch, not a signature failure)", async () => {
    const signed = await sign();
    const modified = { ...signed, decision: "deny" };
    const result = await verifyEvidenceEnvelope(modified, DECISION_EVIDENCE_MEDIA_TYPE, resolvePdpKey);
    // The embedded JWS is byte-for-byte the one `sign()` produced and DOES
    // verify against the publisher key; asserting the reason (not just
    // valid:false) proves rejection happened at the byte-equality step,
    // before signature verification ever runs.
    expect(result).toEqual({ valid: false, reason: "byte_mismatch" });
  });

  it("rejects a bad signature (payload matches, signature bytes corrupted)", async () => {
    const signed = await sign();
    const [h, p, s] = signed.evidence_envelope.value.split(".");
    const corruptSig = s.slice(0, -2) + (s.slice(-2) === "AA" ? "BB" : "AA");
    const tampered = { ...signed, evidence_envelope: { format: "jws-compact" as const, value: `${h}.${p}.${corruptSig}` } };
    const result = await verifyEvidenceEnvelope(tampered, DECISION_EVIDENCE_MEDIA_TYPE, resolvePdpKey);
    expect(result).toEqual({ valid: false, reason: "signature_invalid" });
  });

  it("rejects a signature from a different key over the identical payload", async () => {
    const signed = await sign();
    const result = await verifyEvidenceEnvelope(signed, DECISION_EVIDENCE_MEDIA_TYPE, () => ({
      key: otherKeys.publicKey,
    }));
    expect(result).toEqual({ valid: false, reason: "signature_invalid" });
  });

  it("rejects a wrong typ in the protected header (typ is the ONE fixed value; a JWS built for a different envelope kind is never valid here even with matching cty)", async () => {
    const payload = new TextEncoder().encode(canonicalize(RECORD));
    const value = await new CompactSign(payload)
      .setProtectedHeader({
        alg: "ES256",
        kid: "pdp-key-1",
        typ: "application/some-other-envelope+jws",
        cty: DECISION_EVIDENCE_MEDIA_TYPE,
      })
      .sign(privateKey);
    const signed = { ...RECORD, evidence_envelope: { format: "jws-compact" as const, value } };
    const result = await verifyEvidenceEnvelope(signed, DECISION_EVIDENCE_MEDIA_TYPE, resolvePdpKey);
    expect(result).toEqual({ valid: false, reason: "typ_mismatch" });
  });

  it("rejects a signature using a non-ES256 algorithm even when the header and payload are otherwise well-formed", async () => {
    const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" });
    const payload = new TextEncoder().encode(canonicalize(RECORD));
    const value = await new CompactSign(payload)
      .setProtectedHeader({ alg: "ES384", kid: "pdp-key-1", typ: RUNTIME_EVIDENCE_JWS_TYP, cty: DECISION_EVIDENCE_MEDIA_TYPE })
      .sign(p384.privateKey);
    const signed = { ...RECORD, evidence_envelope: { format: "jws-compact" as const, value } };
    const result = await verifyEvidenceEnvelope(signed, DECISION_EVIDENCE_MEDIA_TYPE, () => ({ key: p384.publicKey }));
    // ES256 is the only algorithm this verifier offers (line 834-836); jose's
    // algorithm allowlist rejects ES384 before signature bytes are even
    // checked, surfacing through the same catch as a corrupted signature.
    expect(result).toEqual({ valid: false, reason: "signature_invalid" });
  });

  it("rejects cty cross-use: a Decision Evidence signature is not valid for Execution Evidence", async () => {
    const signed = await sign();
    const result = await verifyEvidenceEnvelope(signed, EXECUTION_EVIDENCE_MEDIA_TYPE, resolvePdpKey);
    expect(result).toEqual({ valid: false, reason: "cty_mismatch" });
  });

  it("applies the compromise-boundary rule: a compromised key with no qualifying proof does not verify", async () => {
    const signed = await sign();
    const result = await verifyEvidenceEnvelope(signed, DECISION_EVIDENCE_MEDIA_TYPE, () => ({
      key: publicKey,
      status: { compromised: true, boundary: "2026-11-01T00:00:00Z" },
    }));
    expect(result).toEqual({ valid: false, reason: "compromised_key_unproven" });
    // Cross-check directly against the shared evaluator this gates on, so
    // the wiring (not just the evaluator in isolation) is what is tested.
    expect(
      evaluateCompromiseBoundary({ compromised: true, boundary: "2026-11-01T00:00:00Z" }, undefined),
    ).toEqual({ applicable: true, verified: false, failure: "audit", tamperingFinding: false });
  });

  it("a compromised key WITH a qualifying pre-boundary proof still verifies", async () => {
    const signed = await sign();
    const result = await verifyEvidenceEnvelope(
      signed,
      DECISION_EVIDENCE_MEDIA_TYPE,
      () => ({
        key: publicKey,
        status: { compromised: true, boundary: "2026-11-03T00:00:00Z" },
      }),
      {
        presented: true,
        valid: true,
        commits: "complete-artifact",
        authenticatedTime: "2026-11-01T00:00:00Z",
        proofKey: { compromised: false },
      },
    );
    expect(result).toEqual({ valid: true });
  });

  it("a non-compromised key status verifies normally (rule does not apply)", async () => {
    const signed = await sign();
    const result = await verifyEvidenceEnvelope(signed, DECISION_EVIDENCE_MEDIA_TYPE, () => ({
      key: publicKey,
      status: { compromised: false },
    }));
    expect(result).toEqual({ valid: true });
  });
});
