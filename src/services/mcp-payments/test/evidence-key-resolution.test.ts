import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DECISION_EVIDENCE_MEDIA_TYPE, EXECUTION_EVIDENCE_MEDIA_TYPE, REFUSAL_RECORD_MEDIA_TYPE, signEvidenceEnvelope, verifyEvidenceEnvelope } from "@mission/pdp";
import { buildEvidenceKeyResolver } from "../src/evidence.js";

describe("configured evidence key-set scope resolution", () => {
  it("resolves PDP, PEP and executor records by key, exact emitter role and audience", async () => {
    for (const [role, cty] of [["pdp", DECISION_EVIDENCE_MEDIA_TYPE], ["pep", REFUSAL_RECORD_MEDIA_TYPE], ["executor", EXECUTION_EVIDENCE_MEDIA_TYPE]] as const) {
      const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const record = { emitter: { id: "https://component.test", role }, audience: "https://resource.test", record_id: "fixture" };
      const key = { kid: "same-local-key-id", publicKey, role, emitterId: record.emitter.id, audience: record.audience };
      const resolver = buildEvidenceKeyResolver([key]);
      const envelope = await signEvidenceEnvelope(record, cty, { kid: key.kid, key: privateKey });
      expect(await verifyEvidenceEnvelope({ ...record, evidence_envelope: envelope }, cty, resolver)).toEqual({ valid: true });
      for (const change of [{ emitterId: "https://other.test" }, { audience: "https://other.test" }, { kid: "other" }]) {
        expect(await verifyEvidenceEnvelope({ ...record, evidence_envelope: envelope }, cty, buildEvidenceKeyResolver([{ ...key, ...change }])))
          .toEqual({ valid: false, reason: "key_not_resolvable" });
      }
    }
  });

  it("never treats an absent or empty enforcement-point audience as a wildcard", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    for (const role of ["pdp", "pep", "executor"] as const) {
      for (const audience of [undefined, ""]) {
        const malformed = { kid: "key", publicKey, role, emitterId: "component", audience };
        const resolver = buildEvidenceKeyResolver([malformed as never]);
        expect(resolver({ kid: "key", emitter: { id: "component", role }, ...(audience !== undefined ? { audience } : {}) })).toBeUndefined();
      }
    }
  });
});
