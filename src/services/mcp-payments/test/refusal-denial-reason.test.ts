/**
 * @spec runtime-evidence#pre-decision-refusal (#1148, D379): a PEP Refusal
 * Record's `denial_reason` comes from a closed set. The PEP maps each
 * diagnostic on its Refusal Record path exhaustively, refuses one it cannot
 * map before signing, and the evidence store refuses a value outside the
 * emitting role's set. The enforcement-path witness is in
 * operation-profile-intake.test.ts.
 */
import { describe, expect, it } from "vitest";
import {
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  isPepRefusalDiagnostic,
  isRefusalDenialReason,
  PRE_DECISION_DENIAL_REASON,
  REFUSAL_DENIAL_REASONS,
  signedDenialReason,
  UnmappedRefusalDiagnosticError,
} from "../src/index.js";

/** The diagnostics the PEP's `refuse` and `recordRefusal` call sites pass. */
const REFUSAL_RECORD_DIAGNOSTICS = [
  "unknown_tool",
  "invalid_request",
  "unknown_mission",
  "unknown_invoice",
  "unknown_vendor",
  "out_of_authority",
  "instance_revoked",
  "mission_reference_conflict",
  "state_unavailable",
  "capability_source_unresolvable",
  "decision_evidence_unverifiable",
  "channel_failure",
  "pdp_unreachable",
];

const refusalInput = (denial_reason: string) => ({
  missionId: "msn_1148",
  audience: CANONICAL_RESOURCE,
  action: { name: "payments:invoice.read" },
  denial_reason,
});

describe("the PEP maps every Refusal Record diagnostic into the closed set (@spec runtime-evidence#pre-decision-refusal, #1148, D379)", () => {
  it("the mapping covers exactly the Refusal Record path's diagnostics, and each maps to a value in the closed PEP set", () => {
    expect(Object.keys(PRE_DECISION_DENIAL_REASON).sort()).toEqual([...REFUSAL_RECORD_DIAGNOSTICS].sort());
    for (const diagnostic of REFUSAL_RECORD_DIAGNOSTICS) {
      const value = signedDenialReason(diagnostic);
      expect(REFUSAL_DENIAL_REASONS.pep, diagnostic).toContain(value);
    }
  });

  it("an unmapped diagnostic throws instead of being signed, including prototype keys and reasons from other sets", () => {
    const unmapped = [
      "invoice_not_found_here",
      // Post-permit Execution Evidence and a PDP decision denial belong to other sets.
      "unrecognized_condition",
      "unfulfillable_obligation",
      "parameter_violation",
      // The PDP's own refusal is never a PEP diagnostic.
      "mission_context_missing",
      "toString",
      "constructor",
      "__proto__",
    ];
    for (const diagnostic of unmapped) {
      expect(isPepRefusalDiagnostic(diagnostic), diagnostic).toBe(false);
      expect(() => signedDenialReason(diagnostic), diagnostic).toThrow(UnmappedRefusalDiagnosticError);
    }
  });
});

describe("the evidence store refuses a denial_reason outside the emitting role's closed set before signing (@spec runtime-evidence#pre-decision-refusal, #1148, D379)", () => {
  it("a PEP record carrying a diagnostic or another role's value is refused unsigned, while every closed PEP value signs", async () => {
    const keys = createEphemeralEvidenceKeys();
    const evidence = new EvidenceStore(keys.signing, keys.resolver);
    for (const bad of ["out_of_authority", "unknown_invoice", "mission_context_missing", "parameter_violation"]) {
      await expect(evidence.recordRefusal(CANONICAL_RESOURCE, "pep", refusalInput(bad)), bad).rejects.toThrow(/not in the closed set/);
    }
    expect(evidence.all()).toHaveLength(0);
    // Every closed value signs, including the two this PEP never produces.
    for (const value of REFUSAL_DENIAL_REASONS.pep) {
      const record = await evidence.recordRefusal(CANONICAL_RESOURCE, "pep", refusalInput(value));
      expect(record.content.denial_reason, value).toBe(value);
    }
    expect(evidence.all()).toHaveLength(REFUSAL_DENIAL_REASONS.pep.length);
  });

  it("the closed sets are role-aware: mission_context_missing is the PDP's alone", () => {
    expect(isRefusalDenialReason("pdp", "mission_context_missing")).toBe(true);
    expect(isRefusalDenialReason("pep", "mission_context_missing")).toBe(false);
    for (const value of REFUSAL_DENIAL_REASONS.pep) {
      expect(isRefusalDenialReason("pep", value), value).toBe(true);
      expect(isRefusalDenialReason("pdp", value), value).toBe(false);
    }
  });
});
