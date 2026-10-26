/**
 * @spec runtime#mission-binding (#956, D814): an enforcement scope declares
 * exactly the Mission-establishment modes it serves. The reference stack
 * serves the credential-carried mode always, and the externally established
 * mode only where the MAS-governed channel's baseline Join governs the
 * payments resource; the AS-native target (no MAS) declares
 * `credential_carried` alone (as-native-stack.test.ts witnesses the running
 * target's published statement).
 */
import { describe, expect, it } from "vitest";
import { loadRuntimePosture, RUNTIME_POSTURE } from "@mission/pdp";
import { withServedEstablishmentModes } from "../src/stack.js";

describe("the stack declares the Mission-establishment modes it serves (@spec runtime#mission-binding, #956)", () => {
  it("the published statement declares both modes, for the full reference stack that serves the MAS baseline Join", () => {
    expect(RUNTIME_POSTURE.mediated_scope.mission_establishment_mode).toEqual(["credential_carried", "externally_established"]);
  });

  it("declares both modes where the MAS Join governs the payments resource, and credential_carried alone where it does not", () => {
    const both = withServedEstablishmentModes(RUNTIME_POSTURE, true);
    expect(both.mediated_scope.mission_establishment_mode).toEqual(["credential_carried", "externally_established"]);
    const credentialOnly = withServedEstablishmentModes(RUNTIME_POSTURE, false);
    expect(credentialOnly.mediated_scope.mission_establishment_mode).toBe("credential_carried");
    // Either declaration is a statement the loader accepts; nothing else in it changes.
    expect(() => loadRuntimePosture(both)).not.toThrow();
    expect(() => loadRuntimePosture(credentialOnly)).not.toThrow();
    expect({ ...credentialOnly.mediated_scope, mission_establishment_mode: undefined }).toEqual({
      ...RUNTIME_POSTURE.mediated_scope,
      mission_establishment_mode: undefined,
    });
  });
});
