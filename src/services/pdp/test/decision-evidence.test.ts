/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-object,
 * #decision-evidence-integrity; draft-mcguinness-mission-runtime.md#agent-isolated-evidence-emission
 * (issue #741).
 *
 * The PDP builds and signs the Decision Evidence it emits, from the decision
 * it just reached, and returns the complete signed object on the response
 * decision context. These cases assert the emission itself: a record that an
 * independent verifier accepts on a permit and on a deny, ordered
 * verification that rejects a mutated outer object before it ever checks the
 * signature, the protected header the integrity section fixes, the emitter's
 * own monotonic sequence, and the two things a caller cannot do (supply the
 * record's emitter, decision, or sequence position; sign for a scope the
 * emitter's key does not serve).
 *
 * Unconditional: a stub `Fga` satisfies the one method evaluate() calls, so
 * this file never skips.
 */

import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import {
  createDecisionEvidenceEmitter,
  DECISION_EVIDENCE_MEDIA_TYPE,
  type DecisionEvidenceObject,
  evaluate,
  type EvaluateOptions,
  type EvaluationRequest,
  type MissionView,
  relationForAction,
  RUNTIME_EVIDENCE_JWS_TYP,
  stalenessBoundSeconds,
  verifyEvidenceEnvelope,
} from "../src/index.js";

const RESOURCE = "http://localhost:4403/mcp";
const EMITTER = "http://localhost:4403/mcp";
const NOW = new Date("2026-07-22T12:00:00Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const view = (over: Partial<MissionView> = {}): MissionView => ({
  id: "msn_evd_1",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
  ...over,
});

const req = (over: Partial<EvaluationRequest> = {}): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: "payments:invoice.read" },
  context: {
    audience: RESOURCE,
    mission: { id: "msn_evd_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" },
  },
  ...over,
});

/** One emitter plus the public half a verifier resolves, bound to emitter id, role, and audience. */
function emitterFixture(options: { emitterId?: string; audience?: string } = {}) {
  const { emitterId = EMITTER, audience = RESOURCE } = options;
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const kid = "pdp-decision-evidence-test";
  const emitter = createDecisionEvidenceEmitter({ signer: { kid, key: privateKey }, emitterId, audience });
  const resolve = (params: { kid: string; emitter: { id: string; role: string }; audience?: string }) =>
    params.kid === kid && params.emitter.role === "pdp" && params.emitter.id === emitterId && params.audience === audience
      ? { key: publicKey }
      : undefined;
  return { emitter, resolve, kid };
}

function opts(over: Partial<EvaluateOptions> = {}): EvaluateOptions {
  return {
    view: view(),
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    now: () => NOW,
    stalenessBoundSeconds,
    relationForAction,
    ...over,
  } as EvaluateOptions;
}

describe("evaluate() emits the Decision Evidence it decided (@spec runtime-evidence#decision-evidence-object, #741)", () => {
  it("returns a signed record on a PERMIT that an independent verifier accepts", async () => {
    const { emitter, resolve } = emitterFixture();
    const decision = await evaluate(req(), opts({ evidence: emitter }));
    expect(decision.decision).toBe(true);
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    expect(record).toBeDefined();
    expect(record.decision).toBe("permit");
    expect(record.emitter).toEqual({ id: EMITTER, role: "pdp" });
    expect(record.evaluation_id).toBe(decision.context.evaluation_id);
    expect(record.mission).toEqual({
      id: "msn_evd_1",
      issuer: "https://as.test",
      policy_view_id: decision.context.policy_view_id,
      authority_hash: "sha-256:testhash",
    });
    expect(record.evaluated_at).toBe(NOW.toISOString());
    await expect(verifyEvidenceEnvelope(record, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).resolves.toEqual({
      valid: true,
    });
  });

  it("returns a signed record on a DENY, carrying the PDP's own denial reason", async () => {
    const { emitter, resolve } = emitterFixture();
    const decision = await evaluate(req(), opts({ evidence: emitter, view: view({ authority_set: [] }) }));
    expect(decision.decision).toBe(false);
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    expect(record.decision).toBe("deny");
    expect(record.denial_reason).toBe("out_of_authority");
    await expect(verifyEvidenceEnvelope(record, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).resolves.toEqual({
      valid: true,
    });
  });

  it("rejects a mutated outer object at the byte-equality step, BEFORE the signature is checked", async () => {
    const { emitter, resolve } = emitterFixture();
    const decision = await evaluate(req(), opts({ evidence: emitter }));
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    // The envelope still carries the genuine signature over the ORIGINAL
    // payload; the outer object no longer matches it (@spec
    // runtime-evidence#decision-evidence-integrity step 3).
    const tampered = { ...record, decision: "deny" as const };
    await expect(verifyEvidenceEnvelope(tampered, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).resolves.toEqual({
      valid: false,
      reason: "byte_mismatch",
    });
  });

  it("carries the protected header the integrity section fixes: kid, alg, typ, and the record kind's cty", async () => {
    const { emitter, kid } = emitterFixture();
    const decision = await evaluate(req(), opts({ evidence: emitter }));
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    const [protectedB64] = record.evidence_envelope.value.split(".") as [string];
    const header = JSON.parse(Buffer.from(protectedB64, "base64url").toString("utf8"));
    expect(header).toEqual({
      alg: "ES256",
      kid,
      typ: RUNTIME_EVIDENCE_JWS_TYP,
      cty: DECISION_EVIDENCE_MEDIA_TYPE,
    });
  });

  it("allocates the emitter's OWN monotonic per-(Mission, emitter) sequence, which does not reset within a process", async () => {
    const { emitter } = emitterFixture();
    const o = opts({ evidence: emitter });
    const first = await evaluate(req(), o);
    const second = await evaluate(req(), o);
    // A different Mission counts separately; the first Mission's counter is
    // unaffected and keeps climbing afterwards.
    const otherMission = await evaluate(
      req({ context: { audience: RESOURCE, mission: { id: "msn_evd_2", issuer: "https://as.test" } } }),
      opts({ evidence: emitter, view: view({ id: "msn_evd_2" }) }),
    );
    const third = await evaluate(req(), o);
    const seq = (d: { context: Record<string, unknown> }) =>
      (d.context.decision_evidence as DecisionEvidenceObject).sequence;
    expect([seq(first), seq(second), seq(third)]).toEqual([0, 1, 2]);
    expect(seq(otherMission)).toBe(0);
  });

  it("emits NO record when no emitter is wired: an unevidenced decision is visible as such, never silently unsigned", async () => {
    const decision = await evaluate(req(), opts());
    expect(decision.decision).toBe(true);
    expect(decision.context.decision_evidence).toBeUndefined();
  });

  it("refuses to sign for an audience its published key does not serve", async () => {
    const { emitter } = emitterFixture({ audience: "https://other-scope.example.com" });
    await expect(evaluate(req(), opts({ evidence: emitter }))).rejects.toThrow(/audience/);
  });

  it("offers a caller no seam to set the record's emitter, decision, or sequence", () => {
    // The options a caller passes to `evaluate` carry the emission PATH, never
    // the emitted CONTENT (@spec runtime#agent-isolated-evidence-emission: the
    // caller cannot supply the completed record, nor assert the emitter
    // identity and role, the decision, or the sequence position). This is a
    // structural claim about `EvaluateOptions.evidence`, asserted here on the
    // runtime shape the wiring actually hands over.
    const { emitter } = emitterFixture();
    const o = opts({ evidence: emitter });
    expect(Object.keys(o.evidence as object)).toEqual(["emit"]);
    for (const forbidden of ["emitter", "decision", "sequence", "evidence_id", "sign", "kid", "key"]) {
      expect(o).not.toHaveProperty(forbidden);
      expect(o.evidence as object).not.toHaveProperty(forbidden);
    }
  });
});
