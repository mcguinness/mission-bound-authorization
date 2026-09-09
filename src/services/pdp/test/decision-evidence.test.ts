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
import { readFileSync } from "node:fs";
import { canonicalDigest, capabilitySourceDigest, type CapabilitySourceBinding } from "@mission/core";
import { runtimeCapabilitySourceOf, type RuntimeCapabilitySource } from "../src/decision-evidence.js";
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
  stalenessBound,
  verifyEvidenceEnvelope,
} from "../src/index.js";

const RESOURCE = "http://localhost:4403/mcp";
const EMITTER = "http://localhost:4403/mcp";
const NOW = new Date("2026-07-22T12:00:00Z");
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

describe("Decision Evidence records the entries a decision turned on (@spec runtime-evidence#decision-evidence-object)", () => {
  async function recorded(request: EvaluationRequest, v: MissionView, extra: Partial<EvaluateOptions> = {}) {
    const fixture = emitterFixture();
    const decision = await evaluate(request, opts({ view: v, evidence: fixture.emitter, ...extra }));
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    expect(await verifyEvidenceEnvelope(record, DECISION_EVIDENCE_MEDIA_TYPE, fixture.resolve)).toEqual({ valid: true });
    return { record, decision };
  }

  it("a permit lists each evaluated entry type and constraint key, never caller-supplied text", async () => {
    const v = view();
    v.authority_set[0]!.constraints = { vendors: ["acme"], max_amount: { amount: "500", currency: "USD" }, requires_action_approval: false };
    const r = req(); r.context.amount = { amount: "20", currency: "USD" };
    Object.assign(r.context, { contributing_constraints: ["caller-invented"] });
    const { record, decision } = await recorded(r, v);
    expect(decision.decision).toBe(true);
    expect(record.contributing_constraints).toEqual(["mission_resource_access", "vendors", "max_amount", "requires_action_approval"]);
    expect(record).not.toHaveProperty("denial_reason");
  });

  it("a constraint deny keeps parameter_violation separate from the evaluated keys and omits unvisited checks", async () => {
    const v = view();
    v.authority_set[0]!.constraints = { vendors: ["acme"], max_amount: { amount: "500", currency: "USD" }, requires_action_approval: true };
    // A later entry is not evaluated after the first matching entry's denial.
    v.authority_set.push({ type: "not-visited-entry", resource: RESOURCE, actions: ["payments:invoice.read"] } as never);
    const r = req(); r.context.amount = { amount: "501", currency: "USD" };
    const { record, decision } = await recorded(r, v);
    expect(decision.context.reason).toBe("parameter_violation");
    expect(record.denial_reason).toBe("parameter_violation");
    expect(record.contributing_constraints).toEqual(["mission_resource_access", "vendors", "max_amount"]);
  });

  it("a vendor constraint that excludes the target records the key it evaluated and never reaches resource policy", async () => {
    const v = view(); v.authority_set[0]!.constraints = { vendors: ["globex"], max_amount: { amount: "500", currency: "USD" } };
    const throwingFga = { checkWithContext: async () => { throw new Error("must not reach FGA"); } } as unknown as Fga;
    // @spec authzen#runtime-denial-classification (#801): the vendor
    // exclusion is decided BEFORE the contextual tuple is built, so this is
    // a parameter violation on the matched entry, never out_of_authority;
    // the evaluated constraint key is recorded either way, and max_amount is
    // never visited, and resource policy (the stub Fga) is never reached.
    const denied = await recorded(req(), v, { fga: throwingFga });
    expect(denied.record.denial_reason).toBe("parameter_violation");
    expect(denied.record.contributing_constraints).toEqual(["mission_resource_access", "vendors"]);
    v.authority_set[0]!.constraints!.vendors = ["acme"];
    const refused = await recorded(req(), v, { fga: { checkWithContext: async () => false } as unknown as Fga });
    expect(refused.record.denial_reason).toBe("out_of_authority");
    expect(refused.record.contributing_constraints).toEqual(["mission_resource_access", "vendors"]);
  });

  it("an early lifecycle denial records no authority entries and an unsupported type records only its evaluated identifier", async () => {
    const early = await recorded(req(), view({ state: "suspended" }));
    expect(early.record).not.toHaveProperty("contributing_constraints");
    const v = view(); v.authority_set[0]!.type = "future-entry" as never;
    const unsupported = await recorded(req(), v);
    expect(unsupported.record.denial_reason).toBe("unsupported_authorization_type");
    expect(unsupported.record.contributing_constraints).toEqual(["future-entry"]);
  });

  it("a delegate narrowing failure records the loaded entry types without inventing checks of their constraints", async () => {
    const v = view(); v.authority_set[0]!.join_delegation = { max_depth: 0 };
    v.authority_set[0]!.constraints = { max_amount: { amount: "0", currency: "USD" } };
    const r = req(); r.subject.properties = { iss: v.subject.iss };
    r.context.actor = { client_id: "delegate" }; r.context.mission_join = { delegate_depth: 1 };
    const { record } = await recorded(r, v, { delegatePolicy: { delegates: { delegate: {} } } });
    expect(record.denial_reason).toBe("mission_mismatch");
    expect(record.contributing_constraints).toEqual(["mission_resource_access"]);
  });
});

describe("validated capability evidence (#657)", () => {
  it("applies the shared recording digest vectors independently at the evidence boundary", () => {
    const vectors = JSON.parse(readFileSync(new URL("../../../test-fixtures/capability-digests.json", import.meta.url), "utf8")) as Array<{ label: string; value: unknown; valid: boolean }>;
    const binding = { tool_id: "mcp://payments.test/tools/get_invoice", source_uri: "https://payments.test/catalog", operation_ref: "get_invoice", source_digest: capabilitySourceDigest({ name: "get_invoice" }) };
    for (const vector of vectors) for (const member of ["source_digest", "catalog_digest"] as const) {
      expect(runtimeCapabilitySourceOf({ ...binding, [member]: vector.value }) !== undefined, `${member}: ${vector.label}`).toBe(vector.valid);
    }
  });
  const presented: RuntimeCapabilitySource = { tool_id: "mcp://payments.test/tools/get_invoice", source_uri: "https://payments.test/.well-known/mcp", source_digest: capabilitySourceDigest({ name: "get_invoice" }), operation_ref: "get_invoice" };
  const recorded: CapabilitySourceBinding = { action: "payments:invoice.read", ...presented };
  async function decisionFor(value: unknown) {
    const fixture = emitterFixture();
    const v = view(); v.authority_set[0]!.capability_sources = [recorded];
    const request = req(); request.context.capability_source = value as never;
    const decision = await evaluate(request, opts({ view: v, evidence: fixture.emitter }));
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    expect(await verifyEvidenceEnvelope(record, DECISION_EVIDENCE_MEDIA_TYPE, fixture.resolve)).toEqual({ valid: true });
    return { decision, record };
  }

  it("records the compared binding on a permit", async () => {
    const { decision, record } = await decisionFor(presented);
    expect(decision.decision).toBe(true); expect(record.capability_source).toEqual(presented);
  });

  it("records a structurally valid but mismatched binding on a capability_drift denial", async () => {
    const mismatch = { ...presented, source_digest: capabilitySourceDigest({ changed: true }) };
    const { record } = await decisionFor(mismatch);
    expect(record.denial_reason).toBe("capability_drift"); expect(record.capability_source).toEqual(mismatch);
  });

  it.each([
    ["an empty object", {}],
    ["an array", []],
    ["null", null],
    ["a non-string executor", { ...presented, executor: 1 }],
    ["an unknown source_digest prefix", { ...presented, source_digest: "sha-512:abc" }],
    ["an unknown catalog_digest prefix", { ...presented, catalog_digest: "sha-512:abc" }],
    ["an empty source_digest", { ...presented, source_digest: "sha-256:" }],
    ["a supported prefix with a non-digest body", { ...presented, source_digest: "sha-256:not-a-digest" }],
    ["a non-canonical source_digest", { ...presented, source_digest: `sha-256:${"A".repeat(42)}B` }],
    ["an empty catalog_digest", { ...presented, catalog_digest: "sha-256:" }],
    ["a non-canonical catalog_digest", { ...presented, catalog_digest: `sha-256:${"A".repeat(42)}B` }],
  ] as const)("omits malformed capability input (%s) while retaining drift reason and request-summary digest", async (_label, malformed) => {
    const { record } = await decisionFor(malformed);
    expect(record.denial_reason).toBe("capability_drift");
    expect(record).not.toHaveProperty("capability_source");
    expect(record.evaluation_request_digest).toMatch(/^sha-256:/);
    // This digest identifies the documented request summary, NOT omitted bytes.
  });

  it("carries catalog_digest and executor when present and signs only the closed normalized shape", async () => {
    const extra = { ...presented, catalog_digest: capabilitySourceDigest({ whole: true }), executor: "executor-B", unregistered: "do not sign me" };
    const { record } = await decisionFor(extra);
    expect(record.capability_source).toEqual(runtimeCapabilitySourceOf(extra));
    expect(record.capability_source).not.toHaveProperty("unregistered");
    expect(record.capability_source?.catalog_digest).toBe(extra.catalog_digest);
    expect(record.capability_source?.executor).toBe(extra.executor);
  });

  it("omits capability_source where no binding was presented", async () => {
    const { record } = await decisionFor(undefined);
    expect(record).not.toHaveProperty("capability_source");
  });
});

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
    stalenessBound,
    relationForAction,
    ...over,
  } as EvaluateOptions;
}

describe("evaluate() emits the Decision Evidence it decided (@spec runtime-evidence#decision-evidence-object, #741)", () => {
  it("projects subject, actor, resource and credential at runtime and never signs raw nested claims or action parameters", async () => {
    const { emitter, resolve } = emitterFixture();
    const request = req();
    const secret = "RAW-CLAIM-OR-PARAMETER-MUST-NOT-BE-SIGNED";
    request.subject = { id: "alice", properties: { iss: "https://as.test", raw_claims: { secret } }, secret } as never;
    request.resource = { type: "invoice", id: "inv-1", properties: { vendor_id: "acme", secret }, secret } as never;
    request.action = { name: "payments:invoice.read", properties: { parameters: { secret } }, renamed_parameters: { secret } } as never;
    request.context.actor = { client_id: "ap-agent", secret, act: [
      { iss: "https://as.test", sub: "root", sub_profile: "service", cnf: { secret }, secret },
      { iss: "https://as.test", sub: "leaf", secret, act: { secret } },
    ] } as never;
    request.context.credential = { issuer: "https://as.test", expires_at: "2026-07-22T13:00:00Z", raw_token: secret, confirmation: { secret }, claims: { secret } } as never;
    request.context.parameter_digest = canonicalDigest({ secret });
    const decision = await evaluate(request, opts({ evidence: emitter }));
    expect(decision.decision).toBe(true);
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    expect(record.subject).toEqual({ id: "alice", properties: { iss: "https://as.test" } });
    expect(record.resource).toEqual({ type: "invoice", id: "inv-1" });
    expect(record.action).toEqual({ name: "payments:invoice.read" });
    expect(record.actor).toEqual({ client_id: "ap-agent", act: [
      { iss: "https://as.test", sub: "root", sub_profile: "service" }, { iss: "https://as.test", sub: "leaf" },
    ] });
    expect(record.credential).toEqual({ issuer: "https://as.test", expires_at: "2026-07-22T13:00:00Z" });
    expect(record.parameter_digest).toBe(request.context.parameter_digest);
    expect(JSON.stringify(record)).not.toContain(secret);
    const signed = Buffer.from(record.evidence_envelope.value.split(".")[1]!, "base64url").toString("utf8");
    expect(signed).not.toContain(secret);
    expect(await verifyEvidenceEnvelope(record, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    // The record owns its projections; a later caller mutation changes neither bytes nor verification.
    request.context.actor!.act![0]!.sub = "mutated";
    request.context.credential!.issuer = "https://mutated.test";
    expect(await verifyEvidenceEnvelope(record, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({ valid: true });
  });

  it("records the applied class, a permit entry digest and one matching parameter binding for every action class", async () => {
    const { emitter } = emitterFixture();
    for (const actionClass of [undefined, "consequential_read", "consequential_write", "irreversible_action", "external_commitment", "privileged_administration"]) {
      const request = req();
      request.context.action_class = actionClass;
      request.context.parameter_digest = canonicalDigest({ invoice_id: "inv-1" });
      request.context.freshness = { observed_at: NOW.toISOString(), source: "load_view" };
      const decision = await evaluate(request, opts({ evidence: emitter, allowedFreshnessSources: new Set(["load_view"]) }));
      expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
      const record = decision.context.decision_evidence as DecisionEvidenceObject;
      expect(record.action_class).toBe(actionClass ?? "consequential_read");
      expect(record.class_source).toBe(actionClass ? "deployment" : "default");
      expect(record.entry_digest).toMatch(/^sha-256:/);
      expect(record.parameter_digest).toBe((decision.context.conditions as { parameter_digest: string }).parameter_digest);
      expect(record.conditions).not.toHaveProperty("parameter_digest");
      expect(record).not.toHaveProperty("evaluation_request_digest");
      expect(Number.isFinite(Date.parse(record.conditions!.valid_until))).toBe(true);
      if (["irreversible_action", "external_commitment", "privileged_administration"].includes(actionClass ?? "")) expect(record.conditions!.use_limit).toBe(1);
    }
  });

  it("uses only the documented request-summary digest without a parameter binding on permit and deny, and omits absent credential", async () => {
    const { emitter } = emitterFixture();
    for (const authority_set of [view().authority_set, []]) {
      const decision = await evaluate(req(), opts({ view: view({ authority_set }), evidence: emitter }));
      const record = decision.context.decision_evidence as DecisionEvidenceObject;
      expect(record).not.toHaveProperty("parameter_digest");
      expect(record.evaluation_request_digest).toMatch(/^sha-256:/);
      expect(record).not.toHaveProperty("credential");
    }
  });

  it("a view-mismatch denial names the request Mission and the PDP view separately, never another Mission's authority anchor", async () => {
    const { emitter, resolve } = emitterFixture();
    const request = req();
    request.context.mission = { id: "different-mission", issuer: "https://other.test", policy_version: "policy-7" };
    const decision = await evaluate(request, opts({ evidence: emitter }));
    expect(decision.context.denial_reason).toBe("view_inconsistent");
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    expect(record.mission).toEqual({ id: "different-mission", issuer: "https://other.test", policy_version: "policy-7", policy_view_id: decision.context.policy_view_id });
    expect(record.mission).not.toHaveProperty("authority_hash");
    expect(await verifyEvidenceEnvelope(record, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({ valid: true });
  });

  it("refuses an inconsistent binding or unbounded high-consequence permit before signing", async () => {
    const { emitter } = emitterFixture();
    const input = {
      mission: { id: "msn", issuer: "https://as.test", policy_view_id: "pv" }, subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1" }, action: { name: "payments:invoice.read" }, audience: RESOURCE,
      evaluation_id: "evaluation", decision: "permit" as const, evaluated_at: NOW.toISOString(),
      entry_digest: canonicalDigest({ entry: true }), conditions: { valid_until: NOW.toISOString() },
    };
    await expect(emitter.emit({ ...input, parameter_digest: canonicalDigest({ amount: 1 }) })).rejects.toThrow("binding differs");
    await expect(emitter.emit({ ...input, action_class: "privileged_administration" })).rejects.toThrow("use_limit 1");
    await expect(emitter.emit({ ...input, entry_digest: undefined })).rejects.toThrow("entry digest and conditions");
    await expect(emitter.emit({ ...input, action_class: "unregistered" as never })).rejects.toThrow("unknown action class");
  });

  it("evidence_id matches 1*64(ALPHA/DIGIT/-/_) and its random segment decodes to at least 128 bits", async () => {
    const { emitter } = emitterFixture();
    const decision = await evaluate(req(), opts({ evidence: emitter }));
    const record = decision.context.decision_evidence as DecisionEvidenceObject;
    expect(record.evidence_id).toMatch(/^[A-Za-z0-9_-]{1,64}$/);
    expect(record.evidence_id.startsWith("evd_")).toBe(true);
    const randomSegment = record.evidence_id.slice("evd_".length);
    const bytes = Buffer.from(randomSegment, "base64url");
    expect(bytes.toString("base64url")).toBe(randomSegment);
    expect(bytes.byteLength * 8).toBeGreaterThanOrEqual(128);
    // Shape is tested here; entropy is supplied by newRecordId's CSPRNG
    // randomBytes(20), not inferred from sample uniqueness or string length.
  });

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
