import { AUTHORITY_ENTRY_TYP, capabilitySourceDigest, computeAnchor, type CapabilitySourceBinding } from "@mission/core";
import { describe, expect, it } from "vitest";
import { evaluate, type EvaluationRequest, type EvaluateOptions } from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import type { MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBoundSeconds } from "../src/policy.js";

const resource = "https://payments.test/mcp", action = "payments:invoice.read";
const binding: CapabilitySourceBinding = { action, tool_id: "mcp://payments.test/tools/get_invoice", source_uri: "https://payments.test/.well-known/mcp", source_digest: capabilitySourceDigest({ name: "get_invoice" }), operation_ref: "get_invoice" };
const { action: _recordedAction, ...presented } = binding;
const makeView = (): MissionView => ({ id: "msn_cap", issuer: "https://as.test", authority_hash: "sha-256:test", state: "active", version: 1,
  subject: { iss: "https://as.test", sub: "alice" }, client_id: "ap-agent",
  authority_set: [{ type: "mission_resource_access", resource, actions: [action, "payments:vendor.read"], capability_sources: [binding] }] });
const makeRequest = (): EvaluationRequest => ({ subject: { id: "alice" }, resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } }, action: { name: action }, context: {
  audience: resource, mission: { id: "msn_cap", issuer: "https://as.test", authority_hash: "sha-256:test" }, capability_source: { ...presented },
} });
function options(view = makeView()): EvaluateOptions {
  return { view, fga: { checkWithContext: async () => true } as unknown as Fga, modelId: "test", now: () => new Date("2026-09-04T12:00:00Z"), relationForAction, stalenessBoundSeconds };
}

describe("recorded per-action capability verification", () => {
  it("permits when the presented binding matches the recorded one", async () => {
    expect((await evaluate(makeRequest(), options())).decision).toBe(true);
  });

  it.each(["source_digest", "tool_id", "source_uri", "operation_ref"] as const)("denies capability_drift on a mismatched %s before resource policy", async member => {
    const req = makeRequest();
    req.context.capability_source![member] = member === "source_digest" ? capabilitySourceDigest({ changed: true }) : "substituted";
    let calls = 0;
    const opts = options();
    opts.relationForAction = () => { calls++; return null; };
    expect((await evaluate(req, opts)).context.denial_reason).toBe("capability_drift");
    expect(calls).toBe(0);
  });

  it.each([
    ["absent", undefined],
    ["null", null],
    ["an array", []],
    ["an empty object", {}],
    ["a non-string executor", { ...presented, executor: 4 }],
    ["an unknown digest algorithm prefix", { ...presented, source_digest: "sha-512:abc" }],
    ["an empty sha-256 digest", { ...presented, source_digest: "sha-256:" }],
    ["a supported prefix with a non-digest body", { ...presented, source_digest: "sha-256:not-a-digest" }],
    ["a non-canonical base64url digest", { ...presented, source_digest: `sha-256:${"A".repeat(42)}B` }],
    ["a malformed catalog_digest", { ...presented, catalog_digest: "sha-256:" }],
  ] as const)("denies absent or malformed presentation: %s", async (_label, malformed) => {
    const req = makeRequest();
    req.context.capability_source = malformed as never;
    expect((await evaluate(req, options())).context.denial_reason).toBe("capability_drift");
  });

  it("compares catalog_digest where recorded, including omission", async () => {
    const view = makeView();
    const digest = capabilitySourceDigest({ whole: "catalog" });
    view.authority_set[0]!.capability_sources = [{ ...binding, catalog_digest: digest }];
    const req = makeRequest();
    expect((await evaluate(req, options(view))).context.denial_reason).toBe("capability_drift");
    req.context.capability_source!.catalog_digest = digest;
    expect((await evaluate(req, options(view))).decision).toBe(true);
    req.context.capability_source!.catalog_digest = capabilitySourceDigest({ whole: "changed" });
    expect((await evaluate(req, options(view))).context.denial_reason).toBe("capability_drift");
  });

  it("does not bind the request-time executor identity", async () => {
    const req = makeRequest(); req.context.capability_source!.executor = "https://replacement-executor.test";
    expect((await evaluate(req, options())).decision).toBe(true);
  });

  it("does not apply without recorded bindings, regardless of presentation", async () => {
    const view = makeView(); delete view.authority_set[0]!.capability_sources;
    for (const value of [undefined, {}, presented]) {
      const req = makeRequest(); req.context.capability_source = value as never;
      expect((await evaluate(req, options(view))).decision).toBe(true);
    }
  });

  it("uses only bindings for the requested action in a mixed entry", async () => {
    const req = makeRequest(); req.action.name = "payments:vendor.read"; delete req.context.capability_source;
    expect((await evaluate(req, options())).decision).toBe(true);
    req.action.name = action;
    expect((await evaluate(req, options())).context.denial_reason).toBe("capability_drift");
  });

  it("permits any approved tool_id for one action by set membership", async () => {
    const view = makeView();
    view.authority_set[0]!.capability_sources!.push({ ...binding, tool_id: "another-approved-tool" });
    const req = makeRequest(); req.context.capability_source!.tool_id = "another-approved-tool";
    expect((await evaluate(req, options(view))).decision).toBe(true);
  });

  it("preserves never-approved, contained and discharged reason precedence", async () => {
    const req = makeRequest(); delete req.context.capability_source;
    const never = makeView(); never.authority_set = [];
    expect((await evaluate(req, options(never))).context.denial_reason).toBe("out_of_authority");
    const contained = makeView(); contained.containment = { version: 1, contained: [{ resource, actions: [action] }] };
    expect((await evaluate(req, options(contained))).context.denial_reason).toBe("authority_contained");
    const discharged = makeView(); discharged.discharged = { entry_digests: [computeAnchor(AUTHORITY_ENTRY_TYP, discharged.issuer, discharged.authority_set[0] as never)] };
    expect((await evaluate(req, options(discharged))).context.denial_reason).toBe("authority_discharged");
  });
});
