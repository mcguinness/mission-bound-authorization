/**
 * @spec cross-domain#dual-axis, cross-domain#origin-principal-mapping,
 * authzen#pdp-request rule 10 (#539 stage A)
 *
 * The PDP's half of the cross-domain Origin Principal profile's dual-axis
 * authorization: `context.mission.subject` (the origin principal) mapped to
 * the authenticated local subject, and the mapped principal's current
 * entitlement, both resolved through injected, fail-closed resolver
 * contracts (`EvaluateOptions.principalMapping` / `.entitlement`), the same
 * dependency-injection idiom `fga: Fga` already uses. A stub `Fga` that
 * always permits is used throughout: only step 4a's own logic decides these
 * outcomes, never the FGA layer.
 */

import { describe, expect, it } from "vitest";
import type { Fga } from "../src/fga.js";
import { evaluate, type EvaluationRequest, type EvaluateOptions } from "../src/evaluate.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type AuthorityEntry, type MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBoundSeconds } from "../src/policy.js";
import type { EntitlementObservation, OriginPrincipal, PrincipalMappingObservation } from "@mission/core";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-08-23T12:00:00Z");

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const ORIGIN: OriginPrincipal = { iss: "https://id.origin.example", sub: "p-7QxT2m" };
const LOCAL: OriginPrincipal = { iss: "https://as.test", sub: "emp-4417" };

const FRESH_MAPPING: PrincipalMappingObservation = {
  local: LOCAL,
  policy: { id: "policy-1", version: "1" },
  observed_at: "2026-08-23T11:55:00Z",
  valid_until: "2026-08-23T13:00:00Z",
};

const ENTITLED: EntitlementObservation = { entitled: true, observed_at: "2026-08-23T11:59:00Z" };

const entry: AuthorityEntry = {
  type: MISSION_RESOURCE_ACCESS_TYPE,
  resource: RESOURCE,
  actions: ["payments:invoice.read"],
};

const view: MissionView = {
  id: "msn_test_1",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [entry],
};

const baseOpts = (extra: Partial<EvaluateOptions> = {}): EvaluateOptions => ({
  view,
  fga: alwaysAllowFga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBoundSeconds,
  relationForAction,
  allowedFreshnessSources: new Set(["status"]),
  ...extra,
});

const req = (over: Partial<EvaluationRequest> = {}): EvaluationRequest => ({
  subject: { id: LOCAL.sub, properties: { iss: LOCAL.iss } },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: "payments:invoice.read" },
  context: {
    audience: RESOURCE,
    mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash", subject: ORIGIN },
  },
  ...over,
});

// Deliberately no JS default parameter values: `resolverOpts(undefined, ...)`
// must mean "the resolver returns undefined", never "use the happy-path
// fixture" (a default parameter substitutes on an explicit `undefined` too,
// which would silently defeat every negative test below).
const resolverOpts = (
  mapping: PrincipalMappingObservation | undefined,
  entitlement: EntitlementObservation | undefined,
  entitlementStalenessBoundSeconds: number | undefined,
): EvaluateOptions =>
  baseOpts({
    principalMapping: { resolve: async () => mapping },
    entitlement: { resolve: async () => entitlement },
    ...(entitlementStalenessBoundSeconds !== undefined ? { entitlementStalenessBoundSeconds } : {}),
  });

describe("evaluateInner cross-domain Origin Principal dual-axis (#539 stage A)", () => {
  it("a request NOT claiming the profile (no context.mission.subject) is completely unaffected: no resolvers configured, still permits", async () => {
    const dec = await evaluate(req({ context: { audience: RESOURCE, mission: { id: "msn_test_1", issuer: "https://as.test", authority_hash: "sha-256:testhash" } } }), baseOpts());
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    expect(dec.context.principal_mapping).toBeUndefined();
  });

  it("profile claimed, everything valid: permits, and the permit carries a complete principal_mapping evidence object", async () => {
    const dec = await evaluate(req(), resolverOpts(FRESH_MAPPING, ENTITLED, 600));
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    expect(dec.context.principal_mapping).toEqual({
      origin: ORIGIN,
      local: LOCAL,
      policy: FRESH_MAPPING.policy,
      observed_at: FRESH_MAPPING.observed_at,
      valid_until: FRESH_MAPPING.valid_until,
    });
  });

  it("profile claimed, no principalMapping/entitlement resolver configured at all: denies principal_mapping_failed (fail-closed-on-unconfigured, same idiom as allowedFreshnessSources)", async () => {
    const dec = await evaluate(req(), baseOpts());
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("principal_mapping_failed");
  });

  it("mapping resolver returns undefined (missing/ambiguous/disabled mapping): denies principal_mapping_failed", async () => {
    const dec = await evaluate(req(), resolverOpts(undefined, ENTITLED, 600));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("principal_mapping_failed");
    expect(dec.context.principal_mapping).toBeUndefined();
  });

  it("mapping resolved but stale beyond its OWN valid_until: denies principal_mapping_failed", async () => {
    const stale: PrincipalMappingObservation = { ...FRESH_MAPPING, valid_until: "2026-08-23T11:00:00Z" };
    const dec = await evaluate(req(), resolverOpts(stale, ENTITLED, 600));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("principal_mapping_failed");
  });

  it("mapping resolved to a DIFFERENT local principal than the authenticated request subject: denies principal_mapping_failed, never compares context.mission.subject to the request subject directly", async () => {
    const wrong: PrincipalMappingObservation = { ...FRESH_MAPPING, local: { iss: "https://as.test", sub: "someone-else" } };
    const dec = await evaluate(req(), resolverOpts(wrong, ENTITLED, 600));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("principal_mapping_failed");
  });

  it("request subject carries no properties.iss (cannot represent an issuer-qualified local subject): denies principal_mapping_failed", async () => {
    const dec = await evaluate(req({ subject: { id: LOCAL.sub } }), resolverOpts(FRESH_MAPPING, ENTITLED, 600));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("principal_mapping_failed");
  });

  it("mapping valid, entitlement resolver returns undefined: denies principal_mapping_failed, but the mapping WAS established so principal_mapping evidence is still attached (Refusal Record binding)", async () => {
    const dec = await evaluate(req(), resolverOpts(FRESH_MAPPING, undefined, 600));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("principal_mapping_failed");
    expect(dec.context.principal_mapping).toEqual({
      origin: ORIGIN,
      local: LOCAL,
      policy: FRESH_MAPPING.policy,
      observed_at: FRESH_MAPPING.observed_at,
      valid_until: FRESH_MAPPING.valid_until,
    });
  });

  it("mapping valid, entitlement resolved but entitled: false: denies principal_mapping_failed (an established negative result is still \"a failed ... result\")", async () => {
    const dec = await evaluate(req(), resolverOpts(FRESH_MAPPING, { entitled: false, observed_at: "2026-08-23T11:59:00Z" }, 600));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("principal_mapping_failed");
  });

  it("mapping valid, entitlement entitled but stale beyond entitlementStalenessBoundSeconds: denies principal_mapping_failed", async () => {
    const staleEntitlement: EntitlementObservation = { entitled: true, observed_at: "2026-08-23T10:00:00Z" }; // 2h old
    const dec = await evaluate(req(), resolverOpts(FRESH_MAPPING, staleEntitlement, 600));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("principal_mapping_failed");
  });

  it("mapping valid, entitlement.observed_at dated in the future beyond the skew tolerance: denies principal_mapping_failed, never permits on the negative age a future timestamp produces (@spec runtime#state-freshness GAP 3, #612, mirrored here for the entitlement bound)", async () => {
    const futureEntitlement: EntitlementObservation = { entitled: true, observed_at: new Date(NOW.getTime() + 5 * 60_000).toISOString() };
    const dec = await evaluate(req(), resolverOpts(FRESH_MAPPING, futureEntitlement, 600));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("principal_mapping_failed");
  });

  it("mapping valid, entitlement.observed_at dated in the future WITHIN the skew tolerance: still permits (boundary control: the tolerance itself is not itself a denial)", async () => {
    const withinSkew: EntitlementObservation = { entitled: true, observed_at: new Date(NOW.getTime() + 5_000).toISOString() };
    const dec = await evaluate(req(), resolverOpts(FRESH_MAPPING, withinSkew, 600));
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
  });

  it("mapping and entitlement both valid but entitlementStalenessBoundSeconds is not configured: denies principal_mapping_failed (a declared bound is required, never defaulted open)", async () => {
    const dec = await evaluate(req(), resolverOpts(FRESH_MAPPING, ENTITLED, undefined));
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("principal_mapping_failed");
  });

  it("ordering: the dual-axis check runs before the authority-entry match, so a request with NO matching entry at all still denies principal_mapping_failed, not out_of_authority, when the profile check fails first", async () => {
    const noMatchView: MissionView = { ...view, authority_set: [] };
    const opts: EvaluateOptions = { ...resolverOpts(undefined, ENTITLED, 600), view: noMatchView };
    const dec = await evaluate(req(), opts);
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("principal_mapping_failed");
  });

  it("mapping fresh at the exact valid_until boundary (inclusive) still permits", async () => {
    const boundary: PrincipalMappingObservation = { ...FRESH_MAPPING, valid_until: NOW.toISOString() };
    const dec = await evaluate(req(), resolverOpts(boundary, ENTITLED, 600));
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
  });

  it("entitlement observed exactly at the staleness boundary (inclusive) still permits", async () => {
    const boundary: EntitlementObservation = { entitled: true, observed_at: new Date(NOW.getTime() - 600_000).toISOString() };
    const dec = await evaluate(req(), resolverOpts(FRESH_MAPPING, boundary, 600));
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
  });
});
