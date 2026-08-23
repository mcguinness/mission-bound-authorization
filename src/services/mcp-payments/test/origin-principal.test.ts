/**
 * @spec authzen#context-mission, authzen#pdp-request (#539 stage A)
 *
 * The PEP's half of the cross-domain Origin Principal profile's AuthZEN
 * envelope construction: `context.mission.subject` and `subject.properties.iss`
 * are populated ONLY from verified `TokenFacts` -- never from `args`, the
 * per-request tool arguments a client controls -- and the resolved dual-axis
 * result reaches the PDP through `PepDeps.principalMapping`/`.entitlement`,
 * the same forwarding idiom `allowedFreshnessSources` already uses. A stub
 * `Fga` that always permits is used throughout: OpenFGA is not required for
 * any test in this file.
 */

import { describe, expect, it } from "vitest";
import type { EvaluationRequest, Fga, MissionView, OriginPrincipal } from "@mission/pdp";
import { CANONICAL_RESOURCE, EvidenceStore, PaymentsStore, Pep, sourceDigestOf, type TokenFacts } from "../src/index.js";

const ISSUER = "https://as.test";
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const ORIGIN: OriginPrincipal = { iss: "https://id.origin.example", sub: "p-7QxT2m" };

const missionId = "msn_539_envelope";
const view: MissionView = {
  id: missionId,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:hash539",
  authority_set: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:vendor.read"] }],
};

function build(): { pep: Pep; envelopes: EvaluationRequest[] } {
  const envelopes: EvaluationRequest[] = [];
  const pep = new Pep({
    payments: new PaymentsStore(),
    evidence: new EvidenceStore(),
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    loadView: (id) =>
      id === missionId ? { view, freshness: { observed_at: new Date().toISOString(), source: "load_view" } } : undefined,
    instanceEpoch: "epoch-1",
    sourceDigest: sourceDigestOf({ name: "payments" }),
    allowedFreshnessSources: new Set(["load_view"]),
    observe: (e) => envelopes.push(e.envelope),
  });
  return { pep, envelopes };
}

describe("PEP AuthZEN envelope: origin principal and local-subject issuer (#539 stage A)", () => {
  it("@spec authzen#context-mission -- context.mission.subject is populated from the verified TokenFacts, never from an unverified request value", async () => {
    const { pep, envelopes } = build();
    const token: TokenFacts = {
      sub: "emp-4417",
      clientId: "ap-agent",
      iss: ISSUER,
      mission: { id: missionId, issuer: ISSUER, authority_hash: "sha-256:hash539", subject: ORIGIN },
      cnfJkt: "jkt-1",
    };
    // The client-controlled tool arguments attempt to smuggle a different
    // origin principal in; a request field the PEP never reads for this
    // purpose, so it must have zero effect on the built envelope.
    await pep.enforce("lookup_vendor", { vendor_id: "acme", mission: { subject: { iss: "https://evil.example", sub: "attacker" } } }, token);
    expect(envelopes).toHaveLength(1);
    expect(envelopes[0]?.context.mission.subject).toEqual(ORIGIN);
  });

  it("@spec authzen#context-mission -- a token with no mission.subject (the profile not claimed) omits context.mission.subject entirely, never a synthesized empty object", async () => {
    const { pep, envelopes } = build();
    const token: TokenFacts = {
      sub: "emp-4417",
      clientId: "ap-agent",
      iss: ISSUER,
      mission: { id: missionId, issuer: ISSUER, authority_hash: "sha-256:hash539" },
      cnfJkt: "jkt-1",
    };
    await pep.enforce("lookup_vendor", { vendor_id: "acme" }, token);
    expect(envelopes).toHaveLength(1);
    expect(envelopes[0]?.context.mission.subject).toBeUndefined();
  });

  it("@spec authzen#pdp-request (subject.properties.iss) -- populated from the verified TokenFacts.iss (this resource's own issuer), regardless of whether the profile is claimed", async () => {
    const { pep, envelopes } = build();
    const token: TokenFacts = {
      sub: "emp-4417",
      clientId: "ap-agent",
      iss: ISSUER,
      mission: { id: missionId, issuer: ISSUER, authority_hash: "sha-256:hash539" },
      cnfJkt: "jkt-1",
    };
    await pep.enforce("lookup_vendor", { vendor_id: "acme" }, token);
    expect(envelopes[0]?.subject).toEqual({ id: "emp-4417", properties: { iss: ISSUER } });
  });

  it("@spec authzen#pdp-request (subject.properties.iss) -- 'a PEP that cannot establish the Subject's issuer omits it': TokenFacts.iss absent means subject.properties is absent too, never a fabricated value", async () => {
    const { pep, envelopes } = build();
    const token: TokenFacts = {
      sub: "emp-4417",
      clientId: "ap-agent",
      mission: { id: missionId, issuer: ISSUER, authority_hash: "sha-256:hash539" },
      cnfJkt: "jkt-1",
    };
    await pep.enforce("lookup_vendor", { vendor_id: "acme" }, token);
    expect(envelopes[0]?.subject).toEqual({ id: "emp-4417" });
  });

  it("PepDeps.principalMapping/.entitlement/.entitlementStalenessBoundSeconds forward unchanged to the PDP: a profile-claiming request permits once mapping and entitlement both resolve", async () => {
    const envelopes: EvaluationRequest[] = [];
    const LOCAL: OriginPrincipal = { iss: ISSUER, sub: "emp-4417" };
    const pep = new Pep({
      payments: new PaymentsStore(),
      evidence: new EvidenceStore(),
      fga: alwaysAllowFga,
      modelId: "unit-test-model",
      loadView: (id) =>
        id === missionId ? { view, freshness: { observed_at: new Date().toISOString(), source: "load_view" } } : undefined,
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf({ name: "payments" }),
      allowedFreshnessSources: new Set(["load_view"]),
      observe: (e) => envelopes.push(e.envelope),
      principalMapping: {
        resolve: async () => ({
          local: LOCAL,
          policy: { id: "policy-1", version: "1" },
          observed_at: new Date().toISOString(),
          valid_until: new Date(Date.now() + 3_600_000).toISOString(),
        }),
      },
      entitlement: { resolve: async () => ({ entitled: true, observed_at: new Date().toISOString() }) },
      entitlementStalenessBoundSeconds: 600,
    });
    const token: TokenFacts = {
      sub: LOCAL.sub,
      clientId: "ap-agent",
      iss: LOCAL.iss,
      mission: { id: missionId, issuer: ISSUER, authority_hash: "sha-256:hash539", subject: ORIGIN },
      cnfJkt: "jkt-1",
    };
    const res = await pep.enforce("lookup_vendor", { vendor_id: "acme" }, token);
    expect(res.permitted, JSON.stringify(res)).toBe(true);
    expect(res.decision?.context.principal_mapping).toEqual({
      origin: ORIGIN,
      local: LOCAL,
      policy: { id: "policy-1", version: "1" },
      observed_at: expect.any(String),
      valid_until: expect.any(String),
    });
  });

  it("a profile-claiming token at a deployment with no principalMapping/entitlement configured denies principal_mapping_failed, never falls back to ordinary enforcement", async () => {
    const { pep } = build();
    const token: TokenFacts = {
      sub: "emp-4417",
      clientId: "ap-agent",
      iss: ISSUER,
      mission: { id: missionId, issuer: ISSUER, authority_hash: "sha-256:hash539", subject: ORIGIN },
      cnfJkt: "jkt-1",
    };
    const res = await pep.enforce("lookup_vendor", { vendor_id: "acme" }, token);
    expect(res.permitted).toBe(false);
    expect(res.denial_reason).toBe("principal_mapping_failed");
  });
});
