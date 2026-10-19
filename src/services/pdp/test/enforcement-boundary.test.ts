/**
 * @spec runtime#boundary-identifier, runtime#boundary-identifier-change,
 * runtime-oauth#boundary-audience, runtime-evidence#decision-evidence-integrity
 * (#853, D487): the declared boundary identity at its own seams: the
 * statement's version history refused at load when it does not resolve,
 * the boundary established from configuration alone, `aud` validated against
 * it by membership under issuer- and profile-scoped aliases, and evidence
 * keys authorized per boundary and version, with historical records
 * verified under the version their (`audience`, `kid`) pair determines.
 */

import { generateKeyPairSync } from "node:crypto";
import { canonicalize, type JsonValue } from "@mission/core";
import { describe, expect, it } from "vitest";
import {
  boundaryPredecessors,
  boundarySuccessors,
  buildBoundaryEvidenceKeyResolver,
  determinedKeyAuthorization,
  type EnforcementBoundaries,
  EnforcementBoundaryContext,
  enforcementBoundaryFindings,
  evidenceKeyConsumer,
  type HeldEvidenceKey,
} from "../src/enforcement-boundary.js";
import type { EnforcementScopeStatement } from "../src/enforcement-scope.js";
import { openEphemeralClaimDomain } from "../src/idempotency-claims.js";
import { loadRuntimePosture, RUNTIME_POSTURE } from "../src/runtime-posture.js";
import { DECISION_EVIDENCE_MEDIA_TYPE, signEvidenceEnvelope, verifyEvidenceEnvelope } from "../src/runtime-evidence-integrity.js";

const ISSUER = "https://as.test";
const OTHER_ISSUER = "https://other-as.test";
const ERP = "https://erp.example.com";
const LEDGER = "https://ledger.example.com";
const LEGACY = "erp-api";
const PDP = "pdp.example.com";

const keyAuth = (kid: string, role: "pdp" | "pep" | "executor" = "pdp", emitter = PDP) => ({ kid, emitter, role });

/** A statement over the shipped one, with `enforcement_boundaries` and the mediated scope it needs. */
function statement(boundaries: EnforcementBoundaries, resources: string[] = [ERP, LEDGER]): Record<string, unknown> {
  return {
    ...RUNTIME_POSTURE,
    mediated_scope: { ...RUNTIME_POSTURE.mediated_scope, resources, pep_locations: [...RUNTIME_POSTURE.mediated_scope.pep_locations, "erp-pep", "erp-pep-2", "ledger-pep"] },
    enforcement_boundaries: boundaries,
  };
}

const ONE_VERSION: EnforcementBoundaries = {
  versions: [
    {
      version: "v1",
      effective_at: "2026-01-01T00:00:00Z",
      boundaries: [
        {
          boundary: ERP,
          pep_locations: ["erp-pep", "erp-pep-2"],
          audience_aliases: [
            { issuer: ISSUER, token_profile: "at+jwt", alias: LEGACY },
            { issuer: ISSUER, token_profile: "at+jwt", alias: "urn:erp" },
          ],
          evidence_keys: [keyAuth("pdp-1")],
        },
        {
          boundary: LEDGER,
          pep_locations: ["ledger-pep"],
          audience_aliases: [{ issuer: ISSUER, token_profile: "at+jwt", alias: "ledger-api" }],
          evidence_keys: [keyAuth("pdp-ledger")],
        },
      ],
    },
  ],
};

/** A change of identifier: `erp-api` (v1) to the protected resource's identifier (v2), with the old value kept as an alias. */
const CHANGE: EnforcementBoundaries = {
  versions: [
    {
      version: "v1",
      effective_at: "2026-01-01T00:00:00Z",
      boundaries: [{ boundary: LEGACY, pep_locations: ["erp-pep"], evidence_keys: [keyAuth("pdp-1"), keyAuth("legacy-only")] }],
    },
    {
      version: "v2",
      effective_at: "2026-06-01T00:00:00Z",
      boundaries: [
        {
          boundary: ERP,
          pep_locations: ["erp-pep"],
          audience_aliases: [{ issuer: ISSUER, token_profile: "at+jwt", alias: LEGACY }],
          evidence_keys: [keyAuth("pdp-1")],
        },
      ],
      replaces: [{ boundary: ERP, previous_version: "v1", previous_boundary: LEGACY }],
    },
  ],
};

const AT = new Date("2026-03-01T00:00:00Z");
const AFTER = new Date("2026-07-01T00:00:00Z");
const at = { issuer: ISSUER, tokenProfile: "at+jwt" };

describe("the boundary declaration is refused at load unless it resolves (@spec runtime#boundary-identifier-change, #853)", () => {
  it("accepts the shipped statement and a declared change of identifier", () => {
    expect(enforcementBoundaryFindings(RUNTIME_POSTURE)).toEqual([]);
    expect(enforcementBoundaryFindings(statement(CHANGE, [ERP]))).toEqual([]);
    expect(() => loadRuntimePosture(statement(CHANGE, [ERP]))).not.toThrow();
  });

  it("refuses a change of a PEP location's boundary that names no replaces record, and a boundary that is not a mediated resource", () => {
    const undeclared = { versions: [CHANGE.versions[0], { ...CHANGE.versions[1], replaces: [] }] } as unknown as EnforcementBoundaries;
    expect(enforcementBoundaryFindings(statement(undeclared, [ERP])).map((f) => f.problem).join()).toContain("no replaces record");
    expect(() => loadRuntimePosture(statement(undeclared, [ERP]))).toThrow("invalid runtime posture");
    const unmediated = statement(ONE_VERSION, [ERP, { resource: LEDGER, disposition: "reconstructed" } as unknown as string]);
    expect(enforcementBoundaryFindings(unmediated).map((f) => f.problem).join()).toContain(`"${LEDGER}" is not a mediated`);
  });

  it("refuses versions out of order, a replaces record naming a later version, and a PEP location under two boundaries", () => {
    const reversed = { versions: [CHANGE.versions[1], CHANGE.versions[0]] } as unknown as EnforcementBoundaries;
    expect(enforcementBoundaryFindings(statement(reversed, [ERP])).length).toBeGreaterThan(0);
    const twice = structuredClone(ONE_VERSION) as unknown as { versions: { boundaries: { pep_locations: string[] }[] }[] };
    (twice.versions[0]?.boundaries[1] as { pep_locations: string[] }).pep_locations = ["erp-pep"];
    expect(enforcementBoundaryFindings(statement(twice as unknown as EnforcementBoundaries)).map((f) => f.problem).join())
      .toContain('PEP location "erp-pep" names two boundaries');
  });
});

describe("the PEP establishes its boundary from configuration alone (@spec runtime#boundary-identifier, #853)", () => {
  it("names each PEP location's own boundary, and none for an undeclared location or before any version is in force", () => {
    expect(new EnforcementBoundaryContext(statement(ONE_VERSION), "erp-pep").establish(AT)).toEqual({ ok: true, boundary: ERP, version: "v1" });
    expect(new EnforcementBoundaryContext(statement(ONE_VERSION), "erp-pep-2").establish(AT)).toEqual({ ok: true, boundary: ERP, version: "v1" });
    expect(new EnforcementBoundaryContext(statement(ONE_VERSION), "ledger-pep").establish(AT)).toEqual({ ok: true, boundary: LEDGER, version: "v1" });
    expect(new EnforcementBoundaryContext(statement(ONE_VERSION), "unknown-pep").establish(AT)).toEqual({ ok: false, reason: "undeclared_pep_location" });
    expect(new EnforcementBoundaryContext(statement(ONE_VERSION), "erp-pep").establish(new Date("2025-01-01T00:00:00Z")))
      .toEqual({ ok: false, reason: "no_version_in_force" });
  });

  it("switches at the declared cutover instant, for every reader of the same declaration", () => {
    const ctx = new EnforcementBoundaryContext(statement(CHANGE, [ERP]), "erp-pep");
    expect(ctx.establish(AT)).toMatchObject({ ok: true, boundary: LEGACY, version: "v1" });
    expect(ctx.establish(new Date("2026-06-01T00:00:00Z"))).toMatchObject({ ok: true, boundary: ERP, version: "v2" });
  });
});

describe("aud is validated by membership against the established boundary (@spec runtime-oauth#boundary-audience, #853)", () => {
  const erp = new EnforcementBoundaryContext(statement(ONE_VERSION), "erp-pep");
  const ledger = new EnforcementBoundaryContext(statement(ONE_VERSION), "ledger-pep");

  it("accepts a direct or aliased string, and every permutation, duplicate and extra recipient of an array, always binding the established boundary", () => {
    const accepted = [ERP, LEGACY, "urn:erp", [ERP], [LEGACY, ERP], [ERP, LEGACY], [LEGACY, LEGACY], ["ledger-api", LEGACY], [LEGACY, "ledger-api"], ["https://unrelated.example", "urn:erp"]];
    for (const aud of accepted) {
      expect(erp.validateAudience(aud, at, AT), JSON.stringify(aud)).toEqual({ ok: true, boundary: ERP, version: "v1" });
    }
    // One multi-recipient token, two boundaries: each PEP binds its own, never the first member.
    expect(ledger.validateAudience([LEGACY, "ledger-api"], at, AT)).toEqual({ ok: true, boundary: LEDGER, version: "v1" });
    expect(erp.validateAudience(["ledger-api", LEGACY], at, AT)).toEqual({ ok: true, boundary: ERP, version: "v1" });
  });

  it("refuses an absent, malformed or nonmatching aud", () => {
    expect(erp.validateAudience(undefined, at, AT)).toEqual({ ok: false, reason: "audience_absent" });
    for (const aud of ["", [], [""], [ERP, ""], [ERP, 7], 7, { aud: ERP }, null]) {
      expect(erp.validateAudience(aud, at, AT), JSON.stringify(aud)).toEqual({ ok: false, reason: "audience_malformed" });
    }
    for (const aud of [LEDGER, "ledger-api", ["ledger-api"], [LEDGER, "https://unrelated.example"], `${ERP}/`]) {
      expect(erp.validateAudience(aud, at, AT), JSON.stringify(aud)).toEqual({ ok: false, reason: "audience_mismatch" });
    }
  });

  it("accepts an alias only from the issuer and token profile it is declared for", () => {
    expect(erp.validateAudience(LEGACY, { issuer: OTHER_ISSUER, tokenProfile: "at+jwt" }, AT)).toEqual({ ok: false, reason: "audience_mismatch" });
    expect(erp.validateAudience(LEGACY, { issuer: ISSUER, tokenProfile: "aat+jwt" }, AT)).toEqual({ ok: false, reason: "audience_mismatch" });
    // The boundary's own identifier names it under any issuer and profile.
    expect(erp.validateAudience(ERP, { issuer: OTHER_ISSUER, tokenProfile: "aat+jwt" }, AT)).toMatchObject({ ok: true, boundary: ERP });
  });

  it("refuses every token of an issuer and profile whose aliases map one value to two boundaries, and no other issuer's", () => {
    const ambiguous = structuredClone(ONE_VERSION) as unknown as {
      versions: { boundaries: { audience_aliases: { issuer: string; token_profile: string; alias: string }[] }[] }[];
    };
    ambiguous.versions[0]?.boundaries[1]?.audience_aliases.push({ issuer: ISSUER, token_profile: "at+jwt", alias: LEGACY });
    ambiguous.versions[0]?.boundaries[1]?.audience_aliases.push({ issuer: OTHER_ISSUER, token_profile: "at+jwt", alias: "ledger-only" });
    const ctx = new EnforcementBoundaryContext(statement(ambiguous as unknown as EnforcementBoundaries), "erp-pep");
    for (const aud of [ERP, LEGACY, "urn:erp", [ERP, "ledger-api"]]) {
      expect(ctx.validateAudience(aud, at, AT), JSON.stringify(aud)).toEqual({ ok: false, reason: "alias_ambiguous" });
    }
    expect(ctx.validateAudience(ERP, { issuer: OTHER_ISSUER, tokenProfile: "at+jwt" }, AT)).toMatchObject({ ok: true, boundary: ERP });
    // An alias equal to another boundary's own identifier is the same ambiguity.
    const shadow = structuredClone(ONE_VERSION) as unknown as {
      versions: { boundaries: { audience_aliases: { issuer: string; token_profile: string; alias: string }[] }[] }[];
    };
    shadow.versions[0]?.boundaries[0]?.audience_aliases.push({ issuer: ISSUER, token_profile: "at+jwt", alias: LEDGER });
    const shadowed = new EnforcementBoundaryContext(statement(shadow as unknown as EnforcementBoundaries), "erp-pep");
    expect(shadowed.validateAudience(ERP, at, AT)).toEqual({ ok: false, reason: "alias_ambiguous" });
  });

  it("keeps a declared alias for the old identifier usable across a change", () => {
    const ctx = new EnforcementBoundaryContext(statement(CHANGE, [ERP]), "erp-pep");
    expect(ctx.validateAudience(LEGACY, at, AT)).toEqual({ ok: true, boundary: LEGACY, version: "v1" });
    expect(ctx.validateAudience(LEGACY, at, AFTER)).toEqual({ ok: true, boundary: ERP, version: "v2" });
    expect(ctx.validateAudience(ERP, at, AT)).toEqual({ ok: false, reason: "audience_mismatch" });
  });
});

describe("evidence keys are authorized per boundary and version (@spec runtime-evidence#decision-evidence-integrity, #853)", () => {
  const keys = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const legacyOnly = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const published = [
    { kid: "pdp-1", publicKey: keys.publicKey, emitterId: PDP, role: "pdp" as const },
    { kid: "legacy-only", publicKey: legacyOnly.publicKey, emitterId: PDP, role: "pdp" as const },
  ];
  const record = (audience: string, evaluated_at: string) => ({
    evidence_id: "evd_boundary_test",
    audience,
    decision: "permit",
    emitter: { id: PDP, role: "pdp" },
    evaluated_at,
  });
  const signed = async (r: Record<string, unknown>, kid: string, key: unknown) => ({
    ...r,
    evidence_envelope: await signEvidenceEnvelope(r as JsonValue, DECISION_EVIDENCE_MEDIA_TYPE, { kid, key: key as never }),
  });

  it("authorizes a producer only under the version in force, and a disposition under any version in force so far", () => {
    const ctx = new EnforcementBoundaryContext(statement(CHANGE, [ERP]), "erp-pep");
    const legacy = { audience: LEGACY, kid: "pdp-1", emitter: PDP, role: "pdp" as const };
    const erp = { ...legacy, audience: ERP };
    expect(ctx.authorizesEvidence(legacy, "current", AT)).toBe(true);
    expect(ctx.authorizesEvidence(erp, "current", AT)).toBe(false);
    expect(ctx.authorizesEvidence(legacy, "current", AFTER)).toBe(false);
    expect(ctx.authorizesEvidence(erp, "current", AFTER)).toBe(true);
    expect(ctx.authorizesEvidence(legacy, "historical", AFTER)).toBe(true);
    // A version whose cutover is still ahead authorizes nothing yet.
    expect(ctx.authorizesEvidence(erp, "historical", AT)).toBe(false);
    // The replaces record never extends a key to the new boundary.
    expect(ctx.authorizesEvidence({ ...erp, kid: "legacy-only" }, "historical", AFTER)).toBe(false);
  });

  it("verifies a record from before the change, bytes unchanged, under the version its audience and kid select, and never by its time", async () => {
    const resolve = buildBoundaryEvidenceKeyResolver(CHANGE, published);
    const old = await signed(record(LEGACY, "2026-03-01T00:00:00Z"), "pdp-1", keys.privateKey);
    const bytes = canonicalize(old as unknown as JsonValue);
    expect(await verifyEvidenceEnvelope(old, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    expect(canonicalize(old as unknown as JsonValue)).toBe(bytes);
    // A late delivery: produced for the old identifier after the cutover instant, still historical.
    const late = await signed(record(LEGACY, "2026-09-01T00:00:00Z"), "pdp-1", keys.privateKey);
    expect(await verifyEvidenceEnvelope(late, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    // A new-identifier record dated before the cutover still verifies by its pair: time selects nothing.
    const early = await signed(record(ERP, "2025-01-01T00:00:00Z"), "pdp-1", keys.privateKey);
    expect(await verifyEvidenceEnvelope(early, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({ valid: true });
    // Rewriting the old record's audience to the new identifier breaks it.
    expect(await verifyEvidenceEnvelope({ ...old, audience: ERP }, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({
      valid: false,
      reason: "byte_mismatch",
    });
    // Correlation is data after verification, and changes nothing.
    expect(boundarySuccessors(CHANGE, LEGACY)).toEqual([ERP]);
    expect(canonicalize(old as unknown as JsonValue)).toBe(bytes);
  });

  it("never lets a key authorized for the old boundary sign for the new one", async () => {
    const resolve = buildBoundaryEvidenceKeyResolver(CHANGE, published);
    const forged = await signed(record(ERP, "2026-07-01T00:00:00Z"), "legacy-only", legacyOnly.privateKey);
    expect(await verifyEvidenceEnvelope(forged, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({ valid: false, reason: "key_not_resolvable" });
    const legit = await signed(record(LEGACY, "2026-03-01T00:00:00Z"), "legacy-only", legacyOnly.privateKey);
    expect(await verifyEvidenceEnvelope(legit, DECISION_EVIDENCE_MEDIA_TYPE, resolve)).toEqual({ valid: true });
  });

  it("fails when the declared versions do not determine one key authorization, or one key, for the pair", async () => {
    const undetermined: EnforcementBoundaries = {
      versions: [
        CHANGE.versions[0] as EnforcementBoundaries["versions"][number],
        {
          ...(CHANGE.versions[1] as EnforcementBoundaries["versions"][number]),
          boundaries: [
            { boundary: ERP, pep_locations: ["erp-pep"], evidence_keys: [keyAuth("pdp-1")] },
            // The old identifier reused, its key now authorized for another emitter.
            { boundary: LEGACY, pep_locations: ["erp-pep-2"], evidence_keys: [keyAuth("pdp-1", "pdp", "other-pdp.example.com")] },
          ],
        },
      ],
    };
    expect(determinedKeyAuthorization(undetermined, LEGACY, "pdp-1")).toBeUndefined();
    expect(determinedKeyAuthorization(undetermined, ERP, "pdp-1")).toEqual(keyAuth("pdp-1"));
    const old = await signed(record(LEGACY, "2026-03-01T00:00:00Z"), "pdp-1", keys.privateKey);
    expect(await verifyEvidenceEnvelope(old, DECISION_EVIDENCE_MEDIA_TYPE, buildBoundaryEvidenceKeyResolver(undetermined, published)))
      .toEqual({ valid: false, reason: "key_not_resolvable" });
    // Two published keys behind one kid are ambiguous too.
    const twoKeys = [...published, { ...(published[0] as (typeof published)[number]), publicKey: legacyOnly.publicKey }];
    expect(await verifyEvidenceEnvelope(old, DECISION_EVIDENCE_MEDIA_TYPE, buildBoundaryEvidenceKeyResolver(CHANGE, twoKeys)))
      .toEqual({ valid: false, reason: "key_not_resolvable" });
  });
});

describe("the identifiers a boundary replaces, for duplicate-effect lookups (@spec runtime#idempotency, runtime#boundary-identifier-change, #853)", () => {
  it("follows declared replaces records transitively, nearest first, and stops on a cycle", () => {
    const version = (name: string, boundary: string, replaces: { boundary: string; previous_boundary: string }[]) => ({
      version: name,
      effective_at: "2026-01-01T00:00:00Z",
      boundaries: [{ boundary, pep_locations: ["erp-pep"], evidence_keys: [keyAuth("pdp-1")] }],
      replaces: replaces.map((r) => ({ ...r, previous_version: "v0" })),
    });
    const chain: EnforcementBoundaries = {
      versions: [
        version("v1", "a", []),
        version("v2", "b", [{ boundary: "b", previous_boundary: "a" }]),
        version("v3", "c", [{ boundary: "c", previous_boundary: "b" }]),
        // Renamed back: c is replaced by a, which c already succeeded.
        version("v4", "a", [{ boundary: "a", previous_boundary: "c" }]),
      ],
    };
    // Every identifier in one lineage holds the same operations, so a rename back joins it.
    expect(boundaryPredecessors(chain, "b")).toEqual(["a", "c"]);
    expect(boundaryPredecessors(chain, "c")).toEqual(["b", "a"]);
    expect(boundaryPredecessors(chain, "a")).toEqual(["c", "b"]);
    expect(boundaryPredecessors(CHANGE, ERP)).toEqual([LEGACY]);
    expect(boundaryPredecessors(CHANGE, LEGACY)).toEqual([]);
    expect(boundaryPredecessors(ONE_VERSION, ERP)).toEqual([]);
  });
});

describe("a declared version is held until every bound consumer is provisioned for it (@spec runtime#boundary-identifier-change, #853)", () => {
  it("refuses the new boundary while a published key set lacks its bindings, and establishes it once they are published", () => {
    const published = new Map<string, HeldEvidenceKey[]>([
      [LEGACY, [{ kid: "pdp-1", emitterId: PDP, role: "pdp", audience: LEGACY }, { kid: "legacy-only", emitterId: PDP, role: "pdp", audience: LEGACY }]],
    ]);
    let now = AT;
    const context = new EnforcementBoundaryContext(statement(CHANGE), "erp-pep", () => now);
    context.bindConsumer(
      evidenceKeyConsumer({ name: "published", roles: ["pdp", "pep", "executor"], audienceBound: true, keys: (b) => published.get(b) ?? [] }),
    );
    expect(context.establish()).toEqual({ ok: true, boundary: LEGACY, version: "v1" });
    now = AFTER;
    expect(context.establish()).toEqual({ ok: false, reason: "consumer_unprovisioned" });
    expect(context.unprovisioned()).toEqual(["published"]);
    expect(context.validateAudience(ERP, at)).toEqual({ ok: false, reason: "consumer_unprovisioned" });
    // A key published for the old boundary is not a binding for the new one.
    published.set(ERP, [{ kid: "pdp-1", emitterId: PDP, role: "pdp", audience: LEGACY }]);
    expect(context.establish().ok).toBe(false);
    published.set(ERP, [{ kid: "pdp-1", emitterId: PDP, role: "pdp", audience: ERP }]);
    expect(context.establish()).toEqual({ ok: true, boundary: ERP, version: "v2" });
    expect(context.validateAudience(ERP, at)).toEqual({ ok: true, boundary: ERP, version: "v2" });
    expect(context.unprovisioned()).toEqual([]);
  });

  it("reads a verifier's held keys by kid, emitter and role, only for the roles it verifies", () => {
    const v2 = CHANGE.versions[1] as EnforcementBoundaries["versions"][number];
    const erp = v2.boundaries[0] as EnforcementBoundaries["versions"][number]["boundaries"][number];
    const held = (keys: HeldEvidenceKey[]) =>
      evidenceKeyConsumer({ name: "verifier", roles: ["pdp"], audienceBound: false, keys: () => keys });
    expect(held([{ kid: "pdp-1", emitterId: PDP, role: "pdp" }]).provisionedFor(v2, erp)).toBe(true);
    expect(held([{ kid: "pdp-1", emitterId: "other-pdp.example.com", role: "pdp" }]).provisionedFor(v2, erp)).toBe(false);
    expect(held([{ kid: "pdp-1", emitterId: PDP, role: "pep" }]).provisionedFor(v2, erp)).toBe(false);
    expect(held([]).provisionedFor(v2, erp)).toBe(false);
    // A consumer that verifies no role the version authorizes a key for is provisioned by it.
    expect(evidenceKeyConsumer({ name: "executor-only", roles: ["executor"], audienceBound: false, keys: () => [] }).provisionedFor(v2, erp)).toBe(true);
  });

  it("holds the cutover for a PDP claim domain still loaded with the earlier statement", () => {
    const stale = openEphemeralClaimDomain({
      owner: RUNTIME_POSTURE.pdps[0] as string,
      statement: { ...statement(CHANGE), enforcement_boundaries: { versions: [CHANGE.versions[0]] } } as unknown as EnforcementScopeStatement,
    });
    const current = openEphemeralClaimDomain({
      owner: RUNTIME_POSTURE.pdps[0] as string,
      statement: statement(CHANGE) as unknown as EnforcementScopeStatement,
    });
    try {
      const v1 = CHANGE.versions[0] as EnforcementBoundaries["versions"][number];
      const v2 = CHANGE.versions[1] as EnforcementBoundaries["versions"][number];
      expect(stale.boundaryConsumer().provisionedFor(v1, v1.boundaries[0] as never)).toBe(true);
      expect(stale.boundaryConsumer().provisionedFor(v2, v2.boundaries[0] as never)).toBe(false);
      expect(current.boundaryConsumer().provisionedFor(v2, v2.boundaries[0] as never)).toBe(true);
      // A version of the same name with other bytes is not the version in force.
      const altered = { ...v2, effective_at: "2026-06-02T00:00:00Z" };
      expect(current.boundaryConsumer().provisionedFor(altered, v2.boundaries[0] as never)).toBe(false);
      let now = AT;
      const context = new EnforcementBoundaryContext(statement(CHANGE), "erp-pep", () => now);
      context.bindConsumer(stale.boundaryConsumer());
      expect(context.establish().ok).toBe(true);
      now = AFTER;
      expect(context.establish()).toEqual({ ok: false, reason: "consumer_unprovisioned" });
      expect(context.unprovisioned()).toEqual([`pdp-claim-domain:${RUNTIME_POSTURE.pdps[0]}`]);
    } finally {
      stale.close();
      current.close();
    }
  });
});
