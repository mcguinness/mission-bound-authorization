/**
 * @spec resource-access#resource-contract, resource-access#subset,
 * resource-access#scope-projection, runtime#resource-contract (#249, D553):
 * the shared reference, its exact preservation, the declared version states
 * and their resolution, and the credential and scope-projection checks over
 * the same reference.
 */
import { describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  authorityHash,
  credentialEntriesFromAuthority,
  entryCoversFacts,
  entryWithinCeiling,
  isAuthorityEntry,
  isSubsetEntry,
  narrowToCeiling,
  parseCredentialAuthority,
  ResourceContractConfigError,
  ResourceContractDeclarations,
  type ResourceContractRef,
  resourceContractDigest,
  resourceContractViolation,
  type ScopeValueMapping,
  sameResourceContract,
  scopeValueSafeForEntry,
} from "../src/index.js";

const RS = "https://payments.test/mcp";
const CONTRACT = "https://payments.test/contracts/payments";
const ACTION = "payments:payment.execute";

const doc = (version: string, actions: readonly string[] = [ACTION, "payments:invoice.read"]) => ({
  id: CONTRACT,
  version,
  operation_profile: `profile-${version}`,
  operations: Object.fromEntries(actions.map((a, i) => [`tool_${i}`, { action: a }])),
});
const versionDecl = (version: string, state: string, extra: Record<string, unknown> = {}) => {
  const document = doc(version);
  return { version, state, digest: resourceContractDigest(document), document, ...extra };
};
const ref = (version: string): ResourceContractRef => ({
  id: CONTRACT,
  version,
  digest: resourceContractDigest(doc(version)),
});
const declarations = (versions: unknown[], requires: string[] = []) =>
  new ResourceContractDeclarations([
    {
      resource: RS,
      resource_match: "prefix",
      id: CONTRACT,
      requires_reference: requires,
      versions,
    },
  ]);

const V1 = ref("v1");
const V2 = ref("v2");
const entry: AuthorityEntry = { type: "mission_resource_access", resource: RS, actions: [ACTION] };
const pinned = (r: ResourceContractRef = V1): AuthorityEntry => ({
  ...entry,
  resource_contract: r,
});

describe("the resource_contract member's shape (@spec resource-access#entry-validation, #249)", () => {
  it("admits exactly id (an absolute URI), version (non-empty) and digest (sha-256: base64url)", () => {
    expect(resourceContractViolation(V1)).toBeUndefined();
    expect(isAuthorityEntry(pinned())).toBe(true);
  });

  it("refuses an extra member, a relative id, an empty version and a malformed digest, at every boundary that reads the shape", () => {
    for (const bad of [
      { ...V1, note: "x" },
      { ...V1, id: "contracts/payments" },
      { ...V1, version: "" },
      { ...V1, digest: "sha-256:short" },
      { id: CONTRACT, version: "v1" },
      "v1",
      null,
    ]) {
      expect(resourceContractViolation(bad), JSON.stringify(bad)).toBeDefined();
      expect(isAuthorityEntry({ ...entry, resource_contract: bad }), JSON.stringify(bad)).toBe(
        false,
      );
      expect(() => parseCredentialAuthority([{ ...entry, resource_contract: bad }])).toThrow(
        /resource_contract/,
      );
    }
  });

  it("compares member for member: absent equals only absent, and a malformed value equals nothing", () => {
    expect(sameResourceContract(V1, { ...V1 })).toBe(true);
    expect(sameResourceContract(undefined, undefined)).toBe(true);
    expect(sameResourceContract(V1, undefined)).toBe(false);
    expect(sameResourceContract(V1, V2)).toBe(false);
    expect(sameResourceContract(V1, { ...V1, digest: V2.digest })).toBe(false);
    expect(sameResourceContract({ ...V1, x: 1 }, { ...V1, x: 1 })).toBe(false);
  });
});

describe("subset step 4 preserves the reference exactly (@spec resource-access#subset, #249)", () => {
  it("an entry carrying the reference unchanged is a subset, including with fewer actions", () => {
    const two = { ...pinned(), actions: [ACTION, "payments:invoice.read"] };
    expect(isSubsetEntry(pinned(), pinned())).toBe(true);
    expect(isSubsetEntry(pinned(), two)).toBe(true);
  });

  it("removing, replacing or adding a reference is never narrowing", () => {
    expect(isSubsetEntry(entry, pinned())).toBe(false);
    expect(isSubsetEntry(pinned(V2), pinned(V1))).toBe(false);
    expect(
      isSubsetEntry({ ...pinned(), resource_contract: { ...V1, digest: V2.digest } }, pinned()),
    ).toBe(false);
    expect(isSubsetEntry(pinned(), entry)).toBe(false);
  });

  it("a configured ceiling need not carry one: the ceiling comparison sets the member aside and keeps the entry's own", () => {
    expect(entryWithinCeiling(pinned(), [entry])).toBe(true);
    const narrowed = narrowToCeiling(
      [{ ...pinned(), actions: [ACTION, "payments:other"] }],
      [entry],
    );
    expect(narrowed).toEqual([{ ...pinned(), actions: [ACTION] }]);
  });

  it("authority_hash commits the reference: two sets differing only in it hash differently", () => {
    const a = authorityHash("https://as.test", [entry as never]);
    const b = authorityHash("https://as.test", [pinned() as never]);
    const c = authorityHash("https://as.test", [pinned(V2) as never]);
    expect(new Set([a, b, c]).size).toBe(3);
  });
});

describe("declared contract versions (@spec runtime#resource-contract, #249)", () => {
  const now = new Date("2026-10-20T12:00:00Z");
  const at = { target: `${RS}/invoices/inv-1`, action: ACTION, now };

  it("refuses a declaration whose document does not hash to its declared digest: bytes are immutable for a reference", () => {
    const changed = {
      ...versionDecl("v1", "current"),
      document: { ...doc("v1"), operation_profile: "changed" },
    };
    expect(() => declarations([changed])).toThrow(ResourceContractConfigError);
    expect(() => declarations([changed])).toThrow(/does not commit the declared document/);
    expect(() => declarations([versionDecl("v1", "current")])).not.toThrow();
  });

  it("states each version's state: a superseded version declares its retention, and one version at most is current", () => {
    expect(() => declarations([versionDecl("v1", "superseded")])).toThrow(/retention/);
    expect(() =>
      declarations([versionDecl("v1", "current"), versionDecl("v2", "current")]),
    ).toThrow(/more than one current/);
    expect(() => declarations([versionDecl("v1", "pending")])).toThrow(/state/);
    expect(() =>
      declarations([versionDecl("v1", "current", { retained_until: "2027-01-01T00:00:00Z" })]),
    ).toThrow(/only for a superseded/);
  });

  it("resolves a current version, and a superseded one within its declared retention only", () => {
    const d = declarations([
      versionDecl("v1", "superseded", { retained_until: "2026-11-01T00:00:00Z" }),
      versionDecl("v2", "current"),
    ]);
    expect(d.resolve(V2, at)).toMatchObject({ ok: true, ref: V2 });
    expect(d.resolve(V1, at)).toMatchObject({ ok: true, ref: V1 });
    expect(d.resolve(V1, { ...at, now: new Date("2026-11-01T00:00:00.001Z") })).toEqual({
      ok: false,
      reason: "outside_retention",
    });
  });

  it("resolves no retired, unknown, changed, uncovered or malformed reference, and never falls back to another version", () => {
    const d = declarations([
      { version: "v1", state: "retired", digest: V1.digest },
      versionDecl("v2", "current"),
    ]);
    expect(d.resolve(V1, at)).toEqual({ ok: false, reason: "retired" });
    expect(d.resolve(ref("v3"), at)).toEqual({ ok: false, reason: "unknown" });
    expect(d.resolve({ ...V2, digest: V1.digest }, at)).toEqual({
      ok: false,
      reason: "digest_mismatch",
    });
    expect(d.resolve(V2, { ...at, action: "payments:unlisted" })).toEqual({
      ok: false,
      reason: "operation_not_covered",
    });
    expect(d.resolve(V2, { ...at, target: "https://other.test/mcp" })).toEqual({
      ok: false,
      reason: "resource_not_covered",
    });
    expect(d.resolve({ ...V2, id: "https://payments.test/contracts/other" }, at)).toEqual({
      ok: false,
      reason: "unknown",
    });
    expect(d.resolve({ id: CONTRACT }, at)).toEqual({ ok: false, reason: "malformed" });
  });

  it("names the operations that require a reference, at the targets the declaration covers", () => {
    const d = declarations([versionDecl("v1", "current")], [ACTION]);
    expect(d.requiresReference(`${RS}/invoices/inv-1`, ACTION)).toBe(true);
    expect(d.requiresReference(`${RS}/invoices/inv-1`, "payments:invoice.read")).toBe(false);
    expect(d.requiresReference("https://other.test/mcp", ACTION)).toBe(false);
    expect(ResourceContractDeclarations.NONE.requiresReference(RS, ACTION)).toBe(false);
  });

  it("states, per entry at approval, the current reference and whether one is required", () => {
    const d = declarations(
      [
        versionDecl("v1", "superseded", { retained_until: "2026-11-01T00:00:00Z" }),
        versionDecl("v2", "current"),
      ],
      [ACTION],
    );
    expect(d.forEntry(entry)).toEqual({ current: [V2], required: true });
    expect(d.isCurrentFor(entry, V2)).toBe(true);
    expect(d.isCurrentFor(entry, V1)).toBe(false);
    expect(d.forEntry({ ...entry, actions: ["payments:unlisted"] })).toEqual({
      current: [],
      required: false,
    });
    expect(d.forEntry({ ...entry, resource: "https://other.test/mcp" })).toEqual({
      current: [],
      required: false,
    });
  });
});

describe("a credential entry authorizes only under its referenced contract (@spec resource-access#resource-contract, #249)", () => {
  const facts = { resource: RS, action: ACTION, vendorIds: [] };

  it("carries the reference through credential parsing", () => {
    const [read] = credentialEntriesFromAuthority([pinned()]);
    expect(read?.resource_contract).toEqual(V1);
  });

  it("covers the action only when the enforcement point performs under exactly the entry's contract", () => {
    const [c] = parseCredentialAuthority([pinned()]);
    const [plain] = parseCredentialAuthority([entry]);
    if (!c || !plain) throw new Error("parsed");
    expect(entryCoversFacts(c, { ...facts, resourceContract: V1 })).toBe(true);
    expect(entryCoversFacts(c, { ...facts, resourceContract: V2 })).toBe(false);
    expect(entryCoversFacts(c, facts)).toBe(false);
    expect(entryCoversFacts(plain, facts)).toBe(true);
    expect(entryCoversFacts(plain, { ...facts, resourceContract: V1 })).toBe(false);
  });
});

describe("scope projection condition 4 preserves the contract (@spec resource-access#scope-projection, #249)", () => {
  const value = (extra: Partial<ScopeValueMapping> = {}): ScopeValueMapping => ({
    rights: { type: "mission_resource_access", resource: RS, match: "exact", actions: [ACTION] },
    mandatory_controls: {},
    ...extra,
  });

  it("projects an entry carrying a reference only where the mapping states the target performs under exactly that contract", () => {
    expect(scopeValueSafeForEntry(value({ resource_contract: V1 }), pinned(V1))).toBe(true);
    expect(scopeValueSafeForEntry(value({ resource_contract: V2 }), pinned(V1))).toBe(false);
    expect(scopeValueSafeForEntry(value(), pinned(V1))).toBe(false);
  });

  it("projects an entry without one only where the target requires no reference", () => {
    expect(scopeValueSafeForEntry(value(), entry)).toBe(true);
    expect(scopeValueSafeForEntry(value({ resource_contract: V1 }), entry)).toBe(true);
    expect(scopeValueSafeForEntry(value({ requires_resource_contract: true }), entry)).toBe(false);
  });
});
