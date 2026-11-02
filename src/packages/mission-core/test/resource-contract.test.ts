/**
 * @spec resource-access#resource-contract, resource-access#subset,
 * resource-access#scope-projection, runtime#resource-contract (#249, D553):
 * the shared reference, its exact preservation, the declared version states
 * and their resolution, and the credential and scope-projection checks over
 * the same reference.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  assertContractDescriptors,
  authorityHash,
  canonicalDigest,
  contractDescriptor,
  credentialEntriesFromAuthority,
  EvaluationContextBindingDeclarations,
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

  // #1752 (D875): a value naming no served operation, or a family, would
  // leave an operation unprotected while configuration appears to require a
  // reference, so it is refused at load.
  const versionWith = (
    version: string,
    state: string,
    actions: readonly string[],
    extra: Record<string, unknown> = {},
  ) => {
    const document = doc(version, actions);
    return { version, state, digest: resourceContractDigest(document), document, ...extra };
  };
  const RETAINED = { retained_until: "2027-01-01T00:00:00Z" };

  it("refuses at load a required operation that is an action family, outside the action grammar, or defined by no current or superseded version", () => {
    const current = [versionDecl("v1", "current")];
    const refuses = (versions: unknown[], requires: string[], message: RegExp) => {
      expect(() => declarations(versions, requires)).toThrow(ResourceContractConfigError);
      expect(() => declarations(versions, requires)).toThrow(message);
    };
    refuses(
      current,
      ["payments:payment.*"],
      /requires_reference\[0\] "payments:payment\.\*" is an action family/,
    );
    refuses(
      current,
      [ACTION, "payments:payment.exceute"],
      /requires_reference\[1\] "payments:payment\.exceute" is not an operation any current or superseded version defines/,
    );
    refuses(
      current,
      ["payments:payment execute"],
      /requires_reference\[0\] "payments:payment execute" is not an action identifier/,
    );
    // A retired version's operations do not count, though it keeps its document.
    refuses(
      [
        versionWith("v0", "retired", [ACTION, "payments:payment.hold"]),
        versionDecl("v1", "current"),
      ],
      ["payments:payment.hold"],
      /"payments:payment\.hold" is not an operation any current or superseded version defines/,
    );
    // Each form is refused even where a document names it as an operation's
    // action, so the refusal never depends on the documents.
    for (const [value, message] of [
      ["payments:payment.*", /is an action family/],
      ["payments:payment execute", /is not an action identifier/],
    ] as const) {
      refuses([versionWith("v1", "current", [ACTION, value])], [value], message);
    }
  });

  it("accepts a required operation any current or superseded version defines, without every supported version defining it, and both readers then agree on every required operation", () => {
    const REVERSE = "payments:payment.reverse";
    // Only the current version defines it; the superseded one predates it.
    const d = declarations(
      [
        versionWith("v1", "superseded", [ACTION], RETAINED),
        versionWith("v2", "current", [ACTION, REVERSE]),
      ],
      [ACTION, REVERSE],
    );
    expect(d.declarations[0]?.requires_reference).toEqual([ACTION, REVERSE]);
    // Only a superseded version, still served within its retention, defines it.
    expect(() =>
      declarations(
        [
          versionWith("v1", "superseded", [ACTION, "payments:payment.hold"], RETAINED),
          versionWith("v2", "current", [ACTION]),
        ],
        ["payments:payment.hold"],
      ),
    ).not.toThrow();
    // An identifier means the same operation to the resolution-time and the
    // approval-time reader.
    expect(d.requiresReference(`${RS}/payments/p-1`, REVERSE)).toBe(true);
    expect(d.forEntry({ ...entry, actions: [REVERSE] }).required).toBe(true);
    // An operation outside the list needs no reference at enforcement, while
    // approval records one for every entry on the resource (#1847, D989).
    expect(d.requiresReference(`${RS}/invoices/inv-1`, "payments:invoice.read")).toBe(false);
    expect(d.forEntry({ ...entry, actions: ["payments:invoice.read"] }).required).toBe(true);
  });

  it("loads the shipped declaration, and the same declaration requiring the current contract's five non-read actions", () => {
    const shipped = (
      JSON.parse(
        readFileSync(new URL("../../../config/enforcement-scope.json", import.meta.url), "utf8"),
      ) as {
        extensions: { resource_contracts: Record<string, unknown>[] };
      }
    ).extensions.resource_contracts;
    expect(() => new ResourceContractDeclarations(shipped)).not.toThrow();
    const FIVE = [
      "payments:payment.execute",
      "payments:payment.reverse",
      "payments:payment.schedule",
      "payments:payment.schedule.cancel",
      "payments:remittance.send",
    ];
    const cutover = new ResourceContractDeclarations(
      shipped.map((d) => ({ ...d, requires_reference: FIVE })),
    );
    expect(cutover.declarations[0]?.requires_reference).toEqual(FIVE);
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
    // Approval is per resource (#1847, D989): a read-only entry on it records
    // the current reference, and one listing an action no current version
    // defines is required with nothing current to record, so it is refused.
    expect(d.forEntry({ ...entry, actions: ["payments:invoice.read"] })).toEqual({
      current: [V2],
      required: true,
    });
    expect(d.forEntry({ ...entry, actions: ["payments:unlisted"] })).toEqual({
      current: [],
      required: true,
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

// @spec runtime#resource-contract, runtime#evaluation-context-binding (#249,
// D1155): a contract version names the evaluation-context descriptor each
// covered crossing is performed under, in its document or, for a version
// published before its document could, in the deployment's association beside
// it; the two declarations are checked against each other at load.
describe("the evaluation-context descriptors a contract version names (@spec runtime#resource-contract, runtime#evaluation-context-binding, #249, D1155)", () => {
  type Statement = {
    claims: string[];
    extensions: {
      resource_contracts: Array<{
        id: string;
        versions: Array<{
          version: string;
          state: string;
          digest: string;
          retained_until?: string;
          evaluation_context_descriptors?: Record<string, unknown>;
          document: { operations: Record<string, Record<string, unknown>> } & Record<
            string,
            unknown
          >;
        }>;
      }>;
      evaluation_context_binding: {
        operations: Array<{
          operation: string;
          phases?: string[];
          descriptor: { id: string; version: string; digest: string };
        }>;
      };
    };
  };
  const shipped = (): Statement =>
    JSON.parse(
      readFileSync(new URL("../../../config/enforcement-scope.json", import.meta.url), "utf8"),
    ) as Statement;
  const versionOf = (st: Statement, version: string) => {
    const v = st.extensions.resource_contracts[0]?.versions.find((x) => x.version === version);
    if (!v) throw new Error(`${version} is declared`);
    return v;
  };
  const load = (st: Statement) => ({
    contracts: new ResourceContractDeclarations(st.extensions.resource_contracts),
    binding: new EvaluationContextBindingDeclarations(st),
  });
  const declaredVersion = (contracts: ResourceContractDeclarations, version: string) => {
    const v = contracts.declarations[0]?.versions.find((x) => x.version === version);
    if (!v) throw new Error(`${version} is declared`);
    return v;
  };
  const claimDescriptor = (st: Statement, operation: string) =>
    st.extensions.evaluation_context_binding.operations.find((o) => o.operation === operation)
      ?.descriptor;
  /** Re-commit a version's edited document under its digest, as a new publication would. */
  const recommit = (v: { digest: string; document: unknown }) => {
    v.digest = resourceContractDigest(v.document as never);
  };

  it("the shipped declarations agree: the current version names the claim's descriptor for each covered crossing, each superseded version the one in force while it was current, and 2026-10-20, published before the claim, none", () => {
    const st = shipped();
    const { contracts, binding } = load(st);
    expect(() => assertContractDescriptors(contracts, binding)).not.toThrow();
    const execute = claimDescriptor(st, "payments:payment.execute");
    const reverse = claimDescriptor(st, "payments:payment.reverse");
    for (const version of ["2026-11-02", "2026-10-27", "2026-10-26", "2026-10-24"]) {
      for (const phase of ["preflight", "prepare", "commit"]) {
        expect(
          contractDescriptor(
            declaredVersion(contracts, version),
            "payments:payment.execute",
            phase,
          ),
          `${version} ${phase}`,
        ).toEqual(execute);
      }
    }
    expect(
      contractDescriptor(
        declaredVersion(contracts, "2026-11-02"),
        "payments:payment.reverse",
        "compensate",
      ),
    ).toEqual(reverse);
    expect(
      contractDescriptor(
        declaredVersion(contracts, "2026-10-26"),
        "payments:payment.reverse",
        "compensate",
      ),
    ).toEqual(reverse);
    // 2026-10-24's reversal is not performed under its retained v14 profile.
    expect(
      contractDescriptor(
        declaredVersion(contracts, "2026-10-24"),
        "payments:payment.reverse",
        "compensate",
      ),
    ).toBeUndefined();
    for (const phase of ["preflight", "prepare", "commit"]) {
      expect(
        contractDescriptor(
          declaredVersion(contracts, "2026-10-20"),
          "payments:payment.execute",
          phase,
        ),
        phase,
      ).toBeUndefined();
    }
    // The 2026-11-02 descriptors are in its bytes; 2026-10-27's association is beside them.
    expect(declaredVersion(contracts, "2026-11-02").evaluation_context_descriptors).toBeUndefined();
    expect(declaredVersion(contracts, "2026-10-27").evaluation_context_descriptors).toBeDefined();
  });

  it("refuses at load a current version naming a descriptor other than the one the claim declares for the crossing, though the claim publishes it", () => {
    const st = shipped();
    // The claim also publishes an earlier payments:payment.execute descriptor
    // version, while declaring the shipped one for the operation.
    const ecb = st.extensions.evaluation_context_binding as unknown as {
      descriptors: Array<{
        id: string;
        version: string;
        digest: string;
        document: Record<string, unknown>;
      }>;
    };
    const shippedExecute = ecb.descriptors.find((d) => d.id.endsWith("/payment-execute"));
    if (!shippedExecute) throw new Error("the execute descriptor is published");
    const earlierDocument = { ...shippedExecute.document, version: "2026-10-23" };
    const earlier = {
      id: shippedExecute.id,
      version: "2026-10-23",
      digest: canonicalDigest(earlierDocument as never),
    };
    ecb.descriptors.push({ ...earlier, document: earlierDocument });
    const current = versionOf(st, "2026-11-02");
    (
      current.document.operations.execute_wire_transfer as Record<string, unknown>
    ).evaluation_context_descriptor = earlier;
    recommit(current);
    const { contracts, binding } = load(st);
    expect(() => assertContractDescriptors(contracts, binding)).toThrow(
      /must name the descriptor the Evaluation-Context Binding claim declares/,
    );
  });

  it("refuses at load a superseded version naming a descriptor the claim does not publish, or one of another id for the crossing", () => {
    const unpublished = shipped();
    const v16 = versionOf(unpublished, "2026-10-27");
    v16.evaluation_context_descriptors = {
      ...v16.evaluation_context_descriptors,
      execute_wire_transfer: {
        ...(v16.evaluation_context_descriptors?.execute_wire_transfer as object),
        version: "2026-10-23",
      },
    };
    const a = load(unpublished);
    expect(() => assertContractDescriptors(a.contracts, a.binding)).toThrow(
      /names a descriptor the claim does not publish/,
    );

    const otherId = shipped();
    const v16b = versionOf(otherId, "2026-10-27");
    v16b.evaluation_context_descriptors = {
      ...v16b.evaluation_context_descriptors,
      execute_wire_transfer: claimDescriptor(otherId, "payments:remittance.send"),
    };
    const b = load(otherId);
    expect(() => assertContractDescriptors(b.contracts, b.binding)).toThrow(
      /must name a descriptor of the claim's id/,
    );
  });

  it("refuses at load a version naming a descriptor for an operation the claim does not cover", () => {
    const st = shipped();
    const v16 = versionOf(st, "2026-10-27");
    v16.evaluation_context_descriptors = {
      ...v16.evaluation_context_descriptors,
      get_invoice: claimDescriptor(st, "payments:payment.execute"),
    };
    const { contracts, binding } = load(st);
    expect(() => assertContractDescriptors(contracts, binding)).toThrow(/does not cover/);
  });

  it("refuses at parse an association beside a document that names its own descriptors, one naming an operation the document does not define, one on a retired version, and a malformed reference", () => {
    const cases: Array<[string, (st: Statement) => void, RegExp]> = [
      [
        "beside descriptors in the document",
        (st) => {
          versionOf(st, "2026-11-02").evaluation_context_descriptors = {
            execute_wire_transfer: claimDescriptor(st, "payments:payment.execute"),
          };
        },
        /is declared only for a version whose document names no descriptor/,
      ],
      [
        "an undefined operation",
        (st) => {
          versionOf(st, "2026-10-27").evaluation_context_descriptors = {
            wire_everything: claimDescriptor(st, "payments:payment.execute"),
          };
        },
        /must name an operation the version's document defines/,
      ],
      [
        "a retired version",
        (st) => {
          const v = versionOf(st, "2026-10-20");
          v.state = "retired";
          delete v.retained_until;
          v.evaluation_context_descriptors = {
            execute_wire_transfer: claimDescriptor(st, "payments:payment.execute"),
          };
        },
        /is declared only for a current or superseded version/,
      ],
      [
        "a malformed reference",
        (st) => {
          versionOf(st, "2026-10-27").evaluation_context_descriptors = {
            execute_wire_transfer: { id: "not a uri" },
          };
        },
        /must be an evaluation-context descriptor reference/,
      ],
    ];
    for (const [label, edit, message] of cases) {
      const st = shipped();
      edit(st);
      expect(
        () => new ResourceContractDeclarations(st.extensions.resource_contracts),
        label,
      ).toThrow(ResourceContractConfigError);
      expect(
        () => new ResourceContractDeclarations(st.extensions.resource_contracts),
        label,
      ).toThrow(message);
    }
  });

  it("names no descriptor for a crossing whose operations name different ones", () => {
    const st = shipped();
    const v16 = versionOf(st, "2026-10-27");
    // A second commit-phase operation naming the remittance descriptor.
    v16.document.operations.execute_wire_transfer_again = {
      ...(v16.document.operations.execute_wire_transfer as object),
    };
    recommit(v16);
    v16.evaluation_context_descriptors = {
      ...v16.evaluation_context_descriptors,
      execute_wire_transfer_again: claimDescriptor(st, "payments:remittance.send"),
    };
    const contracts = new ResourceContractDeclarations(st.extensions.resource_contracts);
    expect(
      contractDescriptor(
        declaredVersion(contracts, "2026-10-27"),
        "payments:payment.execute",
        "commit",
      ),
    ).toBeUndefined();
    expect(
      contractDescriptor(
        declaredVersion(contracts, "2026-10-27"),
        "payments:payment.execute",
        "prepare",
      ),
    ).toEqual(claimDescriptor(st, "payments:payment.execute"));
  });
});
