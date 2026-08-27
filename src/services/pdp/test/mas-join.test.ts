/**
 * @spec authority-server#mission-join (#557)
 *
 * Standalone unit coverage for the baseline mapping join resolver: subject
 * join (rule 3), client join direct/delegate (rule 4), delegate narrowing
 * (rule 5), and uniform mission_mismatch denial with no fallback (rule 6).
 * Exercised directly against MissionView fixtures, independent of the PEP.
 *
 * Also covers `deriveJoinDelegation` composed with `resolveBaselineJoin`
 * exactly as `src/demo/src/stack.ts`'s canonical `viewFor` loader wires them
 * (#557 review point 2): that call site is the only one populating
 * `join_delegation` from real kernel data, and it lives in `src/demo/*`,
 * outside vitest's `include` pattern, so this file is the only automated
 * check of the composition rather than either function in isolation.
 */

import { describe, expect, it } from "vitest";
import { deriveJoinDelegation, resolveBaselineJoin } from "../src/mas-join.js";
import { MISSION_RESOURCE_ACCESS_TYPE, type AuthorityEntry, type MissionView } from "../src/policy-view.js";

const RESOURCE = "https://api.example.test";
const READ = "payments:invoice.read";
const WRITE = "payments:payment.schedule";

const DIRECT_ENTRY: AuthorityEntry = { type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: [READ, WRITE] };
const DELEGABLE_ENTRY: AuthorityEntry = {
  type: MISSION_RESOURCE_ACCESS_TYPE,
  resource: RESOURCE,
  actions: [READ],
  join_delegation: { max_depth: 2, allowed_delegates: ["delegate-a"] },
};
const NON_DELEGABLE_ENTRY: AuthorityEntry = { type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: [WRITE] };

function view(overrides: Partial<MissionView> = {}): MissionView {
  return {
    id: "mission-1",
    issuer: "https://as.example.test",
    state: "active",
    version: 1,
    authority_hash: "sha-256:test",
    authority_set: [DIRECT_ENTRY],
    subject: { iss: "https://idp.example.test", sub: "alice" },
    client_id: "ap-agent",
    ...overrides,
  };
}

const SUBJECT = { iss: "https://idp.example.test", sub: "alice" };

describe("resolveBaselineJoin: subject join (@spec authority-server#mission-join rule 3)", () => {
  it("joins when the authenticated subject matches the Mission's subject exactly", () => {
    const result = resolveBaselineJoin({ view: view(), subject: SUBJECT, clientId: "ap-agent" });
    expect(result).toEqual({ ok: true, disposition: "direct", authoritySet: [DIRECT_ENTRY] });
  });

  it("denies mission_mismatch when the subject sub differs", () => {
    const result = resolveBaselineJoin({ view: view(), subject: { ...SUBJECT, sub: "mallory" }, clientId: "ap-agent" });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });

  it("denies mission_mismatch when the subject issuer differs (same sub)", () => {
    const result = resolveBaselineJoin({ view: view(), subject: { iss: "https://other-idp.test", sub: "alice" }, clientId: "ap-agent" });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });
});

describe("resolveBaselineJoin: client join (@spec authority-server#mission-join rule 4)", () => {
  it("joins directly when the client_id matches the Mission's own client_id", () => {
    const result = resolveBaselineJoin({ view: view(), subject: SUBJECT, clientId: "ap-agent" });
    expect(result.ok).toBe(true);
    expect(result.ok && result.disposition).toBe("direct");
  });

  it("denies mission_mismatch for an unrecognized client with no delegate policy at all", () => {
    const result = resolveBaselineJoin({ view: view(), subject: SUBJECT, clientId: "unknown-client" });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });

  it("denies mission_mismatch for a client not named in the delegate policy (no default)", () => {
    const result = resolveBaselineJoin({
      view: view(),
      subject: SUBJECT,
      clientId: "unknown-client",
      delegatePolicy: { delegates: { "delegate-a": {} } },
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });
});

describe("resolveBaselineJoin: delegate narrowing (@spec authority-server#mission-join rule 5)", () => {
  it("joins as a delegate and narrows to only the delegable, allowed entries", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [DIRECT_ENTRY, DELEGABLE_ENTRY, NON_DELEGABLE_ENTRY] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } },
      delegateDepth: 1,
    });
    expect(result).toEqual({ ok: true, disposition: "delegate", authoritySet: [DELEGABLE_ENTRY] });
  });

  it("excludes an entry with no delegation member entirely, even for an authorized delegate", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [NON_DELEGABLE_ENTRY] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": {} } },
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });

  it("excludes an entry whose allowed_delegates does not name this delegate", () => {
    const otherDelegateEntry: AuthorityEntry = {
      type: MISSION_RESOURCE_ACCESS_TYPE,
      resource: RESOURCE,
      actions: [READ],
      join_delegation: { allowed_delegates: ["delegate-b"] },
    };
    const result = resolveBaselineJoin({
      view: view({ authority_set: [otherDelegateEntry] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": {} } },
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });

  it("denies mission_mismatch when the recorded depth exceeds the delegate's max_depth", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [DELEGABLE_ENTRY] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } },
      delegateDepth: 5,
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });

  it("joins as a delegate when the recorded depth is within max_depth", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [DELEGABLE_ENTRY] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } },
      delegateDepth: 2,
    });
    expect(result.ok).toBe(true);
  });

  it("denies mission_mismatch when delegateDepth is absent and DelegatePolicy declares a maxDepth (#557 review point 1: absent depth is unbounded, not shallow)", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [DELEGABLE_ENTRY] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } },
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });
});

describe("resolveBaselineJoin: per-entry join_delegation.max_depth (@spec authority-server#mission-join rule 5, #557 review point 3)", () => {
  const SHALLOW_ENTRY: AuthorityEntry = {
    type: MISSION_RESOURCE_ACCESS_TYPE,
    resource: RESOURCE,
    actions: [READ],
    // The deployment-wide DelegatePolicy permits depth up to 3, but THIS
    // entry's own join_delegation caps it at 0: a nonzero depth must still
    // exclude the entry even though the global policy would allow it.
    join_delegation: { max_depth: 0, allowed_delegates: ["delegate-a"] },
  };

  it("excludes an entry whose own max_depth is 0 for a delegate with nonzero recorded depth, even though the deployment's DelegatePolicy permits deeper delegation", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [SHALLOW_ENTRY] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } },
      delegateDepth: 1,
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });

  it("includes an entry whose own max_depth is 0 for a delegate at depth exactly 0", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [SHALLOW_ENTRY] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } },
      delegateDepth: 0,
    });
    expect(result).toEqual({ ok: true, disposition: "delegate", authoritySet: [SHALLOW_ENTRY] });
  });

  it("excludes an entry with a finite max_depth when delegateDepth is absent (unbounded, not assumed shallow)", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [SHALLOW_ENTRY] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": { maxDepth: 3 } } },
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });
});

describe("deriveJoinDelegation: kernel delegation adapter (@spec authority-server#mission-join rule 5, #557 review point 2)", () => {
  it("returns undefined for an entry with no kernel delegation at all (not delegable)", () => {
    expect(deriveJoinDelegation(undefined)).toBeUndefined();
  });

  it("passes max_depth through unchanged and omits allowed_delegates when the kernel policy carries none", () => {
    expect(deriveJoinDelegation({ max_depth: 2 })).toEqual({ max_depth: 2 });
  });

  it("maps an exact sub matcher (no sub_profile) to its bare string", () => {
    expect(deriveJoinDelegation({ max_depth: 1, allowed_delegates: [{ sub: "delegate-a" }] })).toEqual({
      max_depth: 1,
      allowed_delegates: ["delegate-a"],
    });
  });

  it("drops a sub_profile-scoped matcher rather than approximating it, and keeps sibling exact matchers", () => {
    expect(
      deriveJoinDelegation({
        max_depth: 4,
        allowed_delegates: [{ sub: "delegate-a" }, { sub_profile: "workload" }],
      }),
    ).toEqual({ max_depth: 4, allowed_delegates: ["delegate-a"] });
  });

  it("narrows to an EMPTY allowed_delegates (deny all delegates), never absent, when every matcher is sub_profile-only", () => {
    const adapted = deriveJoinDelegation({ max_depth: 4, allowed_delegates: [{ sub_profile: "workload" }] });
    expect(adapted).toEqual({ max_depth: 4, allowed_delegates: [] });
    // Confirms the fail-closed reading against the resolver itself: an
    // empty allowed_delegates excludes every delegate, never "any".
    const result = resolveBaselineJoin({
      view: view({
        authority_set: [
          { type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: [READ], join_delegation: adapted },
        ],
      }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": {} } },
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });
});

describe("deriveJoinDelegation + resolveBaselineJoin: canonical loader composition (#557 review point 2)", () => {
  // Mirrors `src/demo/src/stack.ts`'s `viewFor` exactly: a kernel-shaped
  // AuthorityEntry with a REQUIRED `delegation.max_depth`, mapped through
  // `deriveJoinDelegation` onto `join_delegation`, same as the canonical
  // loader's `authority_set.map((e) => ({...e, ...(e.delegation !== undefined
  // ? {join_delegation: deriveJoinDelegation(e.delegation)} : {})}))`. That
  // call site lives in `src/demo/*`, outside vitest's `include` pattern, so
  // this is the only automated check of the composition. It matters here
  // specifically: a kernel `delegation` member is always concrete
  // (`max_depth` is required, never optional), so every delegate entry
  // populated this way now denies unless the caller also supplies
  // `delegateDepth` -- a coupling introduced by wiring the adapter's output
  // into the resolver, not by either the adapter or the per-entry check
  // alone (#557 review point 3's "absent is unbounded" fail-closed rule).
  const kernelEntry: AuthorityEntry = {
    type: MISSION_RESOURCE_ACCESS_TYPE,
    resource: RESOURCE,
    actions: [READ],
    join_delegation: deriveJoinDelegation({ max_depth: 1, allowed_delegates: [{ sub: "delegate-a" }] }),
  };

  it("denies mission_mismatch for a loader-populated delegate entry when the caller supplies no delegateDepth", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [kernelEntry] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": {} } },
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });

  it("joins as a delegate for a loader-populated entry once the caller supplies a delegateDepth within the kernel's max_depth", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [kernelEntry] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": {} } },
      delegateDepth: 1,
    });
    expect(result).toEqual({ ok: true, disposition: "delegate", authoritySet: [kernelEntry] });
  });

  it("excludes a loader-populated entry once delegateDepth exceeds the kernel's max_depth", () => {
    const result = resolveBaselineJoin({
      view: view({ authority_set: [kernelEntry] }),
      subject: SUBJECT,
      clientId: "delegate-a",
      delegatePolicy: { delegates: { "delegate-a": {} } },
      delegateDepth: 2,
    });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
  });
});

describe("resolveBaselineJoin: no fallback (@spec authority-server#mission-join rule 6)", () => {
  it("a failed join never returns a partial or unjoined authoritySet", () => {
    const result = resolveBaselineJoin({ view: view(), subject: { ...SUBJECT, sub: "mallory" }, clientId: "ap-agent" });
    expect(result).toEqual({ ok: false, reason: "mission_mismatch" });
    expect((result as { authoritySet?: unknown }).authoritySet).toBeUndefined();
  });
});
