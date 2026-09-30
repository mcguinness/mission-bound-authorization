/**
 * @spec mission#scope-projection, resource-access#scope-projection — the pure
 * projection: the mapping's validation, the per-entry type conditions, and
 * the per-audience issuance outcome. The token-endpoint behavior over the
 * same function is exercised in
 * services/authorization-server/test/scope-projection.test.ts.
 */
import { describe, expect, it } from "vitest";
import {
  delegatedRoutingRefusal,
  earlyScopeRefusal,
  parseScopeProjectionMapping,
  projectScope,
  type ScopeProjectionMapping,
  ScopeProjectionMappingError,
  type ScopeValueMapping,
  scopeValueSafeForEntry,
} from "../src/index.js";

const RS = "https://rs.example/api";
const OTHER = "https://other.example/api";

const value = (
  actions: string[],
  over: Partial<ScopeValueMapping["rights"]> = {},
  controls = {},
): ScopeValueMapping => ({
  rights: { type: "mission_resource_access", resource: RS, match: "exact", actions, ...over },
  mandatory_controls: controls,
});
const entry = (actions: string[], extra: Record<string, unknown> = {}) => ({
  type: "mission_resource_access",
  resource: RS,
  actions,
  ...extra,
});

describe("scope-projection mapping validation", () => {
  const valid = {
    audiences: {
      [RS]: {
        version: "1",
        mission_aware: false,
        mode: "scope_only",
        scopes: { "r.read": { rights: value(["read"]).rights, mandatory_controls: {} } },
      },
      [OTHER]: { version: "1", mission_aware: true, mode: "authorization_details" },
    },
  };

  it("accepts a versioned per-audience mapping in both modes", () => {
    const m = parseScopeProjectionMapping(valid);
    expect(m.audiences[RS]?.mode).toBe("scope_only");
    expect(m.audiences[OTHER]).toEqual({
      version: "1",
      mission_aware: true,
      mode: "authorization_details",
    });
  });

  it("rejects unknown members at every level, a missing version, an unknown mode, and a control it has no comparison for", () => {
    /** A copy of `valid` with the member at `path` set to `to` (deleted when undefined). */
    const bad = (path: string[], to: unknown) => {
      const d = structuredClone(valid) as Record<string, unknown>;
      let at = d;
      for (const k of path.slice(0, -1)) at = at[k] as Record<string, unknown>;
      const leaf = path[path.length - 1] as string;
      if (to === undefined) delete at[leaf];
      else at[leaf] = to;
      return () => parseScopeProjectionMapping(d);
    };
    const read = ["audiences", RS, "scopes", "r.read"];
    expect(bad(["extra"], 1)).toThrow(ScopeProjectionMappingError);
    expect(bad(["audiences", OTHER, "scopes"], {})).toThrow(/scopes is not a known member/);
    expect(bad(["audiences", RS, "version"], undefined)).toThrow(/version/);
    expect(bad(["audiences", RS, "mission_aware"], undefined)).toThrow(
      /mission_aware must be a boolean/,
    );
    expect(bad(["audiences", OTHER, "mission_aware"], "true")).toThrow(
      /mission_aware must be a boolean/,
    );
    expect(bad(["audiences", OTHER, "mission_aware"], 1)).toThrow(
      /mission_aware must be a boolean/,
    );
    expect(bad(["audiences", RS, "mode"], "hybrid")).toThrow(/mode/);
    expect(bad([...read, "rights", "match"], "glob")).toThrow(/match/);
    expect(bad([...read, "rights", "extra"], true)).toThrow(/not a known member/);
    expect(bad([...read, "mandatory_controls"], { terminal_when: [] })).toThrow(
      /terminal_when is not a known member/,
    );
    expect(
      bad([...read, "mandatory_controls"], { max_amount: { amount: "1e3", currency: "USD" } }),
    ).toThrow(/decimal amount/);
    expect(
      bad(["audiences", RS, "scopes"], { "bad scope": valid.audiences[RS].scopes["r.read"] }),
    ).toThrow(/scope-token/);
    expect(bad(["audiences", RS, "scopes"], {})).toThrow(/at least one scope value/);
  });
});

describe("mission_resource_access scope-projection conditions (@spec resource-access#scope-projection)", () => {
  it("a value is safe for a constraints-free entry that carries every action it grants", () => {
    expect(scopeValueSafeForEntry(value(["read"]), entry(["read", "write"]))).toBe(true);
  });

  it("action aggregation: a value granting an action the entry does not carry is not safe", () => {
    expect(scopeValueSafeForEntry(value(["read", "write"]), entry(["read"]))).toBe(false);
    expect(scopeValueSafeForEntry(value(["reports.*"]), entry(["reports.read"]))).toBe(false);
  });

  it("resource match: a prefix value is never safe for an exact entry, nor a broader ancestor for a narrower prefix entry", () => {
    expect(scopeValueSafeForEntry(value(["read"], { match: "prefix" }), entry(["read"]))).toBe(
      false,
    );
    const narrowPrefix = entry(["read"], { resource: `${RS}/reports`, resource_match: "prefix" });
    expect(scopeValueSafeForEntry(value(["read"], { match: "prefix" }), narrowPrefix)).toBe(false);
    expect(
      scopeValueSafeForEntry(
        value(["read"], { match: "prefix", resource: `${RS}/reports` }),
        narrowPrefix,
      ),
    ).toBe(true);
    expect(scopeValueSafeForEntry(value(["read"], { resource: OTHER }), entry(["read"]))).toBe(
      false,
    );
    expect(
      scopeValueSafeForEntry(value(["read"]), entry(["read"], { resource_match: "glob" })),
    ).toBe(false);
  });

  it("constraints: every carried key needs an independently enforced control at least as tight", () => {
    const capped = entry(["read"], {
      constraints: { max_amount: { amount: "500.00", currency: "USD" } },
    });
    expect(scopeValueSafeForEntry(value(["read"]), capped)).toBe(false);
    expect(
      scopeValueSafeForEntry(
        value(["read"], {}, { max_amount: { amount: "500", currency: "USD" } }),
        capped,
      ),
    ).toBe(true);
    expect(
      scopeValueSafeForEntry(
        value(["read"], {}, { max_amount: { amount: "100.00", currency: "USD" } }),
        capped,
      ),
    ).toBe(true);
    expect(
      scopeValueSafeForEntry(
        value(["read"], {}, { max_amount: { amount: "500.01", currency: "USD" } }),
        capped,
      ),
    ).toBe(false);
    expect(
      scopeValueSafeForEntry(
        value(["read"], {}, { max_amount: { amount: "100.00", currency: "EUR" } }),
        capped,
      ),
    ).toBe(false);

    const vendors = entry(["read"], { constraints: { vendors: ["acme", "globex"] } });
    expect(scopeValueSafeForEntry(value(["read"]), vendors)).toBe(false);
    expect(scopeValueSafeForEntry(value(["read"], {}, { vendors: ["acme"] }), vendors)).toBe(true);
    expect(
      scopeValueSafeForEntry(value(["read"], {}, { vendors: ["acme", "initech"] }), vendors),
    ).toBe(false);

    // A key with no comparison fails closed; `requires_action_approval: false`
    // is the omitted value.
    expect(
      scopeValueSafeForEntry(
        value(["read"]),
        entry(["read"], { constraints: { requires_action_approval: true } }),
      ),
    ).toBe(false);
    expect(
      scopeValueSafeForEntry(
        value(["read"]),
        entry(["read"], { constraints: { requires_action_approval: false } }),
      ),
    ).toBe(true);
    expect(
      scopeValueSafeForEntry(
        value(["read"]),
        entry(["read"], { constraints: { terminal_when: [{ event_type: "x" }] } }),
      ),
    ).toBe(false);
    expect(
      scopeValueSafeForEntry(value(["read"]), entry(["read"], { constraints: { tenant: "t1" } })),
    ).toBe(false);
  });

  it("an entry member the projection does not understand, or a capability-source binding, fails closed", () => {
    expect(scopeValueSafeForEntry(value(["read"]), entry(["read"], { locations: [RS] }))).toBe(
      false,
    );
    expect(
      scopeValueSafeForEntry(value(["read"]), entry(["read"], { capability_sources: [] })),
    ).toBe(false);
    expect(
      scopeValueSafeForEntry(value(["read"]), entry(["read"], { delegation: { max_depth: 1 } })),
    ).toBe(true);
  });
});

describe("projectScope (@spec mission#scope-projection)", () => {
  const mapping: ScopeProjectionMapping = {
    audiences: {
      [RS]: {
        version: "v1",
        mission_aware: false,
        mode: "scope_only",
        scopes: {
          "r.read": value(["read"]),
          "r.write": value(["write"]),
          "r.rw": value(["read", "write"]),
        },
      },
      [OTHER]: { version: "v1", mission_aware: true, mode: "authorization_details" },
    },
  };

  it("emits exactly the values a single entry covers, sorted", () => {
    expect(projectScope({ mapping, audiences: [RS], entries: [entry(["write", "read"])] })).toEqual(
      {
        outcome: "emit",
        scope: "r.read r.rw r.write",
        values: ["r.read", "r.rw", "r.write"],
      },
    );
  });

  it("union widening: a value only two entries together cover is not emitted", () => {
    const out = projectScope({
      mapping,
      audiences: [RS],
      entries: [entry(["read"]), entry(["write"])],
    });
    expect(out).toMatchObject({ outcome: "emit", values: ["r.read", "r.write"] });
  });

  it("omits scope for an authorization_details audience", () => {
    expect(projectScope({ mapping, audiences: [OTHER], entries: [entry(["read"])] })).toEqual({
      outcome: "omit",
    });
  });

  it("refuses invalid_target for an unknown audience, no mapping, no audience, and a scope-only target with no safe value", () => {
    const target = { outcome: "refuse", error: "invalid_target" };
    expect(
      projectScope({ mapping, audiences: ["https://unknown.example"], entries: [] }),
    ).toMatchObject(target);
    expect(projectScope({ mapping: undefined, audiences: [OTHER], entries: [] })).toMatchObject(
      target,
    );
    expect(projectScope({ mapping, audiences: [], entries: [entry(["read"])] })).toMatchObject(
      target,
    );
    expect(projectScope({ mapping, audiences: [RS], entries: [entry(["delete"])] })).toMatchObject(
      target,
    );
  });

  it("evaluates the mapping current at each issuance: a changed version still projects", () => {
    const bumped: ScopeProjectionMapping = {
      audiences: {
        ...mapping.audiences,
        [RS]: { ...(mapping.audiences[RS] as object), version: "v2" } as never,
      },
    };
    expect(projectScope({ mapping: bumped, audiences: [RS], entries: [entry(["read"])] })).toEqual({
      outcome: "emit",
      scope: "r.read",
      values: ["r.read"],
    });
  });

  it("a requested scope narrows the projection; an explicit ungrantable value refuses invalid_scope; an inherited one narrows", () => {
    const entries = [entry(["read", "write"])];
    const ask = (values: string[], explicit = true) => ({ values, explicit });
    expect(projectScope({ mapping, audiences: [RS], entries, requested: ask(["r.read"]) })).toEqual(
      {
        outcome: "emit",
        scope: "r.read",
        values: ["r.read"],
      },
    );
    expect(
      projectScope({
        mapping,
        audiences: [RS],
        entries: [entry(["read"])],
        requested: ask(["r.write"]),
      }),
    ).toMatchObject({
      outcome: "refuse",
      error: "invalid_scope",
      reason: expect.stringMatching(/r\.write/),
    });
    expect(
      projectScope({ mapping, audiences: [RS], entries, requested: ask(["r.unmapped"]) }),
    ).toMatchObject({ outcome: "refuse", error: "invalid_scope" });
    expect(
      projectScope({ mapping, audiences: [OTHER], entries, requested: ask(["r.read"]) }),
    ).toMatchObject({
      outcome: "refuse",
      error: "invalid_scope",
      reason: expect.stringMatching(/consumes authorization_details/),
    });
    // Inherited (a refresh naming no scope): narrowed to what is still safe, never refused invalid_scope.
    expect(
      projectScope({
        mapping,
        audiences: [RS],
        entries: [entry(["read"])],
        requested: ask(["r.read", "r.write"], false),
      }),
    ).toEqual({ outcome: "emit", scope: "r.read", values: ["r.read"] });
    expect(
      projectScope({
        mapping,
        audiences: [RS],
        entries: [entry(["read"])],
        requested: ask([], false),
      }),
    ).toMatchObject({ outcome: "refuse", error: "invalid_target" });
    expect(
      projectScope({ mapping, audiences: [OTHER], entries, requested: ask(["r.read"], false) }),
    ).toEqual({ outcome: "omit" });
  });

  it("an explicit request naming no resource value refuses invalid_scope at a scope-only audience and omits at an authorization_details one", () => {
    const none = { values: [], explicit: true };
    expect(
      projectScope({ mapping, audiences: [RS], entries: [entry(["read"])], requested: none }),
    ).toMatchObject({ outcome: "refuse", error: "invalid_scope" });
    expect(
      projectScope({ mapping, audiences: [OTHER], entries: [entry(["read"])], requested: none }),
    ).toEqual({ outcome: "omit" });
  });

  it("an unknown mapping refuses invalid_target even when the request names a scope value", () => {
    expect(
      projectScope({
        mapping,
        audiences: ["https://unknown.example"],
        entries: [entry(["read"])],
        requested: { values: ["r.read"], explicit: true },
      }),
    ).toMatchObject({
      outcome: "refuse",
      error: "invalid_target",
      reason: expect.stringMatching(/no scope-projection mapping/),
    });
    expect(
      projectScope({
        mapping: undefined,
        audiences: [RS],
        entries: [entry(["read"])],
        requested: { values: ["r.nope"], explicit: true },
      }),
    ).toMatchObject({ outcome: "refuse", error: "invalid_target" });
  });

  it("earlyScopeRefusal: a value for an authorization_details audience or one the mapping does not name; an unknown audience is left to issuance", () => {
    expect(earlyScopeRefusal(mapping, [OTHER], ["r.read"])).toMatch(
      /consumes authorization_details/,
    );
    expect(earlyScopeRefusal(mapping, [RS], ["r.unmapped"])).toMatch(/does not name it/);
    expect(earlyScopeRefusal(mapping, [RS], ["r.read", "r.write"])).toBeUndefined();
    expect(earlyScopeRefusal(mapping, [RS], [])).toBeUndefined();
    expect(earlyScopeRefusal(mapping, ["https://unknown.example"], ["r.read"])).toBeUndefined();
    expect(earlyScopeRefusal(undefined, [RS], ["r.read"])).toBeUndefined();
  });

  it("per audience: a value is emitted only when safe at every audience, and mixed modes refuse", () => {
    const RS2 = "https://rs2.example/api";
    const two: ScopeProjectionMapping = {
      audiences: {
        ...mapping.audiences,
        [RS2]: {
          version: "v7",
          mission_aware: false,
          mode: "scope_only",
          scopes: { "r.read": value(["read"]), "r.write": value(["write"], { resource: RS2 }) },
        },
      },
    };
    expect(
      projectScope({ mapping: two, audiences: [RS, RS2], entries: [entry(["read", "write"])] }),
    ).toEqual({
      outcome: "emit",
      scope: "r.read",
      values: ["r.read"],
    });
    // Independent of audience order: each audience narrows the emitted set.
    expect(
      projectScope({ mapping: two, audiences: [RS2, RS], entries: [entry(["read", "write"])] }),
    ).toMatchObject({ outcome: "emit", values: ["r.read"] });
    expect(
      projectScope({ mapping: two, audiences: [RS, OTHER], entries: [entry(["read"])] }),
    ).toMatchObject({
      outcome: "refuse",
    });
  });
});

describe("delegated routing (@spec mission#rs-enforcement)", () => {
  const AWARE = "https://aware.example/api";
  const mapping: ScopeProjectionMapping = {
    audiences: {
      [RS]: {
        version: "v1",
        mission_aware: false,
        mode: "scope_only",
        scopes: { "r.read": value(["read"]) },
      },
      [AWARE]: { version: "v1", mission_aware: true, mode: "authorization_details" },
    },
  };

  it("a delegated token reaches only audiences classified mission_aware; an undelegated one keeps its projection", () => {
    expect(delegatedRoutingRefusal(mapping, [AWARE])).toBeUndefined();
    expect(delegatedRoutingRefusal(mapping, [RS])).toMatch(
      /routed only to a Mission-aware Resource Server/,
    );
    expect(delegatedRoutingRefusal(mapping, [AWARE, RS])).toMatch(
      /audience https:\/\/rs\.example\/api/,
    );
    expect(delegatedRoutingRefusal(mapping, ["https://unknown.example"])).toMatch(
      /no scope-projection mapping/,
    );
    expect(delegatedRoutingRefusal(undefined, [AWARE])).toMatch(/no scope-projection mapping/);
    expect(delegatedRoutingRefusal(mapping, [])).toMatch(/no audience/);

    const entries = [entry(["read"])];
    expect(projectScope({ mapping, audiences: [RS], entries, delegated: true })).toMatchObject({
      outcome: "refuse",
      reason: expect.stringMatching(/Mission-aware/),
    });
    expect(projectScope({ mapping, audiences: [RS], entries })).toMatchObject({
      outcome: "emit",
      scope: "r.read",
    });
    expect(projectScope({ mapping, audiences: [AWARE], entries, delegated: true })).toMatchObject({
      outcome: "omit",
    });
  });
});
