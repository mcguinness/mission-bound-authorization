/**
 * @spec cross-domain#origin-principal-mapping, #origin-principal-continuity
 *
 * `resolveLocalPrincipal`/`resolveCoResolvedLocalPrincipal` reject a
 * malformed SELECTED mapping (empty `local_sub`, empty `audience`, or an
 * unidentified `policy.id`/`policy.version`) the same way as a missing,
 * ambiguous, disabled, future-dated, or expired one -- never returning a
 * usable resolution built from an incomplete record.
 */

import { describe, expect, it } from "vitest";
import {
  type LocalMappingPolicy,
  type LocalPrincipalMapping,
  resolveCoResolvedLocalPrincipal,
  resolveLocalPrincipal,
} from "../src/index.js";

const ORIGIN_A = { iss: "https://as.example.test", sub: "svc-acct-42" };
const ORIGIN_B = { iss: "https://idp.example.test", sub: "alice" };
const AUDIENCE = "https://saas.example.test/mcp";
const FAR_PAST = "2020-01-01T00:00:00Z";
const FAR_FUTURE = "2099-01-01T00:00:00Z";
const NOW = new Date("2025-06-01T00:00:00Z");

function entry(overrides: Partial<LocalPrincipalMapping> = {}): LocalPrincipalMapping {
  return {
    origin: ORIGIN_A,
    local_sub: "local-alice",
    observed_at: FAR_PAST,
    valid_until: FAR_FUTURE,
    ...overrides,
  };
}

function policy(
  entries: LocalPrincipalMapping[],
  overrides: Partial<LocalMappingPolicy> = {},
): LocalMappingPolicy {
  return { id: "test-map", version: "v1", entries, ...overrides };
}

describe("resolveLocalPrincipal: complete-mapping validation (@spec cross-domain#origin-principal-mapping)", () => {
  it("resolves a well-formed unambiguous current mapping", () => {
    const resolved = resolveLocalPrincipal(policy([entry()]), ORIGIN_A, AUDIENCE, NOW);
    expect(resolved).toEqual({
      local_sub: "local-alice",
      policy: { id: "test-map", version: "v1" },
      observed_at: FAR_PAST,
      valid_until: FAR_FUTURE,
    });
  });

  it("rejects a selected entry with an empty local_sub", () => {
    const resolved = resolveLocalPrincipal(
      policy([entry({ local_sub: "" })]),
      ORIGIN_A,
      AUDIENCE,
      NOW,
    );
    expect(resolved).toBeUndefined();
  });

  it("rejects a selected entry with a non-string local_sub", () => {
    const malformed = policy([{ ...entry(), local_sub: undefined as unknown as string }]);
    expect(resolveLocalPrincipal(malformed, ORIGIN_A, AUDIENCE, NOW)).toBeUndefined();
  });

  it("rejects a selected entry with an empty (but present) audience", () => {
    // The requested audience must equal the entry's malformed value ("")
    // for the entry to survive the candidate filter at all and reach the
    // new completeness check below; a mismatched request would already be
    // filtered out as "missing" for an unrelated reason.
    const resolved = resolveLocalPrincipal(policy([entry({ audience: "" })]), ORIGIN_A, "", NOW);
    expect(resolved).toBeUndefined();
  });

  it("still matches any audience when the entry's audience is genuinely absent", () => {
    const resolved = resolveLocalPrincipal(
      policy([entry({ audience: undefined })]),
      ORIGIN_A,
      AUDIENCE,
      NOW,
    );
    expect(resolved?.local_sub).toBe("local-alice");
  });

  it("rejects the mapping when the policy id is empty", () => {
    const resolved = resolveLocalPrincipal(policy([entry()], { id: "" }), ORIGIN_A, AUDIENCE, NOW);
    expect(resolved).toBeUndefined();
  });

  it("rejects the mapping when the policy version is empty", () => {
    const resolved = resolveLocalPrincipal(
      policy([entry()], { version: "" }),
      ORIGIN_A,
      AUDIENCE,
      NOW,
    );
    expect(resolved).toBeUndefined();
  });
});

describe("resolveCoResolvedLocalPrincipal: complete-mapping validation propagates (@spec cross-domain#origin-principal-mapping)", () => {
  it("denies co-resolution when the primary side's selected entry has an empty local_sub", () => {
    const table = policy([entry({ origin: ORIGIN_A, local_sub: "" }), entry({ origin: ORIGIN_B })]);
    const resolved = resolveCoResolvedLocalPrincipal(table, ORIGIN_A, ORIGIN_B, AUDIENCE, NOW);
    expect(resolved).toBeUndefined();
  });

  it("denies co-resolution when the secondary side's selected entry has an empty local_sub", () => {
    const table = policy([entry({ origin: ORIGIN_A }), entry({ origin: ORIGIN_B, local_sub: "" })]);
    const resolved = resolveCoResolvedLocalPrincipal(table, ORIGIN_A, ORIGIN_B, AUDIENCE, NOW);
    expect(resolved).toBeUndefined();
  });

  it("denies co-resolution when the shared policy's version is empty", () => {
    const table = policy([entry({ origin: ORIGIN_A }), entry({ origin: ORIGIN_B })], {
      version: "",
    });
    const resolved = resolveCoResolvedLocalPrincipal(table, ORIGIN_A, ORIGIN_B, AUDIENCE, NOW);
    expect(resolved).toBeUndefined();
  });
});
