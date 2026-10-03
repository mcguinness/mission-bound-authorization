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

  // @spec cross-domain#origin-principal-mapping (#832): the summary is as old
  // as its oldest required observation and expires with its earliest bound.
  it("summarizes with the oldest observation and the earliest validity bound, chosen independently, in both argument orders", () => {
    // The oldest observation (A) and the earliest bound (B) sit on different
    // mappings, so each minimum is chosen on its own.
    const table = policy([
      entry({
        origin: ORIGIN_A,
        observed_at: "2025-05-01T00:00:00Z",
        valid_until: "2025-09-01T00:00:00Z",
      }),
      entry({
        origin: ORIGIN_B,
        observed_at: "2025-05-16T00:00:00Z",
        valid_until: "2025-07-01T00:00:00Z",
      }),
    ]);
    for (const [primary, secondary] of [
      [ORIGIN_A, ORIGIN_B],
      [ORIGIN_B, ORIGIN_A],
    ] as const) {
      expect(resolveCoResolvedLocalPrincipal(table, primary, secondary, AUDIENCE, NOW)).toEqual({
        local_sub: "local-alice",
        policy: { id: "test-map", version: "v1" },
        observed_at: "2025-05-01T00:00:00Z",
        valid_until: "2025-07-01T00:00:00Z",
      });
    }
  });

  it("compares by parsed instant across UTC offsets and returns the selected value as recorded", () => {
    // 09:00+02:00 is 07:00Z, older than 08:00Z though its text sorts later;
    // 00:30-01:00 is 01:30Z, later than 01:00Z though its text sorts earlier.
    const table = policy([
      entry({
        origin: ORIGIN_A,
        observed_at: "2025-05-10T09:00:00+02:00",
        valid_until: "2025-07-01T00:30:00-01:00",
      }),
      entry({
        origin: ORIGIN_B,
        observed_at: "2025-05-10T08:00:00Z",
        valid_until: "2025-07-01T01:00:00Z",
      }),
    ]);
    for (const [primary, secondary] of [
      [ORIGIN_A, ORIGIN_B],
      [ORIGIN_B, ORIGIN_A],
    ] as const) {
      const resolved = resolveCoResolvedLocalPrincipal(table, primary, secondary, AUDIENCE, NOW);
      expect(resolved?.observed_at).toBe("2025-05-10T09:00:00+02:00");
      expect(resolved?.valid_until).toBe("2025-07-01T01:00:00Z");
    }
  });

  it("returns the shared value when both observations and bounds are equal", () => {
    const table = policy([
      entry({
        origin: ORIGIN_A,
        observed_at: "2025-05-10T08:00:00Z",
        valid_until: "2025-07-01T00:00:00Z",
      }),
      entry({
        origin: ORIGIN_B,
        observed_at: "2025-05-10T08:00:00Z",
        valid_until: "2025-07-01T00:00:00Z",
      }),
    ]);
    expect(resolveCoResolvedLocalPrincipal(table, ORIGIN_A, ORIGIN_B, AUDIENCE, NOW)).toMatchObject(
      {
        observed_at: "2025-05-10T08:00:00Z",
        valid_until: "2025-07-01T00:00:00Z",
      },
    );
  });

  it("denies co-resolution when the shared policy's version is empty", () => {
    const table = policy([entry({ origin: ORIGIN_A }), entry({ origin: ORIGIN_B })], {
      version: "",
    });
    const resolved = resolveCoResolvedLocalPrincipal(table, ORIGIN_A, ORIGIN_B, AUDIENCE, NOW);
    expect(resolved).toBeUndefined();
  });
});
