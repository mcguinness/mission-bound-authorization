/**
 * @spec derivation-limits#approval-rendering, child-delegation#subtree-rendering
 * (#1119) — the approval page's derivation disclosure for each source of a
 * delegable entry's per-child figure. The policy source is witnessed at the
 * endpoint (child-derivation-limit-endpoint.test.ts); these are the others:
 * an entry committing no policy (the deployment ceiling is the figure), a
 * committed policy this issuer does not hold, and one stating a malformed
 * maximum.
 */

import { describe, expect, it } from "vitest";
import { approvalDerivationRendering } from "../src/adapters/provider.js";
import type { AuthorityEntry } from "../src/index.js";

const REF = { id: "urn:policy:child", version: "1", digest: `sha-256:${"A".repeat(43)}` };
const entry = (children: Record<string, unknown>): AuthorityEntry =>
  ({
    type: "mission_resource_access",
    resource: "https://payments.test/mcp",
    actions: ["payments:invoice.read"],
    delegation: { max_depth: 1, children },
  }) as AuthorityEntry;
const render = (children: Record<string, unknown>, held: (ref: typeof REF) => unknown, deploymentCeiling: number | null = null) =>
  approvalDerivationRendering({
    limit: null,
    deploymentCeiling,
    authority: [entry(children)],
    held: held as never,
    asyncDelegation: false,
    progressive: false,
  });

describe("the approval disclosure for each per-child figure source (@spec child-delegation#subtree-rendering, #1119)", () => {
  it("an entry committing no policy renders the deployment ceiling as its figure, or no finite maximum without one", () => {
    expect(render({ max_children: 2 }, () => undefined, 4).children[0]?.lines).toContain(
      "Each child Mission created under this consent establishes its own derivation limit from its own request, never above 4.",
    );
    expect(render({ max_children: 2 }, () => undefined).children[0]?.lines).toContain(
      "Each child Mission created under this consent establishes its own derivation limit from its own request; no finite maximum is guaranteed.",
    );
  });

  it("a committed policy this issuer does not hold renders that no figure can be shown and the approval is refused", () => {
    const lines = render({ child_creation_policy: REF }, () => undefined).children[0]?.lines ?? [];
    expect(lines).toContain(
      "The per-child derivation limit cannot be shown: child creation policy urn:policy:child version 1 is not one this issuer holds at its committed digest. This approval is refused until it can be shown.",
    );
    expect(lines.some((l) => l.includes("never above"))).toBe(false);
  });

  it("a held policy stating a malformed maximum renders that no figure can be shown", () => {
    const malformed = { version: "1", content_type: "application/json", content: JSON.stringify({ derivation_limit_ceiling: 0 }) };
    const lines = render({ child_creation_policy: REF }, () => malformed).children[0]?.lines ?? [];
    expect(lines).toContain(
      "The per-child derivation limit cannot be shown: child creation policy urn:policy:child states a malformed derivation_limit_ceiling. This approval is refused until it states a usable one.",
    );
  });

  it("renders max_child_depth's default, and no limit where max_children is not set", () => {
    const lines = render({}, () => undefined).children[0]?.lines ?? [];
    expect(lines).toContain("Concurrent children: no limit is set on concurrently non-terminal child Missions.");
    expect(lines).toContain("Child depth: at most 1 (the default).");
  });
});
