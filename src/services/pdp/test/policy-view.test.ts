/**
 * @spec authzen#materialization, authority-server#mission-join
 *
 * `policyViewId` commits a pinned subset of the MissionView (mission_id,
 * mission_version, authority_hash, model_id), never the whole object. This is
 * a pure unit test: no OpenFGA / Docker, never skips.
 */

import { describe, expect, it } from "vitest";
import { joinViewId, policyViewId, type AuthorityEntry, type MissionView } from "../src/policy-view.js";

const baseView: MissionView = {
  id: "msn_test_1",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [
    { type: "mission_resource_access", resource: "http://localhost:4403/mcp", actions: ["payments:invoice.read"] },
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
};

describe("policyViewId commits a pinned subset, not the whole MissionView (@spec authzen#materialization)", () => {
  it("is identical for views differing only in the Join fields (@spec authority-server#mission-join): adding subject/client_id does not perturb an existing pinned hash", () => {
    const withoutJoinFields = policyViewId(baseView, "model-1");
    const withDifferentJoinFields = policyViewId(
      {
        ...baseView,
        subject: { iss: "https://other.example", sub: "someone-else" },
        client_id: "some-other-client",
      },
      "model-1",
    );
    expect(withDifferentJoinFields).toBe(withoutJoinFields);
  });

  it("still moves when a pinned field changes (mission_version), so the pin itself is not a no-op", () => {
    const v1 = policyViewId(baseView, "model-1");
    const v2 = policyViewId({ ...baseView, version: 2 }, "model-1");
    expect(v2).not.toBe(v1);
  });
});

const DIRECT_ENTRY: AuthorityEntry = baseView.authority_set[0] as AuthorityEntry;
const DELEGATE_ENTRY: AuthorityEntry = {
  type: "mission_resource_access",
  resource: "http://localhost:4403/mcp",
  actions: ["payments:invoice.read"],
  join_delegation: { max_depth: 1, allowed_delegates: ["delegate-a"] },
};

describe("joinViewId: a separate commitment for a joined decision (@spec authority-server#mission-join, #557 review point 4)", () => {
  it("differs from policyViewId for the SAME view: evidence can tell a joined decision from a direct Mission-bound one", () => {
    const pvid = policyViewId(baseView, "model-1");
    const jvid = joinViewId(baseView, "model-1", { disposition: "direct", clientId: "ap-agent", authoritySet: [DIRECT_ENTRY] });
    expect(jvid).not.toBe(pvid);
  });

  it("differs between a direct join and a delegate join over the SAME underlying view", () => {
    const direct = joinViewId(baseView, "model-1", { disposition: "direct", clientId: "ap-agent", authoritySet: [DIRECT_ENTRY] });
    const delegate = joinViewId(baseView, "model-1", { disposition: "delegate", clientId: "delegate-a", authoritySet: [DELEGATE_ENTRY] });
    expect(delegate).not.toBe(direct);
  });

  it("differs between two different delegates narrowed to two different subsets", () => {
    const delegateA = joinViewId(baseView, "model-1", { disposition: "delegate", clientId: "delegate-a", authoritySet: [DELEGATE_ENTRY] });
    const otherEntry: AuthorityEntry = { ...DELEGATE_ENTRY, join_delegation: { max_depth: 1, allowed_delegates: ["delegate-b"] } };
    const delegateB = joinViewId(baseView, "model-1", { disposition: "delegate", clientId: "delegate-b", authoritySet: [otherEntry] });
    expect(delegateB).not.toBe(delegateA);
  });

  it("is stable (same inputs, same output) so two decisions over the same joined view carry the same commitment", () => {
    const a = joinViewId(baseView, "model-1", { disposition: "direct", clientId: "ap-agent", authoritySet: [DIRECT_ENTRY] });
    const b = joinViewId(baseView, "model-1", { disposition: "direct", clientId: "ap-agent", authoritySet: [DIRECT_ENTRY] });
    expect(b).toBe(a);
  });
});
