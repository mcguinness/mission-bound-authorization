/**
 * @spec authzen#materialization, authority-server#mission-join
 *
 * `policyViewId` commits a pinned subset of the MissionView (mission_id,
 * mission_version, authority_hash, model_id), never the whole object. This is
 * a pure unit test: no OpenFGA / Docker, never skips.
 */

import { describe, expect, it } from "vitest";
import { policyViewId, type MissionView } from "../src/policy-view.js";

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
