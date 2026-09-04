/**
 * @spec authority-server#mission-join rule 5 (#557)
 *
 * The deployment's actor records and the depth resolution rule 5 evaluates
 * against: "`max_depth` is evaluated from the deployment's actor records
 * rather than from a Mission-bound token's `act` chain", and "a delegate
 * with no actor record under the Mission is not recorded as acting under
 * it, and the join fails `mission_mismatch`". Every case where the ledger
 * does not record a rooted chain resolves ABSENT, which the PDP's resolver
 * denies (`services/pdp/test/mas-join.test.ts`).
 */

import { describe, expect, it } from "vitest";
import { ActorRecords } from "../src/index.js";

const MISSION = { issuer: "https://as.test", id: "msn_557_ledger" };
const MISSION_CLIENT = "ap-agent";

describe("ActorRecords: depth resolution (@spec authority-server#mission-join rule 5)", () => {
  it("resolves depth 0 for the Mission's own client, with no record required", () => {
    const records = new ActorRecords();
    expect(records.resolveDepth(MISSION, MISSION_CLIENT, MISSION_CLIENT)).toBe(0);
  });

  it("resolves depth 1 for a client delegated directly by the Mission's own client", () => {
    const records = new ActorRecords();
    records.record({ mission: MISSION, clientId: "delegate-a", delegatedBy: MISSION_CLIENT });
    expect(records.resolveDepth(MISSION, "delegate-a", MISSION_CLIENT)).toBe(1);
  });

  it("resolves depth 2 across two hops, adding 1 per hop toward the Mission's client", () => {
    const records = new ActorRecords();
    records.record({ mission: MISSION, clientId: "delegate-a", delegatedBy: MISSION_CLIENT });
    records.record({ mission: MISSION, clientId: "delegate-b", delegatedBy: "delegate-a" });
    expect(records.resolveDepth(MISSION, "delegate-b", MISSION_CLIENT)).toBe(2);
  });

  it("resolves ABSENT for a client with no record at all", () => {
    const records = new ActorRecords();
    expect(records.resolveDepth(MISSION, "unknown-client", MISSION_CLIENT)).toBeUndefined();
  });

  it("resolves ABSENT for a cycle rather than walking it forever", () => {
    const records = new ActorRecords();
    records.record({ mission: MISSION, clientId: "delegate-a", delegatedBy: "delegate-b" });
    records.record({ mission: MISSION, clientId: "delegate-b", delegatedBy: "delegate-a" });
    expect(records.resolveDepth(MISSION, "delegate-a", MISSION_CLIENT)).toBeUndefined();
  });

  it("resolves ABSENT for an unrooted chain that runs out of records before the Mission's client", () => {
    const records = new ActorRecords();
    records.record({ mission: MISSION, clientId: "delegate-b", delegatedBy: "delegate-a" });
    // No record for delegate-a, so the walk never reaches ap-agent.
    expect(records.resolveDepth(MISSION, "delegate-b", MISSION_CLIENT)).toBeUndefined();
  });

  it("resolves ABSENT for a chain that roots at another client and cycles there, never reaching the Mission's client", () => {
    const records = new ActorRecords();
    records.record({ mission: MISSION, clientId: "delegate-a", delegatedBy: "other-root" });
    records.record({ mission: MISSION, clientId: "other-root", delegatedBy: "other-root-2" });
    records.record({ mission: MISSION, clientId: "other-root-2", delegatedBy: "other-root" });
    expect(records.resolveDepth(MISSION, "delegate-a", MISSION_CLIENT)).toBeUndefined();
  });

  it("ignores a same-id record from another issuer: records are keyed on the canonical (issuer, id) pair", () => {
    const records = new ActorRecords();
    records.record({
      mission: { issuer: "https://other-as.test", id: MISSION.id },
      clientId: "delegate-a",
      delegatedBy: MISSION_CLIENT,
    });
    expect(records.resolveDepth(MISSION, "delegate-a", MISSION_CLIENT)).toBeUndefined();
    expect(records.resolveDepth({ issuer: "https://other-as.test", id: MISSION.id }, "delegate-a", MISSION_CLIENT)).toBe(
      1,
    );
  });
});

describe("ActorRecords: recording (@spec authority-server#mission-join rule 5)", () => {
  it("returns the recorded edge with a recorded_at timestamp, defaulting to now", () => {
    const records = new ActorRecords();
    const entry = records.record({ mission: MISSION, clientId: "delegate-a", delegatedBy: MISSION_CLIENT });
    expect(entry.mission).toEqual(MISSION);
    expect(entry.clientId).toBe("delegate-a");
    expect(entry.delegatedBy).toBe(MISSION_CLIENT);
    expect(Number.isNaN(Date.parse(entry.recordedAt))).toBe(false);
    expect(records.get(MISSION, "delegate-a")).toEqual(entry);
  });

  it("supersedes an earlier edge for the same (Mission, client), so depth follows the client's CURRENT delegation", () => {
    const records = new ActorRecords();
    records.record({ mission: MISSION, clientId: "delegate-a", delegatedBy: MISSION_CLIENT });
    records.record({ mission: MISSION, clientId: "delegate-b", delegatedBy: "delegate-a" });
    expect(records.resolveDepth(MISSION, "delegate-b", MISSION_CLIENT)).toBe(2);
    records.record({ mission: MISSION, clientId: "delegate-b", delegatedBy: MISSION_CLIENT });
    expect(records.resolveDepth(MISSION, "delegate-b", MISSION_CLIENT)).toBe(1);
  });
});
