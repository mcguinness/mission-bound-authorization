/**
 * Unit tests for the delegation family store (async-delegation foundation).
 * Key-free: the store is self-contained SQLite; `onLifecycleCommit` takes a
 * plain event by value.
 */

import { describe, expect, it } from "vitest";
import { DelegationFamilyStore } from "../src/kernel/delegation-family-store.js";
import type { LifecycleCommit } from "../src/kernel/types.js";

const commit = (id: string, state: LifecycleCommit["state"]): LifecycleCommit => ({
  id,
  issuer: "https://as.test",
  state,
  version: 2,
  committed_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 3600_000).toISOString(),
});

describe("DelegationFamilyStore.record / resolve", () => {
  it("resolves a recorded family to its mission and active state", () => {
    const store = new DelegationFamilyStore();
    store.record({ grantId: "grant_1", missionId: "msn_1" });
    const r = store.resolve("grant_1");
    expect(r).toEqual({ missionId: "msn_1", state: "active" });
  });

  it("returns undefined for an unknown grant", () => {
    expect(new DelegationFamilyStore().resolve("grant_nope")).toBeUndefined();
  });

  it("familiesForMission lists every grant recorded for a mission", () => {
    const store = new DelegationFamilyStore();
    store.record({ grantId: "grant_1", missionId: "msn_1" });
    store.record({ grantId: "grant_2", missionId: "msn_1" });
    store.record({ grantId: "grant_3", missionId: "msn_2" });
    expect(store.familiesForMission("msn_1").sort()).toEqual(["grant_1", "grant_2"]);
    expect(store.familiesForMission("msn_2")).toEqual(["grant_3"]);
    expect(store.familiesForMission("msn_unknown")).toEqual([]);
  });
});

describe("DelegationFamilyStore.onLifecycleCommit", () => {
  it("a terminal Mission commit stops the family resolving but leaves it listed", () => {
    const store = new DelegationFamilyStore();
    store.record({ grantId: "grant_1", missionId: "msn_1" });
    expect(store.resolve("grant_1")).toBeDefined();

    store.onLifecycleCommit(commit("msn_1", "revoked"));

    // Marked terminal, not deleted: resolve stops, but the grant is still
    // enumerable so a caller can drive its revocation.
    expect(store.resolve("grant_1")).toBeUndefined();
    expect(store.familiesForMission("msn_1")).toEqual(["grant_1"]);
  });

  it("a non-terminal commit (suspended) leaves the family resolving", () => {
    const store = new DelegationFamilyStore();
    store.record({ grantId: "grant_1", missionId: "msn_1" });
    store.onLifecycleCommit(commit("msn_1", "suspended"));
    expect(store.resolve("grant_1")).toEqual({ missionId: "msn_1", state: "active" });
  });

  it("only terminates families of the named Mission", () => {
    const store = new DelegationFamilyStore();
    store.record({ grantId: "grant_1", missionId: "msn_1" });
    store.record({ grantId: "grant_2", missionId: "msn_2" });
    store.onLifecycleCommit(commit("msn_1", "completed"));
    expect(store.resolve("grant_1")).toBeUndefined();
    expect(store.resolve("grant_2")).toBeDefined();
  });
});
