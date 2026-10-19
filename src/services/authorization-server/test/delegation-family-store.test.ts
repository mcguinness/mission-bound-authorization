/**
 * Unit tests for the delegation family store (async-delegation foundation).
 * Key-free: the store runs on an injected SQLite database, as it does on the
 * kernel's; the kernel-level terminal propagation is in
 * continuation-durability.test.ts.
 */

import { openStore, withTransaction } from "@mission/store";
import { describe, expect, it } from "vitest";
import { DelegationFamilyStore } from "../src/kernel/delegation-family-store.js";

/** A store on its own in-memory database (the kernel passes its own). */
const newStore = (): DelegationFamilyStore => new DelegationFamilyStore(openStore(""));

/** The kernel's terminal propagation, inside a transaction as the kernel runs it. */
const terminate = (store: DelegationFamilyStore, missionId: string): void =>
  withTransaction(store.db, () => store.terminateMissionInCallerTx(missionId));

describe("DelegationFamilyStore.record / resolve", () => {
  it("resolves a recorded family to its mission and active state", () => {
    const store = newStore();
    store.record({ grantId: "grant_1", missionId: "msn_1" });
    const r = store.resolve("grant_1");
    expect(r).toEqual({ missionId: "msn_1", state: "active" });
  });

  it("returns undefined for an unknown grant", () => {
    expect(newStore().resolve("grant_nope")).toBeUndefined();
  });

  it("familiesForMission lists every grant recorded for a mission", () => {
    const store = newStore();
    store.record({ grantId: "grant_1", missionId: "msn_1" });
    store.record({ grantId: "grant_2", missionId: "msn_1" });
    store.record({ grantId: "grant_3", missionId: "msn_2" });
    expect(store.familiesForMission("msn_1").sort()).toEqual(["grant_1", "grant_2"]);
    expect(store.familiesForMission("msn_2")).toEqual(["grant_3"]);
    expect(store.familiesForMission("msn_unknown")).toEqual([]);
  });
});

describe("DelegationFamilyStore.terminateMissionInCallerTx", () => {
  it("a terminal Mission commit stops the family resolving but leaves it listed", () => {
    const store = newStore();
    store.record({ grantId: "grant_1", missionId: "msn_1" });
    expect(store.resolve("grant_1")).toBeDefined();

    terminate(store, "msn_1");

    // Marked terminal, not deleted: resolve stops, but the grant is still
    // enumerable so a caller can drive its revocation.
    expect(store.resolve("grant_1")).toBeUndefined();
    expect(store.familiesForMission("msn_1")).toEqual(["grant_1"]);
  });

  it("is written only inside the caller's transaction, and changes nothing when refused", () => {
    const store = newStore();
    store.record({ grantId: "grant_1", missionId: "msn_1" });
    expect(() => store.terminateMissionInCallerTx("msn_1")).toThrow("inside the terminal commit's transaction");
    expect(store.resolve("grant_1")).toEqual({ missionId: "msn_1", state: "active" });
  });

  it("only terminates families of the named Mission", () => {
    const store = newStore();
    store.record({ grantId: "grant_1", missionId: "msn_1" });
    store.record({ grantId: "grant_2", missionId: "msn_2" });
    terminate(store, "msn_1");
    expect(store.resolve("grant_1")).toBeUndefined();
    expect(store.resolve("grant_2")).toBeDefined();
  });
});
