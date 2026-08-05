/**
 * Unit tests for the continuation handle store
 * (@spec draft-mcguinness-oauth-id-continuation-assertion-00). Key-free: the
 * store is self-contained SQLite; `onLifecycleCommit` takes a plain event.
 */

import { describe, expect, it } from "vitest";
import { ContinuationStore } from "../src/kernel/continuation-store.js";
import type { LifecycleCommit } from "../src/kernel/types.js";

/** The exact handle shape the ICA validator accepts (continuation-assertion.ts). */
const ICA_HANDLE = /^[A-Za-z0-9_-]{22,256}$/;

const commit = (id: string, state: LifecycleCommit["state"]): LifecycleCommit => ({
  id,
  issuer: "https://as.test",
  state,
  version: 2,
  committed_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 3600_000).toISOString(),
});

const ACTOR = { iss: "https://ca.example", sub: "agent-7" };
const ENV = { authTime: 1_700_000_000, acr: "urn:acr:mfa", amr: ["pwd", "otp"] };

describe("ContinuationStore.mint", () => {
  it("mints a handle that starts ich_, is base64url, and satisfies the ICA handle bounds", () => {
    const store = new ContinuationStore();
    const anchorId = store.rootGrantAnchor({ missionId: "msn_1", authEnvelope: ENV });
    const handle = store.mint({ anchorId, missionId: "msn_1", actor: ACTOR, cnfJkt: "jkt-1" });
    expect(handle.startsWith("ich_")).toBe(true);
    expect(handle.length).toBeGreaterThanOrEqual(22);
    expect(handle.length).toBeLessThanOrEqual(256);
    // Pins the store's output to the same alphabet/bounds Module 2 enforces.
    expect(handle).toMatch(ICA_HANDLE);
  });

  it("mints distinct handles (entropy)", () => {
    const store = new ContinuationStore();
    const anchorId = store.rootGrantAnchor({ missionId: "msn_1", authEnvelope: ENV });
    const seen = new Set(
      Array.from({ length: 50 }, () =>
        store.mint({ anchorId, missionId: "msn_1", actor: ACTOR, cnfJkt: "jkt-1" }),
      ),
    );
    expect(seen.size).toBe(50);
  });
});

describe("ContinuationStore.resolve", () => {
  it("returns the bound mission, actor, auth envelope, and cnf", () => {
    const store = new ContinuationStore();
    const anchorId = store.rootGrantAnchor({ missionId: "msn_1", authEnvelope: ENV });
    const handle = store.mint({ anchorId, missionId: "msn_1", actor: ACTOR, cnfJkt: "jkt-1" });
    const r = store.resolve(handle);
    expect(r?.missionId).toBe("msn_1");
    expect(r?.actor).toEqual(ACTOR);
    expect(r?.cnfJkt).toBe("jkt-1");
    expect(r?.authEnvelope).toEqual(ENV);
    expect(r?.anchor.anchorType).toBe("grant");
    expect(r?.anchor.sessionId).toBeUndefined();
  });

  it("returns undefined for an unknown handle", () => {
    expect(new ContinuationStore().resolve("ich_nope")).toBeUndefined();
  });

  it("does not consume the handle (resolvable repeatedly)", () => {
    const store = new ContinuationStore();
    const anchorId = store.rootGrantAnchor({ missionId: "msn_1", authEnvelope: {} });
    const handle = store.mint({ anchorId, missionId: "msn_1", actor: ACTOR, cnfJkt: "jkt-1" });
    expect(store.resolve(handle)).toBeDefined();
    expect(store.resolve(handle)).toBeDefined();
  });
});

describe("ContinuationStore.onLifecycleCommit", () => {
  it("a terminal Mission commit stops all its handles resolving", () => {
    const store = new ContinuationStore();
    const anchorId = store.rootGrantAnchor({ missionId: "msn_1", authEnvelope: ENV });
    const handle = store.mint({ anchorId, missionId: "msn_1", actor: ACTOR, cnfJkt: "jkt-1" });
    expect(store.resolve(handle)).toBeDefined();
    store.onLifecycleCommit(commit("msn_1", "revoked"));
    expect(store.resolve(handle)).toBeUndefined();
  });

  it("a non-terminal commit (suspended) leaves handles resolving", () => {
    const store = new ContinuationStore();
    const anchorId = store.rootGrantAnchor({ missionId: "msn_1", authEnvelope: ENV });
    const handle = store.mint({ anchorId, missionId: "msn_1", actor: ACTOR, cnfJkt: "jkt-1" });
    store.onLifecycleCommit(commit("msn_1", "suspended"));
    expect(store.resolve(handle)).toBeDefined();
  });

  it("only affects the named Mission", () => {
    const store = new ContinuationStore();
    const a1 = store.rootGrantAnchor({ missionId: "msn_1", authEnvelope: ENV });
    const a2 = store.rootGrantAnchor({ missionId: "msn_2", authEnvelope: ENV });
    const h1 = store.mint({ anchorId: a1, missionId: "msn_1", actor: ACTOR, cnfJkt: "jkt-1" });
    const h2 = store.mint({ anchorId: a2, missionId: "msn_2", actor: ACTOR, cnfJkt: "jkt-2" });
    store.onLifecycleCommit(commit("msn_1", "completed"));
    expect(store.resolve(h1)).toBeUndefined();
    expect(store.resolve(h2)).toBeDefined();
  });
});

describe("ContinuationStore.terminateSession", () => {
  it("terminates session-anchored handles but grant-anchored handles survive", () => {
    const store = new ContinuationStore();
    const sessionAnchor = store.rootSessionAnchor({
      missionId: "msn_1",
      sessionId: "sess-1",
      authEnvelope: ENV,
    });
    const grantAnchor = store.rootGrantAnchor({ missionId: "msn_1", authEnvelope: ENV });
    const sessionHandle = store.mint({
      anchorId: sessionAnchor,
      missionId: "msn_1",
      actor: ACTOR,
      cnfJkt: "jkt-s",
    });
    const grantHandle = store.mint({
      anchorId: grantAnchor,
      missionId: "msn_1",
      actor: ACTOR,
      cnfJkt: "jkt-g",
    });

    store.terminateSession("sess-1");

    expect(store.resolve(sessionHandle)).toBeUndefined();
    expect(store.resolve(grantHandle)).toBeDefined();
  });

  it("only terminates the named session", () => {
    const store = new ContinuationStore();
    const a1 = store.rootSessionAnchor({ missionId: "msn_1", sessionId: "sess-1", authEnvelope: {} });
    const a2 = store.rootSessionAnchor({ missionId: "msn_1", sessionId: "sess-2", authEnvelope: {} });
    const h1 = store.mint({ anchorId: a1, missionId: "msn_1", actor: ACTOR, cnfJkt: "jkt-1" });
    const h2 = store.mint({ anchorId: a2, missionId: "msn_1", actor: ACTOR, cnfJkt: "jkt-2" });
    store.terminateSession("sess-1");
    expect(store.resolve(h1)).toBeUndefined();
    expect(store.resolve(h2)).toBeDefined();
  });
});
