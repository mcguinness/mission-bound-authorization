/**
 * @spec runtime#state-freshness — the one permit-deadline calculation's own
 * case matrix (issue #252 PR C1).
 *
 * "A permit issued from that state view MUST expire no later than this state
 * valid-through: the reported expiry or lease end, or, absent one, the
 * observation time plus the published staleness bound."
 *
 * Unconditional: the helper is pure, so this file never skips. The
 * end-to-end assertion, that `evaluate()` actually issues the capped permit,
 * lives in evaluate-decision.test.ts.
 */

import { describe, expect, it } from "vitest";
import { executionLeaseMs, permitDeadline, type StalenessBound } from "../src/index.js";

const NOW_MS = Date.parse("2026-07-22T12:00:00.000Z");
const bounded = (seconds: number): StalenessBound => ({ kind: "bounded", seconds });

describe("permit deadline (@spec runtime#state-freshness)", () => {
  it("caps a bounded class at the accepted observation plus the class bound, not at the permit lifetime", () => {
    // The observation is 10s old and the class bound is 30s, so the state
    // view is valid through observation+30s = now+20s, well inside the
    // 120-second permit lifetime.
    const deadline = permitDeadline({
      nowMs: NOW_MS,
      permitTtlSeconds: 120,
      stalenessBound: bounded(30),
      stateObservedAtMs: NOW_MS - 10_000,
    });
    expect(deadline).toEqual({
      kind: "bounded",
      validUntilMs: NOW_MS + 20_000,
      validUntil: new Date(NOW_MS + 20_000).toISOString(),
      source: "state_view",
    });
  });

  it("keeps the permit lifetime when it is the tighter bound", () => {
    const deadline = permitDeadline({
      nowMs: NOW_MS,
      permitTtlSeconds: 30,
      stalenessBound: bounded(300),
      stateObservedAtMs: NOW_MS,
    });
    expect(deadline).toMatchObject({ source: "permit_ttl", validUntilMs: NOW_MS + 30_000 });
  });

  it("caps a bounded class with no freshness available at the class bound from the decision instant", () => {
    // Reachable today below the high-consequence floor, where the draft
    // treats credential-lifetime expiry as itself a conforming state source
    // and an absent `context.freshness` is not by itself a refusal. With no
    // observation there is no state valid-through to measure from, so the
    // class's published bound caps from now: never later than the permit
    // lifetime alone, so it can only narrow.
    expect(
      permitDeadline({ nowMs: NOW_MS, permitTtlSeconds: 300, stalenessBound: bounded(60) }),
    ).toMatchObject({ source: "class_staleness_bound", validUntilMs: NOW_MS + 60_000 });
    expect(
      permitDeadline({ nowMs: NOW_MS, permitTtlSeconds: 300, stalenessBound: bounded(300) }),
    ).toMatchObject({ validUntilMs: NOW_MS + 300_000 });
  });

  it("applies no state cap under a declared `none` posture", () => {
    // The draft's "No active freshness required" row is a posture, not a
    // missing bound: the class's own permit lifetime stands alone.
    expect(
      permitDeadline({ nowMs: NOW_MS, permitTtlSeconds: 300, stalenessBound: { kind: "none" } }),
    ).toMatchObject({ source: "permit_ttl", validUntilMs: NOW_MS + 300_000 });
  });

  it("clamps a skew-tolerated future observation to the decision instant, so skew cannot lengthen a permit", () => {
    const skewed = permitDeadline({
      nowMs: NOW_MS,
      permitTtlSeconds: 120,
      stalenessBound: bounded(30),
      stateObservedAtMs: NOW_MS + 4_000,
    });
    const onTime = permitDeadline({
      nowMs: NOW_MS,
      permitTtlSeconds: 120,
      stalenessBound: bounded(30),
      stateObservedAtMs: NOW_MS,
    });
    expect(skewed).toEqual(onTime);
    expect(skewed).toMatchObject({ validUntilMs: NOW_MS + 30_000 });
  });

  it("reports elapsed rather than an expired positive deadline when the bound is already reached", () => {
    // The observation aged past its class bound while evaluation ran: there
    // is no window left to issue a permit inside, so the caller denies.
    expect(
      permitDeadline({
        nowMs: NOW_MS,
        permitTtlSeconds: 120,
        stalenessBound: bounded(30),
        stateObservedAtMs: NOW_MS - 30_000,
      }),
    ).toEqual({ kind: "elapsed", source: "state_view" });
  });

  it("never returns a NaN deadline for a non-finite input", () => {
    for (const input of [
      { nowMs: Number.NaN, permitTtlSeconds: 120, stalenessBound: bounded(30) },
      { nowMs: NOW_MS, permitTtlSeconds: Number.NaN, stalenessBound: bounded(30) },
      { nowMs: NOW_MS, permitTtlSeconds: 120, stalenessBound: bounded(Number.NaN) },
      { nowMs: NOW_MS, permitTtlSeconds: 120, stalenessBound: bounded(30), stateObservedAtMs: Number.NaN },
      { nowMs: NOW_MS, permitTtlSeconds: 120, stalenessBound: bounded(30), ceilings: [{ name: "authority", atMs: Number.NaN }] },
      { nowMs: NOW_MS, permitTtlSeconds: 120, stalenessBound: { kind: "undeclared" as const } },
    ]) {
      const deadline = permitDeadline(input);
      expect(deadline.kind, JSON.stringify(input)).toBe("elapsed");
    }
  });

  it("takes the tightest of the named ceilings #594 W4-13 extends it with", () => {
    // W4-13 adds authority, credential and policy ceilings by pushing entries
    // here, so the winning source stays reportable and there is no competing
    // calculation to reconcile.
    expect(
      permitDeadline({
        nowMs: NOW_MS,
        permitTtlSeconds: 300,
        stalenessBound: bounded(300),
        stateObservedAtMs: NOW_MS,
        ceilings: [
          { name: "credential_expiry", atMs: NOW_MS + 45_000 },
          { name: "authority_expiry", atMs: NOW_MS + 90_000 },
        ],
      }),
    ).toMatchObject({ source: "credential_expiry", validUntilMs: NOW_MS + 45_000 });
  });
});

describe("execution lease derivation (@spec runtime#execution-reverification)", () => {
  it("takes the published maximum when the permit outlives it", () => {
    expect(
      executionLeaseMs({ nowMs: NOW_MS, publishedMaxSeconds: 30, permitValidUntilMs: NOW_MS + 120_000 }),
    ).toBe(30_000);
  });

  it("caps the published maximum by the permit's remaining validity, so a lease never extends authorization", () => {
    expect(
      executionLeaseMs({ nowMs: NOW_MS, publishedMaxSeconds: 30, permitValidUntilMs: NOW_MS + 8_000 }),
    ).toBe(8_000);
  });

  it("yields no lease at all rather than a NaN or negative one", () => {
    expect(executionLeaseMs({ nowMs: NOW_MS, publishedMaxSeconds: 30, permitValidUntilMs: NOW_MS - 1 })).toBe(0);
    // Supplied but unparseable bounds nothing, so it is not silently ignored
    // in favour of the published maximum (the pre-effect check already
    // refuses such a permit before a lease is ever derived from it).
    expect(executionLeaseMs({ nowMs: NOW_MS, publishedMaxSeconds: 30, permitValidUntilMs: Number.NaN })).toBe(0);
    expect(executionLeaseMs({ nowMs: NOW_MS, publishedMaxSeconds: undefined, permitValidUntilMs: undefined })).toBe(0);
    expect(executionLeaseMs({ nowMs: Number.NaN, publishedMaxSeconds: 30, permitValidUntilMs: NOW_MS })).toBe(0);
  });
});
