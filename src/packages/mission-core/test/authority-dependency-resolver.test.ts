/**
 * @spec runtime#input-authority-dependency (#830, D798, D813 review): the
 * identity-state resolver keeps an observation's own time and never lets an
 * older read replace a newer one.
 *
 * "Freshness stays attached to the underlying observation": a read's
 * observation represents the source as of the moment the read was issued, so
 * a slow read does not give old state a fresh validity. Reads that overlap (a
 * scheduled refresh and a reconciliation pass) are ordered by issue: a newer
 * read establishing a withdrawal is not undone by an older read completing
 * after it, while reads completing in issue order publish in that order.
 */

import { describe, expect, it } from "vitest";
import {
  type AuthorityDependencyDeclaration,
  AuthorityDependencyResolver,
  evaluateAuthorityDependency,
  type IdentityStateRecord,
} from "../src/authority-dependency.js";

const declaration = {
  max_staleness_seconds: 300,
  online_check: false,
  invalidating_changes: ["subject_disabled", "subject_deprovisioned", "delegation_withdrawn"],
} as AuthorityDependencyDeclaration;
const principal = { iss: "https://as.test", sub: "alice" };
const active: IdentityStateRecord[] = [
  { sub: "alice", status: "active", withdrawn_delegations: [] },
];
const withdrawn: IdentityStateRecord[] = [
  { sub: "alice", status: "active", withdrawn_delegations: ["client"] },
];

/** A resolver whose reads the test completes by hand, in any order, on a clock it drives. */
function deferred() {
  let now = 0;
  const completions: Array<(v: unknown) => void> = [];
  const failures: Array<(e: Error) => void> = [];
  const resolver = new AuthorityDependencyResolver({
    issuer: principal.iss,
    read: () =>
      new Promise((resolve, reject) => {
        completions.push(resolve);
        failures.push(reject);
      }),
    parse: (raw) => raw as IdentityStateRecord[],
    now: () => now,
  });
  return {
    resolver,
    complete: (i: number, records: unknown) => completions[i]?.(records),
    fail: (i: number) => failures[i]?.(new Error("identity source unreachable")),
    at: (ms: number) => {
      now = ms;
    },
    evaluate: () =>
      evaluateAuthorityDependency(declaration, resolver.view(principal), {
        clientId: "client",
        nowMs: now,
      }),
  };
}

describe("the identity-state resolver orders overlapping reads and keeps each observation's own time (@spec runtime#input-authority-dependency, #830)", () => {
  it("does not let an older read completing late replace a newer read's known withdrawal", async () => {
    const d = deferred();
    const older = d.resolver.refresh();
    d.at(1000);
    const newer = d.resolver.refresh();
    d.complete(1, withdrawn);
    await newer;
    expect(d.evaluate()).toMatchObject({ ok: false, failure: "withdrawn" });
    d.at(2000);
    d.complete(0, active);
    expect(await older).toBe(true);
    expect(d.evaluate()).toMatchObject({ ok: false, failure: "withdrawn" });
    expect(d.resolver.observedAtMs()).toBe(1000);
  });

  it("publishes reads that complete in issue order in that order, the newer last", async () => {
    const d = deferred();
    const older = d.resolver.refresh();
    d.at(1000);
    const newer = d.resolver.refresh();
    d.complete(0, active);
    await older;
    expect(d.evaluate()).toMatchObject({ ok: true });
    expect(d.resolver.observedAtMs()).toBe(0);
    d.complete(1, withdrawn);
    await newer;
    expect(d.evaluate()).toMatchObject({ ok: false, failure: "withdrawn" });
    expect(d.resolver.observedAtMs()).toBe(1000);
  });

  it("dates an observation from when its read was issued, so a slow read does not renew an old state's validity", async () => {
    const d = deferred();
    const slow = d.resolver.refresh();
    d.at(301_000);
    d.complete(0, active);
    await slow;
    expect(d.resolver.observedAtMs()).toBe(0);
    expect(d.evaluate()).toMatchObject({ ok: false, failure: "stale" });
  });

  it("reports the source's availability from the latest-issued read that completed, not the last to complete", async () => {
    const d = deferred();
    const first = d.resolver.refresh();
    d.complete(0, active);
    await first;
    const older = d.resolver.refresh();
    const newer = d.resolver.refresh();
    d.complete(2, active);
    await newer;
    d.fail(1);
    expect(await older).toBe(false);
    expect(d.resolver.view(principal).sourceAvailable).toBe(true);
  });
});
