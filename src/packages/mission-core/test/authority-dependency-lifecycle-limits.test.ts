/**
 * @spec runtime#input-authority-dependency (#830, D798; owner review of
 * #1695): under lifecycle-only enforcement the declared observation limits
 * still hold. The Runtime's refusal and permit-cap rules apply whatever the
 * route, so reliance on the observation the last complete reconciliation
 * acted on stops once it is older than `max_staleness_seconds`, a failed
 * latest read refuses where the declaration requires an online check, and a
 * permit's ceiling is the earlier of the staleness and lag deadlines, measured
 * from the time that observation represents.
 */

import { describe, expect, it } from "vitest";
import {
  type AuthorityDependencyDeclaration,
  AuthorityDependencyEvidence,
  AuthorityDependencyResolver,
  checkAuthorityDependency,
  type IdentityStateRecord,
  parseAuthorityDependencyDeclarations,
} from "../src/authority-dependency.js";

const ISSUER = "https://as.test";

/** A lifecycle-only declaration (no direct evaluation) with a 60 s reconciliation lag bound. */
function declaration(online: boolean, stalenessSeconds: number): AuthorityDependencyDeclaration {
  return parseAuthorityDependencyDeclarations([
    {
      id: "test",
      dependency: "The Subject retains the delegation",
      source: { id: "identity", description: "identity source" },
      observation: "account state",
      governs: { authority_sources: ["user_delegated"], scope: "existing actions" },
      invalidating_changes: ["subject_disabled"],
      max_staleness_seconds: stalenessSeconds,
      online_check: online,
      enforcement: {
        lifecycle: true,
        reconciliation_max_lag_seconds: 60,
        lifecycle_operations: { subject_disabled: "suspend" },
      },
      recovery: "reconcile",
      responsibility_transfer: "authorized handover",
    },
  ])[0] as AuthorityDependencyDeclaration;
}

/** The reconciliation completed on an observation representing t = 0; the clock and the source are the test's. */
async function setup(online: boolean, stalenessSeconds: number) {
  let now = 0;
  let available = true;
  const evidence = new AuthorityDependencyEvidence();
  const resolver = new AuthorityDependencyResolver({
    issuer: ISSUER,
    now: () => now,
    read: async () => {
      if (!available) throw new Error("identity source unreachable");
      return [{ sub: "alice", status: "active", withdrawn_delegations: [] }];
    },
    parse: (raw) => raw as IdentityStateRecord[],
  });
  await resolver.refresh();
  const enforcement = {
    declaration: declaration(online, stalenessSeconds),
    resolver,
    evidence,
    now: () => now,
    governed: () => ({ subject: { iss: ISSUER, sub: "alice" }, clientId: "client" }),
    reconciliation: () => ({ lastReconciledAtMs: 0, unresolved: new Set<string>() }),
  };
  return {
    resolver,
    evidence,
    at: (ms: number) => {
      now = ms;
    },
    offline: () => {
      available = false;
    },
    check: () =>
      checkAuthorityDependency(
        enforcement,
        { id: "m", issuer: ISSUER },
        { enforcer: "pdp", action: "read" },
        { direct: false, lag: true },
      ),
  };
}

describe("lifecycle-only enforcement keeps the declaration's observation limits (@spec runtime#input-authority-dependency, #830)", () => {
  it("refuses unavailable on a failed latest read where the declaration requires an online check, though the reconciliation is current", async () => {
    const x = await setup(true, 300);
    expect(x.check().ok).toBe(true);
    x.at(1000);
    x.offline();
    expect(await x.resolver.refresh()).toBe(false);
    expect(x.check()).toMatchObject({ ok: false, failure: "unavailable" });
    expect(x.evidence.entries().at(-1)).toMatchObject({
      enforcer: "pdp",
      failure: "unavailable",
      observed_at: new Date(0).toISOString(),
    });
  });

  it("keeps relying through a failed read where no online check is declared, within the observation's validity", async () => {
    const x = await setup(false, 300);
    x.at(1000);
    x.offline();
    await x.resolver.refresh();
    expect(x.check()).toMatchObject({ ok: true });
  });

  it("refuses stale once the reconciliation's observation is older than max_staleness_seconds, though the lag bound is longer", async () => {
    const x = await setup(false, 1);
    expect(x.check().ok).toBe(true);
    x.at(999);
    expect(x.check().ok).toBe(true);
    x.at(1000);
    expect(x.check()).toMatchObject({ ok: false, failure: "stale" });
    x.at(2000);
    expect(x.check()).toMatchObject({ ok: false, failure: "stale" });
    expect(x.evidence.entries().at(-1)).toMatchObject({
      failure: "stale",
      observed_at: new Date(0).toISOString(),
    });
  });

  it("caps the permit at the earlier of the staleness and lag deadlines, measured from the time the reconciliation's observation represents", async () => {
    const shortStaleness = await setup(false, 30);
    shortStaleness.at(20_000);
    expect(shortStaleness.check()).toEqual({ ok: true, validUntilMs: 30_000 });
    const longStaleness = await setup(false, 300);
    longStaleness.at(20_000);
    expect(longStaleness.check()).toEqual({ ok: true, validUntilMs: 60_000 });
  });
});
