/**
 * @spec runtime#input-authority-dependency (#830, D798): direct evaluation of
 * a declared authority dependency at the PDP, composed into its
 * Resource-policy step.
 *
 * The declared dependency is the Mission Subject's continuing delegation to
 * the client acting under the Mission, observed in the configuration-backed
 * identity source by the identity-state resolver. The source and the clock
 * are controlled here: a withdrawal, a disabled or deprovisioned Subject, a
 * stale observation, an outage with a still-valid cached observation, an
 * online check, and no observation at all. Every refusal is the mechanism's
 * own `resource_policy`, and the deployment's dependency evidence keeps the
 * cause.
 */

import {
  type AuthorityDependencyDeclaration,
  type AuthorityDependencyEnforcement,
  AuthorityDependencyEvidence,
  AuthorityDependencyResolver,
  parseAuthorityDependencyDeclarations,
} from "@mission/core";
import { AUTHORITY_DEPENDENCIES, parseIdentityState } from "@mission/demo-data";
import { describe, expect, it } from "vitest";
import { evaluate as evaluateRequest, type EvaluateOptions, type EvaluationRequest } from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import type { MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { withCredential } from "./with-credential.js";

const evaluate = (req: EvaluationRequest, opts: EvaluateOptions) => evaluateRequest(withCredential(req), opts);

const RESOURCE = "http://localhost:4403/mcp";
const ISSUER = "https://as.test";
const T0 = Date.parse("2026-10-25T12:00:00Z");
const MISSION = "msn_dep_pdp";

/** The shipped declaration, routed to the PDP, with an online check where asked. */
function declaration(over: { direct?: "pdp" | "pep"; online_check?: boolean } = {}): AuthorityDependencyDeclaration {
  const shipped = AUTHORITY_DEPENDENCIES[0] as AuthorityDependencyDeclaration;
  const [parsed] = parseAuthorityDependencyDeclarations([
    {
      ...shipped,
      online_check: over.online_check ?? shipped.online_check,
      enforcement: { ...shipped.enforcement, direct: over.direct ?? "pdp" },
    },
  ]);
  return parsed as AuthorityDependencyDeclaration;
}

const view: MissionView = {
  id: MISSION,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:dep",
  authority_set: [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } }],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

const allowAll = { checkWithContext: async () => true } as unknown as Fga;

/**
 * A PDP deployment over a controlled identity source and clock: `source` is
 * what the next read returns, an Error for an outage; `at(seconds)` moves the
 * clock to T0 plus that many seconds.
 */
function deployment(decl: AuthorityDependencyDeclaration = declaration(), governs = (id: string) => id === MISSION) {
  let source: unknown = [{ sub: "alice" }, { sub: "bob" }];
  let nowMs = T0;
  const evidence = new AuthorityDependencyEvidence();
  const resolver = new AuthorityDependencyResolver({
    issuer: ISSUER,
    read: async () => {
      if (source instanceof Error) throw source;
      return source;
    },
    parse: (raw) => parseIdentityState(raw),
    now: () => nowMs,
  });
  const enforcement: AuthorityDependencyEnforcement = {
    declaration: decl,
    resolver,
    evidence,
    now: () => nowMs,
    governed: (mission) => (governs(mission.id) ? { subject: { iss: ISSUER, sub: "alice" }, clientId: "ap-agent" } : undefined),
  };
  const decide = (missionId = MISSION) => {
    const now = new Date(nowMs);
    const req: EvaluationRequest = {
      subject: { id: "alice", properties: { iss: ISSUER } },
      resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
      action: { name: "payments:invoice.read" },
      context: {
        mission: { id: missionId, issuer: ISSUER },
        actor: { client_id: "ap-agent" },
        mission_state_observation: { state: "active", mode: "fresh", freshness_at: now.toISOString() },
      },
    };
    return evaluate(req, {
      view: { ...view, id: missionId },
      fga: allowAll,
      modelId: "unit-test-model",
      now: () => now,
      stalenessBound,
      relationForAction,
      stateSourcePlacement: "pep",
      resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
      authorityDependency: enforcement,
    });
  };
  return {
    resolver,
    evidence,
    decide,
    set: (next: unknown) => {
      source = next;
    },
    at: (seconds: number) => {
      nowMs = T0 + seconds * 1000;
    },
    lastFailure: () => evidence.entries().at(-1)?.failure,
  };
}

/** The refusal this mechanism keeps: `resource_policy`, never a Mission-state code. */
function expectResourcePolicyRefusal(dec: { decision: boolean; context: Record<string, unknown> }, label: string): void {
  expect(dec.decision, label).toBe(false);
  expect(dec.context.denial_reason, label).toBe("resource_policy");
  expect(["stale_state", "state_unavailable", "mission_inactive"], label).not.toContain(dec.context.denial_reason);
}

describe("a declared authority dependency evaluated directly at the PDP (@spec runtime#input-authority-dependency, #830)", () => {
  it("permits while an observation within its bound shows the Subject active and the delegation held", async () => {
    const d = deployment();
    expect(await d.resolver.refresh()).toBe(true);
    const dec = await d.decide();
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    expect(d.evidence.entries()).toEqual([]);
  });

  it("refuses resource_policy on a known withdrawal of the delegation, and retains it as withdrawn", async () => {
    const d = deployment();
    d.set([{ sub: "alice", withdrawn_delegations: ["ap-agent"] }]);
    await d.resolver.refresh();
    expectResourcePolicyRefusal(await d.decide(), "withdrawn");
    expect(d.evidence.entries().at(-1)).toMatchObject({
      enforcer: "pdp",
      dependency: "subject-delegation",
      failure: "withdrawn",
      mission: { id: MISSION, issuer: ISSUER },
      subject: { iss: ISSUER, sub: "alice" },
      client: "ap-agent",
      action: "payments:invoice.read",
    });
  });

  it("refuses resource_policy on an observed invalidation: the Subject disabled, or deprovisioned", async () => {
    for (const status of ["disabled", "deprovisioned"] as const) {
      const d = deployment();
      d.set([{ sub: "alice", status }]);
      await d.resolver.refresh();
      expectResourcePolicyRefusal(await d.decide(), status);
      expect(d.lastFailure(), status).toBe("invalidated");
    }
  });

  it("refuses resource_policy once the observation is older than its bound, the source still answering: a stale observation", async () => {
    const d = deployment();
    await d.resolver.refresh();
    d.at(299);
    expect((await d.decide()).decision).toBe(true);
    d.at(300);
    expectResourcePolicyRefusal(await d.decide(), "stale");
    expect(d.lastFailure()).toBe("stale");
  });

  it("keeps serving through a source outage while the cached observation is within its validity, and refuses once no acceptable observation remains", async () => {
    const d = deployment();
    await d.resolver.refresh();
    d.set(new Error("identity source unreachable"));
    d.at(10);
    expect(await d.resolver.refresh()).toBe(false);
    d.at(200);
    const within = await d.decide();
    expect(within.decision, JSON.stringify(within.context)).toBe(true);
    d.at(300);
    expectResourcePolicyRefusal(await d.decide(), "outage past validity");
    expect(d.lastFailure()).toBe("unavailable");
  });

  it("refuses through an outage within the observation's validity where the declaration requires an online check", async () => {
    const d = deployment(declaration({ online_check: true }));
    await d.resolver.refresh();
    expect((await d.decide()).decision).toBe(true);
    d.set(new Error("identity source unreachable"));
    d.at(10);
    await d.resolver.refresh();
    expectResourcePolicyRefusal(await d.decide(), "online check");
    expect(d.lastFailure()).toBe("unavailable");
  });

  it("refuses resource_policy when no observation was ever acceptable: the source never answered", async () => {
    const d = deployment();
    d.set(new Error("identity source unreachable"));
    await d.resolver.refresh();
    expectResourcePolicyRefusal(await d.decide(), "never observed");
    expect(d.lastFailure()).toBe("unavailable");
  });

  it("issues a permit that expires no later than the observation's accepted validity", async () => {
    const d = deployment();
    await d.resolver.refresh();
    d.at(200);
    const dec = await d.decide();
    expect(dec.decision, JSON.stringify(dec.context)).toBe(true);
    // The observation represents T0, so its validity ends at T0 + 300 s,
    // before the permit's own 300 s lifetime from T0 + 200 s would.
    expect(Date.parse((dec.context.conditions as { valid_until: string }).valid_until)).toBe(T0 + 300_000);
  });

  it("retains each refusal's cause so a known withdrawal, a stale observation and an unavailable source stay distinguishable", async () => {
    const d = deployment();
    d.set([{ sub: "alice", withdrawn_delegations: ["ap-agent"] }]);
    await d.resolver.refresh();
    await d.decide();
    d.set([{ sub: "alice" }]);
    await d.resolver.refresh();
    d.at(300);
    await d.decide();
    d.set(new Error("identity source unreachable"));
    await d.resolver.refresh();
    await d.decide();
    expect(d.evidence.entries().map((e) => [e.enforcer, e.failure])).toEqual([
      ["pdp", "withdrawn"],
      ["pdp", "stale"],
      ["pdp", "unavailable"],
    ]);
  });

  it("evaluates only the Missions the declaration governs, and only where it routes direct evaluation to the PDP", async () => {
    const ungoverned = deployment(declaration(), () => false);
    ungoverned.set([{ sub: "alice", withdrawn_delegations: ["ap-agent"] }]);
    await ungoverned.resolver.refresh();
    expect((await ungoverned.decide()).decision).toBe(true);
    // Routed to a composed step at the PEP: the PDP permits within Mission authority.
    const routedToPep = deployment(declaration({ direct: "pep" }));
    routedToPep.set([{ sub: "alice", withdrawn_delegations: ["ap-agent"] }]);
    await routedToPep.resolver.refresh();
    expect((await routedToPep.decide()).decision).toBe(true);
    expect([...ungoverned.evidence.entries(), ...routedToPep.evidence.entries()]).toEqual([]);
  });
});
