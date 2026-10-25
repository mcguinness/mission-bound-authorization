/**
 * @spec runtime#input-authority-dependency (#830, D798): under
 * lifecycle-mediated enforcement, "A current `active` state does not show
 * that this reconciliation is current: when upstream observation or
 * reconciliation exceeds its declared bound, the deployment MUST refuse the
 * actions the dependency governs until it is current again."
 *
 * The PDP is given the reconciler's progress: the time the observation its
 * last complete pass acted on represents. While that progress is within the
 * declared lag bound the PDP decides as usual; past it, or before any pass
 * has completed, it refuses `resource_policy` while the Mission's state still
 * reads `active`, and the deployment's dependency evidence names the cause.
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
const MISSION = "msn_dep_lag";

/** The shipped declaration: lifecycle-mediated with a 60 s lag bound, with or without direct evaluation at the PDP. */
function declaration(direct: boolean): AuthorityDependencyDeclaration {
  const shipped = AUTHORITY_DEPENDENCIES[0] as AuthorityDependencyDeclaration;
  const { direct: _direct, ...lifecycleOnly } = shipped.enforcement;
  return parseAuthorityDependencyDeclarations([{ ...shipped, enforcement: direct ? shipped.enforcement : lifecycleOnly }])[0] as AuthorityDependencyDeclaration;
}

const view: MissionView = {
  id: MISSION,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: "sha-256:lag",
  authority_set: [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } }],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
};

function deployment(direct: boolean) {
  let nowMs = T0;
  let lastReconciledAtMs: number | undefined;
  const evidence = new AuthorityDependencyEvidence();
  const resolver = new AuthorityDependencyResolver({
    issuer: ISSUER,
    read: async () => [{ sub: "alice" }],
    parse: (raw) => parseIdentityState(raw),
    now: () => nowMs,
  });
  const enforcement: AuthorityDependencyEnforcement = {
    declaration: declaration(direct),
    resolver,
    evidence,
    now: () => nowMs,
    reconciliation: () => (lastReconciledAtMs !== undefined ? { lastReconciledAtMs } : {}),
    governed: (mission) => (mission.id === MISSION ? { subject: { iss: ISSUER, sub: "alice" }, clientId: "ap-agent" } : undefined),
  };
  const decide = () => {
    const now = new Date(nowMs);
    return evaluate(
      {
        subject: { id: "alice", properties: { iss: ISSUER } },
        resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, operation_target: RESOURCE, vendor_id: "acme" } },
        action: { name: "payments:invoice.read" },
        context: {
          mission: { id: MISSION, issuer: ISSUER },
          actor: { client_id: "ap-agent" },
          // Mission Status reports the Mission `active`, freshly.
          mission_state_observation: { state: "active", mode: "fresh", freshness_at: now.toISOString() },
        },
      },
      {
        view,
        fga: { checkWithContext: async () => true } as unknown as Fga,
        modelId: "unit-test-model",
        now: () => now,
        stalenessBound,
        relationForAction,
        stateSourcePlacement: "pep",
        resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
        authorityDependency: enforcement,
      },
    );
  };
  return {
    resolver,
    evidence,
    decide,
    reconciled: (seconds: number) => {
      lastReconciledAtMs = T0 + seconds * 1000;
    },
    at: (seconds: number) => {
      nowMs = T0 + seconds * 1000;
    },
  };
}

describe("an overdue reconciliation stops dependent execution while the Mission still reads active (@spec runtime#input-authority-dependency, #830)", () => {
  it("permits while the last complete reconciliation is within the lag bound, refuses resource_policy once it is overdue with the Mission still active, and permits again once a reconciliation completes", async () => {
    const d = deployment(false);
    d.reconciled(0);
    d.at(59);
    const within = await d.decide();
    expect(within.decision, JSON.stringify(within.context)).toBe(true);
    // A permit relying on the reconciliation expires when the lag bound would refuse it.
    expect(Date.parse((within.context.conditions as { valid_until: string }).valid_until)).toBe(T0 + 60_000);
    d.at(60);
    const overdue = await d.decide();
    expect(overdue.decision, JSON.stringify(overdue.context)).toBe(false);
    expect(overdue.context.denial_reason).toBe("resource_policy");
    expect(view.state).toBe("active");
    expect(d.evidence.entries().at(-1)).toMatchObject({
      enforcer: "pdp",
      failure: "reconciliation_overdue",
      mission: { id: MISSION },
      observed_at: new Date(T0).toISOString(),
    });
    // Current again: a reconciliation completes on a fresh observation.
    d.reconciled(60);
    expect((await d.decide()).decision).toBe(true);
  });

  it("refuses before any reconciliation has completed: a reconciler that never ran, or lost its progress in a restart, fails closed", async () => {
    const d = deployment(false);
    const dec = await d.decide();
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("resource_policy");
    expect(d.evidence.entries().at(-1)?.failure).toBe("reconciliation_overdue");
  });

  it("refuses an overdue reconciliation where the PDP also evaluates the dependency directly, though the observation shows the delegation held", async () => {
    const d = deployment(true);
    await d.resolver.refresh();
    d.reconciled(-61);
    const dec = await d.decide();
    expect(dec.decision).toBe(false);
    expect(dec.context.denial_reason).toBe("resource_policy");
    expect(d.evidence.entries().at(-1)?.failure).toBe("reconciliation_overdue");
    d.reconciled(0);
    const permit = await d.decide();
    expect(permit.decision).toBe(true);
    // Capped at the earlier of the observation's validity (T0 + 300 s) and the reconciliation's currency (T0 + 60 s).
    expect(Date.parse((permit.context.conditions as { valid_until: string }).valid_until)).toBe(T0 + 60_000);
  });
});
