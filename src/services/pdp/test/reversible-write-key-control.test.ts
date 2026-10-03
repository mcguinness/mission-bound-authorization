/**
 * @spec runtime#permit-binding, runtime#idempotency (#918): the reversible
 * consequential write's "short validity window combined with an idempotency
 * key" permit-lifetime control, as this PDP reads and enforces it.
 *
 * The Enforcement Scope Statement declares which operations elect the
 * control and the retention posture their keys get outside the
 * high-consequence classes. The statement is refused at load when a
 * declaration names no resolvable retention longer than the permit, an owner
 * that is not a PEP location, a scope that is not the fixed-member one, or a
 * class other than the reversible write. At decision time the PDP makes no
 * claim for the key (the enforcing PEP reserves it), and refuses a request
 * for a declared operation that carries no well-formed key, so its permit is
 * never the validity window alone.
 *
 * Unconditional: a stub `Fga` satisfies the one method evaluate() calls.
 */

import { describe, expect, it } from "vitest";
import {
  type EnforcementScopeStatement,
  reversibleWriteDeclarationFor,
  reversibleWriteRetentionSeconds,
  validateEnforcementScopeStatement,
} from "../src/enforcement-scope.js";
import type { Fga } from "../src/fga.js";
import { evaluate, type EvaluationRequest, type MissionView, relationForAction, stalenessBound } from "../src/index.js";
import {
  loadRuntimePosture,
  PostureConfigError,
  reversibleWritePermitMaxSeconds,
  RUNTIME_POSTURE,
  type RuntimePosture,
} from "../src/runtime-posture.js";

const RESOURCE = "http://localhost:4403/mcp";
const NOW = new Date("2026-10-02T12:00:00Z");
const KEY = "idem_reversible-write-key-1";
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const view: MissionView = {
  id: "msn_918",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:m918",
  authority_set: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:payment.schedule", "payments:payment.schedule.cancel", "payments:payment.execute"],
    },
  ],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
};

const request = (action: string, key?: unknown): EvaluationRequest => ({
  subject: { id: "alice", properties: { iss: "https://as.test" } },
  resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, vendor_id: "acme" } },
  action: { name: action, ...(key !== undefined ? { properties: { idempotency_key: key as string } } : {}) },
  context: {
    mission: { id: "msn_918", issuer: "https://as.test", authority_hash: "sha-256:m918" },
    action_class: "consequential_write",
    parameter_digest: "sha-256:params-918",
    freshness: { observed_at: NOW.toISOString(), source: "status" },
    actor: { client_id: "ap-agent" },
  },
});

/** No claim is made for this control: a claim domain that is reached fails the test. */
const unreachableClaims = {
  declares: () => {
    throw new Error("the reversible-write key control reached the PDP claim domain");
  },
  claim: () => {
    throw new Error("the reversible-write key control reached the PDP claim domain");
  },
};

const opts = {
  view,
  fga: alwaysAllowFga,
  modelId: "unit-test-model",
  now: () => NOW,
  stalenessBound,
  relationForAction,
  allowedFreshnessSources: new Set(["status"]),
  claims: unreachableClaims as never,
};

/** The shipped statement with its reversible-write declarations replaced. */
const withDeclarations = (edit: (decls: Array<Record<string, unknown>>) => void): EnforcementScopeStatement => {
  const statement = structuredClone(RUNTIME_POSTURE) as unknown as EnforcementScopeStatement & {
    extensions: { reversible_write_idempotency: Array<Record<string, unknown>> };
  };
  edit(statement.extensions.reversible_write_idempotency);
  return statement;
};
const findingsFor = (edit: (decls: Array<Record<string, unknown>>) => void) =>
  validateEnforcementScopeStatement(withDeclarations(edit)).map((f) => f.problem);

describe("the reversible-write key control the statement declares (@spec runtime#permit-binding, #918)", () => {
  it("the statement this PDP loads publishes, for every keyed operation outside the high-consequence classes, its reservation owner and a retention longer than the permit", () => {
    const declared = RUNTIME_POSTURE.extensions?.reversible_write_idempotency ?? [];
    expect(declared.map((d) => d.mediated_class_or_scope).sort()).toEqual([
      "payments:payment.schedule",
      "payments:payment.schedule.cancel",
    ]);
    for (const d of declared) {
      expect(d.permit_lifetime_control).toBe("validity_window_plus_idempotency_key");
      expect(d.retention_posture).toBe("declared_horizon");
      expect(reversibleWriteRetentionSeconds(RUNTIME_POSTURE, d)).toBe(604800);
      expect(reversibleWriteRetentionSeconds(RUNTIME_POSTURE, d)).toBeGreaterThan(d.permit_validity_max_seconds);
      expect(RUNTIME_POSTURE.mediated_scope.pep_locations).toContain(d.reservation_owner);
    }
    // A statement naming no retention posture for such a key is refused at load.
    const unpublished = withDeclarations((decls) => {
      delete decls[0]?.retention_posture;
    });
    expect(() => loadRuntimePosture(unpublished)).toThrow(PostureConfigError);
  });

  it("refuses a declaration whose retention is not longer than the permit, whose owner is not a PEP location, whose scope is not the fixed-member one, or that covers another class", () => {
    expect(validateEnforcementScopeStatement(RUNTIME_POSTURE)).toEqual([]);
    expect(findingsFor((d) => void (d[0] && (d[0].retention_horizon = "PT5M")))).toContain(
      "the 300s retention is not longer than the 300s permit window",
    );
    expect(findingsFor((d) => void (d[0] && (d[0].retention_horizon = "P1M")))).toContain(
      "retention_horizon must be an ISO 8601 duration of days or below",
    );
    expect(findingsFor((d) => void (d[0] && (d[0].reservation_owner = "mcp-payments-pdp")))).toContain(
      'reservation_owner "mcp-payments-pdp" is not a declared mediated_scope.pep_locations entry',
    );
    const scopeProblem = "idempotency_scope must name each of mission, subject, actor, audience, action, resource, phase once, and no volatile member";
    expect(findingsFor((d) => void (d[0] && ((d[0].idempotency_scope as string[]).push("client_instance_id"))))).toContain(scopeProblem);
    expect(findingsFor((d) => void (d[0] && (d[0].idempotency_scope = ["mission", "action", "resource"])))).toContain(scopeProblem);
    expect(findingsFor((d) => void (d[0] && (d[0].mediated_class_or_scope = "irreversible_action")))).toContain(
      'mediated_class_or_scope "irreversible_action" is neither consequential_write nor an action identifier inside it',
    );
    expect(findingsFor((d) => void (d[0] && (d[0].permit_lifetime_control = "single_use")))).toContain(
      "permit_lifetime_control must be validity_window_plus_idempotency_key",
    );
  });

  it("covers exactly the operations it names, or the whole reversible-write class when it names the class, and never a high-consequence class", () => {
    expect(reversibleWriteDeclarationFor(RUNTIME_POSTURE, "consequential_write", "payments:payment.schedule")).toBeDefined();
    expect(reversibleWriteDeclarationFor(RUNTIME_POSTURE, "consequential_write", "payments:payment.schedule.cancel")).toBeDefined();
    // The prepare-phase hold shares the class and elects no key control.
    expect(reversibleWriteDeclarationFor(RUNTIME_POSTURE, "consequential_write", "payments:payment.execute")).toBeUndefined();
    expect(reversibleWriteDeclarationFor(RUNTIME_POSTURE, "irreversible_action", "payments:payment.schedule")).toBeUndefined();
    const classWide = withDeclarations((d) => {
      d.splice(1);
      if (d[0]) d[0].mediated_class_or_scope = "consequential_write";
    });
    expect(validateEnforcementScopeStatement(classWide)).toEqual([]);
    expect(reversibleWriteDeclarationFor(classWide, "consequential_write", "payments:payment.execute")).toBeDefined();
  });
});

describe("the PDP refuses a declared reversible write that carries no idempotency key (@spec runtime#permit-binding, #918)", () => {
  it("without a well-formed key a declared operation is refused parameter_violation; with one it is permitted under the short validity window, no use limit, and no claim", async () => {
    for (const action of ["payments:payment.schedule", "payments:payment.schedule.cancel"]) {
      for (const bad of [undefined, "short", 42, "has spaces in it!!!!"]) {
        const denied = await evaluate(request(action, bad), opts);
        expect(denied.decision, `${action} ${String(bad)}`).toBe(false);
        expect(denied.context.denial_reason).toBe("parameter_violation");
      }
      const permit = await evaluate(request(action, KEY), opts);
      expect(permit.decision, action).toBe(true);
      const conditions = permit.context.conditions as { valid_until: string; use_limit?: number };
      expect(conditions.use_limit).toBeUndefined();
      const windowMs = Date.parse(conditions.valid_until) - NOW.getTime();
      expect(windowMs).toBeGreaterThan(0);
      expect(windowMs).toBeLessThanOrEqual(300_000);
    }
  });

  it("caps the permit at the operation's published permit_validity_max_seconds: 30 s under a 30 s maximum, and the shipped 300 s posture is unchanged", async () => {
    const short = withDeclarations((decls) => {
      for (const d of decls) {
        d.permit_validity_max_seconds = 30;
        d.retention_horizon = "PT60S";
      }
    }) as unknown as RuntimePosture;
    // A valid statement: the retention is still longer than the permit.
    expect(validateEnforcementScopeStatement(short)).toEqual([]);
    expect(() => loadRuntimePosture(short)).not.toThrow();
    const capped = await evaluate(request("payments:payment.schedule", KEY), {
      ...opts,
      reversibleWritePermitMaxSeconds: (c: string | undefined, a: string) => reversibleWritePermitMaxSeconds(short, c, a),
    });
    expect(capped.decision).toBe(true);
    const cappedUntil = (capped.context.conditions as { valid_until: string }).valid_until;
    expect(Date.parse(cappedUntil) - NOW.getTime()).toBeLessThanOrEqual(30_000);
    expect(Date.parse(cappedUntil) - NOW.getTime()).toBeGreaterThan(0);

    const shipped = await evaluate(request("payments:payment.schedule", KEY), opts);
    const shippedUntil = (shipped.context.conditions as { valid_until: string }).valid_until;
    expect(Date.parse(shippedUntil) - NOW.getTime()).toBe(300_000);
  });
});
