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
 * Each declaration is one variant of `permit_lifetime_control` (#1080, D333):
 * the key control above, or `single_use_decision_identifier`, which the
 * statement publishes as the `consequential_write` class default. The most
 * specific declaration is selected before any variant is considered.
 *
 * Unconditional: a stub `Fga` satisfies the one method evaluate() calls.
 */

import { describe, expect, it } from "vitest";
import {
  type EnforcementScopeStatement,
  reversibleWriteControlFor,
  reversibleWriteDeclarationFor,
  type ReversibleWriteIdempotencyDeclaration,
  reversibleWriteRetentionSeconds,
  validateEnforcementScopeStatement,
} from "../src/enforcement-scope.js";
import type { Fga } from "../src/fga.js";
import { evaluate as evaluateRequest, type EvaluationRequest, type MissionView, relationForAction, stalenessBound } from "../src/index.js";
import {
  loadRuntimePosture,
  PostureConfigError,
  reversibleWritePermitMaxSeconds,
  RUNTIME_POSTURE,
  type RuntimePosture,
} from "../src/runtime-posture.js";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "../src/test-support.js";
import { withCredential } from "./with-credential.js";

// Every decision carries the credential's own authority (#825 PR 2b); the
// fixture adds a neutral one where a test does not name it.
const evaluate = (req: EvaluationRequest, opts: Parameters<typeof evaluateRequest>[1]) =>
  evaluateRequest(withCredential(req), opts);

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
    mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
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
  resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE,
  stateSourcePlacement: "pep" as const,
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
/** The statement's idempotency-key declarations, the D333 key variant. */
const keyDeclarations = (stmt: EnforcementScopeStatement): ReversibleWriteIdempotencyDeclaration[] =>
  (stmt.extensions?.reversible_write_idempotency ?? []).filter(
    (d): d is ReversibleWriteIdempotencyDeclaration => d.permit_lifetime_control === "validity_window_plus_idempotency_key",
  );
const KEY_CONTROL = "validity_window_plus_idempotency_key";
const SINGLE_USE = "single_use_decision_identifier";
/** The shipped class default (D333), a single-use declaration. */
const SINGLE_USE_DEFAULT = {
  mediated_class_or_scope: "consequential_write",
  permit_lifetime_control: SINGLE_USE,
  consumed_identifier_domain: "pep-local: mcp-payments-pep, durable single-writer SQLite",
  consumed_identifier_owner: "mcp-payments-pep",
  retention_posture: "permit_acceptance_window",
};

describe("the reversible-write key control the statement declares (@spec runtime#permit-binding, #918)", () => {
  it("the statement this PDP loads publishes, for every keyed operation outside the high-consequence classes, its reservation owner and a retention longer than the permit", () => {
    const declared = keyDeclarations(RUNTIME_POSTURE);
    expect(declared.map((d) => d.mediated_class_or_scope).sort()).toEqual([
      "payments:payment.schedule",
      "payments:payment.schedule.cancel",
    ]);
    for (const d of declared) {
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
      "permit_lifetime_control must be validity_window_plus_idempotency_key or single_use_decision_identifier",
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

describe("the statement's permit-lifetime controls, discriminated on permit_lifetime_control (@spec runtime#permit-binding, runtime#single-use-identifiers, #1080, D333)", () => {
  it("publishes single_use_decision_identifier as the consequential_write class default, with its consumed-identifier owner, domain and permit_acceptance_window posture and no key member, while the schedule and cancel entries keep the key control", () => {
    const declared = RUNTIME_POSTURE.extensions?.reversible_write_idempotency ?? [];
    expect(declared.map((d) => [d.mediated_class_or_scope, d.permit_lifetime_control])).toEqual([
      ["payments:payment.schedule", KEY_CONTROL],
      ["payments:payment.schedule.cancel", KEY_CONTROL],
      ["consequential_write", SINGLE_USE],
    ]);
    // Exactly the single-use members: no reservation, key scope, key window or horizon.
    expect(declared.find((d) => d.mediated_class_or_scope === "consequential_write")).toEqual(SINGLE_USE_DEFAULT);
    expect(RUNTIME_POSTURE.mediated_scope.pep_locations).toContain(SINGLE_USE_DEFAULT.consumed_identifier_owner);
    // The prepare-phase hold resolves to the default; the keyed writes to their own entries.
    expect(reversibleWriteControlFor(RUNTIME_POSTURE, "consequential_write", "payments:payment.execute")).toEqual(SINGLE_USE_DEFAULT);
    for (const action of ["payments:payment.schedule", "payments:payment.schedule.cancel"]) {
      expect(reversibleWriteControlFor(RUNTIME_POSTURE, "consequential_write", action)?.permit_lifetime_control).toBe(KEY_CONTROL);
    }
    expect(reversibleWriteControlFor(RUNTIME_POSTURE, "irreversible_action", "payments:payment.execute")).toBeUndefined();
  });

  it("selects the most specific declaration before the class default, and returns a key declaration only when that selection is the key control: a less-specific key default never covers an operation that elects single use", async () => {
    // A class-wide key default, and one operation that elects single use.
    const [schedule] = keyDeclarations(RUNTIME_POSTURE);
    const mixed = withDeclarations((d) => {
      d.splice(0, d.length, { ...schedule, mediated_class_or_scope: "consequential_write" }, {
        ...SINGLE_USE_DEFAULT,
        mediated_class_or_scope: "payments:payment.execute",
      });
    });
    expect(validateEnforcementScopeStatement(mixed)).toEqual([]);
    expect(reversibleWriteControlFor(mixed, "consequential_write", "payments:payment.execute")?.permit_lifetime_control).toBe(SINGLE_USE);
    expect(reversibleWriteDeclarationFor(mixed, "consequential_write", "payments:payment.execute")).toBeUndefined();
    expect(reversibleWriteDeclarationFor(mixed, "consequential_write", "payments:payment.schedule")?.mediated_class_or_scope).toBe(
      "consequential_write",
    );
    // So the PDP issues that operation a single-use permit with no key, and
    // still refuses a keyless request for an operation the key default covers.
    const mixedOpts = {
      ...opts,
      reversibleWritePermitMaxSeconds: (c: string | undefined, a: string) =>
        reversibleWritePermitMaxSeconds(mixed as RuntimePosture, c, a),
    };
    const hold = await evaluate(request("payments:payment.execute"), mixedOpts);
    expect(hold.decision).toBe(true);
    expect((hold.context.conditions as { use_limit?: number }).use_limit).toBe(1);
    expect((await evaluate(request("payments:payment.schedule"), mixedOpts)).context.denial_reason).toBe("parameter_violation");

    // The shipped statement, the other way round: the operations' key entries
    // win over the single-use class default.
    expect(reversibleWriteDeclarationFor(RUNTIME_POSTURE, "consequential_write", "payments:payment.schedule")?.mediated_class_or_scope).toBe(
      "payments:payment.schedule",
    );
    expect(reversibleWriteDeclarationFor(RUNTIME_POSTURE, "consequential_write", "payments:payment.execute")).toBeUndefined();
  });

  it("refuses an invalid or ambiguous declaration: a key member on a single-use entry, a single-use member on a key entry, a missing single-use member, the other variant's retention posture, an owner outside the PEP locations, an unknown control, and a class or operation declared twice", () => {
    const single = (d: Array<Record<string, unknown>>) => d.find((x) => x.permit_lifetime_control === SINGLE_USE) as Record<string, unknown>;
    const keyMembers: Record<string, unknown> = {
      reservation_domain: "pep-local: mcp-payments-pep, durable single-writer SQLite",
      reservation_owner: "mcp-payments-pep",
      idempotency_scope: ["mission", "subject", "actor", "audience", "action", "resource", "phase"],
      permit_validity_max_seconds: 300,
      retention_horizon: "P7D",
    };
    for (const [name, value] of Object.entries(keyMembers)) {
      expect(findingsFor((d) => void (single(d)[name] = value)), name).toContain(
        `a single_use_decision_identifier declaration names no ${name}`,
      );
    }
    for (const name of ["consumed_identifier_owner", "consumed_identifier_domain"]) {
      expect(findingsFor((d) => void (d[0] && (d[0][name] = "mcp-payments-pep"))), name).toContain(
        `a validity_window_plus_idempotency_key declaration names no ${name}`,
      );
    }
    expect(findingsFor((d) => void delete single(d).consumed_identifier_owner)).toContain(
      "missing the consumed_identifier_owner that holds the consumed identifiers",
    );
    expect(findingsFor((d) => void delete single(d).consumed_identifier_domain)).toContain(
      "missing the consumed-identifier domain and the component that holds it",
    );
    expect(findingsFor((d) => void (single(d).consumed_identifier_owner = "mcp-payments-pdp"))).toContain(
      'consumed_identifier_owner "mcp-payments-pdp" is not a declared mediated_scope.pep_locations entry',
    );
    expect(findingsFor((d) => void (single(d).retention_posture = "declared_horizon"))).toContain(
      "a single_use_decision_identifier declaration's retention_posture must be permit_acceptance_window",
    );
    expect(findingsFor((d) => void (d[0] && (d[0].retention_posture = "permit_acceptance_window")))).toContain(
      "retention_posture must be declared_horizon or reconciliation_window",
    );
    expect(findingsFor((d) => void (single(d).permit_lifetime_control = "single_use"))).toContain(
      "permit_lifetime_control must be validity_window_plus_idempotency_key or single_use_decision_identifier",
    );
    // Two declarations for one target are ambiguous, whichever controls they name.
    expect(findingsFor((d) => void d.push({ ...SINGLE_USE_DEFAULT }))).toContain(
      'mediated_class_or_scope "consequential_write" is declared twice',
    );
    expect(findingsFor((d) => void d.push({ ...SINGLE_USE_DEFAULT, mediated_class_or_scope: "payments:payment.schedule" }))).toContain(
      'mediated_class_or_scope "payments:payment.schedule" is declared twice',
    );
    // And the loader refuses each such statement.
    const invalid = withDeclarations((d) => void (single(d).retention_horizon = "P7D"));
    expect(() => loadRuntimePosture(invalid)).toThrow(PostureConfigError);
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
      for (const d of decls.filter((x) => x.permit_lifetime_control === KEY_CONTROL)) {
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

describe("a reversible write that elects no key control defaults to single use (@spec runtime#permit-binding, #1080)", () => {
  it("the prepare-phase hold (payments:payment.execute, no key control) is permitted with use_limit: 1, with or without a key, and no claim; a keyed write carries none; a class-wide key control removes the default", async () => {
    for (const k of [undefined, KEY]) {
      const permit = await evaluate(request("payments:payment.execute", k), opts);
      expect(permit.decision, String(k)).toBe(true);
      const conditions = permit.context.conditions as { valid_until: string; use_limit?: number };
      expect(conditions.use_limit).toBe(1);
      expect(Date.parse(conditions.valid_until)).toBeGreaterThan(NOW.getTime());
    }
    for (const action of ["payments:payment.schedule", "payments:payment.schedule.cancel"]) {
      const keyed = await evaluate(request(action, KEY), opts);
      expect(keyed.decision, action).toBe(true);
      expect((keyed.context.conditions as { use_limit?: number }).use_limit, action).toBeUndefined();
    }
    // The default follows the declaration, not the action name: under a
    // class-wide key control the same hold needs a key and carries no use limit.
    const classWide = withDeclarations((d) => {
      d.splice(1);
      if (d[0]) d[0].mediated_class_or_scope = "consequential_write";
    }) as unknown as RuntimePosture;
    const classOpts = {
      ...opts,
      reversibleWritePermitMaxSeconds: (c: string | undefined, a: string) => reversibleWritePermitMaxSeconds(classWide, c, a),
    };
    expect((await evaluate(request("payments:payment.execute"), classOpts)).context.denial_reason).toBe("parameter_violation");
    const keyedHold = await evaluate(request("payments:payment.execute", KEY), classOpts);
    expect(keyedHold.decision).toBe(true);
    expect((keyedHold.context.conditions as { use_limit?: number }).use_limit).toBeUndefined();
  });
});
