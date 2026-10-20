/**
 * @spec runtime#execution-capabilities (#817): the Operation Profile's
 * execution capabilities, as the reference Enforcement Scope Statement
 * declares them per operation, and the admission rules the loader applies at
 * load: each capability stated even where the answer is no; a
 * durable-idempotency holder this statement resolves; `exactly_once` only on
 * durable idempotency held by the resource; the enforced Evaluation-Context
 * Binding property only on declared conditional-effect support; and a
 * recovery from an unknown outcome only on a declared outcome lookup or on
 * resource idempotency.
 *
 * Every refusal is the loader's (`loadRuntimePosture`), the function the PDP
 * runs on its own configuration at boot, so an unsupported claim never
 * reaches a published statement.
 */

import { describe, expect, it } from "vitest";
import { RUNTIME_SCOPE_CONFIG } from "@mission/demo-data";
import { executionCapabilityFindings } from "../src/enforcement-scope.js";
import { executionCapabilitiesFor, loadRuntimePosture, PostureConfigError, RUNTIME_POSTURE } from "../src/runtime-posture.js";

type Entry = Record<string, unknown>;
type Statement = { extensions: { execution_capabilities: Entry[]; transaction_assurance: Entry[] } };

/** The shipped statement with one edit applied to a fresh copy. */
function edited(edit: (s: Statement) => void): Statement {
  const s = structuredClone(RUNTIME_POSTURE) as unknown as Statement;
  edit(s);
  return s;
}

/** The shipped declaration of one operation (and phase), in a copy. */
function entry(s: Statement, operation: string, phase?: string): Entry {
  const found = s.extensions.execution_capabilities.find((d) => d.operation === operation && d.phase === phase);
  if (!found) throw new Error(`the shipped statement lost ${operation} ${phase ?? ""}`);
  return found;
}

const WIRE = ["payments:payment.execute", "commit"] as const;
const HOLD = ["payments:payment.execute", "prepare"] as const;
const SCHEDULE = ["payments:payment.schedule"] as const;

/** A resource-held durable idempotency declaration, complete. */
const RESOURCE_IDEMPOTENCY = {
  held_by: "resource",
  key: "Idempotency-Key header",
  scope: ["account", "operation"],
  retention: "P30D",
  new_operation: "a new Idempotency-Key",
};

describe("execution capabilities in the Enforcement Scope Statement (@spec runtime#execution-capabilities, #817)", () => {
  it("the shipped statement declares every execution capability of each effectful payments operation and asserts no transaction claim", () => {
    expect(executionCapabilityFindings(RUNTIME_SCOPE_CONFIG)).toEqual([]);
    const declared = RUNTIME_POSTURE.extensions?.execution_capabilities ?? [];
    expect(declared.map((d) => [d.operation, d.phase ?? null, d.action_class])).toEqual([
      ["payments:payment.schedule", null, "consequential_write"],
      ["payments:payment.schedule.cancel", null, "consequential_write"],
      ["payments:payment.execute", "prepare", "consequential_write"],
      ["payments:payment.execute", "commit", "irreversible_action"],
      ["payments:remittance.send", null, "external_commitment"],
    ]);
    for (const d of declared) {
      expect(d.asserted, d.operation).toEqual([]);
      expect(d.conditional_effect, d.operation).toBe("none");
      expect(d.compensation, d.operation).toBe("none");
    }
    // The high-consequence operations: the PDP's claim deduplicates a
    // retransmission, and the connector's entry for the permit identifier is
    // the outcome lookup the declared reconciler reads.
    const wire = executionCapabilitiesFor(RUNTIME_POSTURE, ...WIRE);
    expect(wire?.durable_idempotency).toEqual({
      held_by: "pdp_claim",
      new_operation: expect.stringContaining("refused operation_already_claimed"),
    });
    expect(wire?.outcome_lookup).toEqual(expect.objectContaining({ identifier: "evaluation_id" }));
    expect(wire?.unknown_outcome_recovery).toBe("outcome_lookup");
    // The simulated hold records nothing: no idempotency, no lookup, and an
    // unknown outcome is held.
    const hold = executionCapabilitiesFor(RUNTIME_POSTURE, ...HOLD);
    expect(hold?.durable_idempotency).toBe("none");
    expect(hold?.outcome_lookup).toBe("none");
    expect(hold?.unknown_outcome_recovery).toBe("hold");
    expect(executionCapabilitiesFor(RUNTIME_POSTURE, "payments:invoice.read")).toBeUndefined();
  });

  it("refuses at load a declaration that leaves an execution capability unstated, naming the entry", () => {
    const members = [
      "durable_idempotency",
      "conditional_effect",
      "outcome_lookup",
      "commit_point",
      "cancellation",
      "compensation",
      "unknown_outcome_recovery",
      "asserted",
    ];
    for (const name of members) {
      const s = edited((st) => {
        delete entry(st, ...WIRE)[name];
      });
      expect(() => loadRuntimePosture(s), name).toThrow(PostureConfigError);
      expect(() => loadRuntimePosture(s), name).toThrow("extensions.execution_capabilities[3]");
    }
  });

  it("refuses at load an exactly-once claim with no durable idempotency held by the resource, and admits it once the resource holds a key, scope and retention", () => {
    // The PDP's claim prevents a second permit; it does not make the
    // resource deduplicate a re-drive, so it backs no exactly-once claim.
    const onClaim = edited((s) => {
      entry(s, ...WIRE).asserted = ["exactly_once"];
    });
    expect(() => loadRuntimePosture(onClaim)).toThrow("claims exactly-once execution with no durable idempotency held by the resource");
    const onNothing = edited((s) => {
      entry(s, ...HOLD).asserted = ["exactly_once"];
    });
    expect(() => loadRuntimePosture(onNothing)).toThrow("claims exactly-once execution with no durable idempotency held by the resource");
    const onResource = edited((s) => {
      const wire = entry(s, ...WIRE);
      wire.durable_idempotency = RESOURCE_IDEMPOTENCY;
      wire.asserted = ["exactly_once"];
    });
    const loaded = loadRuntimePosture(onResource);
    expect(executionCapabilitiesFor(loaded, ...WIRE)?.asserted).toEqual(["exactly_once"]);
  });

  it("refuses at load an enforced Evaluation-Context Binding claim with no declared conditional-effect support, and admits it with a declared precondition", () => {
    const reread = edited((s) => {
      entry(s, ...WIRE).asserted = ["evaluation_context_enforced"];
    });
    expect(() => loadRuntimePosture(reread)).toThrow(
      "claims the enforced Evaluation-Context Binding property with no declared conditional-effect support",
    );
    const conditional = edited((s) => {
      const wire = entry(s, ...WIRE);
      wire.conditional_effect = { precondition: "If-Match: the bound revision" };
      wire.asserted = ["evaluation_context_enforced"];
    });
    expect(executionCapabilitiesFor(loadRuntimePosture(conditional), ...WIRE)?.asserted).toEqual(["evaluation_context_enforced"]);
  });

  it("refuses at load an unknown-outcome recovery that rests on no declared outcome lookup or resource idempotency", () => {
    // Re-presenting the effect is a recovery only where the resource itself
    // deduplicates it.
    const retransmitOnClaim = edited((s) => {
      entry(s, ...WIRE).unknown_outcome_recovery = "resource_retransmission";
    });
    expect(() => loadRuntimePosture(retransmitOnClaim)).toThrow(
      "a resource_retransmission recovery rests on no durable idempotency held by the resource",
    );
    // A lookup recovery needs a declared lookup.
    const lookupOnNothing = edited((s) => {
      entry(s, ...HOLD).unknown_outcome_recovery = "outcome_lookup";
    });
    expect(() => loadRuntimePosture(lookupOnNothing)).toThrow("an outcome_lookup recovery rests on no declared outcome lookup");
    const lookupWithdrawn = edited((s) => {
      entry(s, ...WIRE).outcome_lookup = "none";
    });
    expect(() => loadRuntimePosture(lookupWithdrawn)).toThrow("an outcome_lookup recovery rests on no declared outcome lookup");
    // Both admitted when the capability is declared, and `hold` always is.
    const retransmitOnResource = edited((s) => {
      const wire = entry(s, ...WIRE);
      wire.durable_idempotency = RESOURCE_IDEMPOTENCY;
      wire.unknown_outcome_recovery = "resource_retransmission";
    });
    expect(executionCapabilitiesFor(loadRuntimePosture(retransmitOnResource), ...WIRE)?.unknown_outcome_recovery).toBe(
      "resource_retransmission",
    );
    const held = edited((s) => {
      const wire = entry(s, ...WIRE);
      wire.outcome_lookup = "none";
      wire.unknown_outcome_recovery = "hold";
    });
    expect(executionCapabilitiesFor(loadRuntimePosture(held), ...WIRE)?.unknown_outcome_recovery).toBe("hold");
  });

  it("refuses at load a durable-idempotency holder the statement does not resolve", () => {
    // The PDP's claim: its class's transaction_assurance declaration names
    // the scope and the horizon.
    const noHorizon = edited((s) => {
      delete s.extensions.transaction_assurance[0]!.idempotency_horizon_seconds;
    });
    expect(() => loadRuntimePosture(noHorizon)).toThrow(
      "durable idempotency held by the PDP claim, but no transaction_assurance declaration for its class names the scope and horizon",
    );
    // The PEP's reservation: the operation's key control, never the
    // class-wide single-use default the hold resolves to.
    const holdOnReservation = edited((s) => {
      entry(s, ...HOLD).durable_idempotency = { held_by: "pep_reservation", new_operation: "a new key" };
    });
    expect(() => loadRuntimePosture(holdOnReservation)).toThrow(
      "durable idempotency held by the PEP reservation, but no reversible_write_idempotency key control covers the operation",
    );
    // The resource's own record names its key, scope and retention.
    for (const missing of ["key", "scope", "retention"]) {
      const partial = edited((s) => {
        const declaration: Entry = { ...RESOURCE_IDEMPOTENCY };
        delete declaration[missing];
        entry(s, ...SCHEDULE).durable_idempotency = declaration;
      });
      expect(() => loadRuntimePosture(partial), missing).toThrow(
        "durable idempotency held by the resource names no key, scope of distinct members, or retention of days or below",
      );
    }
    const unknownHolder = edited((s) => {
      entry(s, ...SCHEDULE).durable_idempotency = { held_by: "gateway", new_operation: "a new key" };
    });
    expect(() => loadRuntimePosture(unknownHolder)).toThrow("durable_idempotency.held_by must be one of resource, pdp_claim, pep_reservation");
    const noDistinction = edited((s) => {
      entry(s, ...SCHEDULE).durable_idempotency = { held_by: "pep_reservation" };
    });
    expect(() => loadRuntimePosture(noDistinction)).toThrow(
      "durable_idempotency names nothing that distinguishes a new operation from a retransmission",
    );
  });

  it("refuses at load malformed or duplicate declarations and an operation outside the declared classes", () => {
    const cases: Array<[string, (s: Statement) => void, string]> = [
      ["not an array", (s) => { (s.extensions as Record<string, unknown>).execution_capabilities = {}; }, "must be an array of per-operation declarations"],
      ["not an object", (s) => { s.extensions.execution_capabilities[0] = "payments:payment.schedule" as unknown as Entry; }, "entry must be an object"],
      ["no action identifier", (s) => { entry(s, ...SCHEDULE).operation = "schedule"; }, "operation must be an action identifier"],
      ["unknown phase", (s) => { entry(s, ...HOLD).phase = "settle"; }, "phase must be one of preflight, prepare, commit, compensate"],
      ["undeclared class", (s) => { entry(s, ...SCHEDULE).action_class = "privileged_administration"; }, "is outside mediated_scope.action_classes"],
      ["declared twice", (s) => { s.extensions.execution_capabilities.push({ ...entry(s, ...WIRE) }); }, "is declared twice"],
      ["empty precondition", (s) => { entry(s, ...WIRE).conditional_effect = {}; }, "conditional_effect must be none or name the precondition carried to the resource"],
      ["lookup with no identifier", (s) => { entry(s, ...WIRE).outcome_lookup = { method: "ledger" }; }, "outcome_lookup must be none or name the recorded identifier and how it is queried"],
      ["empty commit point", (s) => { entry(s, ...WIRE).commit_point = ""; }, "missing the commit point"],
      ["compensation with no action", (s) => { entry(s, ...WIRE).compensation = { action: "refund" }; }, "compensation must be none or name the compensating action identifier"],
      ["unknown recovery", (s) => { entry(s, ...WIRE).unknown_outcome_recovery = "retry"; }, "unknown_outcome_recovery must be one of hold, outcome_lookup, resource_retransmission"],
      ["unknown claim", (s) => { entry(s, ...WIRE).asserted = ["rollback"]; }, "asserted must list distinct values of exactly_once, evaluation_context_enforced, or none"],
      ["repeated claim", (s) => { entry(s, ...WIRE).asserted = ["exactly_once", "exactly_once"]; }, "asserted must list distinct values"],
    ];
    for (const [label, edit, problem] of cases) {
      expect(() => loadRuntimePosture(edited(edit)), label).toThrow(problem);
    }
  });
});
