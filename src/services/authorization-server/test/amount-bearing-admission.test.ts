/**
 * @spec mission#authority-proposal, runtime#input-parameters (issue #743)
 *
 * The defect class #743 named, closed at both model-admission boundaries by
 * ONE catalog-owned property. `config/catalog.json` marks each action
 * `amount_bearing`; a `max_amount` bound alongside an action marked false is a
 * cap no request for that action can ever satisfy, so the PDP refuses it at
 * every call. That is a modeling fault, not a runtime one, and it is refused
 * where models are admitted:
 *
 *  1. the typed config loader (`@mission/demo-data`), which rejects such a
 *     ceiling entry with a ConfigError at load, and
 *  2. PAR intake (`validateAuthorityProposal`), which refuses such an
 *     `authorization_details` entry `invalid_authorization_details`, a request
 *     fault, so a client cannot reintroduce the defect against a correct
 *     ceiling.
 *
 * Both gates call the same `amountBearingBindingError`, and the tables the
 * PDP and the PEP carry are held equal to the catalog here, so no two of them
 * can drift. The derivation kernel is untouched: `derive.ts` still treats
 * actions as opaque strings, and `evaluate.ts` still keys enforcement on the
 * matched entry's own `constraints.max_amount` presence.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ACTION_AMOUNT_BEARING,
  amountBearingBindingError,
  CANONICAL_RESOURCE,
  DEMO_AGENT_PROPOSAL,
} from "@mission/demo-data";
import { TOOL_ACTIONS } from "@mission/mcp-payments";
import { PAYMENTS_RELATIONS } from "@mission/pdp";
import { IntentError, validateAuthorityProposal } from "../src/index.js";

const RESOURCE = CANONICAL_RESOURCE;
const CAP = { amount: "500.00", currency: "USD" };

/** The shipped config dir the loader reads (src/config). */
const REAL_CONFIG_DIR = fileURLToPath(new URL("../../../config", import.meta.url));

describe("the deployment catalog is the single source of truth for amount-bearing actions (#743)", () => {
  it("the PDP's own needsAmount table equals the catalog, action for action", () => {
    for (const [action, mapping] of Object.entries(PAYMENTS_RELATIONS)) {
      expect(ACTION_AMOUNT_BEARING.get(action), `catalog claim for ${action}`).toBe(
        mapping.needsAmount,
      );
    }
    // And the reverse direction: no catalog-declared payments action is
    // missing from the PDP's mapping, so neither table can grow alone.
    for (const action of ACTION_AMOUNT_BEARING.keys()) {
      if (!action.startsWith("payments:")) continue;
      expect(PAYMENTS_RELATIONS[action], `PDP mapping for ${action}`).toBeDefined();
    }
  });

  it("the catalog's claim equals what the payments tools actually supply", () => {
    // An action is amount-bearing exactly when its tool loads the invoice the
    // amount comes from (`buildEffectiveParams`, mcp-payments/src/pep.ts): a
    // true claim the PEP could not honor would bind a cap the PDP can never
    // evaluate, and a false claim on a tool that does supply one would refuse
    // a cap the deployment could enforce.
    for (const mapping of Object.values(TOOL_ACTIONS)) {
      expect(ACTION_AMOUNT_BEARING.get(mapping.action), `catalog claim for ${mapping.action}`).toBe(
        mapping.needsInvoice,
      );
    }
  });
});

describe("PAR intake refuses a max_amount bound to a non-amount-bearing action (#743)", () => {
  const proposal = (actions: string[], constraints?: Record<string, unknown>) =>
    JSON.stringify([
      { type: "mission_resource_access", resource: RESOURCE, actions, ...(constraints ? { constraints } : {}) },
    ]);

  it("refuses the entry with invalid_authorization_details, naming the offending action", () => {
    try {
      validateAuthorityProposal(proposal(["payments:invoice.list"], { max_amount: CAP }), [RESOURCE]);
      expect.unreachable("a cap bound to a non-amount-bearing action must be refused");
    } catch (e) {
      expect(e).toBeInstanceOf(IntentError);
      expect((e as IntentError).code).toBe("invalid_authorization_details");
      expect((e as IntentError).message).toMatch(/payments:invoice\.list/);
      expect((e as IntentError).message).toMatch(/not amount-bearing/);
    }
  });

  it("refuses a MIXED entry: one non-amount-bearing action among amount-bearing ones is enough", () => {
    // The exact shape #743 reported. An entry's constraints bind every action
    // in it, so the cap reaches `payments:vendor.read` too.
    expect(() =>
      validateAuthorityProposal(
        proposal(["payments:payment.execute", "payments:vendor.read"], { max_amount: CAP, vendors: ["acme"] }),
        [RESOURCE],
      ),
    ).toThrow(/payments:vendor\.read/);
  });

  it("admits the same actions when no max_amount is bound", () => {
    const entries = validateAuthorityProposal(
      proposal(["payments:invoice.list", "payments:vendor.read"], { vendors: ["acme"] }),
      [RESOURCE],
    );
    expect(entries).toHaveLength(1);
  });

  it("admits a cap bound only to amount-bearing actions", () => {
    const entries = validateAuthorityProposal(
      proposal(["payments:payment.execute", "payments:remittance.send"], { max_amount: CAP }),
      [RESOURCE],
    );
    expect(entries[0]?.constraints?.max_amount?.amount).toBe("500.00");
  });

  it("admits a cap on an action the catalog does not declare (no claim, not a refusal)", () => {
    // Deliberate posture: the catalog refuses a binding it MARKS
    // unsatisfiable, never one it has never heard of. An undeclared action is
    // still narrowed away by derivation against the ceiling.
    const entries = validateAuthorityProposal(proposal(["payments:vendor.delete"], { max_amount: CAP }), [
      RESOURCE,
    ]);
    expect(entries).toHaveLength(1);
  });

  it("the shipped demo proposal still validates unchanged", () => {
    const entries = validateAuthorityProposal(JSON.stringify(DEMO_AGENT_PROPOSAL), [RESOURCE]);
    expect(entries).toHaveLength(DEMO_AGENT_PROPOSAL.length);
  });
});

describe("the shared validator is the same rule at both gates (#743)", () => {
  it("reports the fault for a bound cap and stays silent otherwise", () => {
    expect(amountBearingBindingError({ actions: ["payments:invoice.list"], constraints: { max_amount: CAP } })).toMatch(
      /not amount-bearing/,
    );
    expect(amountBearingBindingError({ actions: ["payments:invoice.list"] })).toBeNull();
    expect(
      amountBearingBindingError({ actions: ["payments:payment.execute"], constraints: { max_amount: CAP } }),
    ).toBeNull();
  });
});

describe("the typed config loader refuses such a ceiling entry at load (#743)", () => {
  let previous: string | undefined;
  let dir: string | undefined;

  afterEach(() => {
    if (previous === undefined) delete process.env.MISSION_CONFIG_DIR;
    else process.env.MISSION_CONFIG_DIR = previous;
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
    vi.resetModules();
  });

  /** A copy of the shipped config dir with `policy.json` rewritten by `mutate`. */
  function configDirWith(mutate: (policy: Record<string, unknown>) => void): string {
    dir = mkdtempSync(join(tmpdir(), "mission-config-743-"));
    const configDir = join(dir, "config");
    cpSync(REAL_CONFIG_DIR, configDir, { recursive: true });
    const policyPath = join(configDir, "policy.json");
    const policy = JSON.parse(readFileSync(policyPath, "utf8")) as Record<string, unknown>;
    mutate(policy);
    writeFileSync(policyPath, JSON.stringify(policy, null, 2));
    previous = process.env.MISSION_CONFIG_DIR;
    process.env.MISSION_CONFIG_DIR = configDir;
    vi.resetModules();
    return configDir;
  }

  it("rejects a ceiling entry binding max_amount to an action marked not amount-bearing", async () => {
    configDirWith((policy) => {
      // Re-merge the read actions into the money entry: the exact regression
      // PR #745 split apart, now refused before it can be loaded.
      const ceiling = policy.ceiling as { actions: string[]; constraints?: Record<string, unknown> }[];
      const money = ceiling.find((e) => e.constraints?.max_amount);
      money?.actions.push("payments:invoice.list");
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(
      /policy\.ceiling\[\d+\] binds max_amount to payments:invoice\.list, an action the deployment catalog marks not amount-bearing/,
    );
  });

  it("names the offending file as a ConfigError, not a bare throw", async () => {
    configDirWith((policy) => {
      const ceiling = policy.ceiling as { actions: string[]; constraints?: Record<string, unknown> }[];
      const money = ceiling.find((e) => e.constraints?.max_amount);
      money?.actions.push("payments:vendor.read");
    });
    const error = await import("@mission/demo-data").then(
      () => undefined,
      (e: Error) => e,
    );
    expect(error?.name).toBe("ConfigError");
    expect(error?.message).toMatch(/^\[config:policy\.json\]/);
  });

  it("loads the shipped config unchanged (positive control: the fixture dir itself is sound)", async () => {
    configDirWith(() => {});
    const mod = await import("@mission/demo-data");
    expect(mod.DERIVATION_POLICY.ceiling.length).toBeGreaterThan(1);
  });
});
