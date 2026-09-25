/**
 * @spec runtime#compound-actions, runtime#execution-reverification (issue #252
 * PR C1) — the load-time refusals for a compound action's declared phases and
 * for the published execution lease.
 *
 * Each case copies the shipped `config/` with one member broken, points the
 * loader at the copy through `MISSION_CONFIG_DIR`, and resets the module
 * registry, so the refusal under test is the real boot path a deployment hits
 * rather than a re-implementation of it (the pattern
 * `authorization-server/test/shipped-config.test.ts` established).
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RUNTIME_POSTURE, executionLeaseMaxSeconds, validateEnforcementScopeStatement } from "@mission/pdp";

const SHIPPED_CONFIG = join(import.meta.dirname, "../../../config");

describe("compound-action phase configuration (@spec runtime#compound-actions)", () => {
  const dirs: string[] = [];
  const original = process.env.MISSION_CONFIG_DIR;

  afterEach(() => {
    if (original === undefined) delete process.env.MISSION_CONFIG_DIR;
    else process.env.MISSION_CONFIG_DIR = original;
    vi.resetModules();
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  /** A copy of the shipped config with `catalog.json` rewritten. */
  const configWith = (edit: (actions: Record<string, unknown>[]) => void): string => {
    const dir = mkdtempSync(join(tmpdir(), "mission-phase-config-"));
    dirs.push(dir);
    cpSync(SHIPPED_CONFIG, dir, { recursive: true });
    const file = join(dir, "catalog.json");
    const doc = JSON.parse(readFileSync(file, "utf8")) as Array<{ id: string; actions?: Record<string, unknown>[] }>;
    const payments = doc.find((s) => s.id === "payments");
    if (!payments?.actions) throw new Error("shipped catalog lost the payments actions");
    edit(payments.actions);
    writeFileSync(file, JSON.stringify(doc, null, 2));
    return dir;
  };

  const execute = (actions: Record<string, unknown>[]) => {
    const entry = actions.find((a) => a.id === "payments:payment.execute");
    if (!entry) throw new Error("shipped catalog lost payments:payment.execute");
    return entry;
  };

  it("refuses a phase outside the closed four-value vocabulary", async () => {
    process.env.MISSION_CONFIG_DIR = configWith((actions) => {
      (execute(actions).tools as Record<string, unknown>[])[1]!.action_phase = "settle";
    });
    vi.resetModules();
    await expect(import("@mission/demo-data")).rejects.toThrow(
      /action_phase must be one of preflight, prepare, commit, compensate/,
    );
  });

  it("refuses ambiguous single-tool/multi-tool configuration for one action", async () => {
    process.env.MISSION_CONFIG_DIR = configWith((actions) => {
      execute(actions).tool_name = "execute_wire_transfer";
    });
    vi.resetModules();
    await expect(import("@mission/demo-data")).rejects.toThrow(
      /declares both tool_name and tools; use exactly one/,
    );
  });

  it("refuses one tool declared twice under an action, leaving its phase ambiguous", async () => {
    process.env.MISSION_CONFIG_DIR = configWith((actions) => {
      const tools = execute(actions).tools as Record<string, unknown>[];
      tools.push({ tool_name: "hold_transfer", action_phase: "commit" });
    });
    vi.resetModules();
    await expect(import("@mission/demo-data")).rejects.toThrow(
      /declares hold_transfer twice, leaving its phase ambiguous/,
    );
  });

  it("refuses one tool name resolving to two different (action, phase) pairs", async () => {
    process.env.MISSION_CONFIG_DIR = configWith((actions) => {
      actions.push({
        id: "payments:payment.settle",
        amount_bearing: true,
        tools: [{ tool_name: "hold_transfer", action_phase: "prepare" }],
      });
    });
    vi.resetModules();
    await expect(import("@mission/demo-data")).rejects.toThrow(
      /resolves to two different \(action, phase\) pairs/,
    );
  });

  it("refuses an action declaring an empty tools list", async () => {
    process.env.MISSION_CONFIG_DIR = configWith((actions) => {
      execute(actions).tools = [];
    });
    vi.resetModules();
    await expect(import("@mission/demo-data")).rejects.toThrow(/tools must declare at least one tool/);
  });

  it("allows two legitimate aliases sharing one action AND one phase", async () => {
    // The merged contract binds a permit to a PHASE, not to a tool, so two
    // aliases at one phase are indistinguishable to it by design. Refusing
    // them would reject a conforming deployment, so no uniqueness rule of
    // that kind is added.
    process.env.MISSION_CONFIG_DIR = configWith((actions) => {
      (execute(actions).tools as Record<string, unknown>[]).push({
        tool_name: "check_transfer_alias",
        action_phase: "preflight",
      });
    });
    vi.resetModules();
    const mod = await import("@mission/demo-data");
    expect(mod.CATALOG_TOOL_BINDINGS.get("check_transfer_alias")).toEqual({
      action: "payments:payment.execute",
      action_phase: "preflight",
    });
  });
});

describe("published execution lease declaration (@spec runtime#execution-reverification)", () => {
  it("resolves the published maximum for each mediated high-consequence class", () => {
    expect(executionLeaseMaxSeconds(RUNTIME_POSTURE, "irreversible_action")).toBe(30);
    expect(executionLeaseMaxSeconds(RUNTIME_POSTURE, "external_commitment")).toBe(30);
    // A class with no declaration publishes no bound, and the executing PEP
    // must not invent one.
    expect(executionLeaseMaxSeconds(RUNTIME_POSTURE, "consequential_read")).toBeUndefined();
    expect(executionLeaseMaxSeconds(RUNTIME_POSTURE, undefined)).toBeUndefined();
  });

  it("refuses a declaration naming a class or a consumer the baseline does not declare", () => {
    const statement = structuredClone(RUNTIME_POSTURE) as unknown as Record<string, unknown>;
    const declarations = (statement.extensions as { transaction_assurance: Record<string, unknown>[] })
      .transaction_assurance;
    declarations[0]!.mediated_class_or_scope = "speculative_write";
    expect(validateEnforcementScopeStatement(statement)).toEqual([
      {
        member: "extensions.transaction_assurance[0]",
        problem: 'mediated_class_or_scope "speculative_write" is outside mediated_scope.action_classes',
      },
    ]);

    const unknownConsumer = structuredClone(RUNTIME_POSTURE) as unknown as Record<string, unknown>;
    (
      (unknownConsumer.extensions as { transaction_assurance: Record<string, unknown>[] }).transaction_assurance
    )[0]!.execution_lease_consumer = "some-other-pep";
    expect(validateEnforcementScopeStatement(unknownConsumer)).toEqual([
      {
        member: "extensions.transaction_assurance[0]",
        problem: 'execution_lease_consumer "some-other-pep" is not a declared mediated_scope.pep_locations entry',
      },
    ]);
  });

  it("refuses a lease maximum that is not a positive whole number of seconds, or is missing", () => {
    for (const bad of [0, -1, 1.5, "30", undefined]) {
      const statement = structuredClone(RUNTIME_POSTURE) as unknown as Record<string, unknown>;
      const declaration = (
        (statement.extensions as { transaction_assurance: Record<string, unknown>[] }).transaction_assurance
      )[0]!;
      if (bad === undefined) delete declaration.execution_lease_max_seconds;
      else declaration.execution_lease_max_seconds = bad;
      expect(validateEnforcementScopeStatement(statement), String(bad)).toEqual([
        {
          member: "extensions.transaction_assurance[0]",
          problem: "execution_lease_max_seconds must be a positive whole number of seconds",
        },
      ]);
    }
  });
});
