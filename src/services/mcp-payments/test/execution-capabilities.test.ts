/**
 * @spec runtime#execution-capabilities (#817): the payments operations'
 * execution capabilities as the resource publishes them, and the boot-path
 * refusal of a configuration that claims what no declared capability
 * supports.
 *
 * The declarations live in the Enforcement Scope Statement the resource
 * publishes in its Protected Resource Metadata, so a relying party reads each
 * operation's capabilities and claims from the same bytes the PDP loaded.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { executionCapabilitiesFor, type RuntimePosture } from "@mission/pdp";
import { TOOL_ACTIONS } from "../src/pep.js";
import { PROTECTED_RESOURCE_METADATA_PATH, startResourceMetadataServer } from "../src/resource-metadata.js";
import { McpPaymentsServer } from "../src/server.js";
import { openEphemeralWriteReservationStore } from "../src/write-reservations.js";

const SHIPPED_CONFIG = join(import.meta.dirname, "../../../config");
/** The classes whose operations release an effect. */
const EFFECT_CLASSES = ["consequential_write", "irreversible_action", "external_commitment", "privileged_administration"];
const HIGH_CONSEQUENCE = ["irreversible_action", "external_commitment", "privileged_administration"];

describe("execution capabilities on the resource metadata surface (@spec runtime#execution-capabilities, #817)", () => {
  const dirs: string[] = [];
  const original = process.env.MISSION_CONFIG_DIR;

  afterEach(() => {
    if (original === undefined) delete process.env.MISSION_CONFIG_DIR;
    else process.env.MISSION_CONFIG_DIR = original;
    vi.resetModules();
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("publishes the execution capabilities of every effectful operation the PEP serves, each under its own class and phase", async () => {
    const server = new McpPaymentsServer({ writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }), issuer: "https://as.test", jwks: { keys: [] }, keyRoles: { accessToken: [], attenuationRoot: [], transactionToken: [] } } as never);
    const listener = await startResourceMetadataServer(() => server);
    try {
      const response = await fetch(`${listener.origin}${PROTECTED_RESOURCE_METADATA_PATH}`);
      expect(response.status).toBe(200);
      const statement = ((await response.json()) as { enforcement_scope_statement: RuntimePosture }).enforcement_scope_statement;
      const effectful = Object.values(TOOL_ACTIONS).filter((m) => EFFECT_CLASSES.includes(m.actionClass));
      expect(effectful.length).toBeGreaterThan(0);
      for (const mapping of effectful) {
        const label = `${mapping.action} ${mapping.phase ?? ""}`;
        const declared = executionCapabilitiesFor(statement, mapping.action, mapping.phase);
        expect(declared, label).toBeDefined();
        expect(declared?.action_class, label).toBe(mapping.actionClass);
        for (const item of ["durable_idempotency", "conditional_effect", "outcome_lookup", "commit_point", "cancellation", "compensation", "unknown_outcome_recovery", "asserted"]) {
          expect(Object.hasOwn(declared ?? {}, item), `${label}: ${item}`).toBe(true);
        }
        // No transaction claim is published that a declared capability does
        // not support: the shipped statement asserts none.
        expect(declared?.asserted, label).toEqual([]);
        if (HIGH_CONSEQUENCE.includes(mapping.actionClass)) {
          expect(declared?.durable_idempotency, label).toEqual(expect.objectContaining({ held_by: "pdp_claim" }));
          expect(declared?.unknown_outcome_recovery, label).toBe("outcome_lookup");
        }
      }
      // Nothing is declared for an operation the PEP does not serve.
      expect(statement.extensions?.execution_capabilities).toHaveLength(effectful.length);
    } finally {
      await listener.close();
    }
  });

  it("a configuration claiming exactly-once execution on the PDP's claim alone refuses the boot", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mission-execution-capabilities-"));
    dirs.push(dir);
    cpSync(SHIPPED_CONFIG, dir, { recursive: true });
    const file = join(dir, "enforcement-scope.json");
    const statement = JSON.parse(readFileSync(file, "utf8")) as { extensions: { execution_capabilities: Array<Record<string, unknown>> } };
    const wire = statement.extensions.execution_capabilities.find((d) => d.operation === "payments:payment.execute" && d.phase === "commit");
    if (!wire) throw new Error("the shipped statement lost the wire's declaration");
    wire.asserted = ["exactly_once"];
    writeFileSync(file, JSON.stringify(statement));
    process.env.MISSION_CONFIG_DIR = dir;
    vi.resetModules();
    await expect(import("@mission/pdp")).rejects.toThrow(/claims exactly-once execution with no durable idempotency held by the resource/);
  });
});
