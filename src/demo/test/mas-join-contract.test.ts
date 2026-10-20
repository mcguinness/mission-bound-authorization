/**
 * @spec authority-server#mapping-contract (#818)
 *
 * "Every deployment documents the mapping contract its joins apply." Each
 * shipped deployment that mounts a join route declares its contract in
 * configuration, read by a strict loader: the shared demo stack's join
 * (`config/mas-join.json` `mapping_contract`, with its `scope_actions` and
 * `delegates`) and the MAS pilot, in process and separated
 * (`config/mas-pilot.json` `mapping_contract`). A composition that would
 * mount a join route without one refuses to start, before it connects to
 * anything. Never skips: nothing here reaches OpenFGA, an authorization
 * server or a MAS.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CANONICAL_RESOURCE, MAS_JOIN, type MasJoinPolicy, parseMasJoinPolicy } from "@mission/demo-data";
import { Fga } from "@mission/pdp";
import { afterEach, describe, expect, it, vi } from "vitest";
import { composeMasPilot, requireDeclaredMappingContract } from "../src/mas-pilot/compose.js";
import { loadMasPilotConfig, type MasPilotConfig } from "../src/mas-pilot/config.js";
import { parseMappingContract } from "../src/mas-pilot/mapping-contract.js";
import { composeSeparatedMasPilot } from "../src/mas-pilot/separated.js";
import { composeStack } from "../src/stack.js";
import { relocateEstate } from "./mas-pilot-support.js";

const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);
/** An unused estate port, so a composition that started anything would not collide with another file's. */
const ESTATE_PORT = 14855;

afterEach(() => {
  vi.restoreAllMocks();
});

describe("every join-enabling deployment declares the mapping contract its joins apply (@spec authority-server#mapping-contract, #818)", () => {
  it("the shipped deployments each load a declared contract: the shared stack's join, and the MAS pilot in process and separated", () => {
    // The shared stack's join: a strict declaration whose members are the
    // behavior that join implements, beside its scope mapping and delegate policy.
    expect(MAS_JOIN.governed_resources).toContain(CANONICAL_RESOURCE);
    expect(MAS_JOIN.mapping_contract).toEqual({
      contract_id: "shared-demo-join",
      version: 1,
      subject_mapping: "identity",
      client_mapping: "identity",
      delegate_entry_rule: "client_id_matchers",
      instance: { supported: false, required: false },
      audit: "decision_evidence",
      failure: "mission_binding_failed",
    });
    expect(Object.keys(MAS_JOIN.scope_actions).length).toBeGreaterThan(0);
    expect(Object.keys(MAS_JOIN.delegates).length).toBeGreaterThan(0);

    // The MAS pilot: both compositions read this one contract, and refuse
    // to start without it (below).
    const pilot = loadMasPilotConfig();
    expect(() => requireDeclaredMappingContract(pilot)).not.toThrow();
    const contract = parseMappingContract(pilot.mapping_contract);
    expect(contract.subjects.length).toBeGreaterThan(0);
    expect(contract.clients.length).toBeGreaterThan(0);
    expect(Object.keys(contract.scopes.issuers).length).toBeGreaterThan(0);
    expect(Object.keys(contract.delegates).length).toBeGreaterThan(0);
    expect(contract.instance).toEqual({ supported: false, required: false });
    expect(contract.version).toBeGreaterThan(0);
    expect(contract.failure).toBe("mission_binding_failed");
  });

  it("refuses to start a composition that would mount a join route with no declared contract, before it connects to anything", async () => {
    const bootstrap = vi.spyOn(Fga, "bootstrap").mockRejectedValue(new Error("OpenFGA was reached"));
    const attach = vi.spyOn(Fga, "attach").mockRejectedValue(new Error("OpenFGA was reached"));
    const undeclared: MasJoinPolicy = { ...MAS_JOIN };
    delete undeclared.mapping_contract;
    await expect(
      composeStack({
        openfgaUrl: "http://unused.test",
        presharedKey: "unused",
        masJoinPolicy: undeclared,
        claimsFile: tempFile("demo-claims-", "claims.sqlite"),
        writeReservationsFile: tempFile("demo-reservations-", "write-reservations.sqlite"),
        resourcePolicyStore: { bootstrap: "development" },
      }),
    ).rejects.toThrow(/declares no mapping contract for its join/);

    const withoutContract = { ...relocateEstate(loadMasPilotConfig(), ESTATE_PORT), mapping_contract: undefined } as MasPilotConfig;
    const pilotOptions = {
      openfga: { apiUrl: "http://unused.test", presharedKey: "unused" },
      resourcePolicyStore: { bootstrap: "development" } as const,
      config: withoutContract,
    };
    await expect(composeMasPilot(pilotOptions)).rejects.toThrow(/declares no usable mapping contract/);
    await expect(
      composeSeparatedMasPilot({ ...pilotOptions, mas: { url: "http://127.0.0.1:1", pdpToken: "unused" } }),
    ).rejects.toThrow(/declares no usable mapping contract/);
    expect(bootstrap).not.toHaveBeenCalled();
    expect(attach).not.toHaveBeenCalled();
  });

  it("the shared join's contract loader refuses an unknown member, a missing one, a mapping this join does not implement, and an instance it does not establish", () => {
    const shipped = () => ({
      governed_resources: [CANONICAL_RESOURCE],
      delegates: MAS_JOIN.delegates,
      scope_actions: MAS_JOIN.scope_actions,
      mapping_contract: { ...(MAS_JOIN.mapping_contract as object) },
    });
    expect(parseMasJoinPolicy(shipped()).mapping_contract).toEqual(MAS_JOIN.mapping_contract);
    const withContract = (over: Record<string, unknown>) => ({ ...shipped(), mapping_contract: { ...shipped().mapping_contract, ...over } });
    expect(() => parseMasJoinPolicy({ ...shipped(), extra: true })).toThrow(/unknown member extra/);
    expect(() => parseMasJoinPolicy(withContract({ mapping_version: 2 }))).toThrow(/unknown member mapping_version/);
    const { audit: _audit, ...noAudit } = shipped().mapping_contract as Record<string, unknown>;
    expect(() => parseMasJoinPolicy({ ...shipped(), mapping_contract: noAudit })).toThrow(/is missing audit/);
    expect(() => parseMasJoinPolicy(withContract({ subject_mapping: "rows" }))).toThrow(/subject_mapping must be "identity"/);
    expect(() => parseMasJoinPolicy(withContract({ failure: "out_of_authority" }))).toThrow(/failure must be "mission_binding_failed"/);
    expect(() => parseMasJoinPolicy(withContract({ instance: { supported: true, required: false } }))).toThrow(/establishes no client instance/);
    expect(() => parseMasJoinPolicy(withContract({ version: 0 }))).toThrow(/version must be a positive integer/);
  });
});
