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
import { readFileSync } from "node:fs";
import {
  CANONICAL_RESOURCE,
  MAS_JOIN,
  type MasJoinPolicy,
  parseMasJoinPolicy,
  RESOURCE_CONTRACTS,
  scopeMappingEntries,
} from "@mission/demo-data";
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
      composeSeparatedMasPilot({ ...pilotOptions, mas: { url: "http://127.0.0.1:1", pdpKey: {} } }),
    ).rejects.toThrow(/declares no usable mapping contract/);
    expect(bootstrap).not.toHaveBeenCalled();
    expect(attach).not.toHaveBeenCalled();
  });

  it("the shared join's contract loader refuses an unknown member, a missing one, a mapping this join does not implement, and an instance it does not establish", () => {
    const shipped = () => ({
      governed_resources: [CANONICAL_RESOURCE],
      join_resource: MAS_JOIN.join_resource,
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

  it("the join route's own resource is required, an absolute URI, and distinct from every governed resource (#1531, D741)", () => {
    expect(MAS_JOIN.join_resource).not.toBe(CANONICAL_RESOURCE);
    const shipped = () => ({
      governed_resources: [CANONICAL_RESOURCE],
      join_resource: MAS_JOIN.join_resource,
      delegates: MAS_JOIN.delegates,
      scope_actions: MAS_JOIN.scope_actions,
      mapping_contract: { ...(MAS_JOIN.mapping_contract as object) },
    });
    expect(parseMasJoinPolicy(shipped()).join_resource).toBe(MAS_JOIN.join_resource);
    const { join_resource: _join, ...missing } = shipped();
    expect(() => parseMasJoinPolicy(missing)).toThrow(/join_resource must be a non-empty string/);
    expect(() => parseMasJoinPolicy({ ...shipped(), join_resource: "not a uri" })).toThrow(/join_resource must be an absolute URI/);
    expect(() => parseMasJoinPolicy({ ...shipped(), join_resource: CANONICAL_RESOURCE })).toThrow(
      /join_resource must differ from every governed resource/,
    );
  });
});

const [PAYMENTS_DECLARED] = RESOURCE_CONTRACTS.declarations;
/** The reference of the payments contract's declared `version`. */
const contractAt = (version: string) => {
  const v = PAYMENTS_DECLARED?.versions.find((x) => x.version === version);
  return { id: PAYMENTS_DECLARED?.id as string, version, digest: v?.digest as string };
};
const CURRENT_VERSION = PAYMENTS_DECLARED?.versions.find((v) => v.state === "current")?.version as string;
const OLDER_VERSION = PAYMENTS_DECLARED?.versions.find((v) => v.state === "superseded")?.version as string;
const LACKING_REVERSE = PAYMENTS_DECLARED?.versions.find(
  (v) => v.state !== "retired" && !v.operations.includes("payments:payment.reverse"),
)?.version as string;

/** The shipped mas-join.json with `scope_actions` replaced. */
const joinWith = (scope_actions: Record<string, unknown>) => ({
  ...(JSON.parse(readFileSync(new URL("../../config/mas-join.json", import.meta.url), "utf8")) as Record<string, unknown>),
  scope_actions,
});

/**
 * @spec authority-server#mission-join rule 8, resource-access#resource-contract
 * (#1847, D989): the shared-namespace route's scope mapping may state the
 * contract a scope value grants its actions under, validated at load; the
 * bound is one entry per distinct contract, never combining them, and a value
 * stating none keeps its own entry.
 */
describe("the shared-namespace join's scope mapping states a scope value's contract (@spec authority-server#mission-join, resource-access#resource-contract, #1847, D989)", () => {
  const READS = ["payments:invoice.read", "payments:invoice.list"];

  it("records the contract a value states, and none for an action list", () => {
    const policy = parseMasJoinPolicy(
      joinWith({ "payments.read": READS, "payments.read.contract-current": { actions: READS, resource_contract: contractAt(CURRENT_VERSION) } }),
    );
    expect(policy.scope_actions["payments.read.contract-current"]).toEqual(READS);
    expect(policy.scope_contracts["payments.read.contract-current"]).toEqual(contractAt(CURRENT_VERSION));
    expect(policy.scope_contracts).not.toHaveProperty("payments.read");
  });

  it.each([
    ["an unknown version", { actions: READS, resource_contract: contractAt("1999-01-01") }, /resource_contract/],
    ["another digest", { actions: READS, resource_contract: { ...contractAt(CURRENT_VERSION), digest: contractAt(OLDER_VERSION).digest } }, /digest/],
    ["an action its version does not define", { actions: ["payments:payment.reverse"], resource_contract: contractAt(LACKING_REVERSE) }, /every action/],
    ["no reference in the object form", { actions: READS }, /resource_contract is required/],
    ["an unknown member", { actions: READS, resource_contract: contractAt(CURRENT_VERSION), note: "x" }, /not a known member/],
  ])("refuses at load a value stating %s", (_why, value, message) => {
    expect(() => parseMasJoinPolicy(joinWith({ "payments.read.bad": value }))).toThrow(message);
  });

  it("confers one entry per distinct contract, a value stating none in its own, and merges values under the same contract", () => {
    const current = contractAt(CURRENT_VERSION);
    const older = contractAt(OLDER_VERSION);
    const mapping = {
      actions: { legacy: ["payments:invoice.read"], now: ["payments:invoice.read"], nowList: ["payments:invoice.list"], before: ["payments:invoice.read"] },
      contracts: { now: current, nowList: current, before: older },
    };
    expect(scopeMappingEntries(["legacy", "now", "nowList", "before", "unmapped"], mapping, CANONICAL_RESOURCE)).toEqual([
      { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] },
      { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read", "payments:invoice.list"], resource_contract: current },
      { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"], resource_contract: older },
    ]);
    expect(scopeMappingEntries(["unmapped"], mapping, CANONICAL_RESOURCE)).toBeUndefined();
  });
});

/**
 * @spec authority-server#mission-join rule 8 (#1847, #1866 review): a scope
 * value is looked up as the mapping's own entry. A value naming an inherited
 * member confers nothing and never throws, alone or beside a mapped value, and
 * a mapping key such as `__proto__` is an ordinary entry.
 */
describe("the shared-namespace scope mapping reads only its own entries (@spec authority-server#mission-join, #1847)", () => {
  const INHERITED = ["constructor", "toString", "hasOwnProperty", "valueOf", "__proto__"];
  const READ = ["payments:invoice.read"];

  it.each(INHERITED)("an unmapped value named %s confers nothing alone, and beside a mapped value only that value's entry", (name) => {
    const mapping = { actions: { legacy: READ }, contracts: {} };
    expect(scopeMappingEntries([name], mapping, CANONICAL_RESOURCE)).toBeUndefined();
    expect(scopeMappingEntries([name, "legacy"], mapping, CANONICAL_RESOURCE)).toEqual([
      { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: READ },
    ]);
  });

  it("loads mapping keys named __proto__ and constructor as ordinary scope values, and a stated contract under one", () => {
    const current = contractAt(CURRENT_VERSION);
    const raw = JSON.parse(
      JSON.stringify({ constructor: READ }).replace("{", `{"__proto__": ${JSON.stringify({ actions: READ, resource_contract: current })},`),
    ) as Record<string, unknown>;
    expect(Object.keys(raw)).toEqual(["__proto__", "constructor"]);
    const policy = parseMasJoinPolicy(joinWith(raw));
    expect(Object.keys(policy.scope_actions)).toEqual(["__proto__", "constructor"]);
    expect(policy.scope_contracts.__proto__).toEqual(current);
    const mapping = { actions: policy.scope_actions, contracts: policy.scope_contracts };
    expect(scopeMappingEntries(["__proto__"], mapping, CANONICAL_RESOURCE)).toEqual([
      { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: READ, resource_contract: current },
    ]);
    expect(scopeMappingEntries(["toString"], mapping, CANONICAL_RESOURCE)).toBeUndefined();
  });
});
