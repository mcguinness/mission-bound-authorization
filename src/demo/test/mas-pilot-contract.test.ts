/**
 * @spec authority-server#mission-join rule 8, authority-server#mapping-contract,
 * resource-access#resource-contract (#249 C.3a and C.3b, #1847, D967 test 4, D1071, D1091)
 *
 * Joined credentials across the payments contract cutover, under the shipped
 * configuration: the payments resource requires a reference for its five
 * non-read actions, so a Mission approved now carries the current contract's
 * (D989). A credential issued under a scope value whose mapping states that
 * contract joins it and is permitted end to end; a legacy value, which states
 * none, keeps its meaning and joins only a Mission approved before the
 * cutover. Mapping-unit evidence (mas-pilot-mapping, mas-join-contract) does
 * not establish this. The write values are test configuration: the shipped
 * pilot maps no execute scope. Needs a live OpenFGA, as every MAS pilot
 * end-to-end file does.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ResourceContractDeclarations, type ResourceContractRef } from "@mission/core";
import { contractsRequiring, currentContractRef, RESOURCE_CONTRACTS, RUNTIME_SCOPE_CONFIG } from "@mission/demo-data";
import { CANONICAL_RESOURCE } from "@mission/mcp-payments";
import type { EvaluationRequest } from "@mission/pdp";
import type { MasPilot } from "../src/mas-pilot/compose.js";
import { loadMasPilotConfig, type MasPilotConfig } from "../src/mas-pilot/config.js";
import {
  admin,
  approve,
  call,
  composeRecorded,
  estateToken,
  INVOICES_READ,
  openfgaReachable,
  READ_ACTIONS,
  relocateEstate,
} from "./mas-pilot-support.js";

const up = await openfgaReachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping the MAS pilot contract-stating mapping tests");

const EXECUTE = "payments:payment.execute";
/** Test configuration: an execute value stating the current contract, and a legacy one stating none. */
const EXECUTE_STATING = "payments.execute.2026-11-02";
const EXECUTE_LEGACY = "payments.execute";
const CURRENT = currentContractRef({ resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] });

/** The read value stating the superseded 2026-10-27 contract, kept in the shipped mapping for Missions approved under it (#249, D1155). */
const INVOICES_READ_RETAINED = "invoices.read.2026-10-27";
/** The shipped reference to contract version 2026-10-27, superseded within its retention. */
const RETAINED: ResourceContractRef = (() => {
  const [declaration] = RESOURCE_CONTRACTS.declarations;
  const v = declaration?.versions.find((x) => x.version === "2026-10-27");
  if (!declaration || !v) throw new Error("2026-10-27 is declared");
  return { id: declaration.id, version: v.version, digest: v.digest };
})();

/** The shipped declarations as they stood while `version` was current: the later versions not yet published. */
function contractsWhileCurrent(version: string): ResourceContractDeclarations {
  const raw = structuredClone(
    (RUNTIME_SCOPE_CONFIG as { extensions: { resource_contracts: Array<{ versions: Array<Record<string, unknown>> }> } }).extensions
      .resource_contracts,
  );
  for (const declaration of raw) {
    declaration.versions = declaration.versions.slice(declaration.versions.findIndex((v) => v.version === version));
    const [now] = declaration.versions;
    if (!now) throw new Error(`${version} is declared`);
    now.state = "current";
    delete now.retained_until;
  }
  return new ResourceContractDeclarations(raw);
}

type Mapping = { scopes: { issuers: Record<string, Record<string, unknown>> } };

/** The shipped pilot configuration with its estate at `port`, and the two execute values mapped, registered for the resource, and granted to the agent's estate client. */
function contractConfig(port: number): MasPilotConfig {
  const moved = relocateEstate(loadMasPilotConfig(), port) as MasPilotConfig & { mapping_contract: Mapping };
  const issuer = moved.estate.issuer;
  moved.mapping_contract.scopes.issuers[issuer] = {
    ...moved.mapping_contract.scopes.issuers[issuer],
    [EXECUTE_STATING]: { actions: [EXECUTE], resource_contract: currentContractRef({ resource: CANONICAL_RESOURCE, actions: [EXECUTE] }) },
    [EXECUTE_LEGACY]: [EXECUTE],
  };
  const served = moved.estate.resource_servers[CANONICAL_RESOURCE]?.scope ?? "";
  moved.estate.resource_servers[CANONICAL_RESOURCE] = { scope: `${served} ${EXECUTE_STATING} ${EXECUTE_LEGACY}` };
  moved.estate.clients = moved.estate.clients.map((c) =>
    c.client_id === "estate-ap-bot-7f3" ? { ...c, scope: `${c.scope} ${EXECUTE_STATING} ${EXECUTE_LEGACY}` } : c,
  );
  return moved;
}

/**
 * The controlled clock every in-process component reads (`Date` faked,
 * advancing with real time): the estate, the gateway, the PEP, the PDP and
 * the MAS kernel. The shared `approve` helper's Intent expires on 2027-06-01,
 * after it, and no assertion moves with the real date.
 */
const CLOCK_MS = Date.parse("2026-11-02T12:00:00Z");

const claimsOf = (token: string) => JSON.parse(Buffer.from(token.split(".")[1] as string, "base64url").toString()) as Record<string, unknown>;

d("MAS pilot: a joined credential under a contract-stating scope value works end to end (@spec authority-server#mission-join, resource-access#resource-contract, #249, D967)", () => {
  let pilot: MasPilot;
  let requests: EvaluationRequest[];
  let pinnedMission: string;
  let unpinnedMission: string;
  let retainedMission: string;

  beforeAll(async () => {
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    vi.setSystemTime(CLOCK_MS);
    ({ pilot, requests } = await composeRecorded({ config: contractConfig(14985) }));
    // Approved under the shipped configuration, against the intended contract (D989).
    pinnedMission = approve(pilot, "alice", { label: "contract-pinned", actions: [...READ_ACTIONS, EXECUTE] });
    // Approved before the cutover: the configuration then required no reference.
    const before = vi.spyOn(pilot.kernel, "resourceContracts").mockReturnValue(contractsRequiring([]));
    try {
      unpinnedMission = approve(pilot, "alice", { label: "contract-unpinned" });
    } finally {
      before.mockRestore();
    }
    // Approved while 2026-10-27 was current (#249, D1155): pinned to it, now a
    // superseded version within its retention.
    const v16Current = vi.spyOn(pilot.kernel, "resourceContracts").mockReturnValue(contractsWhileCurrent("2026-10-27"));
    try {
      retainedMission = approve(pilot, "alice", { label: "contract-retained" });
    } finally {
      v16Current.mockRestore();
    }
  }, 30_000);
  afterAll(async () => {
    await pilot?.close();
    vi.useRealTimers();
  });
  /** The pilot's Execution Evidence records, all Missions. */
  const executionCount = (): number => pilot.evidence.all().filter((e) => e.kind === "execution").length;

  it("joins a credential the estate issues under the contract-stating value to the Mission approved against the same contract, and permits the read under that contract", async () => {
    const record = pilot.kernel.get(pinnedMission) as { authority_set: Array<{ resource_contract?: unknown }>; intent: { expires_at: string } };
    expect(Date.parse(record.intent.expires_at)).toBeGreaterThan(Date.now());
    const authority = record.authority_set;
    expect(authority.length).toBeGreaterThan(0);
    for (const e of authority) expect(e.resource_contract).toEqual(CURRENT);

    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", INVOICES_READ);
    expect(String(claimsOf(credential.token).scope).split(" ")).toEqual([INVOICES_READ]);
    const res = await call(pilot, credential, pinnedMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const last = requests.at(-1);
    expect(last?.resource.properties?.resource_contract).toEqual(CURRENT);
    expect(last?.subject).toEqual({ id: "u-1001", properties: { iss: pilot.estate.issuer } });
    expect(last?.context.credential?.issuer).toBe(pilot.estate.issuer);
  });

  // @spec authority-server#mission-join rule 8, resource-access#resource-contract
  // (#249, D1155, D1170): mapping v3 keeps the .2026-10-27 values, so a
  // credential the estate issues under one still joins a Mission approved
  // while 2026-10-27 was current, within its retention.
  it("joins a credential under the retained .2026-10-27 value to a Mission approved while 2026-10-27 was current, and the read reaches the PEP within the retention under exactly that reference", async () => {
    const declared = RESOURCE_CONTRACTS.versionOf(RETAINED)?.version;
    expect(declared?.state).toBe("superseded");
    expect(Date.parse(declared?.retained_until as string)).toBeGreaterThan(Date.now());
    const record = pilot.kernel.get(retainedMission) as { authority_set: Array<{ resource_contract?: unknown }> };
    expect(record.authority_set.length).toBeGreaterThan(0);
    for (const e of record.authority_set) expect(e.resource_contract).toEqual(RETAINED);

    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", INVOICES_READ_RETAINED);
    expect(String(claimsOf(credential.token).scope).split(" ")).toEqual([INVOICES_READ_RETAINED]);
    const res = await call(pilot, credential, retainedMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(requests.at(-1)?.resource.properties?.resource_contract).toEqual(RETAINED);
  });

  it("denies resource_contract_drift, performing nothing, a credential whose value states the other version: .2026-11-02 against the Mission pinned to 2026-10-27, and .2026-10-27 against the Mission pinned to 2026-11-02", async () => {
    for (const [value, mission] of [
      [INVOICES_READ, retainedMission],
      [INVOICES_READ_RETAINED, pinnedMission],
    ] as const) {
      const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", value);
      const executions = executionCount();
      const res = await call(pilot, credential, mission, "get_invoice", { invoice_id: "inv-1" });
      expect(res, value).toMatchObject({ ok: false, denial_reason: "resource_contract_drift" });
      expect((res as { result?: unknown }).result, value).toBeUndefined();
      expect(executionCount(), value).toBe(executions);
    }
  });

  it("denies resource_contract_drift, performing nothing, a legacy value that states no contract against the Mission approved against the contract", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    const executions = executionCount();
    const res = await call(pilot, credential, pinnedMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res).toMatchObject({ ok: false, denial_reason: "resource_contract_drift" });
    expect((res as { result?: unknown }).result).toBeUndefined();
    expect(executionCount()).toBe(executions);
  });

  it("denies resource_contract_drift, performing nothing, the contract-stating value against a Mission approved with no reference", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", INVOICES_READ);
    const executions = executionCount();
    const res = await call(pilot, credential, unpinnedMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res).toMatchObject({ ok: false, denial_reason: "resource_contract_drift" });
    expect((res as { result?: unknown }).result).toBeUndefined();
    expect(executionCount()).toBe(executions);
  });

  it("keeps a legacy value's meaning: it joins a Mission approved before the cutover, with no reference, and the read is permitted with no contract", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    const res = await call(pilot, credential, unpinnedMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(requests.at(-1)?.resource.properties?.resource_contract).toBeUndefined();
  });

  it("permits a joined, reference-required write under the contract-stating value, and refuses the legacy credential resource_contract_unresolvable before any decision, performing nothing (D1091)", async () => {
    await admin(pilot, "grant", "--iss", pilot.estate.issuer, "--sub", "u-1001", "--relation", "payer", "--vendor", "acme");
    try {
      const stating = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", EXECUTE_STATING);
      const held = await call(pilot, stating, pinnedMission, "hold_transfer", { invoice_id: "inv-1" });
      expect(held.ok, JSON.stringify(held)).toBe(true);
      expect(requests.at(-1)?.resource.properties?.resource_contract).toEqual(CURRENT);

      const legacy = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", EXECUTE_LEGACY);
      const decided = requests.length;
      const executions = executionCount();
      const refused = await call(pilot, legacy, pinnedMission, "hold_transfer", { invoice_id: "inv-1" });
      expect(refused).toMatchObject({ ok: false, refusal_reason: "resource_contract_unresolvable" });
      expect((refused as { result?: unknown }).result).toBeUndefined();
      expect(requests.length).toBe(decided);
      expect(executionCount()).toBe(executions);
    } finally {
      await admin(pilot, "revoke", "--iss", pilot.estate.issuer, "--sub", "u-1001", "--relation", "payer", "--vendor", "acme");
    }
  });
});
