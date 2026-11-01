/**
 * @spec authority-server#mission-join rule 8, authority-server#mapping-contract,
 * resource-access#resource-contract (#249 C.3a, #1847, D967 test 4, D1071)
 *
 * A joined credential newly issued under a scope value whose mapping states
 * the payments contract works end to end: the estate issues it, the gateway
 * joins it to a Mission approved against the intended contract, and the PDP
 * permits the read under that contract. Mapping-unit evidence
 * (mas-pilot-mapping, mas-join-contract) does not establish this. The
 * contract-stating value and the requiring configuration are test
 * configuration: the shipped mapping states no contract until the flip
 * (C.3b). Needs a live OpenFGA, as every MAS pilot end-to-end file does.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { contractsRequiring, currentContractRef } from "@mission/demo-data";
import { CANONICAL_RESOURCE } from "@mission/mcp-payments";
import type { EvaluationRequest } from "@mission/pdp";
import type { MasPilot } from "../src/mas-pilot/compose.js";
import { loadMasPilotConfig, type MasPilotConfig } from "../src/mas-pilot/config.js";
import { approve, call, composeRecorded, estateToken, openfgaReachable, relocateEstate } from "./mas-pilot-support.js";

const up = await openfgaReachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping the MAS pilot contract-stating mapping tests");

/** The five non-read payments actions the cutover requires a reference for (D865). */
const CUTOVER = [
  "payments:payment.schedule",
  "payments:payment.schedule.cancel",
  "payments:payment.execute",
  "payments:payment.reverse",
  "payments:remittance.send",
];
/** A new estate scope value whose mapping states the current payments contract. */
const STATING = "invoices.read.contract";
const STATED_ACTIONS = ["payments:invoice.read"];
const CURRENT = currentContractRef({ resource: CANONICAL_RESOURCE, actions: STATED_ACTIONS });

type Mapping = { scopes: { issuers: Record<string, Record<string, unknown>> } };

/** The pilot configuration with its estate at `port`, and `STATING` mapped, registered for the resource, and granted to the agent's estate client. */
function statingConfig(port: number): MasPilotConfig {
  const moved = relocateEstate(loadMasPilotConfig(), port) as MasPilotConfig & { mapping_contract: Mapping };
  const issuer = moved.estate.issuer;
  moved.mapping_contract.scopes.issuers[issuer] = {
    ...moved.mapping_contract.scopes.issuers[issuer],
    [STATING]: { actions: STATED_ACTIONS, resource_contract: CURRENT },
  };
  const served = moved.estate.resource_servers[CANONICAL_RESOURCE]?.scope ?? "";
  moved.estate.resource_servers[CANONICAL_RESOURCE] = { scope: `${served} ${STATING}` };
  moved.estate.clients = moved.estate.clients.map((c) => (c.client_id === "estate-ap-bot-7f3" ? { ...c, scope: `${c.scope} ${STATING}` } : c));
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

  beforeAll(async () => {
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    vi.setSystemTime(CLOCK_MS);
    ({ pilot, requests } = await composeRecorded({ config: statingConfig(14985) }));
    // Approved against the intended contract, as a Mission created after the flip is (D989).
    const requiring = vi.spyOn(pilot.kernel, "resourceContracts").mockReturnValue(contractsRequiring(CUTOVER));
    try {
      pinnedMission = approve(pilot, "alice", { label: "contract-pinned" });
    } finally {
      requiring.mockRestore();
    }
    unpinnedMission = approve(pilot, "alice", { label: "contract-unpinned" });
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

    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", STATING);
    expect(String(claimsOf(credential.token).scope).split(" ")).toEqual([STATING]);
    const res = await call(pilot, credential, pinnedMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const last = requests.at(-1);
    expect(last?.resource.properties?.resource_contract).toEqual(CURRENT);
    expect(last?.subject).toEqual({ id: "u-1001", properties: { iss: pilot.estate.issuer } });
    expect(last?.context.credential?.issuer).toBe(pilot.estate.issuer);
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
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", STATING);
    const executions = executionCount();
    const res = await call(pilot, credential, unpinnedMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res).toMatchObject({ ok: false, denial_reason: "resource_contract_drift" });
    expect((res as { result?: unknown }).result).toBeUndefined();
    expect(executionCount()).toBe(executions);
  });
});
