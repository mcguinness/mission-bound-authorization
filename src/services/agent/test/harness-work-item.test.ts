/**
 * @spec harness#work-item-identity (#815): the harness is the attacher of its
 * work items. It attaches the work item it assigned, in the propagated
 * Mission reference in the call's transport metadata, on every governed call
 * it originates for that item; a resumed submission keeps the same item; and
 * concurrent items, under one Mission or several, each ride only their own
 * calls under their own Mission. Nothing the planner returns, tool arguments
 * included, is merged into the attachment.
 *
 * The first block drives a spy channel. The second runs the whole path over
 * the real MCP in-memory transport to the PEP and the co-resident PDP: the
 * harness's work item is what reaches `context.work_item`, the permit and the
 * evidence. Unconditional: the FGA check is a stub, so this file never skips.
 */

import { randomUUID } from "node:crypto";
import type { MissionStatusLease } from "@mission/core";
import {
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  createMediatedClient,
  type DecisionEvidence,
  EvidenceStore,
  type ExecutionEvidence,
  McpPaymentsServer,
  openEphemeralWriteReservationStore,
  PaymentsStore,
  Pep,
  TransactionEngine,
} from "@mission/mcp-payments";
import {
  type Decision,
  type EvaluationRequest,
  type Fga,
  type MissionView,
  readWorkItemAttribution,
  RUNTIME_POSTURE,
  WORK_ITEM_ATTRIBUTION_EXTENSION,
} from "@mission/pdp";
import { RESOURCE_POLICY_PERMITS_ALL_FIXTURE } from "@mission/pdp/test-support";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import type { MissionState } from "../src/harness.js";
import { type HarnessWorkItem, MediatedHarness, type MediatedToolChannel } from "../src/mediated-harness.js";

const ISSUER = "https://as.test";
const HARNESS = "https://harness.example.com";
const MISSION_A = "msn_815_a";
const MISSION_B = "msn_815_b";
const W1: HarnessWorkItem = { issuer: HARNESS, id: "work-1", missionIssuer: ISSUER };
const W2: HarnessWorkItem = { issuer: HARNESS, id: "work-2", missionIssuer: ISSUER };
const active = async (): Promise<MissionState> => "active";
const idem = (): string => `idem_${randomUUID()}`;

interface SpyCall {
  name: string;
  args: Record<string, unknown>;
  missionReference: unknown;
}

function spyChannel(): { channel: MediatedToolChannel; calls: SpyCall[] } {
  const calls: SpyCall[] = [];
  const channel: MediatedToolChannel = {
    async listTools() {
      return ["get_invoice"];
    },
    async callTool(name, args, _missionToken, missionReference) {
      calls.push({ name, args, missionReference });
      return { ok: true, result: {} };
    },
  };
  return { channel, calls };
}

describe("the harness attaches its own work item (@spec harness#work-item-identity, #815)", () => {
  it("attaches its work item in the propagated Mission reference on every call, and never from tool arguments", async () => {
    const { channel, calls } = spyChannel();
    const harness = new MediatedHarness(channel, MISSION_A, active, { workItem: W1 });
    await harness.callTool("get_invoice", { invoice_id: "inv-1" }, "jwt");
    // A planner that names another work item, or a reference, in its arguments
    // changes nothing the harness attaches: the arguments pass as arguments.
    await harness.callTool(
      "get_invoice",
      { invoice_id: "inv-1", work_item: "work-2", work_item_issuer: "https://other.example", mission_id: MISSION_B },
      "jwt",
    );
    const expected = { mission_id: MISSION_A, issuer: ISSUER, work_item_issuer: HARNESS, work_item: "work-1" };
    expect(calls.map((c) => c.missionReference)).toEqual([expected, expected]);
    expect(calls[1]?.args.work_item).toBe("work-2");
  });

  it("a resumed submission keeps the same work item, and is re-checked as a new continuation point", async () => {
    const { channel, calls } = spyChannel();
    let lease: MissionStatusLease = {
      state: "active",
      status_checked_at: "2026-10-25T22:00:00Z",
      status_expires_at: "2026-10-25T22:05:00Z",
      state_source: "status",
    };
    const harness = new MediatedHarness(channel, MISSION_A, active, {
      readStatus: async () => lease,
      now: () => new Date("2026-10-26T02:00:00Z"),
      workItem: W1,
    });
    // Stale at 02:00: refused before the channel, so nothing is attached.
    const stale = await harness.callTool("get_invoice", { invoice_id: "inv-1" }, "jwt");
    expect(stale.ok).toBe(false);
    expect(calls).toHaveLength(0);
    // A fresh lease: the resumed submission proceeds under the same work item.
    lease = { ...lease, status_checked_at: "2026-10-26T01:59:00Z", status_expires_at: "2026-10-26T02:30:00Z" };
    const resumed = await harness.callTool("get_invoice", { invoice_id: "inv-1" }, "jwt");
    expect(resumed.ok).toBe(true);
    expect(calls.map((c) => c.missionReference)).toEqual([
      { mission_id: MISSION_A, issuer: ISSUER, work_item_issuer: HARNESS, work_item: "work-1" },
    ]);
  });

  it("concurrent work items under one Mission or two attach distinct identifiers, each under its own Mission", async () => {
    const { channel, calls } = spyChannel();
    const one = new MediatedHarness(channel, MISSION_A, active, { workItem: W1 });
    const two = new MediatedHarness(channel, MISSION_A, active, { workItem: W2 });
    const other = new MediatedHarness(channel, MISSION_B, active, { workItem: { ...W1, id: "work-3" } });
    await Promise.all([
      one.callTool("get_invoice", { invoice_id: "inv-1" }, "jwt-a"),
      two.callTool("get_invoice", { invoice_id: "inv-1" }, "jwt-a"),
      other.callTool("get_invoice", { invoice_id: "inv-1" }, "jwt-b"),
    ]);
    expect(calls.map((c) => c.missionReference)).toEqual([
      { mission_id: MISSION_A, issuer: ISSUER, work_item_issuer: HARNESS, work_item: "work-1" },
      { mission_id: MISSION_A, issuer: ISSUER, work_item_issuer: HARNESS, work_item: "work-2" },
      { mission_id: MISSION_B, issuer: ISSUER, work_item_issuer: HARNESS, work_item: "work-3" },
    ]);
  });

  it("without a work item, a call carries no propagated reference, as before", async () => {
    const { channel, calls } = spyChannel();
    await new MediatedHarness(channel, MISSION_A, active).callTool("get_invoice", { invoice_id: "inv-1" }, "jwt");
    expect(calls[0]?.missionReference).toBeUndefined();
  });
});

const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const view = (id: string): MissionView => ({
  id,
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: `sha-256:${id}`,
  authority_set: [
    {
      type: "mission_resource_access",
      resource: CANONICAL_RESOURCE,
      actions: ["payments:invoice.read", "payments:invoice.list", "payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
    },
  ],
  subject: { iss: ISSUER, sub: "alice" },
  client_id: "ap-agent",
});

let signKey: CryptoKey;
let pubJwk: Record<string, unknown>;

/** A real ES256 Mission access token for `mission`, for the one client. */
async function missionToken(mission: string): Promise<string> {
  return new SignJWT({
    client_id: "ap-agent",
    client_instance_id: "inst-1",
    mission: { id: mission, issuer: ISSUER, authority_hash: `sha-256:${mission}` },
    cnf: { jkt: "jkt-815" },
    authorization_details: view(mission).authority_set,
  })
    .setProtectedHeader({ alg: "ES256", kid: "mission-key", typ: "at+jwt" })
    .setIssuer(ISSUER)
    .setAudience(CANONICAL_RESOURCE)
    .setSubject("alice")
    .setIssuedAt()
    .setExpirationTime("5m")
    .setJti(randomUUID())
    .sign(signKey);
}

/** The whole path: harness, real MCP channel, PEP, co-resident PDP; a test-only statement names the harness. */
async function stack() {
  const stmt = structuredClone(RUNTIME_POSTURE) as unknown as Record<string, unknown> & { extensions: Record<string, unknown> };
  stmt.extensions = {
    ...stmt.extensions,
    [WORK_ITEM_ATTRIBUTION_EXTENSION]: { attachers: [{ client_id: "ap-agent", harness: HARNESS }], covered_classes: [] },
  };
  const attribution = readWorkItemAttribution(stmt);
  const keys = createEphemeralEvidenceKeys({ resourcePolicy: RESOURCE_POLICY_PERMITS_ALL_FIXTURE });
  const payments = new PaymentsStore();
  payments.seed(
    [{ id: "acme", name: "Acme", status: "approved" }],
    [{ id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" }],
  );
  const loadView = (ref: { id: string; issuer: string }) =>
    (ref.id === MISSION_A || ref.id === MISSION_B) && ref.issuer === ISSUER
      ? { view: view(ref.id), observation: { state: "active", version: 1, mode: "fresh", freshness_at: new Date().toISOString() } }
      : undefined;
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const connectors = new Connectors();
  const requests: EvaluationRequest[] = [];
  const decisions: Decision[] = [];
  const pep = new Pep({
    decide: async (req, options) => {
      requests.push(structuredClone(req));
      const decision = await keys.decide(req, options);
      decisions.push(decision);
      return decision;
    },
    payments,
    evidence,
    fga: alwaysAllowFga,
    modelId: "unit-test-model",
    loadView,
    instanceEpoch: "epoch-815",
    workItemAttachers: attribution.attachers,
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [pubJwk] },
    keyRoles: { accessToken: ["mission-key"], attenuationRoot: [], transactionToken: [] },
    issuer: ISSUER,
    transaction: { engine: new TransactionEngine("epoch-815"), connectors, evidence },
    writeReservations: openEphemeralWriteReservationStore({ owner: "mcp-payments-pep" }),
  });
  const { client } = await createMediatedClient(server);
  return { client, evidence, connectors, requests, decisions };
}

describe("harness to PEP to PDP to evidence over the real MCP channel (@spec harness#work-item-identity, authzen#context-work-item, #815)", () => {
  beforeAll(async () => {
    const kp = await generateKeyPair("ES256", { extractable: true });
    signKey = kp.privateKey;
    pubJwk = { ...(await exportJWK(kp.publicKey)), kid: "mission-key", alg: "ES256" };
  });

  it("the harness's work item reaches context.work_item, the permit's condition, Decision Evidence and Execution Evidence", async () => {
    const s = await stack();
    const harness = new MediatedHarness(s.client, MISSION_A, active, { workItem: W1 });
    const res = await harness.callTool(
      "execute_wire_transfer",
      { invoice_id: "inv-1", idempotency_key: idem() },
      await missionToken(MISSION_A),
    );
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const ref = { issuer: HARNESS, id: "work-1" };
    expect((s.requests[0]?.context as Record<string, unknown>).work_item).toEqual(ref);
    expect((s.decisions[0]?.context.conditions as Record<string, unknown>).work_item).toEqual(ref);
    const records = s.evidence.forMission(MISSION_A);
    expect(records.filter((e): e is DecisionEvidence => e.kind === "decision").at(-1)?.content.work_item).toEqual(ref);
    const completed = records.filter((e): e is ExecutionEvidence => e.kind === "execution" && e.content.outcome === "completed");
    expect(completed.map((e) => e.content.work_item)).toEqual([ref]);
    expect(s.connectors.ledgerEntries(MISSION_A)).toHaveLength(1);
  });

  it("one client holding credentials for two Missions: a work item bound to Mission A on a call with Mission B's credential is refused, with no decision and no effect", async () => {
    const s = await stack();
    const harness = new MediatedHarness(s.client, MISSION_A, active, { workItem: W1 });
    const res = await harness.callTool(
      "execute_wire_transfer",
      { invoice_id: "inv-1", idempotency_key: idem() },
      await missionToken(MISSION_B),
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_reference_conflict");
    expect(s.requests).toHaveLength(0);
    expect(s.connectors.ledgerEntries(MISSION_A)).toHaveLength(0);
    expect(s.connectors.ledgerEntries(MISSION_B)).toHaveLength(0);
  });
});
