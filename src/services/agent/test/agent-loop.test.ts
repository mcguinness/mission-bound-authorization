/**
 * Increment 2 -- the opt-in LLM planner reaches tools ONLY through the mediated
 * harness (@spec draft-mcguinness-mission-harness, both duties).
 *
 * Mirrors services/mcp-payments/test/mcp-channel.test.ts's setup: the live-OpenFGA
 * composed stack, a real ES256-signed mission access token minted inline, and the
 * unchanged McpPaymentsServer/PEP behind the real MCP channel. The planner is a
 * MockLanguageModelV3 (from `ai/test`) so the test is KEY-FREE -- it scripts "a
 * tool call, then a final text" without any provider. Auto-skips when OpenFGA is
 * unreachable.
 *
 * The four assertions prove the planner cannot escape the channel: an adversarial
 * (out-of-bounds) plan is DENIED with zero side effects; an in-authority plan
 * PERMITS with exactly one ledger entry; a non-active mission fails closed BEFORE
 * the channel is ever touched; and the tool set the model is handed is
 * mission-scoped (ungranted tools never reach the LLM).
 */

import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { MockLanguageModelV3 } from "ai/test";
import {
  createMediatedHarness,
  type HarnessToolResult,
  MediatedHarness,
  type MediatedToolChannel,
  type MissionState,
  runAgentLoop,
} from "../src/index.js";
import { Fga, type MissionView } from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  TransactionEngine,
} from "@mission/mcp-payments";

// @spec runtime-evidence#decision-evidence-object (#741): one bundle per
// test module. `signing`/`resolver` wire the PEP's store; `decide` is the
// decision point's entry point, which closes over the PDP's emission path.
const EVIDENCE_KEYS = createEphemeralEvidenceKeys();

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;
const ISSUER = "https://as.test";
const AUTHORITY_HASH = "sha-256:mcphash";
const CNF_JKT = "jkt-1";
const GOAL = "Pay the payable Acme invoices within your mission's limits.";

async function reachable(): Promise<boolean> {
  try {
    if (CA) process.env.NODE_EXTRA_CA_CERTS = CA;
    return (await fetch(`${API_URL}/healthz`, { headers: { authorization: `Bearer ${KEY}` } })).ok;
  } catch {
    return false;
  }
}
const up = await reachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping agent-loop tests");

// A read+execute mission: reads + wire execution under a 500 cap for acme only.
// It does NOT grant remittance.send or payment.schedule (the ungranted tools).
const VIEW: MissionView = {
  id: "msn_agent",
  issuer: ISSUER,
  state: "active",
  version: 1,
  authority_hash: AUTHORITY_HASH,
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
};

let fga: Fga;
let modelId: string;
let signKey: CryptoKey;
let pubJwk: Record<string, unknown>;

/** Mint a real ES256-signed mission access token (aud = the RS resource). */
async function signMissionToken(): Promise<string> {
  return new SignJWT({
    client_id: "ap-agent",
    client_instance_id: "inst-1",
    mission: { id: VIEW.id, issuer: ISSUER, authority_hash: AUTHORITY_HASH },
    cnf: { jkt: CNF_JKT },
  })
    .setProtectedHeader({ alg: "ES256", kid: "mission-key" })
    .setIssuer(ISSUER)
    .setAudience(CANONICAL_RESOURCE)
    .setSubject("alice")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(signKey);
}

/** A fresh composed stack: authoritative store, live-FGA PEP, transaction tier. */
async function build(): Promise<{ server: McpPaymentsServer; connectors: Connectors; evidence: EvidenceStore }> {
  const payments = new PaymentsStore();
  payments.seed(
    [
      { id: "acme", name: "Acme", status: "approved" },
      { id: "globex", name: "Globex", status: "pending" },
    ],
    [
      { id: "inv-1", vendor_id: "acme", amount: "125.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-2", vendor_id: "acme", amount: "900.00", currency: "USD", payee_account: "acct-acme", status: "payable" },
      { id: "inv-3", vendor_id: "globex", amount: "50.00", currency: "USD", payee_account: "acct-globex", status: "payable" },
    ],
  );
  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
  const connectors = new Connectors();
  const engine = new TransactionEngine("epoch-1");
  // @spec runtime#state-freshness: a synchronous live read, freshness-
  // stamped at this read (Finding 1); "load_view" declared trusted below.
  // Implements the canonical (issuer, id) tuple contract (@spec
  // authority-server#reference-tuple, #685 review).
  const loadView = (ref: { id: string; issuer: string }) =>
    ref.id === VIEW.id && ref.issuer === VIEW.issuer
      ? { view: VIEW, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
      : undefined;
  const pep = new Pep({
    decide: EVIDENCE_KEYS.decide,
    payments,
    evidence,
    fga,
    modelId,
    loadView,
    instanceEpoch: "epoch-1",
    allowedFreshnessSources: new Set(["load_view"]),
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [pubJwk] },
    issuer: ISSUER,
    transaction: { engine, connectors, evidence },
  });
  return { server, connectors, evidence };
}

const active = async (): Promise<MissionState> => "active";
const revoked = async (): Promise<MissionState> => "revoked";

/** The V3 usage/finish shapes the mock's doGenerate must carry (values are nominal). */
const USAGE = {
  inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: 0 },
};

/** A planner that emits ONE tool call on step 1, then a final text on step 2. */
function toolThenText(toolName: string, args: Record<string, unknown>): MockLanguageModelV3 {
  let n = 0;
  return new MockLanguageModelV3({
    doGenerate: async () => {
      n += 1;
      if (n === 1) {
        return {
          content: [{ type: "tool-call", toolCallId: "call-1", toolName, input: JSON.stringify(args) }],
          finishReason: { unified: "tool-calls", raw: undefined },
          usage: USAGE,
          warnings: [],
        };
      }
      return {
        content: [{ type: "text", text: "done." }],
        finishReason: { unified: "stop", raw: undefined },
        usage: USAGE,
        warnings: [],
      };
    },
  });
}

/** A planner that emits only a final text (no tool call). */
function textOnly(text: string): MockLanguageModelV3 {
  return new MockLanguageModelV3({
    doGenerate: async () => ({
      content: [{ type: "text", text }],
      finishReason: { unified: "stop", raw: undefined },
      usage: USAGE,
      warnings: [],
    }),
  });
}

/** A spy channel that records every touch; its callTool is the side-effect oracle. */
function spyChannel(): { channel: MediatedToolChannel; calls: string[] } {
  const calls: string[] = [];
  const channel: MediatedToolChannel = {
    async listTools() {
      calls.push("listTools");
      return ["get_invoice", "execute_wire_transfer"];
    },
    async callTool(name) {
      calls.push(`callTool:${name}`);
      return { ok: true, result: { executed: true } };
    },
  };
  return { channel, calls };
}

/** The mediated tool results the planner saw, in order. */
function toolOutputs(res: { steps: { toolResults: { output: unknown }[] }[] }): HarnessToolResult[] {
  return res.steps.flatMap((s) => s.toolResults.map((t) => t.output)) as HarnessToolResult[];
}

d("agent loop (increment 2): the LLM planner reaches tools ONLY through the mediated harness", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
    const kp = await generateKeyPair("ES256", { extractable: true });
    signKey = kp.privateKey;
    pubJwk = { ...(await exportJWK(kp.publicKey)), kid: "mission-key", alg: "ES256" };
  });

  it("(a) adversarial: an out-of-bounds plan is DENIED at the channel; the ledger is UNCHANGED (0)", async () => {
    const { server, connectors } = await build();
    const harness = await createMediatedHarness(server, VIEW.id, active);
    const jwt = await signMissionToken();
    expect(connectors.ledgerEntries()).toHaveLength(0);
    // inv-2 is $900 > the $500 cap: the PEP must deny it at the mediated channel.
    const model = toolThenText("execute_wire_transfer", { invoice_id: "inv-2" });
    const res = await runAgentLoop({ harness, missionToken: jwt, goal: GOAL, model });
    const outputs = toolOutputs(res);
    expect(outputs).toHaveLength(1);
    expect(outputs[0]?.ok, JSON.stringify(outputs[0])).toBe(false);
    expect(outputs[0]?.denial_reason).toBe("constraint_exceeded");
    // The planner could not escape the channel -> no unauthorized side effect.
    expect(connectors.ledgerEntries()).toHaveLength(0);
  });

  it("(b) in-authority: an under-cap Acme wire PERMITS and commits exactly ONE ledger entry", async () => {
    const { server, connectors } = await build();
    const harness = await createMediatedHarness(server, VIEW.id, active);
    const jwt = await signMissionToken();
    // inv-1 is $125 <= cap, acme: in authority.
    const model = toolThenText("execute_wire_transfer", { invoice_id: "inv-1" });
    const res = await runAgentLoop({ harness, missionToken: jwt, goal: GOAL, model });
    const outputs = toolOutputs(res);
    expect(outputs).toHaveLength(1);
    expect(outputs[0]?.ok, JSON.stringify(outputs[0])).toBe(true);
    expect((outputs[0]?.result as { executed: boolean }).executed).toBe(true);
    expect(connectors.ledgerEntries()).toHaveLength(1);
  });

  it("(c) non-active mission: resumeGuard fails closed BEFORE the channel is touched (no side effect)", async () => {
    const spy = spyChannel();
    // A spy channel makes "the channel was never reached" directly observable; its
    // callTool is the side-effect oracle, so an untouched spy == no ledger entry.
    const harness = new MediatedHarness(spy.channel, VIEW.id, revoked);
    const jwt = await signMissionToken();
    const res = await runAgentLoop({ harness, missionToken: jwt, goal: GOAL, model: textOnly("mission not active; stopping.") });
    // The guard suppressed the whole tool surface: listTools never reached the channel.
    expect(spy.calls).toEqual([]);
    expect(res.text).toContain("stopping");
    // A direct attempt to act also fails closed before the channel (mirrors increment 1).
    const direct = await harness.callTool("execute_wire_transfer", { invoice_id: "inv-1" }, jwt);
    expect(direct.ok).toBe(false);
    expect(direct.refusal_reason).toBe("mission_not_active:revoked");
    expect(spy.calls).toEqual([]);
  });

  it("(d) the tool set handed to the model is mission-scoped -- ungranted tools are absent", async () => {
    const { server } = await build();
    const harness = await createMediatedHarness(server, VIEW.id, active);
    const jwt = await signMissionToken();
    const model = textOnly("nothing to do.");
    await runAgentLoop({ harness, missionToken: jwt, goal: GOAL, model });
    const offered = (model.doGenerateCalls[0]?.tools ?? []).map((t) => t.name).sort();
    expect(offered).toContain("get_invoice");
    expect(offered).toContain("execute_wire_transfer");
    // Ungranted for a read+execute mission -> never described to the planner.
    expect(offered).not.toContain("send_remittance_email");
    expect(offered).not.toContain("schedule_payment");
  });
});
