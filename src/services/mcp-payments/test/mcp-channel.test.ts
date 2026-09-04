/**
 * Increment 1 -- the mediated MCP channel no-bypass proof (@spec harness duty 2).
 *
 * Drives a REAL @modelcontextprotocol/sdk in-memory transport (client -> MCP
 * server -> the unchanged McpPaymentsServer/PEP) against the live-OpenFGA
 * composed stack, mirroring enforcement.test.ts's beforeAll. The mission
 * credential (a real ES256-signed mission access token) crosses IN the MCP
 * request under the `_meta` key and is validated server-side into TokenFacts.
 *
 * The centerpiece assertion: the mediated channel enforces IDENTICALLY to the
 * direct PEP path (parity), and every denied adversarial call produces ZERO
 * unauthorized side effects (ledger unchanged) with a decision/refusal record
 * present. Auto-skips when OpenFGA is unreachable. Key-free: keys are minted
 * inline per run.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { Fga, type MissionView } from "@mission/pdp";
import {
  CANONICAL_RESOURCE,
  Connectors,
  createEphemeralEvidenceKeys,
  createMcpChannel,
  createMediatedClient,
  EvidenceStore,
  type ExecutionEvidence,
  type MediatedClient,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;
const ISSUER = "https://as.test";
const AUTHORITY_HASH = "sha-256:mcphash";
const CNF_JKT = "jkt-1";

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
if (!up) console.warn("OpenFGA unreachable; skipping mediated MCP channel tests");

// A read+execute mission: reads + wire execution under a 500 cap for acme only.
// Note it does NOT grant remittance.send (an ungranted tool) or payment.schedule.
const VIEW: MissionView = {
  id: "msn_m4",
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
async function signMissionToken(opts: {
  missionId?: string;
  authorityHash?: string;
  cnfJkt?: string;
  key?: CryptoKey;
  jti?: string;
  identityContinuationHandle?: string;
}): Promise<string> {
  const token = new SignJWT({
    client_id: "ap-agent",
    client_instance_id: "inst-1",
    mission: { id: opts.missionId ?? VIEW.id, issuer: ISSUER, authority_hash: opts.authorityHash ?? AUTHORITY_HASH },
    cnf: { jkt: opts.cnfJkt ?? CNF_JKT },
    ...(opts.identityContinuationHandle ? { identity_continuation_handle: opts.identityContinuationHandle } : {}),
  })
    .setProtectedHeader({ alg: "ES256", kid: "mission-key" })
    .setIssuer(ISSUER)
    .setAudience(CANONICAL_RESOURCE)
    .setSubject("alice")
    .setIssuedAt()
    .setExpirationTime("5m");
  if (opts.jti) token.setJti(opts.jti);
  return token.sign(opts.key ?? signKey);
}

/** The TokenFacts the direct PEP path uses, equivalent to the signed token. */
function tokenFacts(missionId: string = VIEW.id): TokenFacts {
  return {
    sub: "alice",
    clientId: "ap-agent",
    clientInstanceId: "inst-1",
    mission: { id: missionId, issuer: ISSUER, authority_hash: AUTHORITY_HASH },
    cnfJkt: CNF_JKT,
  };
}

/** A fresh composed stack: authoritative store, live-FGA PEP, transaction tier,
 * and a connected mediated MCP client over the real in-memory transport. */
async function build(): Promise<{
  server: McpPaymentsServer;
  client: MediatedClient;
  connectors: Connectors;
  evidence: EvidenceStore;
}> {
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
  const evidence = new EvidenceStore(createEphemeralEvidenceKeys().signing);
  const connectors = new Connectors();
  const engine = new TransactionEngine("epoch-1");
  const card = { name: "payments" };
  // @spec runtime#state-freshness: a synchronous live read, freshness-
  // stamped at this read (Finding 1); "load_view" declared trusted below.
  // Deliberately NONCONFORMING (@spec authority-server#reference-tuple,
  // #685 review): matches on `id` alone so the issuer-conflict tests below
  // exercise enforceInner's OWN view-issuer check (mission_reference_conflict)
  // rather than the loader silently absorbing the mismatch. An ordinary
  // fixture keys on the full (issuer, id) tuple; this is the one
  // negative-boundary loader that intentionally does not.
  const loadView = (ref: { id: string }) =>
    ref.id === VIEW.id
      ? { view: VIEW, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
      : undefined;
  const pep = new Pep({
    payments,
    evidence,
    fga,
    modelId,
    loadView,
    instanceEpoch: "epoch-1",
    sourceDigest: sourceDigestOf(card),
    allowedFreshnessSources: new Set(["load_view"]),
  });
  const server = new McpPaymentsServer({
    pep,
    payments,
    loadView,
    jwks: { keys: [pubJwk] },
    issuer: ISSUER,
    serverCard: card,
    transaction: { engine, connectors, evidence },
  });
  const { client } = await createMediatedClient(server);
  return { server, client, connectors, evidence };
}

d("mediated MCP channel (harness duty 2: no bypass)", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
    const kp = await generateKeyPair("ES256", { extractable: true });
    signKey = kp.privateKey;
    pubJwk = { ...(await exportJWK(kp.publicKey)), kid: "mission-key", alg: "ES256" };
  });

  it("1: tools/list over MCP is mission-scoped -- an ungranted tool is not listed", async () => {
    const { client } = await build();
    const jwt = await signMissionToken({});
    const tools = (await client.listTools(jwt)).sort();
    expect(tools).toContain("get_invoice");
    expect(tools).toContain("execute_wire_transfer");
    // Ungranted for a read+execute mission -> absent (least exposure).
    expect(tools).not.toContain("send_remittance_email");
    expect(tools).not.toContain("schedule_payment");
    expect(tools).not.toContain("lookup_vendor");
  });

  it("2: an in-authority call over MCP permits, records evidence, and commits one ledger entry", async () => {
    const { client, connectors, evidence } = await build();
    expect(connectors.ledgerEntries()).toHaveLength(0);
    const jwt = await signMissionToken({});
    const res = await client.callTool("execute_wire_transfer", { invoice_id: "inv-1" }, jwt);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect((res.result as { executed: boolean }).executed).toBe(true);
    // Side-effect oracle: exactly one authorized ledger entry.
    expect(connectors.ledgerEntries()).toHaveLength(1);
    const ev = evidence.forMission("msn_m4");
    expect(
      ev.some(
        (e) =>
          e.kind === "decision" &&
          e.content.decision === "permit" &&
          e.content.action.name === "payments:payment.execute",
      ),
    ).toBe(true);
    expect(ev.some((e) => e.kind === "execution" && e.content.outcome === "completed")).toBe(true);
  });

  it("2c: a continued credential's jti + continuation handle reach Execution Evidence as hop_reference", async () => {
    // End to end: the claims are set on the SIGNED token, so this proves the
    // validateMissionToken -> TokenFacts -> ExecutionEvidence.hop_reference
    // wiring, not just the evidence-construction shape.
    const { client, evidence } = await build();
    const JTI = "jag_hopref_e2e";
    const HANDLE = "ich_0123456789abcdefABCD";
    const jwt = await signMissionToken({ jti: JTI, identityContinuationHandle: HANDLE });
    const res = await client.callTool("execute_wire_transfer", { invoice_id: "inv-1" }, jwt);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const exec = evidence.forMission("msn_m4").find((e): e is ExecutionEvidence => e.kind === "execution");
    expect(exec?.content.hop_reference).toEqual({ jti: JTI, mission_id: "msn_m4", continuation_handle: HANDLE });
  });

  // Each adversarial input is run twice on fresh stacks -- once over the direct
  // PEP method, once over MCP -- to prove the channel enforces IDENTICALLY.
  const adversarial: { name: string; tool: string; args: Record<string, unknown>; missionId?: string }[] = [
    { name: "over-cap wire (inv-2, 900 > 500)", tool: "execute_wire_transfer", args: { invoice_id: "inv-2" } },
    { name: "wrong-vendor wire (inv-3, globex)", tool: "execute_wire_transfer", args: { invoice_id: "inv-3" } },
    { name: "ungranted tool (send_remittance_email)", tool: "send_remittance_email", args: { invoice_id: "inv-1" } },
    { name: "unknown mission (msn_unknown)", tool: "execute_wire_transfer", args: { invoice_id: "inv-1" }, missionId: "msn_unknown" },
  ];

  for (const c of adversarial) {
    it(`3: adversarial "${c.name}" is DENIED over MCP with zero side effects and parity with the direct PEP`, async () => {
      // Direct PEP path.
      const direct = await build();
      const directRes = await direct.server.callTransactionTool(c.tool, c.args, tokenFacts(c.missionId));
      const directReason = directRes.denial_reason ?? directRes.refusal_reason;
      expect(directRes.ok).toBe(false);
      expect(direct.connectors.ledgerEntries()).toHaveLength(0);

      // Mediated MCP path.
      const mcp = await build();
      const jwt = await signMissionToken({ missionId: c.missionId });
      const mcpRes = await mcp.client.callTool(c.tool, c.args, jwt);
      const mcpReason = mcpRes.denial_reason ?? mcpRes.refusal_reason;
      expect(mcpRes.ok).toBe(false);

      // Identical enforcement: same verdict + reason.
      expect(mcpReason).toBe(directReason);
      expect(mcpReason).toBeTruthy();

      // Zero unauthorized side effects over MCP.
      expect(mcp.connectors.ledgerEntries()).toHaveLength(0);

      // Non-vacuous: the PEP recorded a deny/refusal carrying this exact reason.
      const recorded = mcp.evidence
        .all()
        .some(
          (e) =>
            (e.kind === "decision" && e.content.decision === "deny" && e.content.denial_reason === mcpReason) ||
            (e.kind === "refusal" && e.content.denial_reason === mcpReason),
        );
      expect(recorded, "expected a decision-deny or refusal record for this reason").toBe(true);
    });
  }

  it("3b: a tampered credential (bad signature) is denied at the channel with no PEP evidence", async () => {
    const { client, connectors, evidence } = await build();
    const otherKey = (await generateKeyPair("ES256", { extractable: true })).privateKey;
    const forged = await signMissionToken({ key: otherKey }); // not the server's jwks key
    const res = await client.callTool("execute_wire_transfer", { invoice_id: "inv-1" }, forged);
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("invalid_credential");
    // Never reached the PEP: no ledger entry, no evidence recorded.
    expect(connectors.ledgerEntries()).toHaveLength(0);
    expect(evidence.all()).toHaveLength(0);
  });

  it("3c: a call with NO credential in _meta is denied at the channel (the credential is required to cross in)", async () => {
    const { server, connectors, evidence } = await build();
    // A raw SDK client that attaches no `_meta` at all -- the most direct
    // bypass attempt against duty 2.
    const { clientTransport } = await createMcpChannel(server);
    const raw = new Client({ name: "raw", version: "0.0.1" }, { capabilities: {} });
    await raw.connect(clientTransport);

    const list = await raw.listTools();
    expect(list.tools).toHaveLength(0); // least exposure: no credential, no tools

    const res = await raw.callTool({ name: "execute_wire_transfer", arguments: { invoice_id: "inv-1" } });
    expect(res.isError).toBe(true);
    expect((res.structuredContent as { denial_reason?: string }).denial_reason).toBe("invalid_credential");

    // Never reached the PEP or the store.
    expect(connectors.ledgerEntries()).toHaveLength(0);
    expect(evidence.all()).toHaveLength(0);
    await raw.close();
  });

  it("2b: the standard reasons match the known direct-path denials (over-cap, wrong-vendor)", async () => {
    const { client } = await build();
    const jwt = await signMissionToken({});
    const overCap = await client.callTool("execute_wire_transfer", { invoice_id: "inv-2" }, jwt);
    expect(overCap.denial_reason).toBe("constraint_exceeded");
    const wrongVendor = await client.callTool("execute_wire_transfer", { invoice_id: "inv-3" }, jwt);
    expect(wrongVendor.denial_reason).toBe("out_of_authority");
  });
});

// @spec authority-server#mcp-reference — the reference rides params._meta on
// tools/call under the namespaced key; a conforming Mission PEP never
// silently ignores it.
d("MCP _meta Mission reference propagation", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
    const kp = await generateKeyPair("ES256", { extractable: true });
    signKey = kp.privateKey;
    pubJwk = { ...(await exportJWK(kp.publicKey)), kid: "mission-key", alg: "ES256" };
  });

  it("a credential naming a different Mission issuer than the loaded view is refused with mission_reference_conflict", async () => {
    const { client } = await build();
    const jwt = await new SignJWT({
      client_id: "ap-agent",
      client_instance_id: "inst-1",
      mission: { id: VIEW.id, issuer: "https://other.example", authority_hash: AUTHORITY_HASH },
      cnf: { jkt: CNF_JKT },
    })
      .setProtectedHeader({ alg: "ES256", kid: "mission-key" })
      .setIssuer(ISSUER)
      .setAudience(CANONICAL_RESOURCE)
      .setSubject("alice")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(signKey);
    const res = await client.callTool("get_invoice", { invoice_id: "inv-1" }, jwt);
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_reference_conflict");
  });

  it("a mission claim with a non-string issuer fails closed at validation", async () => {
    const { client } = await build();
    const jwt = await new SignJWT({
      client_id: "ap-agent",
      client_instance_id: "inst-1",
      mission: { id: VIEW.id, issuer: { evil: true }, authority_hash: AUTHORITY_HASH },
      cnf: { jkt: CNF_JKT },
    })
      .setProtectedHeader({ alg: "ES256", kid: "mission-key" })
      .setIssuer(ISSUER)
      .setAudience(CANONICAL_RESOURCE)
      .setSubject("alice")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(signKey);
    // Least exposure: an unvalidatable credential sees no tools at all.
    expect(await client.listTools(jwt)).toEqual([]);
    const res = await client.callTool("get_invoice", { invoice_id: "inv-1" }, jwt);
    expect(res.ok).toBe(false);
  });

  it("a matching _meta reference permits the call", async () => {
    const { client } = await build();
    const jwt = await signMissionToken({});
    const res = await client.callTool(
      "execute_wire_transfer",
      { invoice_id: "inv-1" },
      jwt,
      { mission_id: VIEW.id, issuer: ISSUER },
    );
    expect(res.ok).toBe(true);
  });

  it("a conflicting _meta reference is refused with mission_reference_conflict", async () => {
    const { client } = await build();
    const jwt = await signMissionToken({});
    const res = await client.callTool(
      "execute_wire_transfer",
      { invoice_id: "inv-1" },
      jwt,
      { mission_id: "msn_other", issuer: ISSUER },
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_reference_conflict");
  });

  it("a malformed _meta reference (extra member) is refused with mission_reference_conflict", async () => {
    const { client } = await build();
    const jwt = await signMissionToken({});
    const res = await client.callTool(
      "execute_wire_transfer",
      { invoice_id: "inv-1" },
      jwt,
      { mission_id: VIEW.id, issuer: ISSUER, state: "active" },
    );
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_reference_conflict");
  });

  it("an ORDINARY credential with a well-formed _meta reference is refused: this transport stays Mission-bound-only", async () => {
    // @spec authority-server#mission-join (#557) — the MAS Join is a property
    // of a CONFIGURED route, not of the reference. This mediated channel
    // validates through validateCredential and admits no ordinary credential,
    // so a perfectly good _meta reference joins nothing here: the reference
    // never becomes an admission path of its own.
    const { client, evidence } = await build();
    const ordinary = await new SignJWT({ client_id: "ap-agent", scope: "payments.read", cnf: { jkt: CNF_JKT } })
      .setProtectedHeader({ alg: "ES256", kid: "mission-key" })
      .setIssuer(ISSUER)
      .setAudience(CANONICAL_RESOURCE)
      .setSubject("alice")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(signKey);
    // Least exposure: an unadmitted credential sees no tools at all.
    expect(await client.listTools(ordinary)).toEqual([]);
    const res = await client.callTool(
      "get_invoice",
      { invoice_id: "inv-1" },
      ordinary,
      { mission_id: VIEW.id, issuer: ISSUER },
    );
    expect(res.ok).toBe(false);
    // The PEP was never reached, so nothing was decided or refused there.
    expect(evidence.all()).toHaveLength(0);
  });
});
