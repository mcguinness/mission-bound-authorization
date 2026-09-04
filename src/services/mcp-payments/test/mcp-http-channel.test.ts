/**
 * Increment 3 -- the mediated MCP channel over REAL HTTP with DPoP
 * proof-of-possession (@spec harness duty 2, closing the in-memory channel's PoP
 * gap). Drives a @modelcontextprotocol/sdk StreamableHTTP client -> a node HTTP
 * server (DPoP-auth middleware) -> StreamableHTTPServerTransport -> the unchanged
 * McpPaymentsServer/PEP, on an ephemeral 127.0.0.1 port, against the live-OpenFGA
 * composed stack (mirrors mcp-channel.test.ts's beforeAll). Auto-skips when
 * OpenFGA is unreachable. Key-free: mission + DPoP keys are minted inline per run.
 *
 * The mission access token is bound to the client's DPoP key (cnf.jkt = that key's
 * thumbprint); the credential travels IN the HTTP headers (Authorization: DPoP +
 * DPoP proof), not `_meta`. The centerpiece: a valid DPoP-bound call PERMITS
 * (happy path proves the canonical htu + PoP happy path), the channel enforces
 * IDENTICALLY to the direct PEP path (parity), and -- the point of increment 3 --
 * a token WITHOUT a matching DPoP proof (bearer-only, or a proof signed by the
 * wrong key) is rejected at the gate BEFORE the PEP: zero evidence, zero ledger.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { Fga, type MissionView } from "@mission/pdp";
import {
  ActorRecords,
  CANONICAL_RESOURCE,
  Connectors,
  canonicalHtu,
  createHttpMcpChannel,
  createHttpMediatedClient,
  type DpopKeys,
  dpopProofFor,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  type HttpMediatedClient,
  McpPaymentsServer,
  PaymentsStore,
  Pep,
  sourceDigestOf,
  type TokenFacts,
  TransactionEngine,
} from "../src/index.js";

// @spec runtime-evidence#decision-evidence-object (#741): one bundle per
// test module. `signing`/`resolver` wire the PEP's store; `decide` is the
// decision point's entry point, which closes over the PDP's emission path.
const EVIDENCE_KEYS = createEphemeralEvidenceKeys();

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;
const ISSUER = "https://as.test";
const AUTHORITY_HASH = "sha-256:mcphash";

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
if (!up) console.warn("OpenFGA unreachable; skipping HTTP mediated MCP channel tests");

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
// The client's DPoP keypair and its thumbprint; the mission token's cnf.jkt binds
// to THIS key, so a valid proof-of-possession must be signed by it.
let dpopKeys: DpopKeys;
let cnfJkt: string;

/** Mint a real ES256-signed mission access token bound to the DPoP key (cnf.jkt). */
async function signMissionToken(opts: { missionId?: string; cnfJkt?: string; key?: CryptoKey }): Promise<string> {
  return new SignJWT({
    client_id: "ap-agent",
    client_instance_id: "inst-1",
    mission: { id: opts.missionId ?? VIEW.id, issuer: ISSUER, authority_hash: AUTHORITY_HASH },
    cnf: { jkt: opts.cnfJkt ?? cnfJkt },
  })
    .setProtectedHeader({ alg: "ES256", kid: "mission-key" })
    .setIssuer(ISSUER)
    .setAudience(CANONICAL_RESOURCE)
    .setSubject("alice")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(opts.key ?? signKey);
}

/** The TokenFacts the direct PEP path uses, equivalent to the signed token. */
function tokenFacts(missionId: string = VIEW.id): TokenFacts {
  return {
    sub: "alice",
    clientId: "ap-agent",
    clientInstanceId: "inst-1",
    mission: { id: missionId, issuer: ISSUER, authority_hash: AUTHORITY_HASH },
    cnfJkt,
  };
}

// Each channel/client is registered here and torn down after the test so the
// ephemeral HTTP servers (and undici keep-alive sockets) never leak.
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const c of cleanups.splice(0).reverse()) await c().catch(() => {});
});

/** A fresh composed stack: authoritative store, live-FGA PEP, transaction tier,
 * and a started HTTP MCP channel on an ephemeral port. */
async function build(): Promise<{
  server: McpPaymentsServer;
  url: string;
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
  const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
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
    decide: EVIDENCE_KEYS.decide,
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
  const channel = await createHttpMcpChannel(server);
  cleanups.push(channel.close);
  return { server, url: channel.url, connectors, evidence };
}

/** Connect a valid DPoP-bound HTTP mediated client, registered for teardown. */
async function connect(url: string, jwt: string, keys: DpopKeys = dpopKeys): Promise<HttpMediatedClient> {
  const { client, close } = await createHttpMediatedClient(url, jwt, keys);
  cleanups.push(close);
  return client;
}

/** A raw JSON-RPC tools/call body -- an enforcement-bearing request, so a 401 on
 * it proves the credential gate fires before the PEP, not merely a failed handshake. */
function toolsCallBody(tool: string, args: Record<string, unknown>): string {
  return JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool, arguments: args } });
}

d("HTTP mediated MCP channel (harness duty 2 + DPoP proof-of-possession over HTTP)", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
    const kp = await generateKeyPair("ES256", { extractable: true });
    signKey = kp.privateKey;
    pubJwk = { ...(await exportJWK(kp.publicKey)), kid: "mission-key", alg: "ES256" };
    dpopKeys = await generateKeyPair("ES256", { extractable: true });
    cnfJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));
  });

  it("1: HAPPY PATH -- a valid DPoP-bound in-authority call PERMITS, commits one ledger entry, records evidence", async () => {
    const { url, connectors, evidence } = await build();
    expect(connectors.ledgerEntries()).toHaveLength(0);
    const jwt = await signMissionToken({});
    const client = await connect(url, jwt);
    const res = await client.callTool("execute_wire_transfer", { invoice_id: "inv-1" });
    // Proves the canonical htu derivation + DPoP PoP happy path really work over HTTP.
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect((res.result as { executed: boolean }).executed).toBe(true);
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

  it("2: tools/list over HTTP is mission-scoped -- an ungranted tool is not listed", async () => {
    const { url } = await build();
    const jwt = await signMissionToken({});
    const client = await connect(url, jwt);
    const tools = (await client.listTools()).sort();
    expect(tools).toContain("get_invoice");
    expect(tools).toContain("execute_wire_transfer");
    // Ungranted for a read+execute mission -> absent (least exposure).
    expect(tools).not.toContain("send_remittance_email");
    expect(tools).not.toContain("schedule_payment");
    expect(tools).not.toContain("lookup_vendor");
  });

  // Each adversarial input runs twice on fresh stacks -- once over the direct PEP
  // method, once over HTTP -- to prove the channel enforces IDENTICALLY.
  const adversarial: { name: string; tool: string; args: Record<string, unknown> }[] = [
    { name: "over-cap wire (inv-2, 900 > 500)", tool: "execute_wire_transfer", args: { invoice_id: "inv-2" } },
    { name: "wrong-vendor wire (inv-3, globex)", tool: "execute_wire_transfer", args: { invoice_id: "inv-3" } },
    { name: "ungranted tool (send_remittance_email)", tool: "send_remittance_email", args: { invoice_id: "inv-1" } },
  ];

  for (const c of adversarial) {
    it(`3: adversarial "${c.name}" is DENIED over HTTP with zero side effects and parity with the direct PEP`, async () => {
      // Direct PEP path.
      const direct = await build();
      const directRes = await direct.server.callTransactionTool(c.tool, c.args, tokenFacts());
      const directReason = directRes.denial_reason ?? directRes.refusal_reason;
      expect(directRes.ok).toBe(false);
      expect(direct.connectors.ledgerEntries()).toHaveLength(0);

      // Mediated HTTP path.
      const mcp = await build();
      const jwt = await signMissionToken({});
      const client = await connect(mcp.url, jwt);
      const mcpRes = await client.callTool(c.tool, c.args);
      const mcpReason = mcpRes.denial_reason ?? mcpRes.refusal_reason;
      expect(mcpRes.ok).toBe(false);

      // Identical enforcement: same verdict + reason.
      expect(mcpReason).toBe(directReason);
      expect(mcpReason).toBeTruthy();

      // Zero unauthorized side effects over HTTP.
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

  it("4a: DISCRIMINATING token-without-a-DPoP-proof (valid token, no proof header; and the bearer scheme) is rejected at the gate BEFORE the PEP -- zero evidence/ledger; a valid DPoP client on the SAME server then permits", async () => {
    const { url, connectors, evidence } = await build();
    const jwt = await signMissionToken({});
    const body = toolsCallBody("execute_wire_transfer", { invoice_id: "inv-1" });

    // THE increment-1 -> increment-3 delta: a VALID token presented in the DPoP
    // scheme but with NO DPoP proof header. This passes the scheme check and is
    // rejected specifically because proof-of-possession is absent -- in increment 1
    // the token alone sufficed; here it must not.
    const noProof = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `DPoP ${jwt}` },
      body,
    });
    await noProof.text();
    expect(noProof.status).toBe(401);

    // The bearer scheme (token as a plain Bearer) is likewise refused.
    const bearer = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${jwt}` },
      body,
    });
    await bearer.text();
    expect(bearer.status).toBe(401);

    // Neither reached the PEP: no ledger entry, no evidence recorded.
    expect(connectors.ledgerEntries()).toHaveLength(0);
    expect(evidence.all()).toHaveLength(0);

    // The SDK client cannot even initialize with bearer-only headers (401 at initialize).
    const bearerTransport = new StreamableHTTPClientTransport(new URL(url), {
      fetch: async (input, init) => {
        const headers = new Headers(init?.headers);
        headers.set("authorization", `Bearer ${jwt}`); // Bearer, and deliberately NO DPoP proof.
        return fetch(input, { ...init, headers });
      },
    });
    const bearerClient = new Client({ name: "bearer-only", version: "0.0.1" }, { capabilities: {} });
    await expect(bearerClient.connect(bearerTransport as never)).rejects.toThrow();

    // Non-vacuous: the same live server permits a valid DPoP-bound call, so the
    // zeros above are attributable to the missing proof, not a dead stack.
    const client = await connect(url, jwt);
    const okRes = await client.callTool("execute_wire_transfer", { invoice_id: "inv-1" });
    expect(okRes.ok, JSON.stringify(okRes)).toBe(true);
    expect(connectors.ledgerEntries()).toHaveLength(1);
  });

  it("4b: DISCRIMINATING mismatched-key (DPoP proof signed by a DIFFERENT key than cnf.jkt) is rejected BEFORE the PEP -- zero evidence/ledger; a valid DPoP client on the SAME server then permits", async () => {
    const { url, connectors, evidence } = await build();
    const jwt = await signMissionToken({});
    const wrongKeys = await generateKeyPair("ES256", { extractable: true });

    // A well-formed DPoP proof (correct canonical htu/htm) signed by the WRONG key:
    // its thumbprint != token cnf.jkt, so validateToken rejects at the gate.
    const badProof = await dpopProofFor(wrongKeys, canonicalHtu(new URL(url)), "POST");
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `DPoP ${jwt}`, dpop: badProof },
      body: toolsCallBody("execute_wire_transfer", { invoice_id: "inv-1" }),
    });
    await res.text();
    expect(res.status).toBe(401);
    // The PEP was never reached.
    expect(connectors.ledgerEntries()).toHaveLength(0);
    expect(evidence.all()).toHaveLength(0);

    // The SDK client whose fetch signs proofs with the wrong key cannot initialize.
    const badTransport = new StreamableHTTPClientTransport(new URL(url), {
      fetch: async (input, init) => {
        const proof = await dpopProofFor(wrongKeys, canonicalHtu(input), init?.method ?? "GET");
        const headers = new Headers(init?.headers);
        headers.set("authorization", `DPoP ${jwt}`);
        headers.set("dpop", proof);
        return fetch(input, { ...init, headers });
      },
    });
    const badClient = new Client({ name: "wrong-key", version: "0.0.1" }, { capabilities: {} });
    await expect(badClient.connect(badTransport as never)).rejects.toThrow();

    // Non-vacuous: the RIGHT key (matching cnf.jkt) on the SAME server permits.
    const client = await connect(url, jwt);
    const okRes = await client.callTool("execute_wire_transfer", { invoice_id: "inv-1" });
    expect(okRes.ok, JSON.stringify(okRes)).toBe(true);
    expect(connectors.ledgerEntries()).toHaveLength(1);
  });
});

// @spec authority-server#reference-verification — the gateway PEP path:
// the propagated reference is a selection assertion checked against the
// credential-carried reference; conflicts and unusable carriage refuse as
// mission_reference_conflict, and a matching reference changes nothing.
d("Mission-Reference propagation (gateway PEP)", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
    const kp = await generateKeyPair("ES256", { extractable: true });
    signKey = kp.privateKey;
    pubJwk = { ...(await exportJWK(kp.publicKey)), kid: "mission-key", alg: "ES256" };
    dpopKeys = await generateKeyPair("ES256", { extractable: true });
    cnfJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));
  });

  async function callWithHeader(header?: string) {
    const { url } = await build();
    const jwt = await signMissionToken({});
    const { client, close } = await createHttpMediatedClient(
      url,
      jwt,
      dpopKeys,
      header === undefined ? {} : { "mission-reference": header },
    );
    cleanups.push(close);
    return client.callTool("execute_wire_transfer", { invoice_id: "inv-1" });
  }

  it("a matching propagated reference permits the governed call", async () => {
    const res = await callWithHeader(`id="${VIEW.id}", issuer="${ISSUER}"`);
    expect(res.ok).toBe(true);
  });

  it("a propagated reference naming a different Mission is refused with mission_reference_conflict", async () => {
    const res = await callWithHeader(`id="msn_other", issuer="${ISSUER}"`);
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_reference_conflict");
  });

  it("a propagated reference naming a different issuer is refused with mission_reference_conflict", async () => {
    const res = await callWithHeader(`id="${VIEW.id}", issuer="https://other.example"`);
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_reference_conflict");
  });

  it("a malformed reference (extra member) is refused with mission_reference_conflict", async () => {
    const res = await callWithHeader(`id="${VIEW.id}", issuer="${ISSUER}", state="active"`);
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_reference_conflict");
  });

  it("an absent reference leaves the credential-established path unchanged", async () => {
    const res = await callWithHeader(undefined);
    expect(res.ok).toBe(true);
  });
});

// @spec authority-server#mission-join (#557) — the MAS-GOVERNED route: an
// ORDINARY OAuth credential (no `mission` claim at all) admitted by the
// channel's own validator and joined against the propagated Mission
// Reference, which is the ONLY thing naming a Mission on this path. Auto-skips
// without OpenFGA like every block here, so each conformance claim also
// anchors on services/mcp-payments/test/mas-join.test.ts, which always runs.
d("MAS-governed HTTP MCP channel (baseline Join)", () => {
  beforeAll(async () => {
    const conn = await Fga.connect({ apiUrl: API_URL, presharedKey: KEY, caCertPath: CA });
    fga = conn.fga;
    modelId = conn.modelId;
    const kp = await generateKeyPair("ES256", { extractable: true });
    signKey = kp.privateKey;
    pubJwk = { ...(await exportJWK(kp.publicKey)), kid: "mission-key", alg: "ES256" };
    dpopKeys = await generateKeyPair("ES256", { extractable: true });
    cnfJkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));
  });

  /** This route's scope-to-authority model (rule 8, bound 1), as config ships it. */
  const SCOPE_ACTIONS: Record<string, string[]> = {
    "payments.read": ["payments:invoice.read", "payments:invoice.list", "payments:payment.execute"],
  };

  /**
   * An ORDINARY DPoP-bound credential: this AS's own issuer and the payments
   * audience, a `scope`, and NO `mission` claim. Minted inline with this
   * file's own key, so the coverage here is independent of the demo stack's
   * dev issuance route.
   */
  async function signOrdinaryToken(opts: { scope?: string; sub?: string; clientId?: string } = {}): Promise<string> {
    return new SignJWT({
      client_id: opts.clientId ?? "ap-agent",
      scope: opts.scope ?? "payments.read",
      cnf: { jkt: cnfJkt },
    })
      .setProtectedHeader({ alg: "ES256", kid: "mission-key" })
      .setIssuer(ISSUER)
      .setAudience(CANONICAL_RESOURCE)
      .setSubject(opts.sub ?? "alice")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(signKey);
  }

  /**
   * @spec authority-server#mission-join rule 5 — the same Mission with its
   * one entry made delegable to `delegate-client` at a depth of 1.
   */
  const DELEGATE_VIEW: MissionView = {
    ...VIEW,
    authority_set: VIEW.authority_set.map((e) => ({
      ...e,
      join_delegation: { max_depth: 1, allowed_delegates: ["delegate-client"] },
    })),
  };

  /**
   * A stack whose ONE channel is MAS-governed, with the PEP configured to
   * join. `delegate` swaps in the delegable view, the enumerated delegate
   * policy, and a deployment actor-record ledger; `recordEdge` decides
   * whether that ledger actually records the delegation.
   */
  async function buildGoverned(
    opts: { delegate?: boolean; recordEdge?: boolean } = {},
  ): Promise<{ url: string; evidence: EvidenceStore }> {
    const payments = new PaymentsStore();
    payments.seed(
      [{ id: "acme", name: "Acme", status: "approved" }],
      [
        {
          id: "inv-1",
          vendor_id: "acme",
          amount: "125.00",
          currency: "USD",
          payee_account: "acct-acme",
          status: "payable",
        },
      ],
    );
    // @spec runtime-evidence#decision-evidence-object (#741): this module's
    // one bundle, the same one the Mission-bound fixture above uses. The
    // joined path is a decision path like any other, so its PEP receives
    // `decide` and a resolver that verifies what the decision point emits.
    const evidence = new EvidenceStore(EVIDENCE_KEYS.signing, EVIDENCE_KEYS.resolver);
    const card = { name: "payments" };
    // Conforming (@spec authority-server#reference-tuple): keyed on the full
    // canonical pair, unlike this file's Mission-bound fixture, which keys on
    // `id` alone on purpose.
    const view = opts.delegate ? DELEGATE_VIEW : VIEW;
    const loadView = (ref: { id: string; issuer: string }) =>
      ref.id === view.id && ref.issuer === view.issuer
        ? { view, freshness: { observed_at: new Date().toISOString(), source: "load_view" } }
        : undefined;
    // The deployment's actor records: rule 5's depth source. Empty unless this
    // deployment recorded the edge, which is what makes an unrecorded
    // delegate fail closed rather than join on a declared ceiling alone.
    const records = new ActorRecords();
    if (opts.recordEdge) {
      records.record({
        mission: { id: view.id, issuer: view.issuer },
        clientId: "delegate-client",
        delegatedBy: view.client_id,
      });
    }
    const pep = new Pep({
      decide: EVIDENCE_KEYS.decide,
      payments,
      evidence,
      fga,
      modelId,
      loadView,
      instanceEpoch: "epoch-1",
      sourceDigest: sourceDigestOf(card),
      allowedFreshnessSources: new Set(["load_view"]),
      masJoin: {
        // Rule 8, bound 1: read from the credential AS ISSUED, its own scope.
        resolveOrdinaryAuthority: (token) => {
          if (token.mission || !token.scope) return undefined;
          const actions = SCOPE_ACTIONS[token.scope];
          return actions
            ? [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions }]
            : undefined;
        },
        // Rule 4: enumerated, never a default.
        ...(opts.delegate ? { delegatePolicy: { delegates: { "delegate-client": { maxDepth: 1 } } } } : {}),
        resolveDelegateDepth: records.resolveDepth.bind(records),
      },
    });
    const server = new McpPaymentsServer({
      pep,
      payments,
      loadView,
      jwks: { keys: [pubJwk] },
      issuer: ISSUER,
      serverCard: card,
    });
    const channel = await createHttpMcpChannel(server, { masGoverned: true });
    cleanups.push(channel.close);
    return { url: channel.url, evidence };
  }

  it("permits a joined read for an ordinary credential when the Mission-Reference field is present", async () => {
    const { url } = await buildGoverned();
    const { client, close } = await createHttpMediatedClient(url, await signOrdinaryToken(), dpopKeys, {
      "mission-reference": `id="${VIEW.id}", issuer="${ISSUER}"`,
    });
    cleanups.push(close);
    const res = await client.callTool("get_invoice", { invoice_id: "inv-1" });
    expect(res.ok, JSON.stringify(res)).toBe(true);
  });

  it("refuses unknown_mission with the Mission-Reference field ABSENT: the credential establishes no Mission of its own", async () => {
    const { url } = await buildGoverned();
    const { client, close } = await createHttpMediatedClient(url, await signOrdinaryToken(), dpopKeys);
    cleanups.push(close);
    const res = await client.callTool("get_invoice", { invoice_id: "inv-1" });
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("unknown_mission");
  });

  it("refuses mission_reference_conflict with a MALFORMED Mission-Reference field, a different failure from an absent one", async () => {
    const { url } = await buildGoverned();
    const { client, close } = await createHttpMediatedClient(url, await signOrdinaryToken(), dpopKeys, {
      "mission-reference": `id="${VIEW.id}", issuer="${ISSUER}", state="active"`,
    });
    cleanups.push(close);
    const res = await client.callTool("get_invoice", { invoice_id: "inv-1" });
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("mission_reference_conflict");
  });

  it("refuses out_of_authority for a scope this route maps to nothing, even with a well-formed reference", async () => {
    const { url } = await buildGoverned();
    const { client, close } = await createHttpMediatedClient(
      url,
      await signOrdinaryToken({ scope: "payments.unmapped" }),
      dpopKeys,
      { "mission-reference": `id="${VIEW.id}", issuer="${ISSUER}"` },
    );
    cleanups.push(close);
    const res = await client.callTool("get_invoice", { invoice_id: "inv-1" });
    expect(res.ok).toBe(false);
    expect(res.refusal_reason).toBe("out_of_authority");
  });

  it("permits a delegate whose depth the deployment's actor records supply, narrowed to the delegable subset", async () => {
    const { url } = await buildGoverned({ delegate: true, recordEdge: true });
    const { client, close } = await createHttpMediatedClient(
      url,
      await signOrdinaryToken({ clientId: "delegate-client" }),
      dpopKeys,
      { "mission-reference": `id="${VIEW.id}", issuer="${ISSUER}"` },
    );
    cleanups.push(close);
    const res = await client.callTool("get_invoice", { invoice_id: "inv-1" });
    expect(res.ok, JSON.stringify(res)).toBe(true);
  });

  it("denies mission_mismatch for the SAME delegate when nothing recorded the edge: no actor record, no join", async () => {
    const { url } = await buildGoverned({ delegate: true });
    const { client, close } = await createHttpMediatedClient(
      url,
      await signOrdinaryToken({ clientId: "delegate-client" }),
      dpopKeys,
      { "mission-reference": `id="${VIEW.id}", issuer="${ISSUER}"` },
    );
    cleanups.push(close);
    const res = await client.callTool("get_invoice", { invoice_id: "inv-1" });
    expect(res.ok).toBe(false);
    expect(res.denial_reason).toBe("mission_mismatch");
  });

  it("the MISSION-BOUND channel rejects the same ordinary credential at the gate, before the PEP", async () => {
    // The route's validator is the first of the two keys: a channel that is
    // not MAS-governed keeps validateCredential and refuses a credential with
    // no `mission` claim outright, whatever the reference says.
    const { url, evidence } = await build();
    const jwt = await signOrdinaryToken();
    const proof = await dpopProofFor(dpopKeys, canonicalHtu(new URL(url)), "POST");
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `DPoP ${jwt}`,
        dpop: proof,
        "mission-reference": `id="${VIEW.id}", issuer="${ISSUER}"`,
      },
      body: toolsCallBody("get_invoice", { invoice_id: "inv-1" }),
    });
    await res.text();
    expect(res.status).toBe(401);
    // Never reached the PEP: no decision, no refusal record.
    expect(evidence.all()).toHaveLength(0);
  });
});
