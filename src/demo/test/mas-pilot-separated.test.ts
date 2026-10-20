/**
 * @spec authority-server#mission-join rules 2 and 7, authority-server#join-disclosure,
 * runtime#state-freshness, authzen#failure-condition-coverage (#818 slice 4b, D560)
 *
 * The separated MAS pilot end to end: the MAS is the reference authorization
 * server in its own OS process (`mas-process.ts`), holding the Missions; the
 * pilot holds no kernel and reads them through the MAS's signed Mission
 * Status. The test approves Missions through the MAS's operator channel and
 * changes their state through its HTTP Lifecycle surface only. Every refusal
 * asserts that no effect was committed and names its evidence carrier: the
 * PDP's signed Decision Evidence, or the PEP's signed Refusal Record when no
 * decision was reached.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { initSigningKeyRing } from "@mission/authorization-server";
import { DEV_SERVICE_TOKEN, TOPOLOGY } from "@mission/demo-data";
import { CANONICAL_RESOURCE, type DecisionEvidence, type RefusalRecord } from "@mission/mcp-payments";
import { type EvaluationRequest, type MissionView, policyViewId } from "@mission/pdp";
import { decodeJwt, generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadMasPilotConfig, type MasPilotConfig } from "../src/mas-pilot/config.js";
import { type MasProcess, startMasProcess } from "../src/mas-pilot/mas-process.js";
import { composeSeparatedMasPilot, type SeparatedMasPilot } from "../src/mas-pilot/separated.js";
import { admin, call, estateToken, OPENFGA, openfgaReachable, READ_ACTIONS, relocateEstate } from "./mas-pilot-support.js";

const d = (await openfgaReachable()) ? describe : describe.skip;

const MAS_PORT = 14835;
const MAS_URL = `http://127.0.0.1:${MAS_PORT}`;
const ESTATE_PORT = 14843;
const UNENROLLED_ESTATE_PORT = 14847;
const TIMEOUT_ESTATE_PORT = 14850;
const DOUBLE_ESTATE_PORT = 14852;
const EXECUTE = "payments:payment.execute";

/**
 * The pilot configuration for the separated MAS: the estate at `estatePort`,
 * the Mission issuer moved to the MAS's own URL (wherever the configuration
 * names it), and, for the commit-phase witness, one estate scope that maps to
 * `payments:payment.execute`, which the shipped configuration maps to none.
 */
function separatedConfig(estatePort: number, timeoutMs?: number): MasPilotConfig {
  const base = relocateEstate(loadMasPilotConfig(), estatePort);
  const moved = JSON.parse(
    JSON.stringify(base).split(JSON.stringify(base.mission_issuer).slice(1, -1)).join(MAS_URL),
  ) as MasPilotConfig & { mapping_contract: { scopes: { issuers: Record<string, Record<string, string[]>> } } };
  moved.mapping_contract.scopes.issuers[moved.estate.issuer] = {
    ...moved.mapping_contract.scopes.issuers[moved.estate.issuer],
    "payments.execute": [EXECUTE],
  };
  moved.estate.resource_servers[CANONICAL_RESOURCE] = { scope: "invoices.read vendors.read remit.send payments.execute" };
  moved.estate.clients = moved.estate.clients.map((c) =>
    c.client_id === "estate-ap-bot-7f3" ? { ...c, scope: `${c.scope} payments.execute` } : c,
  );
  return {
    ...moved,
    separated_mas: {
      ...moved.separated_mas,
      port: MAS_PORT,
      state_source: { ...moved.separated_mas.state_source, ...(timeoutMs ? { timeout_ms: timeoutMs } : {}) },
    },
  };
}

const dirs: string[] = [];
const servers: Server[] = [];
let mas: MasProcess;
let masOptions: Parameters<typeof startMasProcess>[0];
let pilot: SeparatedMasPilot;
const requests: EvaluationRequest[] = [];
const pdpToken = `pdp-${crypto.randomUUID()}`;

/**
 * One offset for this process's PEP, PDP and resolver clocks and the MAS's
 * kernel clock. It only grows across the file (61 s per advance, 183 s by the
 * last test); estate tokens live 300 s from their real-time issue and the
 * mapping contract's 300 s bound starts at composition, so a test added after
 * these must keep the total well under 300 s or compose its own pilot.
 */
let offsetMs = 0;
const now = () => new Date(Date.now() + offsetMs);
async function advance(ms: number): Promise<void> {
  offsetMs += ms;
  await mas.setClockOffset(offsetMs);
}

/** A Mission the MAS approves for `sub` under `ap-agent`, through its operator channel. */
function approveAtMas(sub: string, label: string, actions: string[] = READ_ACTIONS): Promise<string> {
  return mas.approve({
    intent: JSON.stringify({ goal: `Separated MAS pilot: ${label}`, target_resources: [CANONICAL_RESOURCE], expires_at: "2027-06-01T00:00:00Z" }),
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: CANONICAL_RESOURCE,
        actions,
        constraints: { vendors: ["acme"], ...(actions.includes(EXECUTE) ? { max_amount: { amount: "500.00", currency: "USD" } } : {}) },
      },
    ],
    subject: { iss: MAS_URL, sub },
    approver: { iss: MAS_URL, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-separated-${label}-${crypto.randomUUID()}`,
  });
}

/** A Lifecycle operation at the MAS, as its operator's tooling sends it. */
async function lifecycle(missionId: string, body: Record<string, unknown>): Promise<void> {
  const res = await fetch(`${MAS_URL}/missions/${missionId}/lifecycle`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
    body: JSON.stringify({ nonce: crypto.randomUUID(), ...body }),
  });
  expect(res.status, await res.clone().text()).toBe(200);
  await res.arrayBuffer();
}

const decisions = (p: SeparatedMasPilot, missionId: string) =>
  p.evidence.forMission(missionId).filter((e): e is DecisionEvidence => e.kind === "decision");
const refusals = (p: SeparatedMasPilot, missionId: string) =>
  p.evidence.forMission(missionId).filter((e): e is RefusalRecord => e.kind === "refusal");

beforeAll(async () => {
  const dir = mkdtempSync(join(tmpdir(), "mas-pilot-separated-"));
  dirs.push(dir);
  const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
  const keyRing = join(dir, "keys", "ring.json");
  await initSigningKeyRing(keyRing, MAS_URL, { asToken, asStatus, asTxn, asContinuation });
  const configPath = join(dir, "mas-pilot.json");
  const config = separatedConfig(ESTATE_PORT);
  writeFileSync(configPath, JSON.stringify(config));
  masOptions = { configPath, pdpToken, keyRing, kernelStore: join(dir, "state", "kernel.db") };
  mas = await startMasProcess(masOptions);
  pilot = await composeSeparatedMasPilot({
    openfga: OPENFGA,
    resourcePolicyStore: { bootstrap: "development" },
    observeDecisionRequest: (r) => requests.push(r),
    config,
    now,
    mas: { url: MAS_URL, pdpToken },
  });
}, 120_000);

afterAll(async () => {
  await pilot?.close();
  await mas?.stop();
  for (const s of servers) {
    s.closeAllConnections();
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

d("the separated MAS pilot: the PDP reads Missions through the MAS's signed Mission Status (#818 slice 4b)", () => {
  it("permits a joined read on the Status view, with Join Disclosure, the MAS's own state version, and a permit capped by the signed fresh_until", async () => {
    const missionId = await approveAtMas("alice", "positive");
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read vendors.read");
    const res = await call(pilot, credential, missionId, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok, JSON.stringify(res)).toBe(true);
    // Placed with the PDP: the PEP sends no state observation.
    expect(requests.at(-1)?.context.mission_state_observation).toBeUndefined();
    // What the PDP read: the MAS's signed answer, with the disclosed Subject and client.
    const read = pilot.resolver.peek({ id: missionId, issuer: MAS_URL });
    expect(read?.view).toMatchObject({ state: "active", subject: { iss: MAS_URL, sub: "alice" }, client_id: "ap-agent" });
    // The decision is the MAS's state: its version, read back directly.
    const direct = await fetch(`${MAS_URL}/missions/${missionId}/status?audience=${encodeURIComponent(CANONICAL_RESOURCE)}`, {
      headers: { "x-service-token": pdpToken },
    });
    const status = decodeJwt(await direct.text()) as { mission: { version: number; authority_hash: string } };
    const decision = decisions(pilot, missionId).at(-1)?.content;
    expect(decision?.decision).toBe("permit");
    // `policy_view_id` commits the Mission's state version and authority_hash.
    const committed = policyViewId(
      { id: missionId, version: status.mission.version, authority_hash: status.mission.authority_hash } as MissionView,
      pilot.resourcePolicy.modelId,
    );
    expect(decision?.mission).toMatchObject({ policy_view_id: committed, authority_hash: status.mission.authority_hash });
    // The signed window (60 s) is shorter than the read class's 300 s, and the permit ends inside it.
    const freshUntilMs = read?.freshUntilMs as number;
    expect(freshUntilMs - (read?.observedAtMs as number)).toBeLessThan(300_000);
    expect(Date.parse(decision?.conditions?.valid_until as string)).toBeLessThanOrEqual(freshUntilMs);
  });

  it("denies the action a containment at the MAS removed out_of_authority, the Status view's declared diagnostic, while the uncontained read still permits", async () => {
    const missionId = await approveAtMas("alice", "contained");
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read vendors.read");
    expect((await call(pilot, credential, missionId, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    await lifecycle(missionId, {
      operation: "contain",
      event: { type: "anomaly.detected", source: "svc:soc", observed_at: now().toISOString(), event_id: `evt-${crypto.randomUUID()}` },
      remove: [{ resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
    });
    await advance(61_000);
    const after = await call(pilot, credential, missionId, "get_invoice", { invoice_id: "inv-1" });
    // The PDP decides it: the Status view no longer carries the action, so it
    // is outside the Authority Set (rule 7), not a contained entry.
    expect(after).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
    expect(decisions(pilot, missionId).at(-1)?.content).toMatchObject({ decision: "deny", denial_reason: "out_of_authority" });
    expect(pilot.resolver.peek({ id: missionId, issuer: MAS_URL })?.view.authority_set.flatMap((e) => e.actions)).not.toContain(
      "payments:invoice.read",
    );
    const vendor = await call(pilot, credential, missionId, "lookup_vendor", { vendor_id: "acme" });
    expect(vendor.ok, JSON.stringify(vendor)).toBe(true);
  });

  it("observes a revocation at the MAS within the signed bound: relied on until its fresh_until, then mission_inactive", async () => {
    const missionId = await approveAtMas("alice", "revoked");
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    expect((await call(pilot, credential, missionId, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    await lifecycle(missionId, { operation: "revoke" });
    // Inside the signed window the earlier observation stands (the declared bound).
    expect((await call(pilot, credential, missionId, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    await advance(61_000);
    const after = await call(pilot, credential, missionId, "get_invoice", { invoice_id: "inv-1" });
    expect(after).toMatchObject({ ok: false, denial_reason: "mission_inactive" });
    expect(decisions(pilot, missionId).at(-1)?.content).toMatchObject({ decision: "deny", denial_reason: "mission_inactive" });
  });

  it("refuses the commit crossing of a Mission revoked after its prepare: the commit-phase decision reads the MAS now, and commits nothing", async () => {
    const missionId = await approveAtMas("alice", "commit", [...READ_ACTIONS, EXECUTE]);
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read payments.execute");
    await admin(pilot, "grant", "--iss", pilot.estate.issuer, "--sub", "u-1001", "--relation", "payer", "--vendor", "acme");
    try {
      const prepare = await call(pilot, credential, missionId, "hold_transfer", { invoice_id: "inv-1" });
      expect(prepare.ok, JSON.stringify(prepare)).toBe(true);
      await lifecycle(missionId, { operation: "revoke" });
      const commit = await call(pilot, credential, missionId, "execute_wire_transfer", {
        invoice_id: "inv-1",
        idempotency_key: `idem_${crypto.randomUUID()}`,
      });
      // A cached read would still say active, and the decision would reach
      // the class reservation (mission_binding_failed); the fresh read says revoked.
      expect(commit).toMatchObject({ ok: false, denial_reason: "mission_inactive" });
      expect(decisions(pilot, missionId).at(-1)?.content).toMatchObject({
        decision: "deny",
        denial_reason: "mission_inactive",
        action_phase: "commit",
      });
      expect(pilot.connectors.committedEffects()).toEqual([]);
    } finally {
      await admin(pilot, "revoke", "--iss", pilot.estate.issuer, "--sub", "u-1001", "--relation", "payer", "--vendor", "acme");
    }
  });
});

d("the separated MAS pilot: a PDP the MAS has not enrolled, a slow source, an answer that does not verify (#818 slice 4b)", () => {
  it("an unenrolled PDP reads no Subject or client, so the join denies mission_binding_failed and nothing is permitted", async () => {
    const other = await composeSeparatedMasPilot({
      openfga: OPENFGA,
      resourcePolicyStore: { bootstrap: "development" },
      config: separatedConfig(UNENROLLED_ESTATE_PORT),
      now,
      // The console's credential: it holds mission_status, and no enrollment.
      mas: { url: MAS_URL, pdpToken: DEV_SERVICE_TOKEN },
    });
    try {
      const missionId = await approveAtMas("alice", "unenrolled");
      const credential = await estateToken(other, "estate-ap-bot-7f3", "u-1001", "invoices.read");
      const res = await call(other, credential, missionId, "get_invoice", { invoice_id: "inv-1" });
      expect(res).toMatchObject({ ok: false, denial_reason: "mission_binding_failed" });
      const read = other.resolver.peek({ id: missionId, issuer: MAS_URL });
      expect(read?.view.state).toBe("active");
      expect(read?.view.subject).toBeUndefined();
      expect(read?.view.client_id).toBeUndefined();
      expect(decisions(other, missionId).at(-1)?.content).toMatchObject({ decision: "deny", denial_reason: "mission_binding_failed" });
    } finally {
      await other.close();
    }
  });

  it("a source slower than the deadline establishes no state: the PEP refuses state_unavailable before any decision", async () => {
    const proxy = createServer((req, res) => {
      setTimeout(async () => {
        try {
          const upstream = await fetch(`${MAS_URL}${req.url}`, { headers: { "x-service-token": String(req.headers["x-service-token"]) } });
          res.writeHead(upstream.status, { "content-type": upstream.headers.get("content-type") ?? "text/plain" });
          res.end(Buffer.from(await upstream.arrayBuffer()));
        } catch {
          res.destroy();
        }
      }, 1500);
    });
    servers.push(proxy);
    await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
    const via = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
    const slow = await composeSeparatedMasPilot({
      openfga: OPENFGA,
      resourcePolicyStore: { bootstrap: "development" },
      config: separatedConfig(TIMEOUT_ESTATE_PORT, 300),
      now,
      mas: { url: MAS_URL, pdpToken },
      statusUrl: (id) => `${via}/missions/${id}/status`,
    });
    try {
      const missionId = await approveAtMas("alice", "slow");
      const credential = await estateToken(slow, "estate-ap-bot-7f3", "u-1001", "invoices.read");
      const started = Date.now();
      const res = await call(slow, credential, missionId, "get_invoice", { invoice_id: "inv-1" });
      expect(Date.now() - started).toBeLessThan(1500);
      expect(res).toMatchObject({ ok: false, refusal_reason: "state_unavailable" });
      expect(decisions(slow, missionId)).toEqual([]);
      expect(refusals(slow, missionId).at(-1)?.content.denial_reason).toBe("state_unavailable");
    } finally {
      await slow.close();
    }
  });

  it("a Status answer that does not verify establishes no state: the PEP refuses state_unavailable before any decision", async () => {
    // A double that answers for the MAS, signing with a key the MAS never published.
    const stranger = await generateKeyPair("ES256");
    const double = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://double");
      const missionId = url.pathname.split("/")[2] as string;
      const iat = Math.floor(Date.now() / 1000);
      void new SignJWT({
        nonce: url.searchParams.get("nonce"),
        mission: { id: missionId, issuer: MAS_URL, state: "active", version: 1, authority_hash: "sha-256:x", fresh_until: new Date((iat + 60) * 1000).toISOString() },
        authorization_details: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: READ_ACTIONS }],
      })
        .setProtectedHeader({ alg: "ES256", kid: TOPOLOGY.keys.asStatus.kid, typ: "mission-status-response+jwt" })
        .setIssuer(MAS_URL)
        .setAudience(CANONICAL_RESOURCE)
        .setIssuedAt(iat)
        .setExpirationTime(iat + 60)
        .sign(stranger.privateKey)
        .then((jws) => {
          res.writeHead(200, { "content-type": "application/mission-status-response+jwt" });
          res.end(jws);
        });
    });
    servers.push(double);
    await new Promise<void>((resolve) => double.listen(0, "127.0.0.1", resolve));
    const at = `http://127.0.0.1:${(double.address() as AddressInfo).port}`;
    const forged = await composeSeparatedMasPilot({
      openfga: OPENFGA,
      resourcePolicyStore: { bootstrap: "development" },
      config: separatedConfig(DOUBLE_ESTATE_PORT),
      now,
      mas: { url: MAS_URL, pdpToken },
      statusUrl: (id) => `${at}/missions/${id}/status`,
    });
    try {
      const missionId = await approveAtMas("alice", "forged");
      const credential = await estateToken(forged, "estate-ap-bot-7f3", "u-1001", "invoices.read");
      const res = await call(forged, credential, missionId, "get_invoice", { invoice_id: "inv-1" });
      expect(res).toMatchObject({ ok: false, refusal_reason: "state_unavailable" });
      expect(decisions(forged, missionId)).toEqual([]);
      expect(refusals(forged, missionId).at(-1)?.content.denial_reason).toBe("state_unavailable");
    } finally {
      await forged.close();
    }
  });
});

d("the separated MAS pilot: the MAS stops and starts (#818 slice 4b)", () => {
  it("with the MAS down, a commit decision denies stale_state and an expired read refuses state_unavailable; restarted with its key ring and store, it reads again", async () => {
    const missionId = await approveAtMas("alice", "stop-start", [...READ_ACTIONS, EXECUTE]);
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read payments.execute");
    expect((await call(pilot, credential, missionId, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    await mas.stop();
    try {
      // The PEP's read is still within its bounds; the PDP's commit-phase
      // read reaches no MAS, so the decision has no state.
      await admin(pilot, "grant", "--iss", pilot.estate.issuer, "--sub", "u-1001", "--relation", "payer", "--vendor", "acme");
      try {
        const commit = await call(pilot, credential, missionId, "execute_wire_transfer", {
          invoice_id: "inv-1",
          idempotency_key: `idem_${crypto.randomUUID()}`,
        });
        expect(commit).toMatchObject({ ok: false, denial_reason: "stale_state" });
        expect(decisions(pilot, missionId).at(-1)?.content).toMatchObject({ decision: "deny", denial_reason: "stale_state" });
      } finally {
        await admin(pilot, "revoke", "--iss", pilot.estate.issuer, "--sub", "u-1001", "--relation", "payer", "--vendor", "acme");
      }
      // Past the signed window, nothing cached is relied on and nothing new is read.
      offsetMs += 61_000;
      const expired = await call(pilot, credential, missionId, "get_invoice", { invoice_id: "inv-1" });
      expect(expired).toMatchObject({ ok: false, refusal_reason: "state_unavailable" });
      expect(refusals(pilot, missionId).at(-1)?.content.denial_reason).toBe("state_unavailable");
      expect(pilot.connectors.committedEffects()).toEqual([]);
    } finally {
      mas = await startMasProcess(masOptions);
      await mas.setClockOffset(offsetMs);
    }
    // The same keys and the same Missions: the read verifies and permits.
    const again = await call(pilot, credential, missionId, "get_invoice", { invoice_id: "inv-1" });
    expect(again.ok, JSON.stringify(again)).toBe(true);
  });
});
