/**
 * @spec runtime#state-freshness, authzen#pdp-request rule 1,
 * status#mission-status-caching, status#mission-status-failures (#1101, D293,
 * D1258)
 *
 * The separated AS-native configuration end to end: the authorization server
 * runs in its own OS process (`as-process.ts`) and alone holds the Missions;
 * the payments PEP and PDP run here with no kernel and read Mission state over
 * the AS's signed Mission Status, as the client `pdp_client_id`. Missions are
 * approved through the real flow (PAR, the Approver's upstream login, the
 * token endpoint, DPoP-bound) and revoked at the AS's Lifecycle endpoint.
 * Every refusal asserts that nothing executed and names its evidence carrier:
 * the PDP's signed Decision Evidence, or the PEP's signed Refusal Record when
 * no decision was reached.
 *
 * One controlled clock: this process's (`controlled-clock.helper.ts`) and the
 * AS process's, kept at the same offset from real time through its operator
 * channel, so the tokens it stamps and the Status it signs agree with the
 * resource's clock. The AS signs a 60 s Status window; the read classes allow
 * 300 s and the irreversible class 30 s.
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const SEPARATED = vi.hoisted(() => {
  const ports = { as: 15201, resource: 15202, txnMetadata: 15203, idp: 15204 };
  // The payments resource's audience for this file: its own port, so the
  // co-located target's tests can hold 4403 at the same time.
  process.env.MCP_PAYMENTS_RESOURCE = `http://localhost:${ports.resource}/mcp`;
  return { ports };
});
const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});

const { APPROVER_LOGIN_CALLBACK_PATH, bindSigningKeyRing, initSigningKeyRing, reconcileKernelRecovery } = await import(
  "@mission/authorization-server"
);
const { TOPOLOGY } = await import("@mission/demo-data");
const { canonicalHtu, CANONICAL_RESOURCE, createHttpMediatedClient, dpopProofFor } = await import("@mission/mcp-payments");
const { Fga, policyViewId, privateKeyJwtClient, RUNTIME_POSTURE } = await import("@mission/pdp");
const { decodeJwt, generateKeyPair, importJWK, SignJWT } = await import("jose");
const { issueMissionToken } = await import("../src/approval-console.js");
const { startApproverIdp } = await import("../src/approver-idp.js");
const { requestLifecycle, newLifecycleConsole } = await import("../src/lifecycle-client.js");
const { newStatusClientKey } = await import("../src/mas-pilot/mas-as.js");
const { AS_NATIVE_CAPABILITIES } = await import("../src/stack.js");
const { AS_NATIVE_SEPARATED_CAPABILITIES } = await import("../src/as-native-separated/as-server.js");
const { startSeparatedAsProcess } = await import("../src/as-native-separated/as-process.js");
const { composeSeparatedAsNative } = await import("../src/as-native-separated/compose.js");
const { AsNativeSeparatedConfigError, parseAsNativeSeparatedConfig, SEPARATED_STATE_SOURCE, separatedStatement } = await import(
  "../src/as-native-separated/config.js"
);

type SeparatedAsProcess = Awaited<ReturnType<typeof startSeparatedAsProcess>>;
type SeparatedAsNative = Awaited<ReturnType<typeof composeSeparatedAsNative>>;
type ComposeOptions = Parameters<typeof composeSeparatedAsNative>[0];
type Issued = Awaited<ReturnType<typeof issueMissionToken>>;
type Evidence = ReturnType<SeparatedAsNative["evidence"]["forMission"]>[number];

const STUB_FGA = {
  checkWithContext: async () => true,
  checkStored: async () => true,
  client: { write: async () => ({}) },
  modelId: "test",
};
const STUB_BOOTSTRAP = { fga: STUB_FGA, storeId: "test", modelId: "test" };

const AS_URL = `http://localhost:${SEPARATED.ports.as}`;
const SHAPE = {
  authorization_server: { host: "localhost", port: SEPARATED.ports.as },
  pdp_client_id: "payments-pdp",
  txn_challenge_metadata: { host: "127.0.0.1", port: SEPARATED.ports.txnMetadata },
  state_source: { placement: "pdp", timeout_ms: 2000, max_response_bytes: 65536 },
};
const CONFIG = parseAsNativeSeparatedConfig(SHAPE);
/** A second Status client the AS registers with no disclosure privilege: its reads commit no `authority_hash`. */
const PLAIN_CLIENT = "payments-pdp-plain";
const READ = "payments:invoice.read";
const VENDOR_READ = "payments:vendor.read";
const EXECUTE = "payments:payment.execute";
const PAY = { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] };
const SIGNED_WINDOW_MS = 60_000;
/** This process's clock's offset from real time: the AS process runs at the same. */
const offsetFromReal = (): number => Date.now() - (performance.timeOrigin + performance.now());

const dirs: string[] = [];
const servers: Server[] = [];
let as: SeparatedAsProcess;
let asOptions: Parameters<typeof startSeparatedAsProcess>[0];
let resource: SeparatedAsNative;
let idp: Awaited<ReturnType<typeof startApproverIdp>>;
let pdpKey: ComposeOptions["pdpKey"];
let plainKey: ComposeOptions["pdpKey"];
let lifecycleConsole: Awaited<ReturnType<typeof newLifecycleConsole>>;
let agentClientJwk: Record<string, unknown>;

const tempDir = (prefix: string): string => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
};

/** Advance both clocks by `ms`. */
async function advance(ms: number): Promise<void> {
  controlledClock.advance(ms);
  await as.setClockOffset(offsetFromReal());
}

function compose(overrides: Partial<ComposeOptions> = {}): Promise<SeparatedAsNative> {
  const dir = tempDir("sep-stores-");
  return composeSeparatedAsNative({
    config: CONFIG,
    openfgaUrl: "http://unused.test",
    presharedKey: "unused",
    resourcePolicyStore: { bootstrap: "development" },
    pdpKey,
    claimsFile: join(dir, "claims.sqlite"),
    writeReservationsFile: join(dir, "write-reservations.sqlite"),
    ...overrides,
  });
}

/**
 * Run `fn` against another composition of the resource side, which holds the
 * same audience and listener ports: the file's own is closed for it and
 * composed again after.
 */
async function withComposition(overrides: Partial<ComposeOptions>, fn: (alt: SeparatedAsNative) => Promise<void>): Promise<void> {
  await resource.close();
  const alt = await compose(overrides);
  try {
    await fn(alt);
  } finally {
    await alt.close();
    resource = await compose();
  }
}

/** A Mission-bound token from the AS process: the agent's PAR, Bob's upstream login and approval for Alice, the token endpoint, DPoP-bound. */
function issue(actions: string[], constraints: Record<string, unknown> = { vendors: ["acme"] }): Promise<Issued> {
  return issueMissionToken(
    AS_URL,
    agentClientJwk,
    {
      missionIntent: JSON.stringify({
        intent: {
          goal: "Read approved Acme invoices and pay them",
          target_resources: [CANONICAL_RESOURCE],
          expires_at: new Date(Date.now() + 61 * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z"),
        },
      }),
      authorizationDetails: JSON.stringify([{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions, constraints }]),
    },
    { upstream: { account: idp.accounts.get("bob@example.com") as never, secondFactor: "code" } },
  );
}

const missionIdOf = (issued: Issued): string => (decodeJwt(issued.accessToken) as { mission: { id: string } }).mission.id;

async function callTool(issued: Issued, tool: string, args: Record<string, unknown>) {
  const { client, close } = await createHttpMediatedClient(CANONICAL_RESOURCE, issued.accessToken, issued.dpopKeys);
  try {
    return await client.callTool(tool, args);
  } finally {
    await close();
  }
}

const decisions = (r: SeparatedAsNative, missionId: string) =>
  r.evidence.forMission(missionId).filter((e): e is Extract<Evidence, { kind: "decision" }> => e.kind === "decision");
const refusals = (r: SeparatedAsNative, missionId: string) =>
  r.evidence.forMission(missionId).filter((e): e is Extract<Evidence, { kind: "refusal" }> => e.kind === "refusal");
const executions = (r: SeparatedAsNative, missionId: string) =>
  r.evidence.forMission(missionId).filter((e) => e.kind === "execution");

/** A Status read at the AS's endpoint, as the PDP's client, for the payments audience: the signed response. */
async function statusAsPdp(missionId: string): Promise<{ iat: number; mission: { version: number; authority_hash: string; fresh_until: string }; authorization_details: { actions: string[] }[] }> {
  const client = privateKeyJwtClient({
    clientId: CONFIG.pdp_client_id,
    issuer: AS_URL,
    privateKey: (await importJWK(pdpKey, "ES256")) as CryptoKey,
    kid: pdpKey.kid as string,
  });
  const res = await fetch(`${AS_URL}/mission/status`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      mission_id: missionId,
      audience: CANONICAL_RESOURCE,
      nonce: crypto.randomUUID(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: await client.assertion(),
    }).toString(),
  });
  expect(res.status).toBe(200);
  return decodeJwt(await res.text()) as never;
}

/**
 * A stand-in for the AS's Status endpoint: it forwards each request, its form
 * rewritten by `request`, after `delayMs`, and answers with what the AS
 * answered, or with what `answer` makes of it.
 */
async function statusProxy(opts: {
  request?: (form: URLSearchParams) => URLSearchParams;
  answer?: (upstream: { status: number; body: string }) => { status: number; contentType: string; body: string };
  delayMs?: number;
}): Promise<string> {
  const proxy = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      setTimeout(async () => {
        try {
          const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
          const upstream = await fetch(`${AS_URL}/mission/status`, {
            method: "POST",
            headers: { "content-type": "application/x-www-form-urlencoded" },
            body: (opts.request ? opts.request(form) : form).toString(),
          });
          const got = { status: upstream.status, body: await upstream.text() };
          const out = opts.answer
            ? opts.answer(got)
            : { status: got.status, contentType: upstream.headers.get("content-type") ?? "text/plain", body: got.body };
          res.writeHead(out.status, { "content-type": out.contentType });
          res.end(out.body);
        } catch {
          res.destroy();
        }
      }, opts.delayMs ?? 0);
    });
  });
  servers.push(proxy);
  await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(proxy.address() as AddressInfo).port}/mission/status`;
}

/** Revoke a Mission at the AS's advertised Lifecycle endpoint, as the Lifecycle console. */
async function revoke(missionId: string): Promise<void> {
  const res = await requestLifecycle(AS_URL, lifecycleConsole.credentials, { mission_id: missionId, operation: "revoke", nonce: crypto.randomUUID() });
  expect(res.status, res.text).toBe(200);
}

/**
 * The refusal a source that established nothing leaves: no decision, the
 * PEP's signed Refusal Record, nothing disclosed or executed. The caller is
 * told `unknown_mission` where the AS answered that it holds no such Mission
 * (or none this client may see), else `state_unavailable`; the Refusal Record
 * carries `state_unavailable` either way (view-source.ts).
 */
function expectRefusedBeforeDecision(
  r: SeparatedAsNative,
  missionId: string,
  res: { ok: boolean; result?: unknown },
  reason: "state_unavailable" | "unknown_mission" = "state_unavailable",
): void {
  expect(res, JSON.stringify(res)).toMatchObject({ ok: false, refusal_reason: reason });
  expect(res.result).toBeUndefined();
  expect(decisions(r, missionId)).toEqual([]);
  expect(refusals(r, missionId).at(-1)?.content.denial_reason).toBe("state_unavailable");
  expect(executions(r, missionId)).toEqual([]);
}

beforeAll(async () => {
  vi.spyOn(Fga, "bootstrap").mockResolvedValue(STUB_BOOTSTRAP as never);
  const dir = tempDir("sep-as-");
  const configPath = join(dir, "as-native-separated.json");
  writeFileSync(configPath, JSON.stringify(SHAPE));
  // The AS keeps its keys and its Missions across a restart.
  const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
  const ring = join(dir, "keys", "ring.json");
  await initSigningKeyRing(ring, AS_URL, { asToken, asStatus, asTxn, asContinuation });
  // The binding record lives apart from the ring (#1815).
  const bindings = join(tempDir("sep-bindings-"), "bindings.json");
  await bindSigningKeyRing(ring, AS_URL, { asToken, asStatus, asTxn, asContinuation }, bindings);
  const kernelFile = join(dir, "state", "kernel.db");
  const witness = join(dir, "witness", "kernel.witness");
  mkdirSync(dirname(kernelFile), { recursive: true });
  mkdirSync(dirname(witness), { recursive: true });
  reconcileKernelRecovery({ storeFile: kernelFile, witnessFile: witness, action: "init" });

  idp = await startApproverIdp({
    redirectUri: `${AS_URL}${APPROVER_LOGIN_CALLBACK_PATH}`,
    accounts: [{ sub: "idp-bob", username: "bob@example.com" }],
    port: SEPARATED.ports.idp,
  });
  // The PDP's Status client registers `provenance`, so its reads commit the
  // authority_hash its committed-set proof reads (D335); the plain one does not.
  const pdp = await newStatusClientKey(CONFIG.pdp_client_id, { disclose: ["provenance"] });
  const plain = await newStatusClientKey(PLAIN_CLIENT);
  pdpKey = pdp.privateJwk;
  plainKey = plain.privateJwk;
  lifecycleConsole = await newLifecycleConsole();
  asOptions = {
    configPath,
    statusClients: [pdp.registration, plain.registration],
    lifecycleClient: lifecycleConsole.registration,
    approverLogin: {
      issuer: idp.issuer,
      clientId: idp.client.clientId,
      clientSecret: idp.client.clientSecret,
      idTokenSigningAlgs: ["ES256"],
      identities: [{ iss: idp.issuer, sub: "idp-bob", approver: "bob" }],
      acrValues: ["mfa"],
    },
    keyRing: { ring, bindings },
    kernelStore: { file: kernelFile, witness },
    clockOffsetMs: offsetFromReal(),
  };
  as = await startSeparatedAsProcess(asOptions);
  agentClientJwk = await as.agentClientJwk();
  resource = await compose();
}, 120_000);

afterAll(async () => {
  await resource?.close();
  await as?.stop();
  await idp?.close();
  for (const s of servers) {
    s.closeAllConnections();
    await new Promise<void>((resolve) => s.close(() => resolve()));
  }
  vi.restoreAllMocks();
  controlledClock.restore();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

describe("the separated AS-native configuration: its declared shape (#1101, D1258)", () => {
  it("enables status beside the co-located target's capability set, which stays without it, and the AS serves and advertises Mission Status", async () => {
    expect([...AS_NATIVE_SEPARATED_CAPABILITIES].sort()).toEqual([...AS_NATIVE_CAPABILITIES, "status"].sort());
    expect(AS_NATIVE_CAPABILITIES.has("status")).toBe(false);
    const metadata = (await (await fetch(`${AS_URL}/.well-known/openid-configuration`)).json()) as Record<string, unknown>;
    expect(metadata.mission_status_endpoint).toBe(`${AS_URL}/mission/status`);
  });

  it("declares its state source with the PDP, and the composition holds no kernel", () => {
    expect(resource.statement.state_source).toMatchObject({ source: SEPARATED_STATE_SOURCE, placement: "pdp" });
    expect("kernel" in resource).toBe(false);
  });

  it("refuses an undeclared placement at load and a remote PDP hop at composition, before anything connects", async () => {
    expect(() => parseAsNativeSeparatedConfig({ ...SHAPE, state_source: { ...SHAPE.state_source, placement: "pep" } })).toThrow(
      AsNativeSeparatedConfigError,
    );
    expect(() => parseAsNativeSeparatedConfig({ ...SHAPE, state_source: { ...SHAPE.state_source, source: "kernel" } })).toThrow(
      AsNativeSeparatedConfigError,
    );
    await expect(compose({ pdpMode: "remote" })).rejects.toThrow("co-resident PDP only");
  });
});

describe("the separated AS-native configuration: the PDP decides on its own signed Status read (#1101)", () => {
  it("permits a read on the signed Status view: the PEP forwards no observation, the decision commits the AS's state, and the permit ends inside the signed window", async () => {
    const envelopes: { mission_state_observation?: unknown }[] = [];
    resource.onEnforce((e) => envelopes.push(e.envelope.context as never));
    const issued = await issue([READ]);
    const missionId = missionIdOf(issued);
    const res = await callTool(issued, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok, JSON.stringify(res)).toBe(true);
    // Placed with the PDP: the PEP sends no state observation.
    expect(envelopes.at(-1)?.mission_state_observation).toBeUndefined();
    const read = resource.resolver.peek({ id: missionId, issuer: AS_URL });
    expect(read?.view.state).toBe("active");
    // The decision is the AS's state: its version and authority_hash, read back directly.
    const status = await statusAsPdp(missionId);
    const decision = decisions(resource, missionId).at(-1)?.content;
    expect(decision?.decision).toBe("permit");
    expect(decision?.mission).toMatchObject({
      policy_view_id: policyViewId({ id: missionId, version: status.mission.version, authority_hash: status.mission.authority_hash } as never, STUB_BOOTSTRAP.modelId),
      authority_hash: status.mission.authority_hash,
    });
    // The signed window (60 s) is shorter than the read class's 300 s, and the permit ends inside it.
    const freshUntilMs = read?.freshUntilMs as number;
    expect(freshUntilMs - (read?.observedAtMs as number)).toBe(SIGNED_WINDOW_MS);
    expect(Date.parse(decision?.conditions?.valid_until as string)).toBeLessThanOrEqual(read?.relianceBoundMs as number);
  });

  it("decides over the Status response's audience-scoped authorization_details: an action the AS contained denies out_of_authority at the PDP though the credential still carries it, and the credential's own authority stays a separate bound", async () => {
    const issued = await issue([READ, VENDOR_READ]);
    const missionId = missionIdOf(issued);
    expect((await callTool(issued, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    const status = await statusAsPdp(missionId);
    const view = resource.resolver.peek({ id: missionId, issuer: AS_URL })?.view;
    expect(view?.authority_set.flatMap((e) => e.actions)).toEqual(status.authorization_details.flatMap((e) => e.actions));
    // This capability set serves no containment; the harness applies it at the AS.
    await as.contain(missionId, [{ resource: CANONICAL_RESOURCE, actions: [READ] }]);
    await advance(SIGNED_WINDOW_MS + 1_000);
    const contained = await callTool(issued, "get_invoice", { invoice_id: "inv-1" });
    expect(contained, JSON.stringify(contained)).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
    expect(contained.result).toBeUndefined();
    // The PDP decided it: the Status view no longer carries the action, so it
    // is outside the Authority Set; a contained action is offered no way back.
    expect(contained.insufficient_authorization).toBeUndefined();
    expect(decisions(resource, missionId).at(-1)?.content).toMatchObject({ decision: "deny", denial_reason: "out_of_authority" });
    expect((decodeJwt(issued.accessToken) as { authorization_details: { actions: string[] }[] }).authorization_details.flatMap((e) => e.actions)).toContain(READ);
    expect((await statusAsPdp(missionId)).authorization_details.flatMap((e) => e.actions)).not.toContain(READ);
    expect((await callTool(issued, "lookup_vendor", { vendor_id: "acme" })).ok).toBe(true);
    // An action the credential never carried is refused at the credential
    // bound, before any decision, whatever the Status view says.
    const reader = await issue([READ]);
    const readerId = missionIdOf(reader);
    const outside = await callTool(reader, "lookup_vendor", { vendor_id: "acme" });
    expect(outside).toMatchObject({ ok: false, denial_reason: "out_of_authority" });
    expect(decisions(resource, readerId)).toEqual([]);
    expect(refusals(resource, readerId).at(-1)?.content.denial_reason).toBe("credential_authority_insufficient");
  });

  it("establishes no state through a Status client the AS grants no provenance: the PDP's view must commit authority_hash, so state_unavailable before any decision", async () => {
    await withComposition({ config: { ...CONFIG, pdp_client_id: PLAIN_CLIENT }, pdpKey: plainKey }, async (alt) => {
      const issued = await issue([READ]);
      expectRefusedBeforeDecision(alt, missionIdOf(issued), await callTool(issued, "get_invoice", { invoice_id: "inv-1" }));
    });
  });

  it("relies on a cached read at its signed observation point, never re-stamped, and caps every permit on it at the same signed bound", async () => {
    const issued = await issue([READ]);
    const missionId = missionIdOf(issued);
    expect((await callTool(issued, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    const first = resource.resolver.peek({ id: missionId, issuer: AS_URL });
    await advance(20_000);
    expect((await callTool(issued, "get_invoice", { invoice_id: "inv-2" })).ok).toBe(true);
    const second = resource.resolver.peek({ id: missionId, issuer: AS_URL });
    expect(second?.source).toBe("cached");
    expect(second?.observedAtMs).toBe(first?.observedAtMs);
    const permits = decisions(resource, missionId).map((d) => Date.parse(d.content.conditions?.valid_until as string));
    expect(permits).toHaveLength(2);
    for (const until of permits) expect(until).toBeLessThanOrEqual(first?.relianceBoundMs as number);
  });

  it("ages each observation against its action class's window, apart from the signed bound: past a 20 s read window the PDP reads again though the signed 60 s window has not passed (test statement)", async () => {
    const shortRead = separatedStatement({
      ...RUNTIME_POSTURE,
      state_source: {
        ...RUNTIME_POSTURE.state_source,
        per_class: {
          ...RUNTIME_POSTURE.state_source.per_class,
          consequential_read: { ...RUNTIME_POSTURE.state_source.per_class.consequential_read, max_staleness_seconds: 20 },
        },
      },
    } as never);
    await withComposition({ statement: shortRead }, async (alt) => {
      const issued = await issue([READ]);
      const missionId = missionIdOf(issued);
      expect((await callTool(issued, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
      const first = alt.resolver.peek({ id: missionId, issuer: AS_URL });
      await advance(10_000);
      expect((await callTool(issued, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
      expect(alt.resolver.peek({ id: missionId, issuer: AS_URL })?.observedAtMs).toBe(first?.observedAtMs);
      await advance(11_000);
      expect((await callTool(issued, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
      const reread = alt.resolver.peek({ id: missionId, issuer: AS_URL });
      expect(reread?.observedAtMs).toBeGreaterThan(first?.observedAtMs as number);
      expect((first?.freshUntilMs as number) - Date.now()).toBeGreaterThan(0);
    });
  });
});

describe("the separated AS-native configuration: revocation and suspension at the AS (#1101)", () => {
  it("observes a revocation at the Lifecycle endpoint within the signed bound: relied on until its fresh_until, then mission_inactive", async () => {
    const issued = await issue([READ]);
    const missionId = missionIdOf(issued);
    expect((await callTool(issued, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    await revoke(missionId);
    // Inside the signed window the earlier observation stands: the declared bound.
    expect((await callTool(issued, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    await advance(SIGNED_WINDOW_MS + 1_000);
    const after = await callTool(issued, "get_invoice", { invoice_id: "inv-1" });
    expect(after).toMatchObject({ ok: false, denial_reason: "mission_inactive" });
    expect(after.result).toBeUndefined();
    expect(decisions(resource, missionId).at(-1)?.content).toMatchObject({ decision: "deny", denial_reason: "mission_inactive" });
  });

  it("observes a suspension the same way: then mission_inactive", async () => {
    const issued = await issue([READ]);
    const missionId = missionIdOf(issued);
    expect((await callTool(issued, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    await as.suspend(missionId);
    await advance(SIGNED_WINDOW_MS + 1_000);
    const after = await callTool(issued, "get_invoice", { invoice_id: "inv-1" });
    expect(after).toMatchObject({ ok: false, denial_reason: "mission_inactive" });
    expect(after.result).toBeUndefined();
    expect(decisions(resource, missionId).at(-1)?.content).toMatchObject({ decision: "deny", denial_reason: "mission_inactive" });
  });

  it("refuses the commit of a Mission revoked after its prepare: the commit-phase decision reads the AS now, and nothing executes", async () => {
    const issued = await issue([READ, EXECUTE], PAY);
    const missionId = missionIdOf(issued);
    const prepare = await callTool(issued, "hold_transfer", { invoice_id: "inv-1" });
    expect(prepare.ok, JSON.stringify(prepare)).toBe(true);
    await revoke(missionId);
    const commit = await callTool(issued, "execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${crypto.randomUUID()}` });
    // A cached read would still say active; the fresh read says revoked.
    expect(commit).toMatchObject({ ok: false, denial_reason: "mission_inactive" });
    expect(decisions(resource, missionId).at(-1)?.content).toMatchObject({
      decision: "deny",
      denial_reason: "mission_inactive",
      action_phase: "commit",
    });
    expect(resource.connectors.ledgerEntries(missionId)).toHaveLength(0);
    expect(resource.connectors.committedEffects(missionId)).toEqual([]);
  });
});

describe("the separated AS-native configuration: a source that establishes nothing authorizes nothing (#1101)", () => {
  it("a Status answer for another Mission establishes no state: state_unavailable before any decision", async () => {
    const other = missionIdOf(await issue([READ]));
    const via = await statusProxy({ request: (form) => (form.set("mission_id", other), form) });
    await withComposition({ statusEndpoint: via }, async (alt) => {
      const issued = await issue([READ]);
      const missionId = missionIdOf(issued);
      expectRefusedBeforeDecision(alt, missionId, await callTool(issued, "get_invoice", { invoice_id: "inv-1" }));
    });
  });

  it("a Mission the AS does not hold is unknown_mission before any decision", async () => {
    const via = await statusProxy({ request: (form) => (form.set("mission_id", `m-${crypto.randomUUID()}`), form) });
    await withComposition({ statusEndpoint: via }, async (alt) => {
      const issued = await issue([READ]);
      expectRefusedBeforeDecision(alt, missionIdOf(issued), await callTool(issued, "get_invoice", { invoice_id: "inv-1" }), "unknown_mission");
    });
  });

  it("an unauthenticated read (no client assertion) establishes no state: state_unavailable before any decision", async () => {
    const via = await statusProxy({
      request: (form) => {
        form.delete("client_assertion");
        form.delete("client_assertion_type");
        return form;
      },
    });
    await withComposition({ statusEndpoint: via }, async (alt) => {
      const issued = await issue([READ]);
      expectRefusedBeforeDecision(alt, missionIdOf(issued), await callTool(issued, "get_invoice", { invoice_id: "inv-1" }));
    });
  });

  it("a client the AS has not authorized for Mission Status (its Lifecycle console) gets the not-found an unknown Mission gets: unknown_mission before any decision", async () => {
    await withComposition(
      {
        config: { ...CONFIG, pdp_client_id: lifecycleConsole.credentials.clientId },
        pdpKey: lifecycleConsole.credentials.privateJwk as ComposeOptions["pdpKey"],
      },
      async (alt) => {
        const issued = await issue([READ]);
        expectRefusedBeforeDecision(alt, missionIdOf(issued), await callTool(issued, "get_invoice", { invoice_id: "inv-1" }), "unknown_mission");
      },
    );
  });

  it("a key the AS never registered establishes no state: state_unavailable before any decision", async () => {
    const stranger = await newStatusClientKey(CONFIG.pdp_client_id);
    await withComposition({ pdpKey: stranger.privateJwk }, async (alt) => {
      const issued = await issue([READ]);
      expectRefusedBeforeDecision(alt, missionIdOf(issued), await callTool(issued, "get_invoice", { invoice_id: "inv-1" }));
    });
  });

  it("a signed Status the AS never published a key for establishes no state: state_unavailable before any decision", async () => {
    // A double that answers for the AS, signing with a key the AS never published.
    const stranger = await generateKeyPair("ES256");
    const double = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", async () => {
        const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
        const iat = Math.floor(Date.now() / 1000);
        const jws = await new SignJWT({
          sub: CONFIG.pdp_client_id,
          nonce: form.get("nonce"),
          mission: {
            id: form.get("mission_id"),
            issuer: AS_URL,
            state: "active",
            version: 1,
            authority_hash: "sha-256:x",
            fresh_until: new Date((iat + 60) * 1000).toISOString(),
          },
          authorization_details: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: [READ] }],
        })
          .setProtectedHeader({ alg: "ES256", kid: TOPOLOGY.keys.asStatus.kid, typ: "mission-status-response+jwt" })
          .setIssuer(AS_URL)
          .setAudience(CANONICAL_RESOURCE)
          .setIssuedAt(iat)
          .setExpirationTime(iat + 60)
          .sign(stranger.privateKey);
        res.writeHead(200, { "content-type": "application/mission-status-response+jwt" });
        res.end(jws);
      });
    });
    servers.push(double);
    await new Promise<void>((resolve) => double.listen(0, "127.0.0.1", resolve));
    await withComposition({ statusEndpoint: `http://127.0.0.1:${(double.address() as AddressInfo).port}/mission/status` }, async (alt) => {
      const issued = await issue([READ]);
      expectRefusedBeforeDecision(alt, missionIdOf(issued), await callTool(issued, "get_invoice", { invoice_id: "inv-1" }));
    });
  });

  it("a malformed answer establishes no state: state_unavailable before any decision", async () => {
    const via = await statusProxy({ answer: () => ({ status: 200, contentType: "application/mission-status-response+jwt", body: "not.a.status" }) });
    await withComposition({ statusEndpoint: via }, async (alt) => {
      const issued = await issue([READ]);
      expectRefusedBeforeDecision(alt, missionIdOf(issued), await callTool(issued, "get_invoice", { invoice_id: "inv-1" }));
    });
  });

  it("a source slower than its deadline establishes no state: state_unavailable before any decision, within the deadline", async () => {
    const via = await statusProxy({ delayMs: 1_500 });
    await withComposition({ statusEndpoint: via, config: { ...CONFIG, state_source: { ...CONFIG.state_source, timeout_ms: 300 } } }, async (alt) => {
      const issued = await issue([READ]);
      const started = performance.now();
      const res = await callTool(issued, "get_invoice", { invoice_id: "inv-1" });
      expect(performance.now() - started).toBeLessThan(1_500);
      expectRefusedBeforeDecision(alt, missionIdOf(issued), res);
    });
  });
});

describe("the separated AS-native configuration: the credential and its presenter stay separately enforced (#1101)", () => {
  it("refuses a token presented under another holder's DPoP key though its Mission is active, before any decision", async () => {
    const issued = await issue([READ]);
    const missionId = missionIdOf(issued);
    expect((await callTool(issued, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    const otherHolder = await issue([READ]);
    const before = decisions(resource, missionId).length;
    const res = await fetch(CANONICAL_RESOURCE, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `DPoP ${issued.accessToken}`,
        dpop: await dpopProofFor(otherHolder.dpopKeys, canonicalHtu(CANONICAL_RESOURCE), "POST", issued.accessToken),
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_invoice", arguments: { invoice_id: "inv-1" } } }),
    });
    expect(res.status).toBe(401);
    expect(decisions(resource, missionId)).toHaveLength(before);
  });
});

describe("the separated AS-native configuration: the AS stops and starts (#1101)", () => {
  it("with the AS down, a commit decision denies stale_state though the PEP's read is within its bounds, and an expired read refuses state_unavailable; restarted on its key ring and store, it reads again", async () => {
    const issued = await issue([READ, EXECUTE], PAY);
    const missionId = missionIdOf(issued);
    expect((await callTool(issued, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    await as.stop();
    try {
      // The PEP's read is still within its bounds; the PDP's commit-phase
      // read reaches no AS, so the decision has no state, and nothing the PEP
      // holds stands in for it.
      const commit = await callTool(issued, "execute_wire_transfer", { invoice_id: "inv-1", idempotency_key: `idem_${crypto.randomUUID()}` });
      expect(commit).toMatchObject({ ok: false, denial_reason: "stale_state" });
      expect(decisions(resource, missionId).at(-1)?.content).toMatchObject({ decision: "deny", denial_reason: "stale_state", action_phase: "commit" });
      // Past the signed window, nothing cached is relied on and nothing new is read.
      controlledClock.advance(SIGNED_WINDOW_MS + 1_000);
      const expired = await callTool(issued, "get_invoice", { invoice_id: "inv-1" });
      expect(expired).toMatchObject({ ok: false, refusal_reason: "state_unavailable" });
      expect(expired.result).toBeUndefined();
      expect(refusals(resource, missionId).at(-1)?.content.denial_reason).toBe("state_unavailable");
      expect(resource.connectors.ledgerEntries(missionId)).toHaveLength(0);
    } finally {
      as = await startSeparatedAsProcess({ ...asOptions, clockOffsetMs: offsetFromReal() });
      agentClientJwk = await as.agentClientJwk();
    }
    // The same keys and the same Missions: the read verifies and permits.
    const again = await callTool(issued, "get_invoice", { invoice_id: "inv-1" });
    expect(again.ok, JSON.stringify(again)).toBe(true);
  });
});
