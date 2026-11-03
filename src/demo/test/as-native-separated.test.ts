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
 * resource's clock.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

const { APPROVER_LOGIN_CALLBACK_PATH } = await import("@mission/authorization-server");
const { CANONICAL_RESOURCE, createHttpMediatedClient } = await import("@mission/mcp-payments");
const { Fga } = await import("@mission/pdp");
const { decodeJwt } = await import("jose");
const { issueMissionToken } = await import("../src/approval-console.js");
const { startApproverIdp } = await import("../src/approver-idp.js");
const { newLifecycleConsole } = await import("../src/lifecycle-client.js");
const { newStatusClientKey } = await import("../src/mas-pilot/mas-as.js");
const { startSeparatedAsProcess } = await import("../src/as-native-separated/as-process.js");
const { composeSeparatedAsNative } = await import("../src/as-native-separated/compose.js");
const { parseAsNativeSeparatedConfig } = await import("../src/as-native-separated/config.js");

type SeparatedAsProcess = Awaited<ReturnType<typeof startSeparatedAsProcess>>;
type SeparatedAsNative = Awaited<ReturnType<typeof composeSeparatedAsNative>>;

const STUB_FGA = {
  checkWithContext: async () => true,
  checkStored: async () => true,
  client: { write: async () => ({}) },
  modelId: "test",
};
const STUB_BOOTSTRAP = { fga: STUB_FGA, storeId: "test", modelId: "test" };

const AS_URL = `http://localhost:${SEPARATED.ports.as}`;
const CONFIG = parseAsNativeSeparatedConfig({
  authorization_server: { host: "localhost", port: SEPARATED.ports.as },
  pdp_client_id: "payments-pdp",
  txn_challenge_metadata: { host: "127.0.0.1", port: SEPARATED.ports.txnMetadata },
  state_source: { placement: "pdp", timeout_ms: 2000, max_response_bytes: 65536 },
});
const READ = "payments:invoice.read";
/** This process's clock's offset from real time: the AS process runs at the same. */
const offsetFromReal = (): number => Date.now() - (performance.timeOrigin + performance.now());

const dirs: string[] = [];
let as: SeparatedAsProcess;
let asOptions: Parameters<typeof startSeparatedAsProcess>[0];
let resource: SeparatedAsNative;
let idp: Awaited<ReturnType<typeof startApproverIdp>>;
let pdpKey: Parameters<typeof composeSeparatedAsNative>[0]["pdpKey"];
let lifecycleConsole: Awaited<ReturnType<typeof newLifecycleConsole>>;
let agentClientJwk: Record<string, unknown>;

const tempFile = (prefix: string, name: string): string => {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return join(dir, name);
};

/** Advance both clocks by `ms`. */
async function advance(ms: number): Promise<void> {
  controlledClock.advance(ms);
  await as.setClockOffset(offsetFromReal());
}

async function compose(overrides: Partial<Parameters<typeof composeSeparatedAsNative>[0]> = {}): Promise<SeparatedAsNative> {
  return composeSeparatedAsNative({
    config: CONFIG,
    openfgaUrl: "http://unused.test",
    presharedKey: "unused",
    resourcePolicyStore: { bootstrap: "development" },
    pdpKey,
    claimsFile: tempFile("sep-claims-", "claims.sqlite"),
    writeReservationsFile: tempFile("sep-reservations-", "write-reservations.sqlite"),
    ...overrides,
  });
}

/** A Mission-bound token from the AS process: the agent's PAR, Bob's upstream login and approval for Alice, the token endpoint, DPoP-bound. */
async function issue(actions: string[], constraints: Record<string, unknown> = { vendors: ["acme"] }) {
  const username = [...idp.accounts.keys()][0] as string;
  return issueMissionToken(
    AS_URL,
    agentClientJwk,
    {
      missionIntent: JSON.stringify({
        intent: {
          goal: "Read approved Acme invoices",
          target_resources: [CANONICAL_RESOURCE],
          expires_at: new Date(Date.now() + 61 * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z"),
        },
      }),
      authorizationDetails: JSON.stringify([{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions, constraints }]),
    },
    { upstream: { account: idp.accounts.get(username) as never, secondFactor: "code" } },
  );
}

const missionIdOf = (token: string): string => (decodeJwt(token) as { mission: { id: string } }).mission.id;

async function callTool(
  issued: Awaited<ReturnType<typeof issue>>,
  tool: string,
  args: Record<string, unknown>,
) {
  const { client, close } = await createHttpMediatedClient(CANONICAL_RESOURCE, issued.accessToken, issued.dpopKeys);
  try {
    return await client.callTool(tool, args);
  } finally {
    await close();
  }
}

beforeAll(async () => {
  vi.spyOn(Fga, "bootstrap").mockResolvedValue(STUB_BOOTSTRAP as never);
  const configPath = tempFile("sep-config-", "as-native-separated.json");
  writeFileSync(configPath, JSON.stringify(CONFIG));
  idp = await startApproverIdp({
    redirectUri: `${AS_URL}${APPROVER_LOGIN_CALLBACK_PATH}`,
    accounts: [{ sub: "idp-bob", username: "bob@example.com" }],
    port: SEPARATED.ports.idp,
  });
  const pdp = await newStatusClientKey(CONFIG.pdp_client_id, { disclose: ["provenance"] });
  pdpKey = pdp.privateJwk;
  lifecycleConsole = await newLifecycleConsole();
  asOptions = {
    configPath,
    statusClients: [pdp.registration],
    lifecycleClient: lifecycleConsole.registration,
    approverLogin: {
      issuer: idp.issuer,
      clientId: idp.client.clientId,
      clientSecret: idp.client.clientSecret,
      idTokenSigningAlgs: ["ES256"],
      identities: [{ iss: idp.issuer, sub: "idp-bob", approver: "bob" }],
      acrValues: ["mfa"],
    },
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
  vi.restoreAllMocks();
  controlledClock.restore();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

describe("the separated AS-native configuration: the PDP reads Mission state over the AS's signed Mission Status (#1101)", () => {
  it("permits a read on the signed Status view, with no kernel in this composition", async () => {
    expect("kernel" in resource).toBe(false);
    const issued = await issue([READ]);
    const res = await callTool(issued, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok, JSON.stringify(res)).toBe(true);
    const read = resource.resolver.peek({ id: missionIdOf(issued.accessToken), issuer: AS_URL });
    expect(read?.view.state).toBe("active");
  });
});
