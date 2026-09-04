/**
 * @spec authority-server#mission-join (#557)
 *
 * The baseline MAS Join on the COMPOSED demo stack, end to end and with
 * nothing stubbed across the seam: the real authorization server mints an
 * ordinary DPoP-bound OAuth credential (a `scope`, the payments audience, no
 * `mission` claim), the client presents it over the MAS-governed HTTP MCP
 * channel with the propagated `Mission-Reference` field, and the resource
 * joins it to a Mission the kernel actually approved before permitting a read
 * against that Mission's own Authority Set.
 *
 * This is the configured-route half of the feature: `config/mas-join.json`
 * (the loader), the channel's `masGoverned` validator, the PEP's `masJoin`
 * wiring, and the scope-to-authority evaluator all have to line up, and only
 * the composed stack proves they do. Auto-skips without a live OpenFGA, so
 * every conformance claim also anchors on the always-run unit coverage in
 * `services/mcp-payments/test/mas-join.test.ts`.
 */

import { calculateJwkThumbprint, exportJWK, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { validateMissionIntent } from "@mission/authorization-server";
import { CANONICAL_RESOURCE, DERIVATION_POLICY, DEV_SERVICE_TOKEN, TOPOLOGY } from "@mission/demo-data";
import { createHttpMediatedClient, type DpopKeys } from "@mission/mcp-payments";
import { composeStack, type DemoStack } from "../src/stack.js";

const API_URL = process.env.OPENFGA_HTTP_URL ?? TOPOLOGY.openfga.url;
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? TOPOLOGY.openfga.presharedKey;
const CA = process.env.OPENFGA_CA_CERT;
/** A dedicated port, so this never collides with a running demo. */
const AS_PORT = 14557;

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
if (!up) console.warn("OpenFGA unreachable; skipping the composed MAS Join stack test");

let stack: DemoStack;
let missionId: string;
let credential: string;
let dpopKeys: DpopKeys;
const cleanups: (() => Promise<void> | void)[] = [];

d("composed stack: the MAS-governed channel joins an ordinary credential (#557)", () => {
  beforeAll(async () => {
    stack = await composeStack({
      openfgaUrl: API_URL,
      presharedKey: KEY,
      ...(CA ? { caCertPath: CA } : {}),
      withAuthServer: true,
      asPort: AS_PORT,
    });
    if (stack.masGovernedChannel) cleanups.push(stack.masGovernedChannel.close);
    if (stack.authServer) cleanups.push(stack.authServer.closeAuthServer);

    // A Mission the kernel really approved, whose subject is issuer-qualified
    // under THIS AS: rule 3 is byte-equality on the (iss, sub) pair, and the
    // credential's authenticated issuer is the resource's own AS.
    const intent = validateMissionIntent(
      JSON.stringify({
        goal: "Read approved Acme invoices for the quarter",
        target_resources: [DERIVATION_POLICY.ceiling[0].resource],
        expires_at: "2027-01-01T00:00:00Z",
      }),
    );
    missionId = stack.kernel.approve({
      intent,
      proposedAuthority: [
        {
          type: "mission_resource_access",
          resource: DERIVATION_POLICY.ceiling[0].resource,
          actions: ["payments:invoice.read"],
          constraints: { vendors: ["acme"] },
        },
      ],
      subject: { iss: stack.issuer, sub: "alice" },
      approver: { iss: stack.issuer, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-mas-join-stack",
    }).id;

    // The credential: minted by the AS's own dev ordinary-issuance route, so
    // it verifies on the published jwks_uri exactly as a Mission-bound token
    // does. It carries a scope and NO mission claim.
    dpopKeys = await generateKeyPair("ES256", { extractable: true });
    const jkt = await calculateJwkThumbprint(await exportJWK(dpopKeys.publicKey));
    const res = await fetch(`http://localhost:${AS_PORT}/dev/ordinary-token`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-service-token": DEV_SERVICE_TOKEN },
      body: JSON.stringify({ sub: "alice", client_id: "ap-agent", scope: "payments.read", jkt }),
    });
    expect(res.status, await res.clone().text()).toBe(200);
    credential = ((await res.json()) as { access_token: string }).access_token;
  }, 60_000);

  afterAll(async () => {
    for (const close of cleanups.splice(0).reverse()) await close();
  });

  /**
   * Present the credential on the composed stack's MAS-governed channel.
   * The streamable-HTTP transport is ONE session per channel, and the stack
   * starts exactly one governed channel, so this test connects once: the
   * per-reference negatives (absent, malformed, conflicting) belong to
   * `services/mcp-payments/test/mcp-http-channel.test.ts`, which builds a
   * fresh channel per case.
   */
  async function callGoverned(reference: string) {
    const channel = stack.masGovernedChannel;
    if (!channel) throw new Error("no MAS-governed channel: config/mas-join.json does not govern this resource");
    const { client, close } = await createHttpMediatedClient(channel.url, credential, dpopKeys, {
      "mission-reference": reference,
    });
    cleanups.push(close);
    return client.callTool("get_invoice", { invoice_id: "inv-1" });
  }

  it("starts the MAS-governed channel because config/mas-join.json names this resource governed", () => {
    expect(stack.masGovernedChannel).toBeDefined();
  });

  it("carries no mission claim on the credential, so ONLY the propagated reference names the Mission", () => {
    const claims = JSON.parse(Buffer.from(credential.split(".")[1] as string, "base64url").toString()) as Record<
      string,
      unknown
    >;
    expect(claims.mission).toBeUndefined();
    expect(claims.scope).toBe("payments.read");
    expect(claims.aud).toBe(CANONICAL_RESOURCE);
  });

  it("permits a joined read end to end, with authority drawn from the referenced Mission", async () => {
    const res = await callGoverned(`id="${missionId}", issuer="${stack.issuer}"`);
    expect(res.ok, JSON.stringify(res)).toBe(true);
  });
}, 60_000);
