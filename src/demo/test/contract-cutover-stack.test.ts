/**
 * @spec runtime#resource-contract, resource-access#resource-contract,
 * txn-authorization#resource-challenge (#249 C.3a and C.3b, D967, D1071): the
 * payments contract cutover's witnesses in the composed stack, the
 * Authorization Server, its Transaction Authorization Server and the payments
 * PEP joined, under the shipped configuration, which requires a reference for
 * the cutover's five actions. Where a witness needs the configuration before
 * the cutover, which required none, it applies it by spying on the kernel's or
 * the PEP's declarations, never by a runtime change.
 */
import { mkdtempSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, describe, expect, it, type MockInstance, vi } from "vitest";
import { CANONICAL_RESOURCE, contractsRequiring, currentContractProfileVersion, RESOURCE_CONTRACTS } from "@mission/demo-data";
import { ResourceContractDeclarations } from "@mission/core";
import {
  createHttpMcpChannel,
  createHttpMediatedClient,
  type DpopKeys,
  dpopProofFor,
  type EvaluationRequest,
} from "@mission/mcp-payments";
import { Fga } from "@mission/pdp";
import { issueMissionToken } from "../src/approval-console.js";
import { clientAssertionSigner, type IssuedMission } from "../src/oauth-client.js";
import { callWithTransactionCredential, composeStack, type DemoStack } from "../src/stack.js";

const tempFile = (prefix: string, name: string): string => join(mkdtempSync(join(tmpdir(), prefix)), name);
const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const AT_TYPE = "urn:ietf:params:oauth:token-type:access_token";

/** The five non-read payments actions the cutover requires a reference for (D865). */
const CUTOVER = [
  "payments:payment.schedule",
  "payments:payment.schedule.cancel",
  "payments:payment.execute",
  "payments:payment.reverse",
  "payments:remittance.send",
];

/**
 * The controlled clock every component in this file reads (`Date` faked,
 * advancing with real time): after the current contract's version took effect
 * and inside 2026-10-26's declared retention, so neither the Intent's expiry
 * nor that retention moves with the real date.
 */
const CLOCK_MS = Date.parse("2026-11-02T12:00:00Z");
/** The Intent's expiry: thirty days after the controlled clock. */
const EXPIRES_AT = new Date(CLOCK_MS + 30 * 86_400_000).toISOString();

/**
 * The shipped declarations as they stood while `version` was current: it
 * current, every newer version absent, the cutover's actions required.
 */
function asOf(version: string): ResourceContractDeclarations {
  return new ResourceContractDeclarations(
    RESOURCE_CONTRACTS.declarations.map((d) => {
      const versions = d.versions.filter((v) => v.version <= version);
      const served = new Set(versions.filter((v) => v.state !== "retired").flatMap((v) => v.operations));
      return {
        resource: d.resource,
        ...(d.resource_match !== undefined ? { resource_match: d.resource_match } : {}),
        id: d.id,
        requires_reference: CUTOVER.filter((a) => served.has(a)),
        versions: versions.map((v) => ({
          version: v.version,
          state: v.version === version ? "current" : v.state,
          digest: v.digest,
          ...(v.version !== version && v.retained_until !== undefined ? { retained_until: v.retained_until } : {}),
          ...(v.document !== undefined ? { document: v.document } : {}),
        })),
      };
    }),
  );
}

type Entry = { type: string; resource: string; actions: string[]; resource_contract?: { id: string; version: string; digest: string } };
const entriesOf = (token: string): Entry[] => (decodeJwt(token).authorization_details as Entry[] | undefined) ?? [];
const missionIdOf = (token: string): string => (decodeJwt(token).mission as { id: string }).id;

describe("the payments contract cutover's witnesses in the composed stack, under the shipped configuration (@spec runtime#resource-contract, resource-access#resource-contract, txn-authorization#resource-challenge, #249, D967, D1071)", () => {
  let fgaBootstrap: MockInstance;
  let stack: DemoStack;
  beforeAll(async () => {
    vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
    vi.setSystemTime(CLOCK_MS);
    fgaBootstrap = vi.spyOn(Fga, "bootstrap").mockResolvedValue({
      fga: { checkWithContext: async () => true, checkStored: async () => true, client: { write: async () => ({}) }, modelId: "test" } as unknown as Fga,
      storeId: "test",
      modelId: "test",
    });
    stack = await composeStack({
      openfgaUrl: "http://unused.test",
      presharedKey: "unused",
      withAuthServer: true,
      asPort: 14981,
      claimsFile: tempFile("cutover-claims-", "claims.sqlite"),
      writeReservationsFile: tempFile("cutover-reservations-", "write-reservations.sqlite"),
      resourcePolicyStore: { bootstrap: "development" },
    });
  });
  afterAll(async () => {
    if (stack) {
      await stack.authServer?.closeAuthServer();
      await stack.reconciler.stop();
      await stack.decisionChannel.close();
      await stack.masGovernedChannel?.close();
      stack.pdpClaims.close();
      stack.writeReservations.close();
      stack.evidenceRetention.close();
      stack.payments.db.close();
      stack.kernel.db.close();
    }
    fgaBootstrap.mockRestore();
    vi.useRealTimers();
  });

  const authServer = () => {
    if (!stack.authServer) throw new Error("the stack runs the AS");
    return stack.authServer;
  };

  /** A real Mission-bound token for `actions`: the agent's PAR, the trusted console's approval, the token endpoint, DPoP-bound. */
  const issue = (actions: string[], constraints: Record<string, unknown>): Promise<IssuedMission> =>
    issueMissionToken(
      authServer().asUrl,
      authServer().agentClientJwk,
      {
        missionIntent: JSON.stringify({
          intent: {
            goal: "Pay approved Acme invoices and send their remittance",
            target_resources: [CANONICAL_RESOURCE],
            expires_at: EXPIRES_AT,
          },
        }),
        authorizationDetails: JSON.stringify([{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions, constraints }]),
      },
      authServer().approverConsole,
    );

  /** The client's token endpoint request, authenticated and DPoP-bound to `keys` (retrying once with the server's nonce). */
  const token = async (params: Record<string, string>, keys: DpopKeys): Promise<{ status: number; body: Record<string, unknown> }> => {
    const endpoint = `${authServer().asUrl}/token`;
    const assertion = await clientAssertionSigner(authServer().asUrl, authServer().agentClientJwk);
    const send = async (nonce?: string) =>
      fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProofFor(keys, endpoint, "POST", nonce) },
        body: new URLSearchParams({ ...params, client_assertion: await assertion(), client_assertion_type: CLIENT_ASSERTION_TYPE }).toString(),
      });
    let res = await send();
    const nonce = res.headers.get("dpop-nonce");
    if (res.status === 400 && nonce) res = await send(nonce);
    return { status: res.status, body: (await res.json()) as Record<string, unknown> };
  };

  /** `tool` on `args` over the stack's HTTP MCP endpoint, under `credential` and a DPoP proof under `keys`. */
  const present = async (credential: string, keys: DpopKeys, tool: string, args: Record<string, unknown>, headers: Record<string, string> = {}) => {
    const channel = await createHttpMcpChannel(stack.server);
    try {
      const { client, close } = await createHttpMediatedClient(channel.url, credential, keys, headers);
      try {
        return await client.callTool(tool, args);
      } finally {
        await close();
      }
    } finally {
      await channel.close();
    }
  };

  /** Every effect a payments tool can leave: ledger, reversal, outbox and scheduling records. */
  const effects = () => ({
    ledger: stack.connectors.ledgerEntries().length,
    reversals: stack.connectors.reversalEntries().length,
    committed: stack.connectors.committedEffects().length,
    schedules: stack.writeReservations.schedules().length,
  });
  const recordsOf = (missionId: string, kind: string) => stack.evidence.forMission(missionId).filter((e) => e.kind === kind);

  // D967 test 1: an unpinned credential issued before the requirement stays
  // refused after it, refreshed or not. The shipped ceiling grants no
  // payments:payment.reverse, so no credential this deployment issues carries
  // it; the reversal's refusal is witnessed at the PEP (per-tool witnesses).
  it("refuses, with no decision and no effect, an unpinned credential issued before the requirement and its refresh after it, for every tool of the cutover's actions the deployment issues, and refreshing stamps no reference; both still perform a read", async () => {
    const before = vi.spyOn(stack.kernel, "resourceContracts").mockReturnValue(contractsRequiring([]));
    let issued: IssuedMission;
    try {
      issued = await issue(
        ["payments:invoice.read", "payments:payment.schedule", "payments:payment.schedule.cancel", "payments:payment.execute", "payments:remittance.send"],
        { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      );
    } finally {
      before.mockRestore();
    }
    expect(entriesOf(issued.accessToken).length).toBeGreaterThan(0);
    expect(entriesOf(issued.accessToken).every((e) => e.resource_contract === undefined)).toBe(true);
    const missionId = missionIdOf(issued.accessToken);
    const rt = (issued.artifacts.token.response as { refresh_token?: string }).refresh_token;
    expect(rt, "the code exchange issues a refresh token").toBeTruthy();

    // After the cutover: the shipped configuration, at the AS and the PEP. The
    // credential is otherwise sound: it still performs a read, which requires no reference.
    expect(stack.pep.contracts().declarations[0]?.requires_reference).toEqual(CUTOVER);
    const read = await present(issued.accessToken, issued.dpopKeys, "get_invoice", { invoice_id: "inv-1" });
    expect(read.ok, JSON.stringify(read)).toBe(true);
    expect(recordsOf(missionId, "decision").length).toBeGreaterThan(0);
    const refreshed = await token({ grant_type: "refresh_token", refresh_token: rt as string, resource: CANONICAL_RESOURCE }, issued.dpopKeys);
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    const refreshedToken = refreshed.body.access_token as string;
    expect(entriesOf(refreshedToken).length).toBe(entriesOf(issued.accessToken).length);
    expect(entriesOf(refreshedToken).every((e) => e.resource_contract === undefined)).toBe(true);

    const decisionsBefore = recordsOf(missionId, "decision").length;
    const refusalsBefore = recordsOf(missionId, "refusal").length;
    const executionsBefore = recordsOf(missionId, "execution").length;
    const effectsBefore = effects();
    const tools: Array<[string, string]> = [
      ["schedule_payment", "payments:payment.schedule"],
      ["cancel_scheduled_payment", "payments:payment.schedule.cancel"],
      ["check_transfer", "payments:payment.execute"],
      ["hold_transfer", "payments:payment.execute"],
      ["execute_wire_transfer", "payments:payment.execute"],
      ["send_remittance_email", "payments:remittance.send"],
    ];
    let calls = 0;
    for (const credential of [issued.accessToken, refreshedToken]) {
      for (const [tool] of tools) {
        const args = tool === "check_transfer" || tool === "hold_transfer" ? { invoice_id: "inv-1" } : { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` };
        const res = await present(credential, issued.dpopKeys, tool, args);
        calls += 1;
        expect(res.ok, `${tool}: ${JSON.stringify(res)}`).toBe(false);
        // Refused before the decision request, not after one.
        expect(recordsOf(missionId, "decision").length, `${tool}: decided`).toBe(decisionsBefore);
        expect(res.refusal_reason, tool).toBe("resource_contract_unresolvable");
      }
    }
    expect(new Set(tools.map(([, action]) => action))).toEqual(new Set(CUTOVER.filter((a) => a !== "payments:payment.reverse")));
    expect(recordsOf(missionId, "decision").length).toBe(decisionsBefore);
    expect(recordsOf(missionId, "execution").length).toBe(executionsBefore);
    expect(recordsOf(missionId, "refusal").length).toBe(refusalsBefore + calls);
    expect(effects()).toEqual(effectsBefore);
    const refreshedRead = await present(refreshedToken, issued.dpopKeys, "get_invoice", { invoice_id: "inv-1" });
    expect(refreshedRead.ok, JSON.stringify(refreshedRead)).toBe(true);
  });

  // D967 test 2: a supported older pin still works through transaction
  // authorization, the TAS and the PEP joined, under the requirement.
  it("performs a remittance under a Mission pinned to the superseded 2026-10-26 contract through the challenge, the Transaction Authorization Server and the transaction token's retry, under that version's Operation Profile, never the current one", async () => {
    const OLDER = "2026-10-26";
    const then = vi.spyOn(stack.kernel, "resourceContracts").mockReturnValue(asOf(OLDER));
    let remit: IssuedMission;
    try {
      remit = await issue(["payments:invoice.read", "payments:remittance.send"], { vendors: ["acme"] });
    } finally {
      then.mockRestore();
    }
    const [pinned] = entriesOf(remit.accessToken);
    expect(pinned?.resource_contract?.version).toBe(OLDER);
    const declared = RESOURCE_CONTRACTS.versionOf(pinned?.resource_contract);
    expect(declared?.version.state).toBe("superseded");
    // Within its declared retention at the controlled clock.
    expect(Date.parse(declared?.version.retained_until as string)).toBeGreaterThan(Date.now());
    const olderProfile = declared?.version.operation_profile;
    expect(olderProfile).toBe("payments-runtime-profile-v15");
    expect(olderProfile).not.toBe(currentContractProfileVersion(CANONICAL_RESOURCE));
    const missionId = missionIdOf(remit.accessToken);

    const registry = stack.operationProfiles;
    if (!registry) throw new Error("the stack runs the TAS");
    const admitted = vi.spyOn(registry, "admit");
    const completed = vi.spyOn(registry, "complete");
    const requests: EvaluationRequest[] = [];
    stack.onEnforce((e) => {
      if (e.token.mission?.id === missionId) requests.push(e.envelope);
    });
    try {
      const args = { invoice_id: "inv-1", idempotency_key: `idem_${randomUUID()}` };
      // 1. The gated tool, with the client's Accept-Txn-Challenge signal: denied, with a challenge.
      const challenged = await present(remit.accessToken, remit.dpopKeys, "send_remittance_email", args, { "accept-txn-challenge": "?1" });
      expect(challenged.ok).toBe(false);
      expect(challenged.denial_reason, JSON.stringify(challenged)).toBe("action_approval_required");
      const challenge = challenged.transaction_challenge as string;
      const operation = decodeJwt(challenge).authorization_details as Entry[];
      expect(operation[0]?.resource_contract).toEqual(pinned?.resource_contract);

      // 2. The transaction endpoint, discovered from AS metadata.
      const meta = (await (await fetch(`${authServer().asUrl}/.well-known/openid-configuration`)).json()) as Record<string, string>;
      const txnEndpoint = meta.transaction_authorization_endpoint as string;
      const assertion = await clientAssertionSigner(authServer().asUrl, authServer().agentClientJwk);
      const postTxn = async (payload: Record<string, string>) => {
        const res = await fetch(txnEndpoint, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpopProofFor(remit.dpopKeys, txnEndpoint, "POST") },
          body: new URLSearchParams({ client_id: "ap-agent", client_assertion: await assertion(), client_assertion_type: CLIENT_ASSERTION_TYPE, ...payload }).toString(),
        });
        return { status: res.status, body: (await res.json()) as Record<string, string> };
      };
      const submitted = await postTxn({ transaction_challenge: challenge, subject_token: remit.accessToken, subject_token_type: AT_TYPE });
      expect(submitted.status, JSON.stringify(submitted.body)).toBe(200);
      const handle = submitted.body.transaction_authorization_id as string;
      const task = stack.ars.pending().find((t) => JSON.stringify(t).includes(missionId)) ?? stack.ars.pending()[0];
      if (!task) throw new Error("the transaction endpoint opened no approval task");
      await stack.ars.adjudicate(task.id, "approve", "bob");
      const granted = await postTxn({ transaction_authorization_id: handle });
      expect(granted.status, JSON.stringify(granted.body)).toBe(200);
      const txnToken = granted.body.access_token as string;

      // 3. The retry under the transaction token: performed exactly once.
      const executionsBefore = recordsOf(missionId, "execution").length;
      const executed = await callWithTransactionCredential(stack.server, txnToken, remit.dpopKeys, "send_remittance_email", args);
      expect(executed.ok, JSON.stringify(executed)).toBe(true);
      expect(recordsOf(missionId, "execution").length).toBe(executionsBefore + 1);

      // The TAS admitted and completed under 2026-10-26's own profile.
      const admissions = admitted.mock.results.map((r) => r.value as { ok: boolean; version?: string });
      const completions = completed.mock.results.map((r) => r.value as { ok: boolean; version?: string });
      expect(admissions).toEqual([expect.objectContaining({ ok: true, version: olderProfile })]);
      expect(completions.length).toBeGreaterThan(0);
      for (const c of completions) expect(c).toMatchObject({ ok: true, version: olderProfile });
      // The PEP decided both the challenged attempt and the retry under the 2026-10-26 reference.
      expect(requests.length).toBeGreaterThanOrEqual(2);
      for (const r of requests) {
        expect((r.resource as { properties?: Record<string, unknown> }).properties?.resource_contract).toEqual(pinned?.resource_contract);
      }
    } finally {
      stack.onEnforce(() => {});
      completed.mockRestore();
      admitted.mockRestore();
    }
  });
});
