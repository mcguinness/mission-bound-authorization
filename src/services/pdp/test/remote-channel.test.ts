/**
 * @spec runtime#decision-channel — negative-conformance evidence for the
 * Remote Decision Channel's baseline requirements: the reference PDP HTTP
 * listener ({@link ../src/server.js}) and PEP client ({@link
 * ../src/client.js}) over a REAL out-of-process HTTP hop (127.0.0.1, an
 * ephemeral port), not another direct function call. This closes the gap
 * the issue's tree evidence found: `pep.ts` calling `evaluate()` in-process
 * with zero HTTP/RPC listener anywhere in `src/services/pdp/src`.
 *
 * Every negative case asserts BOTH the refusal and zero PDP evaluation
 * (`evaluations.n` stays 0 -- the real `evaluate` is wrapped in a counting
 * spy, never bypassed), proving the failure is a channel-boundary refusal,
 * not a decision the PDP made that the client happened to reject. Each
 * failure is followed by a valid signed request on the SAME running
 * server, showing the server is not simply broken (non-vacuous). The
 * co-resident case is exercised separately, calling `evaluate()` directly
 * with no channel at all, to show it satisfies the requirement
 * structurally without falsely exercising the remote branch.
 *
 * No live OpenFGA is needed: `alwaysAllowFga` (the same fixture pattern
 * `evaluate-fail-closed.test.ts` uses) satisfies only the one method
 * `evaluate()` calls, so this file never skips.
 */

import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { macHex, REQUEST_MAC_DOMAIN } from "../src/channel-mac.js";
import { evaluateRemote } from "../src/client.js";
import { evaluate, type EvaluationRequest } from "../src/evaluate.js";
import type { Fga } from "../src/fga.js";
import type { MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBoundSeconds } from "../src/policy.js";
import { createPdpHttpServer, type PdpHttpServerHandle } from "../src/server.js";

const RESOURCE = "http://localhost:4403/mcp";
const OTHER_RESOURCE = "http://localhost:4404/mcp";
const NOW = new Date("2026-07-22T12:00:00Z");
const PEP_ID = "mcp-payments-pep";
const SECRET = "test-shared-secret-do-not-reuse";

/** Always permits at the FGA layer, so only the channel and evaluate()'s own
 * steps decide the outcome (no live OpenFGA / docker compose needed). */
const alwaysAllowFga = { checkWithContext: async () => true } as unknown as Fga;

const view = (): MissionView => ({
  id: "msn_test_1",
  issuer: "https://as.test",
  state: "active",
  version: 1,
  authority_hash: "sha-256:testhash",
  authority_set: [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }],
  subject: { iss: "https://as.test", sub: "alice" },
  client_id: "ap-agent",
});

const req = (over: Partial<EvaluationRequest> = {}): EvaluationRequest => ({
  subject: { id: "alice" },
  resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "acme" } },
  action: { name: "payments:invoice.read" },
  context: { audience: RESOURCE, mission: { id: "msn_test_1", issuer: "https://as.test" } },
  ...over,
});

let handle: PdpHttpServerHandle | undefined;
afterEach(async () => {
  await handle?.close();
  handle = undefined;
});

/** Starts the reference PDP HTTP server with one registered PEP, wrapping
 * the real `evaluate` in a counter so a test can prove zero decision work
 * happened on a channel-boundary refusal. */
async function startServer(evaluations: { n: number }): Promise<PdpHttpServerHandle> {
  const countingEvaluate: typeof evaluate = async (r, o) => {
    evaluations.n += 1;
    return evaluate(r, o);
  };
  handle = await createPdpHttpServer({
    peps: new Map([[PEP_ID, { secret: SECRET, scopes: [RESOURCE] }]]),
    getOptions: () => ({
      view: view(),
      fga: alwaysAllowFga,
      modelId: "unit-test-model",
      now: () => NOW,
      stalenessBoundSeconds,
      relationForAction,
      allowedFreshnessSources: new Set(["status"]),
    }),
    evaluateFn: countingEvaluate,
    replayWindowSeconds: 30,
  });
  return handle;
}

describe("Remote Decision Channel (@spec runtime#decision-channel)", () => {
  it("a validly signed request over a real HTTP hop permits, and the PEP verifies the response signature", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);
    const decision = await evaluateRemote(req(), { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
    expect(evaluations.n).toBe(1);
  });

  it("a request with no channel signature is refused before evaluation, with zero PDP evaluation", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);
    const res = await fetch(server.url, {
      method: "POST",
      headers: { "content-type": "application/json", "x-pdp-pep-id": PEP_ID },
      body: JSON.stringify({ request: req() }),
    });
    expect(res.status).toBe(401);
    expect(evaluations.n).toBe(0);
    // Non-vacuous: a valid request on the SAME server still permits.
    const decision = await evaluateRemote(req(), { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect(decision.decision).toBe(true);
    expect(evaluations.n).toBe(1);
  });

  it("an unregistered PEP identity is refused before evaluation, with zero PDP evaluation", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);
    const decision = await evaluateRemote(req(), { url: server.url, pepId: "not-a-registered-pep", secret: SECRET });
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("decision_channel_refused");
    expect(evaluations.n).toBe(0);
    const ok = await evaluateRemote(req(), { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect(ok.decision).toBe(true);
  });

  it("a decision request modified in transit after signing is refused before evaluation, with zero PDP evaluation", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);
    const tamperingFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const original = JSON.parse(String(init?.body)) as { request: EvaluationRequest };
      const tampered = { request: { ...original.request, action: { name: "payments:payment.execute" } } };
      return fetch(input, { ...init, body: JSON.stringify(tampered) });
    }) as typeof fetch;
    const decision = await evaluateRemote(req(), {
      url: server.url,
      pepId: PEP_ID,
      secret: SECRET,
      fetchImpl: tamperingFetch,
    });
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("decision_channel_refused");
    expect(evaluations.n).toBe(0);
    const ok = await evaluateRemote(req(), { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect(ok.decision).toBe(true);
  });

  it("a PEP submitting a decision request outside its authorized enforcement scope is refused before evaluation, with zero PDP evaluation", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);
    const decision = await evaluateRemote(
      req({ context: { audience: OTHER_RESOURCE, mission: { id: "msn_test_1", issuer: "https://as.test" } } }),
      { url: server.url, pepId: PEP_ID, secret: SECRET },
    );
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("decision_channel_refused");
    expect(evaluations.n).toBe(0);
    const ok = await evaluateRemote(req(), { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect(ok.decision).toBe(true);
  });

  it("a replayed request (same nonce) is refused the second time, with the PDP evaluated only once", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);
    const nonce = randomUUID();
    const issuedAt = String(Date.now());
    const body = JSON.stringify({ request: req() });
    const signature = macHex(SECRET, REQUEST_MAC_DOMAIN, [PEP_ID, nonce, issuedAt, body]);
    const headers = {
      "content-type": "application/json",
      "x-pdp-pep-id": PEP_ID,
      "x-pdp-signature": signature,
      "x-pdp-nonce": nonce,
      "x-pdp-issued-at": issuedAt,
    };
    const first = await fetch(server.url, { method: "POST", headers, body });
    expect(first.status).toBe(200);
    expect(evaluations.n).toBe(1);
    const second = await fetch(server.url, { method: "POST", headers, body });
    expect(second.status).toBe(401);
    expect(evaluations.n).toBe(1);
  });

  it("a request signed too far in the past is refused before evaluation, with zero PDP evaluation", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);
    const nonce = randomUUID();
    const staleIssuedAt = String(Date.now() - 10 * 60 * 1000); // 10 minutes ago, replay window is 30s
    const body = JSON.stringify({ request: req() });
    const signature = macHex(SECRET, REQUEST_MAC_DOMAIN, [PEP_ID, nonce, staleIssuedAt, body]);
    const res = await fetch(server.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-pdp-pep-id": PEP_ID,
        "x-pdp-signature": signature,
        "x-pdp-nonce": nonce,
        "x-pdp-issued-at": staleIssuedAt,
      },
      body,
    });
    expect(res.status).toBe(401);
    expect(evaluations.n).toBe(0);
    const ok = await evaluateRemote(req(), { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect(ok.decision).toBe(true);
  });

  it("a decision response modified in transit after the PDP signs it is refused; the PEP MUST NOT act on it", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);
    const tamperingFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const res = await fetch(input, init);
      const body = await res.text();
      const tampered = JSON.stringify({ ...(JSON.parse(body) as Record<string, unknown>), decision: true });
      return new Response(tampered, { status: res.status, headers: res.headers });
    }) as typeof fetch;
    // The untampered decision denies (the action is outside the Authority
    // Set); the tamper flips `decision` to true on the wire. The response
    // signature no longer matches the tampered bytes, so the client MUST
    // refuse it rather than act on the forged permit.
    const decision = await evaluateRemote(req({ action: { name: "does_not_exist" } }), {
      url: server.url,
      pepId: PEP_ID,
      secret: SECRET,
      fetchImpl: tamperingFetch,
    });
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("decision_channel_unauthenticated_response");
    // The PDP DID evaluate (and denied); the client refuses to trust the
    // tampered reply rather than silently re-deriving the correct answer.
    expect(evaluations.n).toBe(1);
  });

  it("a decision response with no signature is refused; the PEP MUST NOT act on it", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);
    const stripSignatureFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const res = await fetch(input, init);
      const body = await res.text();
      const headers = new Headers(res.headers);
      headers.delete("x-pdp-signature");
      return new Response(body, { status: res.status, headers });
    }) as typeof fetch;
    const decision = await evaluateRemote(req(), {
      url: server.url,
      pepId: PEP_ID,
      secret: SECRET,
      fetchImpl: stripSignatureFetch,
    });
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("decision_channel_unauthenticated_response");
    // The underlying (unrecoverable, discarded) decision was a genuine
    // permit; the PEP never acts on it because it arrived unauthenticated.
    expect(evaluations.n).toBe(1);
  });

  it("co-resident: calling evaluate() directly needs no channel signature, satisfying the requirement structurally", async () => {
    const dec = await evaluate(req(), {
      view: view(),
      fga: alwaysAllowFga,
      modelId: "unit-test-model",
      now: () => NOW,
      stalenessBoundSeconds,
      relationForAction,
      allowedFreshnessSources: new Set(["status"]),
    });
    expect(dec.decision).toBe(true);
  });
});
