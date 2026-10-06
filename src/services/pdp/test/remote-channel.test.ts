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
import { evaluateRemote, isDecisionChannelRefusal, requestMacParts } from "../src/client.js";
import { channelDeadlineMs } from "../src/decision-channel.js";
import { evaluate, type EvaluationRequest } from "../src/evaluate.js";
import { withCredential } from "./with-credential.js";
import type { Fga } from "../src/fga.js";
import type { MissionView } from "../src/policy-view.js";
import { relationForAction, stalenessBound } from "../src/policy.js";
import { createPdpHttpServer, type PdpHttpServerHandle } from "../src/server.js";
import { freshKey, openTestClaims } from "./claim-fixture.js";

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

// The credential's own authority rides every request (#825 PR 2b), so the
// fixture runs in the builder: requests reach the PDP over the channel.
const req = (over: Partial<EvaluationRequest> = {}): EvaluationRequest =>
  withCredential({
    subject: { id: "alice" },
    resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, vendor_id: "acme" } },
    action: { name: "payments:invoice.read" },
    // The observation is REQUIRED under the declared pep placement (#1049 owner ruling).
    context: {
      mission: { id: "msn_test_1", issuer: "https://as.test" },
      mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
    },
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
async function startServer(
  evaluations: { n: number },
  overrides: { maxBodyBytes?: number } = {},
): Promise<PdpHttpServerHandle> {
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
      stalenessBound,
      relationForAction,
      stateSourcePlacement: "pep" as const,
    }),
    evaluateFn: countingEvaluate,
    replayWindowSeconds: 30,
    ...overrides,
  });
  return handle;
}

describe("channel deadline inside the action class's staleness budget (@spec authzen#transport-behavior)", () => {
  it("caps the configured deadline at the declared window for the class, and leaves it where the class declares none", () => {
    // irreversible_action publishes 30 s, so a 120 s configured deadline
    // cannot outlive it; consequential_read publishes 300 s, so the tighter
    // configured deadline stands.
    expect(channelDeadlineMs("irreversible_action", 120_000)).toBe(30_000);
    expect(channelDeadlineMs("consequential_read", 120_000)).toBe(120_000);
    expect(channelDeadlineMs("external_commitment", 120_000)).toBe(60_000);
    // A class declared with no active freshness requirement, and a label the
    // statement does not declare, have no window to cap the deadline: the
    // configured value stands, and the PDP applies its own class rule.
    expect(channelDeadlineMs("audit_only", 120_000)).toBe(120_000);
    expect(channelDeadlineMs("unpublished_class", 120_000)).toBe(120_000);
    expect(channelDeadlineMs(undefined)).toBe(5_000);
  });
});

describe("Remote Decision Channel (@spec runtime#decision-channel)", () => {
  it("a validly signed request over a real HTTP hop permits, and the PEP verifies the response signature", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);
    const decision = await evaluateRemote(req(), { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect(decision.decision, JSON.stringify(decision.context)).toBe(true);
    expect(evaluations.n).toBe(1);
  });

  it("enforces the credential bound at the remote PDP: an allowing Mission and policy never override a narrower credential (@spec runtime#input-authority, #825 PR 2b)", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);
    const client = { url: server.url, pepId: PEP_ID, secret: SECRET };
    const built = req();
    const withAuthority = (credential: NonNullable<EvaluationRequest["context"]["credential"]>): EvaluationRequest => ({
      ...built,
      context: { ...built.context, credential },
    });
    // The view and policy allow this invoice read; the credential covers only globex.
    const narrowed = await evaluateRemote(
      withAuthority({
        authority: [
          {
            type: "mission_resource_access",
            resource: RESOURCE,
            actions: ["payments:invoice.read"],
            constraints: { vendors: ["globex"] },
          },
        ],
      }),
      client,
    );
    expect(narrowed.decision).toBe(false);
    expect(narrowed.context.denial_reason).toBe("out_of_authority");
    const missing = await evaluateRemote(withAuthority({}), client);
    expect(missing.decision).toBe(false);
    expect(missing.context.denial_reason).toBe("credential_invalid");
    expect(evaluations.n).toBe(2);
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
      req({ resource: { type: "invoice", id: "inv-1", properties: { audience: OTHER_RESOURCE, vendor_id: "acme" } } }),
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

  it("rejects a replayed permit response bound to a different request", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);

    // Request A: a genuinely permitted decision over a raw, correctly
    // signed request. Its validly signed response is captured.
    const nonceA = randomUUID();
    const issuedAtA = String(Date.now());
    const bodyA = JSON.stringify({ request: req() });
    const signatureA = macHex(SECRET, REQUEST_MAC_DOMAIN, [PEP_ID, nonceA, issuedAtA, bodyA]);
    const resA = await fetch(server.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-pdp-pep-id": PEP_ID,
        "x-pdp-signature": signatureA,
        "x-pdp-nonce": nonceA,
        "x-pdp-issued-at": issuedAtA,
      },
      body: bodyA,
    });
    expect(resA.status).toBe(200);
    const capturedBody = await resA.text();
    const capturedSignature = resA.headers.get("x-pdp-signature");
    expect(capturedSignature).not.toBeNull();
    expect((JSON.parse(capturedBody) as { decision: boolean }).decision).toBe(true);
    expect(evaluations.n).toBe(1);

    // Request B: a distinct request (its own nonce/issuedAt/digest,
    // generated inside evaluateRemote). The server genuinely processes it,
    // then an intermediary substitutes A's captured, validly signed permit
    // response in place of B's own real response.
    const replaySubstitutionFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      await fetch(input, init);
      return new Response(capturedBody, {
        status: 200,
        headers: { "content-type": "application/json", "x-pdp-signature": capturedSignature as string },
      });
    }) as typeof fetch;

    const decision = await evaluateRemote(req(), {
      url: server.url,
      pepId: PEP_ID,
      secret: SECRET,
      fetchImpl: replaySubstitutionFetch,
    });
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("decision_channel_unauthenticated_response");
    // The server evaluated both requests (A directly, B through the real
    // round trip the substitution fetch performs); the PEP still refuses
    // to trust A's response for B, despite both being validly signed for
    // their own request.
    expect(evaluations.n).toBe(2);
  });

  it("a request body larger than the configured bound is refused before evaluation, with zero PDP evaluation", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations, { maxBodyBytes: 512 });
    const nonce = randomUUID();
    const issuedAt = String(Date.now());
    const oversized = JSON.stringify({
      request: req({ resource: { type: "invoice", id: "inv-1", properties: { vendor_id: "x".repeat(500) } } }),
    });
    const signature = macHex(SECRET, REQUEST_MAC_DOMAIN, [PEP_ID, nonce, issuedAt, oversized]);
    const res = await fetch(server.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-pdp-pep-id": PEP_ID,
        "x-pdp-signature": signature,
        "x-pdp-nonce": nonce,
        "x-pdp-issued-at": issuedAt,
      },
      body: oversized,
    });
    expect(res.status).toBe(413);
    expect(evaluations.n).toBe(0);
    // Non-vacuous: a normal-sized valid request on the SAME server still permits.
    const ok = await evaluateRemote(req(), { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect(ok.decision).toBe(true);
    expect(evaluations.n).toBe(1);
  });

  it("a PDP that never responds is refused once the client timeout elapses, with zero PDP evaluation observed by the client", async () => {
    const evaluations = { n: 0 };
    const server = await startServer(evaluations);
    const hangingFetch = ((_input: string | URL | Request, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          const err = new Error("The operation was aborted");
          err.name = "AbortError";
          reject(err);
        });
      })) as typeof fetch;
    const decision = await evaluateRemote(req(), {
      url: server.url,
      pepId: PEP_ID,
      secret: SECRET,
      fetchImpl: hangingFetch,
      timeoutMs: 20,
    });
    expect(decision.decision).toBe(false);
    expect(decision.context.denial_reason).toBe("decision_channel_timeout");
    expect(evaluations.n).toBe(0);
    // Non-vacuous: a valid request over the real channel on the SAME server still permits.
    const ok = await evaluateRemote(req(), { url: server.url, pepId: PEP_ID, secret: SECRET });
    expect(ok.decision).toBe(true);
  });

  it("co-resident: calling evaluate() directly needs no channel signature, satisfying the requirement structurally", async () => {
    const dec = await evaluate(req(), {
      view: view(),
      fga: alwaysAllowFga,
      modelId: "unit-test-model",
      now: () => NOW,
      stalenessBound,
      relationForAction,
      stateSourcePlacement: "pep" as const,
    });
    expect(dec.decision).toBe(true);
  });
});

/**
 * @spec runtime#idempotency, retransmission condition 5 (#917): over the
 * remote channel the claim's requester is the authenticated PEP identity and
 * the MAC-covered epoch of its redemption store, never a member of the
 * request body, and an unreachable claim domain is no decision at all.
 */
describe("the remote channel binds the claim requester (@spec runtime#idempotency, #917)", () => {
  const keyed = (key: string): EvaluationRequest =>
    withCredential({
      subject: { id: "alice" },
      resource: { type: "invoice", id: "inv-1", properties: { audience: RESOURCE, vendor_id: "acme" } },
      action: { name: "payments:invoice.read", properties: { idempotency_key: key } },
      context: {
        mission: { id: "msn_test_1", issuer: "https://as.test" },
        action_class: "irreversible_action",
        parameter_digest: "sha-256:pd-917",
        mission_state_observation: { state: "active", mode: "fresh", freshness_at: NOW.toISOString() },
      },
    });
  async function startClaimServer(claims = openTestClaims({ now: () => NOW })): Promise<PdpHttpServerHandle> {
    handle = await createPdpHttpServer({
      peps: new Map([[PEP_ID, { secret: SECRET, scopes: [RESOURCE] }]]),
      getOptions: () => ({
        view: view(),
        fga: alwaysAllowFga,
        modelId: "unit-test-model",
        now: () => NOW,
        stalenessBound,
        relationForAction,
        stateSourcePlacement: "pep" as const,
      }),
      claims,
      consumptionStatus: (pepId) => (pepId === PEP_ID ? () => "unconsumed" : undefined),
    });
    return handle;
  }

  it("covers the PEP epoch with the request MAC: an altered epoch header is refused before evaluation", async () => {
    const server = await startClaimServer();
    const send = async (signedEpoch: string, sentEpoch: string) => {
      const nonce = randomUUID();
      const issuedAt = String(Date.now());
      const body = JSON.stringify({ request: keyed(freshKey()) });
      const signature = macHex(SECRET, REQUEST_MAC_DOMAIN, requestMacParts(PEP_ID, nonce, issuedAt, body, signedEpoch));
      return fetch(server.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-pdp-pep-id": PEP_ID,
          "x-pdp-signature": signature,
          "x-pdp-nonce": nonce,
          "x-pdp-issued-at": issuedAt,
          "x-pdp-pep-epoch": sentEpoch,
        },
        body,
      });
    };
    expect((await send("epoch-1", "epoch-1")).status).toBe(200);
    expect((await send("epoch-1", "epoch-2")).status).toBe(401);
  });

  it("returns a prior permit only to the authenticated PEP epoch it was issued to", async () => {
    const server = await startClaimServer();
    const key = freshKey();
    const client = (pepEpoch: string) => ({ url: server.url, pepId: PEP_ID, secret: SECRET, pepEpoch });
    const first = await evaluateRemote(keyed(key), client("epoch-1"));
    expect(first.decision, JSON.stringify(first.context)).toBe(true);
    const sameEpoch = await evaluateRemote(keyed(key), client("epoch-1"));
    expect(sameEpoch.context.evaluation_id).toBe(first.context.evaluation_id);
    expect(sameEpoch.decision).toBe(true);
    const otherEpoch = await evaluateRemote(keyed(key), client("epoch-2"));
    expect(otherEpoch.decision).toBe(false);
    expect(otherEpoch.context.denial_reason).toBe("duplicate_suppressed");
  });

  it("answers 503 when the claim domain is unreachable, and the PEP obtains no decision", async () => {
    const claims = openTestClaims({ now: () => NOW });
    const server = await startClaimServer(claims);
    claims.close();
    const decision = await evaluateRemote(keyed(freshKey()), { url: server.url, pepId: PEP_ID, secret: SECRET, pepEpoch: "epoch-1" });
    expect(isDecisionChannelRefusal(decision)).toBe(true);
    expect(decision.context.denial_reason).toBe("decision_channel_refused");
    expect(decision.context.channel_status).toBe(503);
  });
});
