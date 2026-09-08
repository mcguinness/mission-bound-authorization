import { describe, expect, it } from "vitest";
import { evaluateRemote, isDecisionChannelRefusal } from "../src/client.js";
import { macHex, RESPONSE_MAC_DOMAIN, sha256Hex } from "../src/channel-mac.js";
import type { EvaluationRequest } from "../src/evaluate.js";

const request = { subject: { id: "alice" }, resource: { type: "invoice", id: "one" }, action: { name: "read" }, context: { audience: "https://resource.test" } } as EvaluationRequest;
const config = { url: "http://unused.test/evaluate", pepId: "pep", secret: "test-only" };
function signed(raw: string): typeof fetch {
  return (async (_url, init) => {
    const h = new Headers(init?.headers);
    const signature = macHex(config.secret, RESPONSE_MAC_DOMAIN, [config.pepId, h.get("x-pdp-nonce")!, h.get("x-pdp-issued-at")!, sha256Hex(String(init?.body)), "200", raw]);
    return new Response(raw, { headers: { "x-pdp-signature": signature } });
  }) as typeof fetch;
}

describe("remote PDP full-response boundaries", () => {
  it("bounds a stalled body after headers even when the transport ignores abort", async () => {
    const start = Date.now();
    const decision = await evaluateRemote(request, { ...config, timeoutMs: 15, fetchImpl: (async () => new Response(new ReadableStream({ start() {} }))) as typeof fetch });
    expect(Date.now() - start).toBeLessThan(1500);
    expect(decision.context.denial_reason).toBe("decision_channel_timeout");
    expect(isDecisionChannelRefusal(decision)).toBe(true);
  });
  it("classifies a rejecting body locally rather than throwing after headers", async () => {
    const decision = await evaluateRemote(request, { ...config, fetchImpl: (async () => new Response(new ReadableStream({ start(controller) { controller.error(new Error("broken body")); } }))) as typeof fetch });
    expect(decision.context.denial_reason).toBe("decision_channel_unreachable");
    expect(isDecisionChannelRefusal(decision)).toBe(true);
  });
  it("limits streamed response bytes before authentication and parsing", async () => {
    const decision = await evaluateRemote(request, { ...config, maxResponseBytes: 8, fetchImpl: signed("x".repeat(100)) });
    expect(decision.context.denial_reason).toBe("decision_channel_response_too_large");
    expect(isDecisionChannelRefusal(decision)).toBe(true);
  });
  it("rejects authenticated malformed JSON and non-Decision shapes", async () => {
    for (const raw of ["{", "null", "[]", "true", '{"decision":"true","context":{}}', '{"decision":true,"context":null}', '{"decision":true,"context":{"conditions":[]}}', '{"decision":false,"context":{}}']) {
      const decision = await evaluateRemote(request, { ...config, fetchImpl: signed(raw) });
      expect(decision.context.denial_reason, raw).toBe("decision_channel_malformed_response");
      expect(isDecisionChannelRefusal(decision)).toBe(true);
    }
  });
  it("preserves a legitimate authenticated PDP denial and cannot brand it by reason text", async () => {
    for (const reason of ["out_of_authority", "decision_channel_timeout"]) {
      const value = { decision: false, context: { reason, denial_reason: reason } };
      const decision = await evaluateRemote(request, { ...config, fetchImpl: signed(JSON.stringify(value)) });
      expect(decision).toEqual(value);
      expect(isDecisionChannelRefusal(decision)).toBe(false);
    }
  });
  it("rejects an unsigned response and invalid deadline/size configuration", async () => {
    const decision = await evaluateRemote(request, { ...config, fetchImpl: (async () => new Response('{"decision":false,"context":{"reason":"no"}}')) as typeof fetch });
    expect(decision.context.denial_reason).toBe("decision_channel_unauthenticated_response");
    for (const value of [0, -1, Infinity, NaN, 1.5]) {
      await expect(evaluateRemote(request, { ...config, timeoutMs: value })).rejects.toThrow("positive integers");
      await expect(evaluateRemote(request, { ...config, maxResponseBytes: value })).rejects.toThrow("positive integers");
    }
  });
});
