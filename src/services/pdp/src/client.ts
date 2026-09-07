/**
 * @spec runtime#decision-channel — the PEP side of the reference remote
 * decision channel ({@link ./server.js} is the PDP side). Every request is
 * signed and every response's signature is verified before the decision it
 * carries is trusted: an unreachable PDP, a refused channel, or an
 * unauthenticated or tampered response is never surfaced as though it were
 * an ordinary PDP decision, and a decision this client could not
 * authenticate is never honored, mirroring "the PEP authenticates the PDP
 * and verifies response integrity before accepting permit/deny." A request
 * is bounded by {@link RemotePdpClientConfig.timeoutMs}: an unresponsive
 * PDP is refused rather than awaited indefinitely.
 */

import { randomUUID } from "node:crypto";
import { macEqualHex, macHex, REQUEST_MAC_DOMAIN, RESPONSE_MAC_DOMAIN, sha256Hex } from "./channel-mac.js";
import type { Decision, EvaluationRequest } from "./evaluate.js";

export interface RemotePdpClientConfig {
  /** The PDP's /evaluate endpoint URL. */
  url: string;
  /** This PEP's registered identity. */
  pepId: string;
  /** The shared secret registered with the PDP for this identity. */
  secret: string;
  /** Injectable transport for tests (a tampering wrapper, a dead endpoint). Defaults to the global fetch. */
  fetchImpl?: typeof fetch;
  /** Abort the request if the PDP has not responded within this many milliseconds. Default 5000. */
  timeoutMs?: number;
  /** Maximum response bytes, including a signed denial. Default 1 MiB. */
  maxResponseBytes?: number;
}

// Local failures retain the legacy false/context shape for existing callers,
// but are branded by origin, never by a string a remote PDP can supply.
const localRefusals = new WeakSet<object>();
export function isDecisionChannelRefusal(value: unknown): boolean {
  return value !== null && typeof value === "object" && localRefusals.has(value);
}
const object = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);
function channelDeny(denial_reason: string, extra: Record<string, unknown> = {}): Decision {
  const result = { decision: false, context: { denial_reason, ...extra } };
  localRefusals.add(result);
  return result;
}

/**
 * Submit a decision request over the remote channel. Any channel-boundary
 * failure (an unreachable PDP, a refused channel, an unsigned or
 * mis-signed response) returns a synthetic deny; it never surfaces a
 * transport error as though it were a PDP decision, and it never returns a
 * decision this client could not authenticate.
 */
export async function evaluateRemote(req: EvaluationRequest, cfg: RemotePdpClientConfig): Promise<Decision> {
  const doFetch = cfg.fetchImpl ?? fetch;
  const nonce = randomUUID();
  const issuedAt = String(Date.now());
  const body = JSON.stringify({ request: req });
  const signature = macHex(cfg.secret, REQUEST_MAC_DOMAIN, [cfg.pepId, nonce, issuedAt, body]);

  const timeoutMs = cfg.timeoutMs ?? 5000;
  const maxBytes = cfg.maxResponseBytes ?? 1024 * 1024;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || !Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error("remote PDP timeout and response limit must be positive integers");
  }
  const controller = new AbortController();
  const deadline = Date.now() + timeoutMs;
  let timer: ReturnType<typeof setTimeout>;
  const expired = new Promise<Decision>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve(channelDeny("decision_channel_timeout"));
    }, timeoutMs);
  });

  const exchange = async (): Promise<Decision> => {
    let res: Response;
    let raw: string;
    try {
      res = await doFetch(cfg.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-pdp-pep-id": cfg.pepId,
          "x-pdp-signature": signature,
          "x-pdp-nonce": nonce,
          "x-pdp-issued-at": issuedAt,
        },
        body,
        signal: controller.signal,
      });
      if (res.body) {
        const reader = res.body.getReader();
        const chunks: Uint8Array[] = [];
        let bytes = 0;
        try {
          for (;;) {
            const chunk = await reader.read();
            if (chunk.done) break;
            bytes += chunk.value.byteLength;
            if (bytes > maxBytes) {
              void reader.cancel().catch(() => {});
              controller.abort();
              return channelDeny("decision_channel_response_too_large");
            }
            chunks.push(chunk.value);
          }
          raw = Buffer.concat(chunks).toString("utf8");
        } finally { reader.releaseLock(); }
      } else {
        raw = await res.text();
        if (Buffer.byteLength(raw) > maxBytes) return channelDeny("decision_channel_response_too_large");
      }
    } catch (err) {
      return channelDeny(controller.signal.aborted || (err instanceof Error && err.name === "AbortError")
        ? "decision_channel_timeout" : "decision_channel_unreachable");
    }
    if (!res.ok) {
      return channelDeny("decision_channel_refused", { channel_status: res.status });
    }

    // @spec runtime#decision-channel: "the parties MUST authenticate each
    // other" -- the PEP authenticates the PDP, and verifies response
    // integrity, before accepting the permit/deny it carries. The expected
    // MAC is recomputed from THIS call's own outstanding request (its
    // pepId, nonce, issuedAt, and request digest, never values read off the
    // response): a response correctly signed for a different request cannot
    // satisfy it, so a captured, validly signed reply cannot be replayed
    // onto this one.
    const responseSignature = res.headers.get("x-pdp-signature");
    const expected = macHex(cfg.secret, RESPONSE_MAC_DOMAIN, [
      cfg.pepId,
      nonce,
      issuedAt,
      sha256Hex(body),
      String(res.status),
      raw,
    ]);
    if (responseSignature === null || !macEqualHex(responseSignature, expected)) {
      return channelDeny("decision_channel_unauthenticated_response");
    }

    try {
      const parsed: unknown = JSON.parse(raw);
      if (
        !object(parsed) ||
        typeof parsed.decision !== "boolean" ||
        !object(parsed.context) ||
        (parsed.decision && !object(parsed.context.conditions)) ||
        (!parsed.decision &&
          typeof parsed.context.reason !== "string" &&
          typeof parsed.context.denial_reason !== "string")
      ) {
        return channelDeny("decision_channel_malformed_response");
      }
      if (Date.now() >= deadline) return channelDeny("decision_channel_timeout");
      return parsed as unknown as Decision;
    } catch {
      return channelDeny("decision_channel_malformed_response");
    }
  };
  try { return await Promise.race([exchange(), expired]); }
  finally { clearTimeout(timer!); }
}
