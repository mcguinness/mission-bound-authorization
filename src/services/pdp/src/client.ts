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
}

function channelDeny(denial_reason: string, extra: Record<string, unknown> = {}): Decision {
  return { decision: false, context: { denial_reason, ...extra } };
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
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let res: Response;
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
  } catch (err) {
    return channelDeny(
      err instanceof Error && err.name === "AbortError" ? "decision_channel_timeout" : "decision_channel_unreachable",
    );
  } finally {
    clearTimeout(timer);
  }

  const raw = await res.text();
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
    return JSON.parse(raw) as Decision;
  } catch {
    return channelDeny("decision_channel_malformed_response");
  }
}
