/**
 * @spec runtime#decision-channel — the PEP side of the reference remote
 * decision channel ({@link ./server.js} is the PDP side). Every request is
 * signed and every response's signature is verified before the decision it
 * carries is trusted: an unreachable PDP, a refused channel, or an
 * unauthenticated or tampered response is never surfaced as though it were
 * an ordinary PDP decision, and a decision this client could not
 * authenticate is never honored, mirroring "the PEP authenticates the PDP
 * and verifies response integrity before accepting permit/deny."
 */

import { randomUUID } from "node:crypto";
import { macEqualHex, macHex, REQUEST_MAC_DOMAIN, RESPONSE_MAC_DOMAIN } from "./channel-mac.js";
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
    });
  } catch {
    return channelDeny("decision_channel_unreachable");
  }

  const raw = await res.text();
  if (!res.ok) {
    return channelDeny("decision_channel_refused", { channel_status: res.status });
  }

  // @spec runtime#decision-channel: "the parties MUST authenticate each
  // other" -- the PEP authenticates the PDP, and verifies response
  // integrity, before accepting the permit/deny it carries.
  const responseSignature = res.headers.get("x-pdp-signature");
  const expected = macHex(cfg.secret, RESPONSE_MAC_DOMAIN, [raw]);
  if (responseSignature === null || !macEqualHex(responseSignature, expected)) {
    return channelDeny("decision_channel_unauthenticated_response");
  }

  try {
    return JSON.parse(raw) as Decision;
  } catch {
    return channelDeny("decision_channel_malformed_response");
  }
}
