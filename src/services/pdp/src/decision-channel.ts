import { randomBytes, randomUUID } from "node:crypto";
import { evaluateRemote, remoteClaimChannel } from "./client.js";
import { type ClaimChannel, claimChannelFor, type DecisionPoint } from "./decision-point.js";
import type { DecisionFn, DecisionOptions, EvaluationRequest } from "./evaluate.js";
import type { ClaimRequester, ConsumptionStatusFn } from "./idempotency-claims.js";
import { createPdpHttpServer } from "./server.js";
import { stalenessBound } from "./policy.js";

/**
 * @spec authzen#transport-behavior — "A PEP MUST bound each evaluation call
 * with a timeout inside the action class's staleness budget." A class
 * declared with a window caps the configured deadline. A class declared with
 * no active freshness requirement, and a label the statement does not
 * declare, carry no window to cap it, so the configured deadline stands: the
 * transport does not classify the action, and the PDP refuses an undeclared
 * class on its own (@spec authzen#runtime-denial-classification).
 */
export function channelDeadlineMs(actionClass: string | undefined, configuredMs?: number): number {
  const configured = Math.max(1, configuredMs ?? 5000);
  const declared = stalenessBound(actionClass);
  return declared.kind === "bounded" ? Math.max(1, Math.min(configured, declared.seconds * 1000)) : configured;
}

/** Trusted assembly seam: the remote server owns the options resolver and
 * the decision point (including its closed-over evidence signer). The PEP
 * receives a decision function and public verification material only.
 *
 * @spec runtime#idempotency (#917): the channel also binds who is asking:
 * `pepId` and `pepEpoch` (the epoch of the PEP's redemption store) become the
 * claim's requester, and `consumptionStatus` is that store's read-only answer
 * for retransmission condition 6. The PEP receives `claims`, the settlement
 * and reconciliation channel for the same requester, and nothing that could
 * name another. */
export async function createDecisionChannel(point: DecisionPoint, config: {
  mode: "co-resident" | "remote";
  pepId: string;
  audience: string;
  getOptions: (request: EvaluationRequest) => DecisionOptions | Promise<DecisionOptions>;
  timeoutMs?: number;
  pepEpoch?: string;
  consumptionStatus?: ConsumptionStatusFn;
}): Promise<{
  decide: DecisionFn;
  claims: ClaimChannel;
  remoteDecisionChannels: Array<{ boundary: string; trust_mode: string }>;
  close: () => Promise<void>;
}> {
  // Without a configured epoch the requester gets one no other request can
  // present: every claim still holds, and no retransmission can match.
  const pepEpoch = config.pepEpoch ?? `unbound:${randomUUID()}`;
  const requester: ClaimRequester = { pep_id: config.pepId, pep_epoch: pepEpoch };
  const decideAs = point.decideAs;
  const claimsFor = point.claimsFor;
  if (config.mode === "co-resident") return {
    decide: decideAs ? decideAs(requester, config.consumptionStatus) : point.decide,
    claims: claimsFor ? claimsFor(requester) : claimChannelFor(undefined, requester),
    remoteDecisionChannels: [],
    close: async () => {},
  };
  if (config.mode !== "remote") throw new Error("unknown decision channel mode");
  if (config.timeoutMs !== undefined && (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs <= 0)) throw new Error("invalid remote deadline");
  const secret = randomBytes(32).toString("base64url");
  const server = await createPdpHttpServer({
    peps: new Map([[config.pepId, { secret, scopes: [config.audience] }]]),
    getOptions: config.getOptions,
    // The server binds the authenticated requester and its consumption-status
    // capability onto the options; the decision point applies them.
    evaluateFn: (request, options) => decideAs && options.requester
      ? decideAs(options.requester, options.consumptionStatus)(request, options)
      : point.decide(request, options),
    ...(claimsFor ? { claimsFor } : {}),
    ...(config.consumptionStatus
      ? { consumptionStatus: (pepId: string) => (pepId === config.pepId ? config.consumptionStatus : undefined) }
      : {}),
  });
  let closing: Promise<void> | undefined;
  const client = { url: server.url, pepId: config.pepId, secret, pepEpoch };
  return {
    // Caller's options are deliberately not forwarded across this boundary.
    decide: (request: EvaluationRequest) => evaluateRemote(request, {
      ...client,
      timeoutMs: channelDeadlineMs(request.context.action_class, config.timeoutMs),
    }),
    claims: remoteClaimChannel({ ...client, audience: config.audience, ...(config.timeoutMs !== undefined ? { timeoutMs: config.timeoutMs } : {}) }),
    remoteDecisionChannels: [{ boundary: `${config.pepId} -> ${server.url}`, trust_mode: "per-PEP MAC request/response; scope-authorized PEP; PDP-signed Decision Evidence" }],
    close: () => closing ??= server.close(),
  };
}
