import { randomBytes } from "node:crypto";
import { evaluateRemote } from "./client.js";
import type { DecisionPoint } from "./decision-point.js";
import type { DecisionOptions, EvaluationRequest } from "./evaluate.js";
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
 * receives a decision function and public verification material only. */
export async function createDecisionChannel(point: DecisionPoint, config: {
  mode: "co-resident" | "remote";
  pepId: string;
  audience: string;
  getOptions: (request: EvaluationRequest) => DecisionOptions | Promise<DecisionOptions>;
  timeoutMs?: number;
}) {
  if (config.mode === "co-resident") return {
    decide: point.decide, remoteDecisionChannels: [], close: async () => {},
  };
  if (config.mode !== "remote") throw new Error("unknown decision channel mode");
  if (config.timeoutMs !== undefined && (!Number.isSafeInteger(config.timeoutMs) || config.timeoutMs <= 0)) throw new Error("invalid remote deadline");
  const secret = randomBytes(32).toString("base64url");
  const server = await createPdpHttpServer({
    peps: new Map([[config.pepId, { secret, scopes: [config.audience] }]]),
    getOptions: config.getOptions,
    evaluateFn: (request, options) => point.decide(request, options),
  });
  let closing: Promise<void> | undefined;
  return {
    // Caller's options are deliberately not forwarded across this boundary.
    decide: (request: EvaluationRequest) => evaluateRemote(request, {
      url: server.url, pepId: config.pepId, secret,
      timeoutMs: channelDeadlineMs(request.context.action_class, config.timeoutMs),
    }),
    remoteDecisionChannels: [{ boundary: `${config.pepId} -> ${server.url}`, trust_mode: "per-PEP MAC request/response; scope-authorized PEP; PDP-signed Decision Evidence" }],
    close: () => closing ??= server.close(),
  };
}
