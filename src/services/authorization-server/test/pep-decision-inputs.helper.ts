/**
 * Direct-PDP scenario fixtures (@spec runtime#classification, #1994): the
 * decision inputs the payments PEP sends for an action, so a direct PDP call
 * carries the class the deployment assigns it and meets that class's gates
 * instead of relying on a label the deployment never sends. Every action
 * carries a fresh observation of the Mission's state under the `pep`
 * placement; a high-consequence action also carries a parameter digest and a
 * fresh idempotency key, and is claimed in the scenario's claim domain.
 */
import { randomUUID } from "node:crypto";
import { TOOL_ACTIONS } from "@mission/mcp-payments";
import { type IdempotencyClaimDomain, openEphemeralClaimDomain, RUNTIME_POSTURE } from "@mission/pdp";

const HIGH_CONSEQUENCE = new Set(["irreversible_action", "external_commitment", "privileged_administration"]);

/** The class the payments PEP assigns a phaseless action. */
export function pepClassFor(action: string): string {
  const mapping = Object.values(TOOL_ACTIONS).find((m) => m.action === action && m.phase === undefined);
  if (!mapping) throw new Error(`no phaseless payments tool performs ${action}`);
  return mapping.actionClass;
}

/** The request members the payments PEP supplies for `action`, observed at `now`. */
export function pepDecisionInputs(action: string, missionState: string, now: Date) {
  const actionClass = pepClassFor(action);
  const high = HIGH_CONSEQUENCE.has(actionClass);
  return {
    actionProperties: high ? { idempotency_key: `idem_${randomUUID()}` } : undefined,
    context: {
      action_class: actionClass,
      mission_state_observation: { state: missionState, mode: "fresh", freshness_at: now.toISOString() },
      ...(high ? { parameter_digest: `sha-256:${randomUUID()}` } : {}),
    },
  };
}

/** A claim domain over the shipped statement, for a scenario's high-consequence permits. */
export function openScenarioClaims(now: () => Date): IdempotencyClaimDomain {
  return openEphemeralClaimDomain({ owner: RUNTIME_POSTURE.pdps[0] as string, statement: RUNTIME_POSTURE, now });
}
