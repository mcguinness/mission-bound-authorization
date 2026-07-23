/**
 * Agent service (M12): the scenario runner's client end. Declares the MCP EMA
 * capability, drives the OAuth/DPoP/MCP flows, hosts the shaper (untrusted
 * intent proposal) and the minimal harness. This module exposes the harness
 * and the sub-agent spawn helper; the full scripted runner and optional LLM
 * loop are the demo entrypoint (scripts/demo).
 */

export { checkOnResume, type ResumeDecision, type MissionState } from "./harness.js";

export const EMA_CAPABILITY = "io.modelcontextprotocol/enterprise-managed-authorization";

/** The EMA capability the agent declares at MCP `initialize` (D14/M9). */
export function initializeCapabilities(): Record<string, unknown> {
  return { capabilities: { extensions: { [EMA_CAPABILITY]: {} } } };
}

/**
 * A shaper proposal is untrusted client input (@spec mission-shaping, D22).
 * This helper only *proposes* a Mission Intent from a natural-language-ish
 * goal; the AS derives and bounds authority regardless of what is proposed,
 * so a compromised shaper can propose badly but never widen.
 */
export function shapeIntent(input: {
  goal: string;
  resources: string[];
  expiresAt: string;
  proposedActions?: string[];
  vendors?: string[];
}): string {
  const intent: Record<string, unknown> = {
    goal: input.goal,
    resources: input.resources,
    expires_at: input.expiresAt,
  };
  if (input.proposedActions) {
    intent.proposed_authority = [
      {
        type: "mission_resource_access",
        resource: input.resources[0],
        actions: input.proposedActions,
        ...(input.vendors ? { constraints: { vendors: input.vendors } } : {}),
      },
    ];
  }
  return JSON.stringify(intent);
}
