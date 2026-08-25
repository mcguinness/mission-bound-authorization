/**
 * Agent service (M12): the scenario runner's client end. Declares the MCP EMA
 * capability, drives the OAuth/DPoP/MCP flows, hosts the shaper (untrusted
 * intent proposal) and the minimal harness. This module exposes the harness
 * and the sub-agent spawn helper; the full scripted runner and optional LLM
 * loop are the demo entrypoint (scripts/demo).
 */

export { checkOnResume, checkStatusContinuity, type ResumeDecision, type MissionState } from "./harness.js";
export {
  buildScopeStatement,
  CHANNEL_CLASSES,
  type ChannelClass,
  type ChannelClassStatement,
  type ChannelDisposition,
  type ContainmentClaim,
  type ExecutionEnvironmentScopeStatement,
  SCOPE_STATEMENT_TYP,
  scopeDigest,
  type ScopeStatementConfig,
  type ScopeStatementSigner,
  signScopeStatement,
  verifyScopeStatement,
} from "./harness-scope.js";
export {
  EgressGate,
  type EgressDecision,
  type EgressGateConfig,
  type EgressRefusal,
} from "./egress-gate.js";
export {
  createMediatedHarness,
  createStatusMediatedHarness,
  MediatedHarness,
  type MediatedHarnessOptions,
  type MediatedToolChannel,
  type HarnessToolResult,
  resumeGuard,
} from "./mediated-harness.js";
export {
  runAgentLoop,
  type RunAgentLoopOptions,
  type AgentLoopResult,
} from "./agent-loop.js";

export const EMA_CAPABILITY = "io.modelcontextprotocol/enterprise-managed-authorization";

/** The EMA capability the agent declares at MCP `initialize` (D14/M9). */
export function initializeCapabilities(): Record<string, unknown> {
  return { capabilities: { extensions: { [EMA_CAPABILITY]: {} } } };
}

/**
 * A shaper proposal is untrusted client input (@spec mission-shaping, D22).
 * This helper only *proposes* from a natural-language-ish goal; the AS derives
 * and bounds authority regardless of what is proposed, so a compromised shaper
 * can propose badly but never widen. Two wire values come back
 * (@spec mission#authority-proposal): `missionIntent` is the pure task context
 * (the Intent carries no authority members), and `authorizationDetails`, when
 * concrete actions were proposed, is the standard RFC 9396
 * authorization_details array pushed through PAR alongside it.
 */
export function shapeIntent(input: {
  goal: string;
  resources: string[];
  expiresAt: string;
  proposedActions?: string[];
  vendors?: string[];
}): { missionIntent: string; authorizationDetails?: string } {
  const intent: Record<string, unknown> = {
    goal: input.goal,
    // @spec mission#mission-intent — the wire member is `target_resources`
    // (renamed from `resources`); this function's own parameter name is
    // unchanged to keep its call sites stable.
    target_resources: input.resources,
    expires_at: input.expiresAt,
  };
  if (input.proposedActions) {
    return {
      missionIntent: JSON.stringify(intent),
      authorizationDetails: JSON.stringify([
        {
          type: "mission_resource_access",
          resource: input.resources[0],
          actions: input.proposedActions,
          ...(input.vendors ? { constraints: { vendors: input.vendors } } : {}),
        },
      ]),
    };
  }
  return { missionIntent: JSON.stringify(intent) };
}
