/**
 * @spec draft-mcguinness-mission-harness (increment 2: an opt-in LLM planner)
 *
 * An OPT-IN agent loop that plans over a goal with the Vercel AI SDK and reaches
 * tools ONLY through the increment-1 mediated harness. The LLM is the PLANNER; it
 * never touches a tool directly. Every tool the model can call is an AI SDK `tool`
 * whose `execute` delegates to {@link MediatedHarness.callTool}, so BOTH harness
 * duties still hold on every action: duty 2 (no bypass -- the call crosses the MCP
 * channel + PEP) and duty 1 (fail-closed resume -- the harness refuses when the
 * mission is not active, before the channel is touched). A denied action comes
 * back to the model as the tool result (the PEP's denial reason), so the planner
 * observes the boundary rather than escaping it.
 *
 * The loop is model-agnostic: `model` is injected. The live runner passes a real
 * Anthropic model; the key-free test passes a mock. This module imports `ai` but
 * never a concrete provider.
 */

import { generateText, stepCountIs, tool, type LanguageModel, type ToolSet } from "ai";
import { z } from "zod";
import type { HarnessToolResult, MediatedHarness } from "./mediated-harness.js";

/**
 * The FIXED name -> input-schema map for the payments tools the planner may be
 * offered. Only tools whose name the mission GRANTS (returned by the harness's
 * mission-scoped `listTools`) become AI SDK tools, so least exposure flows all
 * the way to the LLM: an ungranted tool is never even described to the model.
 * All four take `{ invoice_id }`.
 */
const INVOICE_INPUT = z.object({ invoice_id: z.string() });
const PAYMENTS_TOOLS: Record<string, { description: string; inputSchema: typeof INVOICE_INPUT }> = {
  get_invoice: { description: "Read one invoice by id.", inputSchema: INVOICE_INPUT },
  execute_wire_transfer: { description: "Execute a wire transfer to pay an invoice.", inputSchema: INVOICE_INPUT },
  send_remittance_email: { description: "Send a remittance-advice email for an invoice.", inputSchema: INVOICE_INPUT },
  schedule_payment: { description: "Schedule a future payment for an invoice.", inputSchema: INVOICE_INPUT },
};

const SYSTEM_FRAMING =
  "You are a payments agent operating under a mission-bound authorization harness. " +
  "You may ONLY act through the provided tools; there is no other way to touch payments. " +
  "Each tool call is mediated by an enforcement point. If a tool result carries a " +
  "denial_reason or refusal_reason, the action was refused and had NO effect -- do not " +
  "retry the same denied action; adapt within your authority or stop. Work only within " +
  "the mission's limits.";

export interface RunAgentLoopOptions {
  /** The increment-1 harness -- the ONLY tool path (mediation + fail-closed resume). */
  harness: MediatedHarness;
  /** The mission access token that crosses IN the MCP `_meta` on every call. */
  missionToken: string;
  /** The natural-language goal the planner works toward. */
  goal: string;
  /** The language model that plans (injected: real Anthropic live, mock in tests). */
  model: LanguageModel;
  /** Cap on planner steps (tool round-trips + final text). Defaults to 8. */
  maxSteps?: number;
}

export interface AgentLoopResult {
  /** The planner's final assistant text. */
  text: string;
  /** Per-step data (tool calls + mediated tool results), for rendering a transcript. */
  steps: Awaited<ReturnType<typeof generateText>>["steps"];
}

/**
 * Run the planner over `goal`, exposing only the mission-granted payments tools,
 * each routed through the mediated harness. Returns the final text and the step
 * trace so a caller can render every tool call and its mediated verdict.
 */
export async function runAgentLoop(opts: RunAgentLoopOptions): Promise<AgentLoopResult> {
  const granted = await opts.harness.listTools(opts.missionToken);

  const tools: ToolSet = {};
  for (const name of granted) {
    const spec = PAYMENTS_TOOLS[name];
    if (!spec) continue; // only the known payments tools are surfaced to the planner
    tools[name] = tool({
      description: spec.description,
      inputSchema: spec.inputSchema,
      execute: async (args: { invoice_id: string }): Promise<HarnessToolResult> =>
        // The mediated harness is the ONLY tool path -- never the PEP/store directly.
        opts.harness.callTool(name, args, opts.missionToken),
    });
  }

  const result = await generateText({
    model: opts.model,
    tools,
    stopWhen: stepCountIs(opts.maxSteps ?? 8),
    system: SYSTEM_FRAMING,
    prompt: opts.goal,
  });

  return { text: result.text, steps: result.steps };
}
