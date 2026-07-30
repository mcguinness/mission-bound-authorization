/**
 * @spec draft-mcguinness-mission-harness (both duties, agent side)
 *
 * The agent harness's mediated tool path. Duty 2 (the mediated execution
 * environment) is realised by the MCP channel in `@mission/mcp-payments`: the
 * harness's only way to touch a tool is through a real MCP `Client`
 * ({@link MediatedClient}), so every action crosses the PEP. This module wires
 * duty 1 on top of it: `resumeGuard` composes {@link checkOnResume} so the
 * harness refuses to issue ANY tool call when the mission is not active (fail
 * closed), before the request ever reaches the channel.
 */

import { createMediatedClient, type MediatedToolResult, type McpPaymentsServer } from "@mission/mcp-payments";
import { checkOnResume, type MissionState, type ResumeDecision } from "./harness.js";

/** Structural view of the mediated channel the harness drives (satisfied by
 * `@mission/mcp-payments`'s MediatedClient; a fake in tests). */
export interface MediatedToolChannel {
  listTools(missionToken: string): Promise<string[]>;
  callTool(name: string, args: Record<string, unknown>, missionToken: string): Promise<MediatedToolResult>;
}

/**
 * Duty 1 at the harness boundary: read the mission's current state and decide
 * whether work may resume. A missing or non-active state fails closed. This is
 * exactly {@link checkOnResume}; naming it `resumeGuard` marks it as the gate the
 * harness consults before issuing tool calls.
 */
export async function resumeGuard(
  missionId: string,
  readState: (id: string) => Promise<MissionState | undefined>,
): Promise<ResumeDecision> {
  return checkOnResume(missionId, readState);
}

/** A tool result that also carries the resume decision when the guard blocked. */
export type HarnessToolResult = MediatedToolResult & { resume?: ResumeDecision };

/**
 * The harness: a mediated channel gated by the duty-1 resume guard. `callTool`
 * and `listTools` consult {@link resumeGuard} first and refuse to reach the
 * channel at all when the mission is not active.
 */
export class MediatedHarness {
  constructor(
    private readonly channel: MediatedToolChannel,
    private readonly missionId: string,
    private readonly readState: (id: string) => Promise<MissionState | undefined>,
  ) {}

  async listTools(missionToken: string): Promise<string[]> {
    const resume = await resumeGuard(this.missionId, this.readState);
    if (!resume.proceed) return [];
    return this.channel.listTools(missionToken);
  }

  async callTool(name: string, args: Record<string, unknown>, missionToken: string): Promise<HarnessToolResult> {
    const resume = await resumeGuard(this.missionId, this.readState);
    if (!resume.proceed) {
      // Fail closed: never issue the tool call.
      return { ok: false, refusal_reason: `mission_not_active:${resume.state}`, resume };
    }
    return this.channel.callTool(name, args, missionToken);
  }
}

/**
 * Compose the real MCP channel (duty 2) with the resume guard (duty 1) into a
 * ready harness bound to one payments server + mission.
 */
export async function createMediatedHarness(
  paymentsServer: McpPaymentsServer,
  missionId: string,
  readState: (id: string) => Promise<MissionState | undefined>,
): Promise<MediatedHarness> {
  const { client } = await createMediatedClient(paymentsServer);
  return new MediatedHarness(client, missionId, readState);
}
