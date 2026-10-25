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

import type { MissionStatusLease } from "@mission/core";
import { createMediatedClient, type MediatedToolResult, type McpPaymentsServer } from "@mission/mcp-payments";
import { checkOnResume, checkStatusContinuity, type MissionState, type ResumeDecision } from "./harness.js";

/** Structural view of the mediated channel the harness drives (satisfied by
 * `@mission/mcp-payments`'s MediatedClient; a fake in tests). */
export interface MediatedToolChannel {
  listTools(missionToken: string): Promise<string[]>;
  /**
   * `missionReference` is the propagated Mission reference the harness
   * attaches in the request's transport metadata (MCP `params._meta`), never
   * in `args` (@spec authority-server#mcp-reference).
   */
  callTool(
    name: string,
    args: Record<string, unknown>,
    missionToken: string,
    missionReference?: unknown,
  ): Promise<MediatedToolResult>;
}

/**
 * @spec harness#work-item-identity (#815): the work item this harness is
 * running, which it assigned and bound to its Mission. `issuer` is the
 * harness's URI and `id` its identifier for the item; `missionIssuer` is the
 * bound Mission's issuer, which with the harness's Mission identifier forms
 * the reference tuple the work item rides in.
 */
export interface HarnessWorkItem {
  issuer: string;
  id: string;
  missionIssuer: string;
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
 * Options that enable the status-lease harness path (@spec harness#resume-algorithm).
 * Additive to the existing three-argument constructor: omitting them preserves
 * the duty-1 `readState` behavior byte-for-byte.
 */
export interface MediatedHarnessOptions {
  /**
   * Lease-based status reader. When present, the harness re-checks lease
   * FRESHNESS at EACH submission via {@link checkStatusContinuity}
   * (fresh-at-submission, not only at resume), and this path takes precedence
   * over `readState`.
   */
  readStatus?: (id: string) => Promise<MissionStatusLease | undefined>;
  /** Injectable clock (defaults to `() => new Date()`), so tests can inject `now`. */
  now?: () => Date;
  /**
   * @spec harness#work-item-identity (#815): present, the harness attaches
   * this work item to every governed call it originates, as the
   * `work_item_issuer` and `work_item` members of the propagated Mission
   * reference in the call's transport metadata. The same item rides every
   * submission, a resumed one included; nothing the planner returns, tool
   * arguments included, is merged into it.
   */
  workItem?: HarnessWorkItem;
}

/**
 * The harness: a mediated channel gated on each submission. `callTool` and
 * `listTools` consult {@link guard} first and refuse to reach the channel at all
 * when the mission is not active (duty 1) or -- on the status-lease path -- when
 * the lease is stale (fail closed before trusting a recorded `active`).
 *
 * The fourth constructor argument is OPTIONAL and additive: existing
 * three-argument construction (and {@link createMediatedHarness}) is unchanged.
 */
export class MediatedHarness {
  private readonly readStatus: ((id: string) => Promise<MissionStatusLease | undefined>) | undefined;
  private readonly now: () => Date;
  private readonly workItem: HarnessWorkItem | undefined;

  constructor(
    private readonly channel: MediatedToolChannel,
    private readonly missionId: string,
    private readonly readState: (id: string) => Promise<MissionState | undefined>,
    options: MediatedHarnessOptions = {},
  ) {
    this.readStatus = options.readStatus;
    this.now = options.now ?? (() => new Date());
    this.workItem = options.workItem === undefined ? undefined : Object.freeze({ ...options.workItem });
  }

  /**
   * @spec harness#work-item-identity (#815): the reference this harness
   * attaches: its own Mission identifier, the bound Mission's issuer and the
   * work item it assigned, from its own state only. Absent without a work
   * item, which leaves the call exactly as before.
   */
  private reference(): Record<string, string> | undefined {
    const w = this.workItem;
    if (w === undefined) return undefined;
    return { mission_id: this.missionId, issuer: w.missionIssuer, work_item_issuer: w.issuer, work_item: w.id };
  }

  /**
   * The freshness/state gate consulted before every submission. With a status
   * reader configured, freshness is re-checked at EACH submission via
   * {@link checkStatusContinuity} (§ resume-algorithm step 5); otherwise it is
   * the duty-1 {@link resumeGuard} over the recorded state.
   */
  private async guard(): Promise<ResumeDecision> {
    if (this.readStatus !== undefined) {
      const lease = await this.readStatus(this.missionId);
      return checkStatusContinuity(lease, this.now());
    }
    return resumeGuard(this.missionId, this.readState);
  }

  async listTools(missionToken: string): Promise<string[]> {
    const resume = await this.guard();
    if (!resume.proceed) return [];
    return this.channel.listTools(missionToken);
  }

  async callTool(name: string, args: Record<string, unknown>, missionToken: string): Promise<HarnessToolResult> {
    const resume = await this.guard();
    if (!resume.proceed) {
      // Fail closed: never issue the tool call.
      const refusal_reason = resume.stale
        ? `mission_status_stale:${resume.state}`
        : `mission_not_active:${resume.state}`;
      return { ok: false, refusal_reason, resume };
    }
    const reference = this.reference();
    return reference === undefined
      ? this.channel.callTool(name, args, missionToken)
      : this.channel.callTool(name, args, missionToken, reference);
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

/**
 * @spec harness#resume-algorithm (freshness-at-submission)
 *
 * The status-lease factory path, beside {@link createMediatedHarness}. Instead
 * of a bare state reader it takes `readStatus`, returning a
 * {@link MissionStatusLease}, and the resulting harness re-checks lease
 * freshness at EACH submission: a stale lease (now > `status_expires_at`) fails
 * closed even when the last-observed state was `active`.
 */
export async function createStatusMediatedHarness(
  paymentsServer: McpPaymentsServer,
  missionId: string,
  readStatus: (id: string) => Promise<MissionStatusLease | undefined>,
  now: () => Date = () => new Date(),
): Promise<MediatedHarness> {
  const { client } = await createMediatedClient(paymentsServer);
  // readState is unused on the status path; guard() prefers readStatus.
  const readState = async (): Promise<MissionState | undefined> => undefined;
  return new MediatedHarness(client, missionId, readState, { readStatus, now });
}
