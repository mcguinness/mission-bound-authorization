/**
 * @spec ARAP (AuthZEN Access Request and Approval Profile), consumed via
 * mission-authzen#requestable-denials.
 *
 * The Access Request Service: a distinct trusted-base component (not the PDP)
 * that adjudicates requestable denials. It verifies the PDP-signed
 * binding_token, runs the task lifecycle, and on approval issues an
 * action-bound approval object the PEP carries back as context.action_approval.
 * Approval is input context, never a bearer grant (reevaluate mode).
 */

import { openStore, type Database } from "@mission/store";
import { createLocalJWKSet, jwtVerify, SignJWT, type CryptoKey, type JWK } from "jose";

export type TaskState = "pending" | "approved" | "denied";

export interface AccessRequestSubmission {
  /** PDP-signed denial binding (the denied evaluation), verified by the ARS. */
  binding_token: string;
  /** Human-readable context for the approver. */
  requested: { action: string; mission_id: string; parameter_digest: string; subject: string };
}

export interface ApprovalObject {
  id: string;
  approved_at: string;
  approved_until: string;
  parameter_digest: string;
}

export interface DenialBinding {
  decision_id: string;
  mission_id: string;
  action: string;
  parameter_digest: string;
}

const SCHEMA = `
CREATE TABLE tasks (
  id TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  action TEXT NOT NULL,
  parameter_digest TEXT NOT NULL,
  subject TEXT NOT NULL,
  approval_json TEXT,
  created_at INTEGER NOT NULL
) STRICT;
`;

export class AccessRequestService {
  readonly db: Database;
  private taskСounterSeed = 0;
  constructor(
    private readonly opts: {
      pdpJwks: { keys: JWK[] };
      approvalKey: CryptoKey;
      approvalKid: string;
      approvalTtlSeconds?: number;
      now?: () => Date;
    },
  ) {
    this.db = openStore(SCHEMA);
  }

  private now(): Date {
    return this.opts.now?.() ?? new Date();
  }

  /**
   * Submit an access request. Verifies the PDP-signed binding_token so a
   * separate ARS cannot be told a denial occurred that did not (AROP's
   * separate-ARS rule). Returns a portable task handle.
   */
  async submit(sub: AccessRequestSubmission): Promise<{ taskId: string; state: TaskState }> {
    const binding = await this.verifyBinding(sub.binding_token);
    if (
      binding.mission_id !== sub.requested.mission_id ||
      binding.action !== sub.requested.action ||
      binding.parameter_digest !== sub.requested.parameter_digest
    ) {
      throw new Error("submission does not match the signed denial binding");
    }
    this.taskСounterSeed += 1;
    const taskId = `arq_${binding.decision_id}_${this.taskСounterSeed}`;
    this.db
      .prepare(
        "INSERT INTO tasks (id, state, mission_id, action, parameter_digest, subject, approval_json, created_at) VALUES (?, 'pending', ?, ?, ?, ?, NULL, ?)",
      )
      .run(taskId, binding.mission_id, binding.action, binding.parameter_digest, sub.requested.subject, this.now().getTime());
    return { taskId, state: "pending" };
  }

  /** The approver's adjudication queue (approver app consumes this). */
  pending(): Array<{ id: string; mission_id: string; action: string; subject: string }> {
    return this.db
      .prepare("SELECT id, mission_id, action, subject FROM tasks WHERE state = 'pending'")
      .all() as Array<{ id: string; mission_id: string; action: string; subject: string }>;
  }

  /** Approver decision. On approval, mint the action-bound approval object. */
  async adjudicate(taskId: string, decision: "approve" | "deny", approver: string): Promise<ApprovalObject | null> {
    const task = this.db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId) as
      | Record<string, unknown>
      | undefined;
    if (!task || task.state !== "pending") throw new Error("task not pending");
    if (decision === "deny") {
      this.db.prepare("UPDATE tasks SET state = 'denied' WHERE id = ?").run(taskId);
      return null;
    }
    const nowIso = this.now().toISOString();
    const ttl = this.opts.approvalTtlSeconds ?? 300;
    const approval: ApprovalObject = {
      id: `apr_${taskId}`,
      approved_at: nowIso,
      approved_until: new Date(this.now().getTime() + ttl * 1000).toISOString(),
      parameter_digest: task.parameter_digest as string,
    };
    // Signed approval state (ARAP approval.state), carried by value if needed.
    const signed = await new SignJWT({ ...approval, approver })
      .setProtectedHeader({ alg: "ES256", kid: this.opts.approvalKid, typ: "arap-approval+jwt" })
      .setIssuedAt()
      .sign(this.opts.approvalKey);
    this.db
      .prepare("UPDATE tasks SET state = 'approved', approval_json = ? WHERE id = ?")
      .run(JSON.stringify({ ...approval, state: signed }), taskId);
    return approval;
  }

  getTask(taskId: string): { state: TaskState; approval?: ApprovalObject & { state?: string } } | undefined {
    const row = this.db.prepare("SELECT state, approval_json FROM tasks WHERE id = ?").get(taskId) as
      | { state: TaskState; approval_json: string | null }
      | undefined;
    if (!row) return undefined;
    return {
      state: row.state,
      ...(row.approval_json ? { approval: JSON.parse(row.approval_json) } : {}),
    };
  }

  private async verifyBinding(bindingToken: string): Promise<DenialBinding> {
    const jwks = createLocalJWKSet({ keys: this.opts.pdpJwks.keys } as never);
    const { payload } = await jwtVerify(bindingToken, jwks, { typ: "pdp-denial-binding+jwt" });
    return {
      decision_id: payload.decision_id as string,
      mission_id: payload.mission_id as string,
      action: payload.action as string,
      parameter_digest: payload.parameter_digest as string,
    };
  }
}
