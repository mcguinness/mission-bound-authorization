/**
 * @spec ARAP (AuthZEN Access Request and Approval Profile), consumed via
 * mission-authzen#requestable-denials.
 *
 * The Access Request Service: a distinct trusted-base component (not the PDP)
 * that adjudicates requestable denials. It verifies the PDP-signed
 * binding_token, runs the task lifecycle, and on approval issues an
 * action-bound approval object the PEP carries back as context.action_approval.
 * Approval is input context, never a bearer grant (reevaluate mode).
 *
 * @spec authzen#context-approval (#2067, D1313): the approval binds to the
 * qualified Mission identity, `issuer` and `id`, taken from the PDP-signed
 * denial binding (or, for a transaction challenge, the AS-vouched binding)
 * and signed into the approval `state`, the integrity-protected material the
 * PDP establishes the binding from.
 */

import { openStore, type Database } from "@mission/store";
import type { TxnApprovalBinding } from "@mission/core";
import { ARAP_APPROVAL_TYP } from "@mission/pdp";
import { createLocalJWKSet, jwtVerify, SignJWT, type CryptoKey, type JWK } from "jose";

export type TaskState = "pending" | "approved" | "denied";

/**
 * @spec txn-authorization#challenge-redemption step 5 — a second open of one
 * (resource, txn) correlation identity under a DIFFERENT transaction binding.
 * Distinct from every ordinary refusal: nothing was adjudicated wrongly, two
 * different transactions claimed one identity, and the service refuses both
 * rather than letting the second inherit the first's approval.
 */
export class TxnBindingConflictError extends Error {
  readonly code = "txn_binding_conflict";
  constructor(readonly taskId: string) {
    super(`task ${taskId} was already opened under a different transaction binding`);
  }
}

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
  /**
   * ARAP's signed approval `state` (`arap-approval+jwt`): every member above,
   * the approved Resource and the qualified Mission identity the approval is
   * bound to (#2067), signed by this service for the re-evaluating PDP.
   */
  state?: string;
  /**
   * @spec authzen#context-approval (#249, D553): the approved Resource,
   * present where a resource contract applied to the denied request: "the
   * approval binds its reference through the approved Resource, which ARAP
   * requires the approval record or its binding material to contain". Taken
   * from the PDP-signed denial binding, never from the submission.
   */
  resource?: { properties: { resource_contract: unknown } };
}

export interface DenialBinding {
  decision_id: string;
  mission_id: string;
  /** @spec authzen#context-approval (#2067): the denied Mission's issuer, so the binding is the qualified identity. */
  mission_issuer: string;
  action: string;
  parameter_digest: string;
  /** @spec authzen#context-approval (#249): the denied request's contract reference, where one applied. */
  resource_contract?: unknown;
  /**
   * @spec authzen#requestable-denials (#2067, D1328): the denial reason the
   * request answers (`action_approval_required`, this implementation's
   * spelling of `approval_required`, or a re-evaluation's `out_of_scope` or
   * `approval_expired`) and the action classes that applied, from the
   * PDP-signed binding. Absent or malformed, auto-approval treats the request
   * as one that needs an independent approver.
   */
  reason?: string;
  action_classes?: readonly string[];
}

/**
 * @spec authzen#requestable-denials: the high-consequence classes in which an
 * approval request needs an independent approver.
 */
const HIGH_CONSEQUENCE_CLASSES: ReadonlySet<string> = new Set([
  "irreversible_action",
  "external_commitment",
  "privileged_administration",
]);

/** The approver identity a synchronous auto-approval is recorded under. */
export const AUTO_APPROVER = "policy:auto-approval";

/** What a deployment's synchronous auto-approval policy sees of a submitted request. */
export interface AutoApprovalRequest {
  action: string;
  mission_id: string;
  mission_issuer: string;
  parameter_digest: string;
  subject: string;
  reason?: string;
  action_classes?: readonly string[];
}

/**
 * @spec authzen#requestable-denials (#2067, D1328): a deployment "MUST NOT
 * auto-approve a request for an `approval_required` denial", or a request
 * renewing or replacing an approval an `out_of_scope` or `approval_expired`
 * denial found insufficient, "in the irreversible, external-commitment, or
 * privileged-administration classes without an independent approver". Only
 * an `out_of_authority` request is outside the rule, and an unnamed class
 * set counts as high-consequence, so neither a changed denial reason nor a
 * missing member lets a request through unattended.
 */
export function requiresIndependentApprover(binding: Pick<DenialBinding, "reason" | "action_classes">): boolean {
  if (binding.reason === "out_of_authority") return false;
  const classes = binding.action_classes;
  return classes === undefined || classes.length === 0 || classes.some((c) => HIGH_CONSEQUENCE_CLASSES.has(c));
}

const SCHEMA = `
CREATE TABLE tasks (
  id TEXT PRIMARY KEY,
  state TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  mission_issuer TEXT NOT NULL,
  action TEXT NOT NULL,
  parameter_digest TEXT NOT NULL,
  subject TEXT NOT NULL,
  approval_json TEXT,
  binding_digest TEXT,
  resource_json TEXT,
  created_at INTEGER NOT NULL
) STRICT;
`;

/**
 * @spec txn-authorization#offline-verification — the ARS correlation identity
 * for one challenged operation. `txn` is unique within a protected resource,
 * so the resource is part of the identity; it is base64url-encoded so a
 * resource URI cannot collide with, or run into, the task id's own separators.
 */
export function txnTaskId(resource: string, txn: string): string {
  return `arq_txn_${Buffer.from(resource, "utf8").toString("base64url")}_${txn}`;
}

export class AccessRequestService {
  readonly db: Database;
  private taskСounterSeed = 0;
  constructor(
    private readonly opts: {
      pdpJwks: { keys: JWK[] };
      approvalKey: CryptoKey;
      approvalKid: string;
      /** ARAP: issuer of the signed approval state (this ARS's identity). */
      issuer: string;
      /** ARAP: intended recipient of the approval state (the AS/PDP that re-evaluates). */
      approvalAudience: string;
      approvalTtlSeconds?: number;
      now?: () => Date;
      /**
       * @spec authzen#requestable-denials: the deployment's synchronous
       * auto-approval policy, consulted at submission. It is never applied to
       * a request that needs an independent approver
       * ({@link requiresIndependentApprover}); such a request stays pending
       * for one. Absent, every request waits for an approver.
       */
      autoApprove?: (request: AutoApprovalRequest) => boolean;
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
    // @spec authzen#context-approval (#249): the approved Resource the
    // approval will bind, from the PDP-signed binding material.
    const resourceJson =
      binding.resource_contract !== undefined
        ? JSON.stringify({ properties: { resource_contract: binding.resource_contract } })
        : null;
    this.db
      .prepare(
        "INSERT INTO tasks (id, state, mission_id, mission_issuer, action, parameter_digest, subject, approval_json, binding_digest, resource_json, created_at) VALUES (?, 'pending', ?, ?, ?, ?, ?, NULL, NULL, ?, ?)",
      )
      .run(
        taskId,
        binding.mission_id,
        binding.mission_issuer,
        binding.action,
        binding.parameter_digest,
        sub.requested.subject,
        resourceJson,
        this.now().getTime(),
      );
    // @spec authzen#requestable-denials (#2067, D1328): synchronous
    // auto-approval, bounded by the independent-approver rule whatever the
    // denial reason.
    const request: AutoApprovalRequest = {
      action: binding.action,
      mission_id: binding.mission_id,
      mission_issuer: binding.mission_issuer,
      parameter_digest: binding.parameter_digest,
      subject: sub.requested.subject,
      ...(binding.reason !== undefined ? { reason: binding.reason } : {}),
      ...(binding.action_classes !== undefined ? { action_classes: binding.action_classes } : {}),
    };
    if (!requiresIndependentApprover(binding) && this.opts.autoApprove?.(request) === true) {
      await this.adjudicate(taskId, "approve", AUTO_APPROVER);
      return { taskId, state: "approved" };
    }
    return { taskId, state: "pending" };
  }

  /**
   * Open a task for an AROP Transaction Challenge, vouched by the AS. The AS
   * has already validated the RS-signed txn-challenge against the resource's
   * txn-challenge keys, so no PDP-signed denial binding is required here
   * (contrast `submit`, which verifies one for a separate ARS). D37: the AS
   * owns the txn pending id; the ARS owns the approval. Reuses the same tasks
   * table + `adjudicate`/`getTask` unchanged.
   *
   * IDEMPOTENT: opening the same (resource, txn) twice resolves to the ONE
   * task, whatever its current state. `txn` is unique within the Challenge-
   * Issuing Resource, never globally, so the correlation identity carries the
   * resource too (@spec txn-authorization#offline-verification).
   */
  openForTxn(input: {
    txn: string;
    resource: string;
    missionId: string;
    action: string;
    parameter_digest: string;
    subject: string;
    /**
     * @spec txn-authorization#challenge-redemption step 5 — the COMPLETE
     * transaction this approval is opened against, and its digest. The
     * approval is only ever good for THIS transaction.
     */
    binding: TxnApprovalBinding;
    binding_digest: string;
  }): { taskId: string; state: TaskState } {
    const taskId = txnTaskId(input.resource, input.txn);
    this.db
      .prepare(
        "INSERT INTO tasks (id, state, mission_id, mission_issuer, action, parameter_digest, subject, approval_json, binding_digest, created_at) VALUES (?, 'pending', ?, ?, ?, ?, ?, NULL, ?, ?) ON CONFLICT(id) DO NOTHING",
      )
      .run(
        taskId,
        input.missionId,
        // @spec authzen#context-approval (#2067): the vouched transaction's Mission issuer.
        input.binding.mission.issuer,
        input.action,
        input.parameter_digest,
        input.subject,
        input.binding_digest,
        this.now().getTime(),
      );
    const row = this.db.prepare("SELECT state, binding_digest FROM tasks WHERE id = ?").get(taskId) as
      | { state: TaskState; binding_digest: string | null }
      | undefined;
    // (resource, txn) is the correlation identity, not the transaction. A
    // second open under the SAME identity but a DIFFERENT binding is a
    // different transaction wearing the first one's name: resolving it to the
    // existing approval would hand it an approval granted for something else,
    // so it FAILS CLOSED rather than resolving. An identical binding is the
    // idempotent retry this endpoint depends on and returns the one task.
    if (row && row.binding_digest !== null && row.binding_digest !== input.binding_digest) {
      throw new TxnBindingConflictError(taskId);
    }
    return { taskId, state: row?.state ?? "pending" };
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
      ...(typeof task.resource_json === "string"
        ? { resource: JSON.parse(task.resource_json) as NonNullable<ApprovalObject["resource"]> }
        : {}),
    };
    // Signed approval state (ARAP approval.state), carried by value if needed.
    // ARAP: the state JWS MUST carry iss (this ARS) and aud (the re-evaluator).
    // @spec authzen#context-approval (#2067, D1313): and the qualified Mission
    // identity the task was opened for, the binding the PDP establishes.
    const mission = { issuer: task.mission_issuer as string, id: task.mission_id as string };
    const signed = await new SignJWT({ ...approval, mission, approver })
      .setProtectedHeader({ alg: "ES256", kid: this.opts.approvalKid, typ: ARAP_APPROVAL_TYP })
      .setIssuer(this.opts.issuer)
      .setAudience(this.opts.approvalAudience)
      .setIssuedAt()
      .sign(this.opts.approvalKey);
    this.db
      .prepare("UPDATE tasks SET state = 'approved', approval_json = ? WHERE id = ?")
      .run(JSON.stringify({ ...approval, state: signed }), taskId);
    // ARAP's approval object carries `state`: the PEP presents it unchanged.
    return { ...approval, state: signed };
  }

  /**
   * The task, and on an approved one the approval WITH the binding digest it
   * was opened under. The relying party recomputes that digest from its own
   * pinned state: an approval whose binding it cannot reproduce is refused.
   */
  getTask(
    taskId: string,
  ): { state: TaskState; approval?: ApprovalObject & { state?: string; binding_digest?: string } } | undefined {
    const row = this.db.prepare("SELECT state, approval_json, binding_digest FROM tasks WHERE id = ?").get(taskId) as
      | { state: TaskState; approval_json: string | null; binding_digest: string | null }
      | undefined;
    if (!row) return undefined;
    return {
      state: row.state,
      ...(row.approval_json
        ? {
            approval: {
              ...(JSON.parse(row.approval_json) as ApprovalObject & { state?: string }),
              ...(row.binding_digest !== null ? { binding_digest: row.binding_digest } : {}),
            },
          }
        : {}),
    };
  }

  private async verifyBinding(bindingToken: string): Promise<DenialBinding> {
    const jwks = createLocalJWKSet({ keys: this.opts.pdpJwks.keys } as never);
    const { payload } = await jwtVerify(bindingToken, jwks, { typ: "pdp-denial-binding+jwt" });
    // @spec authzen#context-approval (#2067): a binding that does not name the
    // qualified Mission identity cannot bind an approval to it.
    if (typeof payload.mission_issuer !== "string" || payload.mission_issuer === "") {
      throw new Error("denial binding names no Mission issuer");
    }
    const classes = payload.action_classes;
    return {
      decision_id: payload.decision_id as string,
      mission_id: payload.mission_id as string,
      mission_issuer: payload.mission_issuer,
      action: payload.action as string,
      parameter_digest: payload.parameter_digest as string,
      ...(payload.resource_contract !== undefined ? { resource_contract: payload.resource_contract } : {}),
      ...(typeof payload.reason === "string" ? { reason: payload.reason } : {}),
      ...(Array.isArray(classes) && classes.every((c) => typeof c === "string")
        ? { action_classes: classes as string[] }
        : {}),
    };
  }
}
