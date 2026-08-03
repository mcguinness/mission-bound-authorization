/**
 * @spec mission#rs-enforcement, runtime (PEP), authzen (envelope)
 *
 * The resource-server PEP for the payments estate. Validates the DPoP-bound
 * token and mission claim, builds the AuthZEN envelope (context.actor via
 * @mission/actor-chain, parameter_digest, capability_source), obtains a PDP
 * decision, and emits Decision Evidence / Refusal Records. Core enforcement
 * tier (M4); the transaction-assurance tier (permits/leases) lands in M5.
 */

import { createHash, randomUUID } from "node:crypto";
import { type ActObject, buildContextActor, flattenActChain } from "@mission/actor-chain";
import { getTracer } from "@mission/telemetry";
import {
  type Decision,
  evaluate,
  type EvaluationRequest,
  type Fga,
  type MissionView,
  relationForAction,
  stalenessBoundSeconds,
} from "@mission/pdp";
import { buildEffectiveParams, type EffectiveParams, parameterDigest } from "./effective-params.js";
import type { EvidenceStore } from "./evidence.js";
import type { PaymentsStore } from "./payments-store.js";
import { signChallenge } from "./txn-challenge.js";

export const CANONICAL_RESOURCE = process.env.MCP_PAYMENTS_RESOURCE ?? "http://localhost:4403/mcp";
export const TOOL_BASE = "mcp://payments.demo/tools";
const SERVER_CARD_URI = `${CANONICAL_RESOURCE.replace(/\/mcp$/, "")}/.well-known/mcp`;

/** Validated token facts the PEP works from (token validation is upstream). */
export interface TokenFacts {
  sub: string;
  clientId: string;
  clientInstanceId?: string;
  act?: ActObject;
  mission: { id: string; authority_hash: string };
  cnfJkt: string;
  /**
   * @spec attenuation#mission-binding-check: present when the credential was a
   * Mission-bound Attenuating Agent Token chain. The effective authority is the
   * leaf's narrowed tools, expressed as {resource, actions}; an action within
   * the Mission but outside this leaf is denied `out_of_authority` (below).
   * Absent for an ordinary Mission-bound token (no leaf narrowing).
   */
  leafAuthority?: ReadonlyArray<{ resource: string; actions: readonly string[] }>;
}

export interface ActionMapping {
  action: string;
  actionClass?: "irreversible_action" | "external_commitment";
  needsInvoice: boolean;
}

const TOOL_ACTIONS: Record<string, ActionMapping> = {
  list_invoices: { action: "payments:invoice.list", needsInvoice: false },
  get_invoice: { action: "payments:invoice.read", needsInvoice: true },
  lookup_vendor: { action: "payments:vendor.read", needsInvoice: false },
  schedule_payment: { action: "payments:payment.schedule", needsInvoice: true },
  execute_wire_transfer: { action: "payments:payment.execute", actionClass: "irreversible_action", needsInvoice: true },
  send_remittance_email: { action: "payments:remittance.send", actionClass: "external_commitment", needsInvoice: true },
};

export interface PepDeps {
  payments: PaymentsStore;
  evidence: EvidenceStore;
  fga: Fga;
  modelId: string;
  /** The PDP's view of a mission (in a real deployment fetched from AS/Status). */
  loadView: (missionId: string) => MissionView | undefined;
  instanceEpoch: string;
  now?: () => Date;
  sourceDigest: string;
  /** Deployment policy: which actions require an action-bound approval (M6). */
  requiresActionApproval?: (action: string, actionClass: string | undefined) => boolean;
  maxApprovalAgeSeconds?: number;
  /** PDP signer + ARS endpoint for requestable denials (M6). */
  requestable?: { sign: import("jose").CryptoKey; kid: string; endpoint: string };
  /**
   * AROP Transaction Challenge signer (rs-txn key). When configured, an
   * `action_approval_required` denial also yields an RS-signed txn-challenge the
   * client presents to the AS transaction_authorization_endpoint. `txnEndpoint`
   * is that endpoint URL; `asIssuer` is the AS issuer used as the challenge aud.
   */
  challengeSigner?: { sign: import("jose").CryptoKey; kid: string; txnEndpoint: string; asIssuer: string };
  /**
   * Per-instance revocation (M12 / D19): "iss sub" keys of agent instances the
   * PEP refuses. Revoking one sub-agent instance kills only that instance;
   * other actors in the chain (the orchestrator) keep working.
   */
  revokedInstances?: Set<string>;
  /**
   * Optional observer for tooling/demos: receives the AuthZEN request the PEP
   * built and the raw PDP decision for each enforced action. Never affects
   * the decision; unset in production.
   */
  observe?: (e: {
    tool: string;
    args: Record<string, unknown>;
    token: TokenFacts;
    envelope: EvaluationRequest;
    decision: Decision;
    effective?: EffectiveParams;
  }) => void;
}

export interface ActionApprovalInput {
  id: string;
  approved_at: string;
  /** ARAP: the approval's validity bound; carried to the PDP for the now-check. */
  approved_until?: string;
  parameter_digest: string;
  state?: string;
}

export interface EnforceResult {
  permitted: boolean;
  decision?: Decision;
  denial_reason?: string;
  refusal_reason?: string;
  effective?: EffectiveParams;
  /** Present on a requestable denial: the ARAP access-request context. */
  access_request?: { endpoint: string; denial_binding: string; binding_token: string; expires_at: string };
  /**
   * Present when `challengeSigner` is configured and the action needs a
   * per-action approval: an RS-signed AROP txn-challenge plus the AS endpoint to
   * present it to. `txn` is the transaction id the RS minted for this challenge;
   * the RS records it so the later txn-token's `txn` can be checked (draft §6.2).
   */
  access_challenge?: { challenge: string; txn_endpoint: string; txn: string };
}

export class Pep {
  private readonly now: () => Date;
  constructor(private readonly deps: PepDeps) {
    this.now = deps.now ?? (() => new Date());
  }

  toolAction(tool: string): ActionMapping | undefined {
    return TOOL_ACTIONS[tool];
  }

  /**
   * Enforce one tool call. Returns the decision; the caller executes only on
   * `permitted`. Records Decision Evidence (always) and a Refusal Record on
   * a PEP-side refusal (e.g. unknown mission, missing invoice).
   */
  async enforce(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
    actionApproval?: ActionApprovalInput,
  ): Promise<EnforceResult> {
    return getTracer("pep").startActiveSpan(`pep.enforce ${tool}`, async (span) => {
      span.setAttribute("mission.tool", tool);
      span.setAttribute("mission.id", token.mission.id);
      try {
        const res = await this.enforceInner(tool, args, token, actionApproval);
        span.setAttribute("mission.permitted", res.permitted);
        if (res.denial_reason) span.setAttribute("mission.denial_reason", res.denial_reason);
        if (res.refusal_reason) span.setAttribute("mission.refusal_reason", res.refusal_reason);
        return res;
      } finally {
        span.end();
      }
    });
  }

  private async enforceInner(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
    actionApproval?: ActionApprovalInput,
  ): Promise<EnforceResult> {
    const mapping = this.toolAction(tool);
    if (!mapping) return this.refuse(token, "unknown_tool", tool);

    const view = this.deps.loadView(token.mission.id);
    if (!view) return this.refuse(token, "unknown_mission", mapping.action);

    // @spec attenuation#mission-binding-check: when the credential is an
    // Attenuating Agent Token chain, the effective authority is the leaf's
    // narrowed tools. An action within the Mission but OUTSIDE the leaf is
    // denied here, reusing the existing out_of_authority DenialReason, before
    // the Mission-level PDP check (which still enforces the Mission and, via
    // view.state, the kill switch). Absent leafAuthority, this is a no-op.
    if (
      token.leafAuthority &&
      !token.leafAuthority.some(
        (e) => e.resource === CANONICAL_RESOURCE && e.actions.includes(mapping.action),
      )
    ) {
      this.recordRefusal(token, "out_of_authority", mapping.action, view);
      return { permitted: false, denial_reason: "out_of_authority" };
    }

    // Per-instance revocation (M12): refuse if any actor in the chain is
    // revoked, keyed on (act.iss, act.sub). Kills one instance, not the chain.
    if (this.deps.revokedInstances?.size) {
      for (const hop of flattenActChain(token.act)) {
        if (this.deps.revokedInstances.has(`${hop.iss} ${hop.sub}`)) {
          return this.refuse(token, "instance_revoked", mapping.action, view);
        }
      }
    }

    // Effective parameters from authoritative store state (D34).
    let effective: EffectiveParams | undefined;
    let amount: { amount: string; currency: string } | undefined;
    let resourceObj: EvaluationRequest["resource"] = { type: "server", id: CANONICAL_RESOURCE };
    if (mapping.needsInvoice) {
      const invoiceId = String(args.invoice_id ?? "");
      const invoice = this.deps.payments.getInvoice(invoiceId);
      if (!invoice) return this.refuse(token, "unknown_invoice", mapping.action, view);
      const vendor = this.deps.payments.getVendor(invoice.vendor_id);
      if (!vendor) return this.refuse(token, "unknown_vendor", mapping.action, view);
      effective = buildEffectiveParams({ action: mapping.action, invoice, vendor, resource: CANONICAL_RESOURCE });
      amount = effective.amount;
      resourceObj = { type: "invoice", id: invoice.id, properties: { vendor_id: vendor.id } };
    }

    const req: EvaluationRequest = {
      subject: { id: token.sub },
      resource: resourceObj,
      action: { name: mapping.action },
      context: {
        audience: CANONICAL_RESOURCE,
        mission: { id: view.id, authority_hash: token.mission.authority_hash },
        actor: buildContextActor({
          ...(token.clientId !== undefined ? { clientId: token.clientId } : {}),
          ...(token.clientInstanceId !== undefined ? { clientInstanceId: token.clientInstanceId } : {}),
          ...(token.act !== undefined ? { act: token.act } : {}),
        }),
        capability_source: {
          tool_id: `${TOOL_BASE}/${tool}`,
          source_uri: SERVER_CARD_URI,
          source_digest: this.deps.sourceDigest,
          operation_ref: `tools/${tool}`,
        },
        ...(effective ? { parameter_digest: parameterDigest(effective) } : {}),
        ...(amount ? { amount } : {}),
        ...(mapping.actionClass ? { action_class: mapping.actionClass } : {}),
        ...(actionApproval ? { action_approval: actionApproval } : {}),
      } as EvaluationRequest["context"],
    };

    const decision = await evaluate(req, {
      view,
      fga: this.deps.fga,
      modelId: this.deps.modelId,
      now: this.now,
      stalenessBoundSeconds,
      relationForAction,
      ...(this.deps.requiresActionApproval ? { requiresActionApproval: this.deps.requiresActionApproval } : {}),
      ...(this.deps.maxApprovalAgeSeconds ? { maxApprovalAgeSeconds: this.deps.maxApprovalAgeSeconds } : {}),
      ...(this.deps.requestable ? { requestable: this.deps.requestable } : {}),
    });

    this.deps.observe?.({ tool, args, token, envelope: req, decision, ...(effective ? { effective } : {}) });

    this.deps.evidence.record({
      kind: "decision",
      decision: decision.decision,
      decision_id: decision.context.decision_id as string,
      policy_view_id: decision.context.policy_view_id as string,
      ...(decision.context.denial_reason ? { denial_reason: decision.context.denial_reason as string } : {}),
      mission_id: view.id,
      authority_hash: view.authority_hash,
      action: mapping.action,
      ...(req.context.parameter_digest ? { parameter_digest: req.context.parameter_digest } : {}),
      instance_epoch: this.deps.instanceEpoch,
    });

    if (!decision.decision) {
      const ar = decision.context.access_request as EnforceResult["access_request"] | undefined;
      const result: EnforceResult = {
        permitted: false,
        decision,
        denial_reason: decision.context.denial_reason as string,
        ...(effective ? { effective } : {}),
        ...(ar ? { access_request: ar } : {}),
      };
      // AROP Transaction Challenge (additive to the access_request path above):
      // on an action_approval_required denial, if the RS is configured to sign
      // challenges, emit an rs-txn-signed txn-challenge scoped to the active
      // Mission's entry for this resource+action and bound to the operation's
      // parameter_digest. The client presents it to the AS transaction endpoint.
      if (
        this.deps.challengeSigner &&
        decision.context.denial_reason === "action_approval_required" &&
        effective &&
        view
      ) {
        const signer = this.deps.challengeSigner;
        // Narrow to the specific gated action (keeping the entry's constraints):
        // a proper subset of the active Mission entry, so the AROP grant and the
        // approver task are scoped to the operation actually being approved, not
        // the whole Mission entry. Still passes the AS subset-gate (D42).
        const requested = view.authority_set
          .filter((e) => e.resource === CANONICAL_RESOURCE && e.actions.includes(mapping.action))
          .map((e) => ({ ...e, actions: [mapping.action] }));
        const txn = randomUUID();
        const challenge = await signChallenge(
          {
            txn,
            authorization_details: requested,
            parameter_digest: parameterDigest(effective),
            iss: CANONICAL_RESOURCE,
            aud: signer.asIssuer,
            reason: "action_approval_required",
          },
          signer.sign,
          signer.kid,
        );
        result.access_challenge = { challenge, txn_endpoint: signer.txnEndpoint, txn };
      }
      return result;
    }
    return { permitted: true, decision, ...(effective ? { effective } : {}) };
  }

  /**
   * @spec operation-profile (parameter binding / TOCTOU): re-verify the
   * effective parameters immediately before execution. A digest mismatch
   * (record changed under us) is a refusal, not an execution.
   */
  reverify(effective: EffectiveParams, expectedDigest: string, token: TokenFacts): boolean {
    const invoice = this.deps.payments.getInvoice(effective.invoice_id);
    const vendor = invoice ? this.deps.payments.getVendor(invoice.vendor_id) : undefined;
    if (!invoice || !vendor) {
      this.recordRefusal(token, "parameter_mismatch", effective.action);
      return false;
    }
    const fresh = buildEffectiveParams({ action: effective.action, invoice, vendor, resource: effective.resource });
    if (parameterDigest(fresh) !== expectedDigest) {
      this.recordRefusal(token, "parameter_mismatch", effective.action);
      return false;
    }
    return true;
  }

  private refuse(token: TokenFacts, reason: string, action: string, view?: MissionView): EnforceResult {
    this.recordRefusal(token, reason, action, view);
    return { permitted: false, refusal_reason: reason };
  }

  private recordRefusal(token: TokenFacts, reason: string, action: string, view?: MissionView): void {
    this.deps.evidence.record({
      kind: "refusal",
      refusal_reason: reason,
      mission_id: token.mission.id,
      authority_hash: view?.authority_hash ?? token.mission.authority_hash,
      action,
      instance_epoch: this.deps.instanceEpoch,
    });
  }
}

export function sourceDigestOf(serverCard: unknown): string {
  return `sha-256:${createHash("sha256").update(JSON.stringify(serverCard), "utf8").digest("base64url")}`;
}

export { TOOL_ACTIONS };
