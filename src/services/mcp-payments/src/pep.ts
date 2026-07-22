/**
 * @spec mission#rs-enforcement, runtime (PEP), authzen (envelope)
 *
 * The resource-server PEP for the payments estate. Validates the DPoP-bound
 * token and mission claim, builds the AuthZEN envelope (context.actor via
 * @mission/actor-chain, parameter_digest, capability_source), obtains a PDP
 * decision, and emits Decision Evidence / Refusal Records. Core enforcement
 * tier (M4); the transaction-assurance tier (permits/leases) lands in M5.
 */

import { createHash } from "node:crypto";
import { type ActObject, buildContextActor } from "@mission/actor-chain";
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
}

export interface EnforceResult {
  permitted: boolean;
  decision?: Decision;
  denial_reason?: string;
  refusal_reason?: string;
  effective?: EffectiveParams;
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
  async enforce(tool: string, args: Record<string, unknown>, token: TokenFacts): Promise<EnforceResult> {
    const mapping = this.toolAction(tool);
    if (!mapping) return this.refuse(token, "unknown_tool", tool);

    const view = this.deps.loadView(token.mission.id);
    if (!view) return this.refuse(token, "unknown_mission", mapping.action);

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
      } as EvaluationRequest["context"],
    };

    const decision = await evaluate(req, {
      view,
      fga: this.deps.fga,
      modelId: this.deps.modelId,
      now: this.now,
      stalenessBoundSeconds,
      relationForAction,
    });

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
      return {
        permitted: false,
        decision,
        denial_reason: decision.context.denial_reason as string,
        ...(effective ? { effective } : {}),
      };
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
