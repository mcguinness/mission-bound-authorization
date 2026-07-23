/**
 * MCP-shaped resource server for the payments estate. Streamable-HTTP MCP
 * transport is the production swap (O-33); this exposes tools/list and
 * tools/call over JSON with the full PEP pipeline, which is what the core
 * enforcement tier (M4) requires. RFC 9728 PRM is published.
 */

import { calculateJwkThumbprint, createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import type { ActObject } from "@mission/actor-chain";
import type { MissionView } from "@mission/pdp";
import { type ActionApprovalInput, CANONICAL_RESOURCE, type EnforceResult, type Pep, type TokenFacts, TOOL_ACTIONS } from "./pep.js";
import type { PaymentsStore } from "./payments-store.js";
import type { Connectors } from "./connectors.js";
import type { EvidenceStore } from "./evidence.js";
import { operationKey, type TransactionEngine } from "./transaction.js";

export interface ToolDef {
  name: string;
  description: string;
  action: string;
}

export const TOOLS: ToolDef[] = [
  { name: "list_invoices", description: "List invoices", action: "payments:invoice.list" },
  { name: "get_invoice", description: "Read one invoice", action: "payments:invoice.read" },
  { name: "lookup_vendor", description: "Look up a vendor", action: "payments:vendor.read" },
  { name: "schedule_payment", description: "Schedule a payment", action: "payments:payment.schedule" },
  { name: "execute_wire_transfer", description: "Execute a wire transfer", action: "payments:payment.execute" },
  { name: "send_remittance_email", description: "Send remittance advice", action: "payments:remittance.send" },
];

export interface McpServerDeps {
  pep: Pep;
  payments: PaymentsStore;
  loadView: (missionId: string) => MissionView | undefined;
  jwks: { keys: Record<string, unknown>[] };
  issuer: string;
  serverCard: unknown;
  /** Transaction-assurance tier (M5); omit for a core-tier-only server. */
  transaction?: { engine: TransactionEngine; connectors: Connectors; evidence: EvidenceStore };
}

export class McpPaymentsServer {
  private readonly resolveKey;
  constructor(private readonly deps: McpServerDeps) {
    this.resolveKey = createLocalJWKSet(deps.jwks as never);
  }

  /** RFC 9728 Protected Resource Metadata. */
  protectedResourceMetadata(): Record<string, unknown> {
    return {
      resource: CANONICAL_RESOURCE,
      authorization_servers: [this.deps.issuer],
      bearer_methods_supported: ["dpop"],
      mission_bound_authorization_required: true,
      mission_constraints_supported: ["max_amount", "vendors"],
    };
  }

  /**
   * Validate a DPoP-bound access token, returning TokenFacts.
   * @spec mission#rs-enforcement: enforce from the token (cnf, mission claim).
   */
  async validateToken(accessToken: string, dpopProof: string, htu: string, htm: string): Promise<TokenFacts> {
    const { payload } = await jwtVerify(accessToken, this.resolveKey, {
      issuer: this.deps.issuer,
      audience: CANONICAL_RESOURCE,
    });
    const cnf = payload.cnf as { jkt?: string } | undefined;
    if (!cnf?.jkt) throw new Error("token missing cnf.jkt");
    // Verify the DPoP proof and bind it to the token's cnf.jkt.
    const proofHeader = decodeProtectedHeader(dpopProof);
    const proofJkt = await calculateJwkThumbprint(proofHeader.jwk as never);
    if (proofJkt !== cnf.jkt) throw new Error("DPoP key does not match token cnf.jkt");
    const { payload: proof } = await jwtVerify(dpopProof, proofHeader.jwk as never, { typ: "dpop+jwt" });
    if (proof.htu !== htu || proof.htm !== htm) throw new Error("DPoP htu/htm mismatch");

    const mission = payload.mission as { id: string; authority_hash: string } | undefined;
    if (!mission?.id) throw new Error("token missing mission claim");
    return {
      sub: payload.sub as string,
      clientId: payload.client_id as string,
      ...(payload.act ? { act: payload.act as ActObject } : {}),
      mission: { id: mission.id, authority_hash: mission.authority_hash },
      cnfJkt: cnf.jkt,
    };
  }

  /**
   * Mission-scoped tools/list (@spec least exposure, D22/E): only tools whose
   * action is within the mission's authority are shown.
   */
  toolsList(token: TokenFacts): ToolDef[] {
    const view = this.deps.loadView(token.mission.id);
    if (!view) return [];
    const granted = new Set(view.authority_set.flatMap((e) => e.actions));
    return TOOLS.filter((t) => granted.has(t.action));
  }

  /** Read-only tool call: enforce then execute. */
  async callReadTool(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
  ): Promise<{ ok: boolean; result?: unknown; denial_reason?: string; refusal_reason?: string }> {
    const res = await this.deps.pep.enforce(tool, args, token);
    if (!res.permitted) {
      return {
        ok: false,
        ...(res.denial_reason ? { denial_reason: res.denial_reason } : {}),
        ...(res.refusal_reason ? { refusal_reason: res.refusal_reason } : {}),
      };
    }
    return { ok: true, result: this.execute(tool, args) };
  }

  /**
   * Write tool call, two-phase for TOCTOU (@spec operation-profile): enforce
   * (decision) -> reverify effective params against fresh store state -> execute.
   * `beforeReverify` is a test hook to mutate state in the decision->execute window.
   */
  async callWriteTool(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
    beforeReverify?: () => void,
  ): Promise<{ ok: boolean; result?: unknown; denial_reason?: string; refusal_reason?: string }> {
    const res = await this.deps.pep.enforce(tool, args, token);
    if (!res.permitted || !res.effective || !res.decision) {
      return {
        ok: false,
        ...(res.denial_reason ? { denial_reason: res.denial_reason } : {}),
        ...(res.refusal_reason ? { refusal_reason: res.refusal_reason } : {}),
      };
    }
    beforeReverify?.();
    const digest = res.decision.context.parameter_digest as string;
    if (!this.deps.pep.reverify(res.effective, digest, token)) {
      return { ok: false, refusal_reason: "parameter_mismatch" };
    }
    return { ok: true, result: this.execute(tool, args) };
  }

  /**
   * @spec runtime transaction-assurance tier, D36 state machine.
   * High-consequence tools (execute_wire_transfer, send_remittance_email):
   * enforce (permit) -> redeem single-use permit -> reverify (TOCTOU) ->
   * commit connector (the commit point) -> Execution Evidence -> reconcile.
   * `beforeCommit` is a test hook for the decision->commit window.
   */
  async callTransactionTool(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
    beforeCommit?: () => void,
    actionApproval?: ActionApprovalInput,
  ): Promise<{
    ok: boolean;
    result?: unknown;
    denial_reason?: string;
    refusal_reason?: string;
    deduped?: boolean;
    access_request?: EnforceResult["access_request"];
  }> {
    const tx = this.deps.transaction;
    if (!tx) throw new Error("transaction tier not configured");

    const res = await this.deps.pep.enforce(tool, args, token, actionApproval);
    if (!res.permitted || !res.effective || !res.decision) {
      return {
        ok: false,
        ...(res.denial_reason ? { denial_reason: res.denial_reason } : {}),
        ...(res.refusal_reason ? { refusal_reason: res.refusal_reason } : {}),
        ...(res.access_request ? { access_request: res.access_request } : {}),
      };
    }
    const digest = res.decision.context.parameter_digest as string;
    const permitId = res.decision.context.decision_id as string;
    const opKey = operationKey(token.mission.id, res.effective.action, digest);

    // Single-use permit redemption (D28): replay -> permit_consumed refusal.
    const redeem = tx.engine.redeemPermit({
      permitId,
      opKey,
      missionId: token.mission.id,
      action: res.effective.action,
      leaseSeconds: 30,
    });
    if (!redeem.ok) return { ok: false, refusal_reason: redeem.reason ?? "permit_consumed" };

    beforeCommit?.();

    // TOCTOU re-verify inside the lease, before commit.
    if (!tx.engine.leaseValid(opKey) || !this.deps.pep.reverify(res.effective, digest, token)) {
      tx.engine.advance(opKey, "abandoned");
      return { ok: false, refusal_reason: "parameter_mismatch" };
    }

    // Commit point (D36): connector accepts with the idempotency key.
    const invoice = this.deps.payments.getInvoice(res.effective.invoice_id);
    const commit =
      tool === "execute_wire_transfer"
        ? tx.connectors.postWire({
            opKey,
            invoiceId: res.effective.invoice_id,
            payeeAccount: res.effective.payee_account,
            amount: res.effective.amount.amount,
            currency: res.effective.amount.currency,
            permitId,
            missionId: token.mission.id,
          })
        : tx.connectors.sendEmail({
            opKey,
            invoiceId: res.effective.invoice_id,
            to: `${res.effective.vendor_id}@vendor.example`,
            permitId,
            missionId: token.mission.id,
          });
    tx.engine.advance(opKey, "connector_committed");

    // Execution Evidence, then reconciliation state.
    tx.evidence.record({
      kind: "execution",
      permit_id: permitId,
      op_key: opKey,
      outcome: commit.deduped ? "deduped" : "committed",
      decision_id: permitId,
      mission_id: token.mission.id,
      authority_hash: token.mission.authority_hash,
      action: res.effective.action,
      parameter_digest: digest,
      instance_epoch: tx.engine.instanceEpoch,
    });
    tx.engine.advance(opKey, "evidence_emitted");
    tx.engine.advance(opKey, "reconciled");

    return {
      ok: true,
      deduped: commit.deduped,
      result: { executed: true, invoice_id: res.effective.invoice_id, op_key: opKey, payee: invoice?.payee_account },
    };
  }

  private execute(tool: string, args: Record<string, unknown>): unknown {
    switch (tool) {
      case "list_invoices":
        return this.deps.payments.listInvoices(args.vendor_id ? String(args.vendor_id) : undefined);
      case "get_invoice":
        return this.deps.payments.getInvoice(String(args.invoice_id));
      case "lookup_vendor":
        return this.deps.payments.getVendor(String(args.vendor_id));
      case "schedule_payment":
        return { scheduled: true, invoice_id: String(args.invoice_id) };
      default:
        return { ok: true };
    }
  }
}

export { TOOL_ACTIONS };
