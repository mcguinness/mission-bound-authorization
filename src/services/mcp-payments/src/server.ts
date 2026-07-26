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
import { TxnReplayCache, TXN_TOKEN_TYP } from "./txn-challenge.js";

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
  /**
   * AROP Transaction Challenge (RS side): the AS's txn public JWKS (as-txn key)
   * and issuer, used to validate a presented txn-token. Omit to disable the
   * hybrid txn-token path.
   */
  txnTokenJwks?: { keys: Record<string, unknown>[] };
  asIssuer?: string;
}

export class McpPaymentsServer {
  private readonly resolveKey;
  private readonly resolveTxnKey?: ReturnType<typeof createLocalJWKSet>;
  private readonly txnReplay = new TxnReplayCache();
  /**
   * §6.2 token-vs-challenge binding: the set of `txn` values this RS has issued
   * a txn-challenge for. Populated when a challenge is emitted (below); a
   * presented txn-token whose `txn` is not in this set is refused (txn_unknown).
   */
  private readonly issuedChallengeTxns = new Set<string>();
  constructor(private readonly deps: McpServerDeps) {
    this.resolveKey = createLocalJWKSet(deps.jwks as never);
    if (deps.txnTokenJwks) this.resolveTxnKey = createLocalJWKSet(deps.txnTokenJwks as never);
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
    txnToken?: string,
  ): Promise<{
    ok: boolean;
    result?: unknown;
    denial_reason?: string;
    refusal_reason?: string;
    deduped?: boolean;
    access_request?: EnforceResult["access_request"];
    access_challenge?: EnforceResult["access_challenge"];
  }> {
    const tx = this.deps.transaction;
    if (!tx) throw new Error("transaction tier not configured");

    // Hybrid AROP path: an AS-signed txn-token carries the verified approval.
    // Validate it (signature/iss/aud/typ, cnf chaining, single-use) and derive
    // the action-bound approval, which the UNCHANGED PDP step 8 then checks.
    // The approval's source is the AS signature; the carrier is the trusted RS.
    // There is no agent-supplied approval entry point: the only way an approval
    // reaches the PDP is via a validated txn-token.
    let derivedApproval: ActionApprovalInput | undefined;
    if (txnToken !== undefined) {
      const derived = await this.deriveApprovalFromTxnToken(txnToken, token);
      if (!derived.ok) return { ok: false, refusal_reason: derived.refusal_reason };
      derivedApproval = derived.approval;
    }

    const res = await this.deps.pep.enforce(tool, args, token, derivedApproval);
    // §6.2: remember the txn we just issued a challenge for, so the later
    // txn-token that quotes it can be bound back to a real challenge.
    if (res.access_challenge) this.issuedChallengeTxns.add(res.access_challenge.txn);
    if (!res.permitted || !res.effective || !res.decision) {
      return {
        ok: false,
        ...(res.denial_reason ? { denial_reason: res.denial_reason } : {}),
        ...(res.refusal_reason ? { refusal_reason: res.refusal_reason } : {}),
        ...(res.access_request ? { access_request: res.access_request } : {}),
        ...(res.access_challenge ? { access_challenge: res.access_challenge } : {}),
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

  /**
   * Validate a presented AROP txn-token and derive the action-bound approval.
   * Checks (in order): AS signature + issuer/audience/typ; `cnf.jkt` chains to
   * the base mission token's key; single-use per `txn` (replay -> txn_replayed).
   */
  private async deriveApprovalFromTxnToken(
    txnToken: string,
    token: TokenFacts,
  ): Promise<{ ok: true; approval: ActionApprovalInput } | { ok: false; refusal_reason: string }> {
    if (!this.resolveTxnKey || !this.deps.asIssuer) return { ok: false, refusal_reason: "txn_not_configured" };
    let payload: Record<string, unknown>;
    try {
      ({ payload } = await jwtVerify(txnToken, this.resolveTxnKey, {
        issuer: this.deps.asIssuer,
        audience: CANONICAL_RESOURCE,
        typ: TXN_TOKEN_TYP,
      }));
    } catch {
      return { ok: false, refusal_reason: "txn_invalid" };
    }
    // The txn-token must be bound to the same key as the base mission token.
    const cnf = payload.cnf as { jkt?: string } | undefined;
    if (cnf?.jkt !== token.cnfJkt) return { ok: false, refusal_reason: "txn_cnf_mismatch" };
    // §6.2 token-vs-challenge binding: the token's txn must be one this RS
    // actually issued a challenge for (checked after cnf, before the replay
    // consume, so a foreign or bad-cnf token never burns a replay slot).
    const txn = payload.txn as string | undefined;
    if (!txn || !this.issuedChallengeTxns.has(txn)) return { ok: false, refusal_reason: "txn_unknown" };
    // Single-use across presentations.
    if (!this.txnReplay.accept(txn)) return { ok: false, refusal_reason: "txn_replayed" };
    const approval = payload.approval as { id: string; approved_at: string; parameter_digest: string } | undefined;
    if (!approval) return { ok: false, refusal_reason: "txn_missing_approval" };
    return {
      ok: true,
      approval: { id: approval.id, approved_at: approval.approved_at, parameter_digest: approval.parameter_digest },
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
