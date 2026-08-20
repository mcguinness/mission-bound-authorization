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
import { TXN_AUTHORIZATION_REQUIRED, type JsonValue, type TxnMissionClaim } from "@mission/core";
import { getTracer } from "@mission/telemetry";
import {
  type AuthorityEntry,
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
import type { PendingOperation } from "./txn-store.js";

export const CANONICAL_RESOURCE = process.env.MCP_PAYMENTS_RESOURCE ?? "http://localhost:4403/mcp";
export const TOOL_BASE = "mcp://payments.demo/tools";
const SERVER_CARD_URI = `${CANONICAL_RESOURCE.replace(/\/mcp$/, "")}/.well-known/mcp`;

/**
 * @spec txn-authorization#offline-verification — present exactly when the
 * credential presented on THIS request was a transaction token. The retry of a
 * challenged operation carries the transaction token as its SOLE OAuth
 * credential, so these are the verified claims the enforcement path works from;
 * a credential carrying this marker authorizes the challenged operation and
 * nothing else.
 */
export interface TxnCredential {
  /** The `txn` the credential is bound to; consumption is keyed on it. */
  txn: string;
  jti: string;
  iatS: number;
  expS: number;
  /** The token's own `parameter_digest`, already matched to the pending operation. */
  parameterDigest: string;
}

/** Validated token facts the PEP works from (token validation is upstream). */
export interface TokenFacts {
  sub: string;
  clientId: string;
  clientInstanceId?: string;
  act?: ActObject;
  mission: { id: string; authority_hash: string };
  /**
   * @spec txn-authorization#resource-challenge — the VERIFIED token's whole
   * `mission` claim. A challenge copies it unchanged (including the invariant
   * origin principal where the Origin Principal profile applies), so the
   * resource must keep the claim it verified, not just the two members the
   * PDP envelope needs. Absent for a credential whose claim is not the
   * profiled shape; the resource then issues no challenge.
   */
  missionClaim?: TxnMissionClaim;
  cnfJkt: string;
  /**
   * @spec continuation: the access token's `jti`, carried so an action taken
   * under a continued credential attributes to the specific hop (below).
   * Absent for non-JWT or older tokens.
   */
  jti?: string;
  /**
   * @spec continuation: the token's top-level `identity_continuation_handle`
   * when present (the new-hop continuation handle from the ID-JAG lineage).
   */
  identityContinuationHandle?: string;
  /**
   * @spec attenuation#mission-binding-check: present when the credential was a
   * Mission-bound Attenuating Agent Token chain. The effective authority is the
   * leaf's narrowed tools, expressed as {resource, actions}; an action within
   * the Mission but outside this leaf is denied `out_of_authority` (below).
   * Absent for an ordinary Mission-bound token (no leaf narrowing).
   */
  leafAuthority?: ReadonlyArray<{ resource: string; actions: readonly string[] }>;
  /**
   * @spec txn-authorization#offline-verification — present when the credential
   * for this request was a transaction token (see {@link TxnCredential}).
   * Absent for every ordinary Mission-bound credential.
   */
  txn?: TxnCredential;
}

export interface ActionMapping {
  action: string;
  actionClass?: "irreversible_action" | "external_commitment";
  needsInvoice: boolean;
  /**
   * @spec runtime#read-binding — this action's unfiltered form requests a
   * bulk, cross-vendor result, which the read-binding floor MUST bind: a
   * supplied `vendor_id` binds through the ordinary vendor-constraint check
   * every invoice-scoped action uses; absent one, the returned set binds to
   * the matched Authority Set entry's OWN vendor scope, never the
   * unconstrained store (see the `bindsVendorScope` branch in
   * {@link Pep.enforceInner}).
   */
  bindsVendorScope?: boolean;
}

const TOOL_ACTIONS: Record<string, ActionMapping> = {
  list_invoices: { action: "payments:invoice.list", needsInvoice: false, bindsVendorScope: true },
  get_invoice: { action: "payments:invoice.read", needsInvoice: true },
  lookup_vendor: { action: "payments:vendor.read", needsInvoice: false },
  schedule_payment: { action: "payments:payment.schedule", needsInvoice: true },
  execute_wire_transfer: { action: "payments:payment.execute", actionClass: "irreversible_action", needsInvoice: true },
  send_remittance_email: { action: "payments:remittance.send", actionClass: "external_commitment", needsInvoice: true },
};

/**
 * @spec runtime#read-binding — synthetic FGA check object for a bulk
 * `list_invoices` request under an entry with NO `vendors` constraint at
 * all (entitled to every vendor already). There is no specific vendor to
 * name, and no FGA object type here supports a wildcard check target, so
 * this fixed placeholder stands in for "the entry's own scope, whatever it
 * is" under the same contextual-tuple pattern every other action uses
 * (the injected tuple names exactly the object being checked).
 */
const UNSCOPED_VENDOR_OBJECT = "__unscoped__";

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
   * @spec txn-authorization#resource-challenge — this resource's txn-challenge
   * signing key (the key published at its `txn_challenge_jwks_uri`). When
   * configured AND the client signalled `Accept-Txn-Challenge`, an
   * `action_approval_required` denial returns a signed challenge. `asIssuer` is
   * the Transaction Authorization Server, used as the challenge `aud`; the
   * client discovers its endpoint from Authorization Server metadata
   * (`transaction_authorization_endpoint`), never from the challenge.
   */
  challengeSigner?: {
    sign: import("jose").CryptoKey;
    kid: string;
    alg?: string;
    asIssuer: string;
    /** Admission window for the challenge (seconds). */
    lifetimeSeconds?: number;
  };
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

/**
 * @spec txn-authorization#resource-challenge — per-request client signals the
 * enforcement path reads. `acceptTxnChallenge` is the `Accept-Txn-Challenge`
 * header: a client that does not signal it never receives a challenge.
 */
export interface RequestSignals {
  acceptTxnChallenge?: boolean;
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
  /**
   * @spec runtime#read-binding — present on a permitted `bindsVendorScope`
   * action (list_invoices): the vendor ids the bound result set is limited
   * to. Absent only when the matched entry carries no vendor constraint and
   * the caller requested no `vendor_id` (entitled to, and requesting, every
   * vendor already).
   */
  list_vendor_scope?: string[];
  /** Present on a requestable denial: the ARAP access-request context. */
  access_request?: { endpoint: string; denial_binding: string; binding_token: string; expires_at: string };
  /**
   * @spec txn-authorization#resource-challenge — present when the action falls
   * under the profile and the client signalled `Accept-Txn-Challenge`. `error`
   * and `transaction_challenge` are the upstream wire members the caller
   * surfaces verbatim; `pending` is the operation the resource RETAINS for the
   * later offline verification and never puts on the wire.
   */
  challenge?: {
    error: typeof TXN_AUTHORIZATION_REQUIRED;
    transaction_challenge: string;
    pending: PendingOperation;
  };
  /**
   * @spec I-D.draft-zehavi-oauth-rar-metadata §4 — present on a genuine
   * out_of_authority denial: the requested (resource, action) is absent from
   * the Mission's Authority Set entirely. One GRAIN of the family's
   * graduated-challenge remediation (composes with, does not replace,
   * access_request/`challenge` above and the AuthZEN ARAP requestable
   * denial): the actionable authorization_details the client could propose
   * next on the standard authorization_details request parameter
   * (@spec mission#authority-proposal).
   */
  insufficient_authorization?: InsufficientAuthorization;
}

/**
 * @spec I-D.draft-zehavi-oauth-rar-metadata §4 — the insufficient_authorization
 * WWW-Authenticate error, plus its `authorization_remediation` parameter
 * (base64url JSON: `{ authorization_details }`). `www_authenticate` is the
 * header VALUE the RS would set on a raw HTTP response; this RS's tokens are
 * DPoP-bound (`bearer_methods_supported: ["dpop"]` above), so the auth-scheme
 * is `DPoP`, not the draft's Bearer example. It travels as a field here (not
 * a literal header) because a PEP denial rides inside an MCP CallToolResult at
 * HTTP 200, not a raw per-call HTTP response -- mcp-http-transport.ts's
 * unauthorized() is the one site that sets a real www-authenticate header, and
 * it fires only pre-dispatch (missing/invalid credential), before the PEP.
 */
export interface InsufficientAuthorization {
  www_authenticate: string;
  authorization_remediation: string;
}

/** Build the insufficient_authorization grain for one or more actionable
 * authorization_details entries (@spec I-D.draft-zehavi-oauth-rar-metadata §4). */
export function buildInsufficientAuthorization(authorizationDetails: AuthorityEntry[]): InsufficientAuthorization {
  const authorization_remediation = Buffer.from(
    JSON.stringify({ authorization_details: authorizationDetails }),
    "utf8",
  ).toString("base64url");
  const www_authenticate =
    'DPoP error="insufficient_authorization", ' +
    'error_description="the requested action is outside the Mission\'s Authority Set", ' +
    `authorization_remediation=${authorization_remediation}`;
  return { www_authenticate, authorization_remediation };
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
    signals?: RequestSignals,
  ): Promise<EnforceResult> {
    return getTracer("pep").startActiveSpan(`pep.enforce ${tool}`, async (span) => {
      span.setAttribute("mission.tool", tool);
      span.setAttribute("mission.id", token.mission.id);
      try {
        const res = await this.enforceInner(tool, args, token, actionApproval, signals);
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
    signals?: RequestSignals,
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
    let listVendorScope: string[] | undefined;
    if (mapping.needsInvoice) {
      const invoiceId = String(args.invoice_id ?? "");
      const invoice = this.deps.payments.getInvoice(invoiceId);
      if (!invoice) return this.refuse(token, "unknown_invoice", mapping.action, view);
      const vendor = this.deps.payments.getVendor(invoice.vendor_id);
      if (!vendor) return this.refuse(token, "unknown_vendor", mapping.action, view);
      effective = buildEffectiveParams({ action: mapping.action, invoice, vendor, resource: CANONICAL_RESOURCE });
      amount = effective.amount;
      resourceObj = { type: "invoice", id: invoice.id, properties: { vendor_id: vendor.id } };
    } else if (mapping.bindsVendorScope) {
      // @spec runtime#read-binding — "a consequential read whose parameters
      // ... request a bulk or export-like result ... MUST bind those
      // parameters. A deployment MUST NOT classify such a read as not
      // materially affecting the resource set." list_invoices without
      // vendor_id is exactly that bulk form; binding it means the returned
      // set never exceeds the Mission's own Authority Set entry.
      const entry = view.authority_set.find(
        (e) => e.resource === CANONICAL_RESOURCE && e.actions.includes(mapping.action),
      );
      const allowedVendors = entry?.constraints?.vendors;
      const requestedVendorId = args.vendor_id !== undefined ? String(args.vendor_id) : undefined;
      if (requestedVendorId !== undefined) {
        // A named vendor_id binds through the SAME vendor-constraint check
        // every invoice-scoped action here uses (out-of-scope -> denied
        // out_of_authority at the FGA step below, same as get_invoice).
        resourceObj = { type: "vendor", id: requestedVendorId, properties: { vendor_id: requestedVendorId } };
        listVendorScope = [requestedVendorId];
      } else if (allowedVendors) {
        // Bulk form, vendor-constrained entry: bind the RESULT SET to the
        // entry's own scope (never the unconstrained store). The set-level
        // authority already comes from the entry match above; one member of
        // the allowlist stands in for the per-object FGA check that every
        // other action performs, so an empty allowlist still denies below.
        listVendorScope = allowedVendors;
        const representative = allowedVendors[0] ?? UNSCOPED_VENDOR_OBJECT;
        resourceObj = { type: "vendor", id: representative, properties: { vendor_id: representative } };
      } else {
        // Bulk form, unconstrained entry: already entitled to every vendor,
        // so the read is bound to that full, documented scope, not an
        // accident of the tool's default arguments.
        resourceObj = { type: "vendor", id: UNSCOPED_VENDOR_OBJECT, properties: {} };
      }
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
      // @spec authzen `entry_digest`: the PDP's resolved-scope anchor, copied
      // from the decision context so the retained record cites the entry.
      ...(decision.context.entry_digest ? { entry_digest: decision.context.entry_digest as string } : {}),
      mission_id: view.id,
      authority_hash: view.authority_hash,
      action: mapping.action,
      ...(req.context.parameter_digest ? { parameter_digest: req.context.parameter_digest } : {}),
      instance_epoch: this.deps.instanceEpoch,
      emitter: { id: CANONICAL_RESOURCE, role: "pep" },
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
      // @spec txn-authorization#resource-challenge — on an
      // action_approval_required denial the resource normalizes the operation,
      // computes the runtime parameter_digest, and returns a signed challenge.
      // The client's Accept-Txn-Challenge signal GATES it: without the signal a
      // client that cannot redeem a challenge just sees the denial. `mission`,
      // `parameter_digest` and `cnf` are derived HERE, from the request and the
      // verified token; nothing the client supplied can replace them.
      if (
        this.deps.challengeSigner &&
        signals?.acceptTxnChallenge &&
        decision.context.denial_reason === "action_approval_required" &&
        effective &&
        token.missionClaim &&
        view
      ) {
        const signer = this.deps.challengeSigner;
        // Exactly one operation-scoped entry: the active Mission's entry for
        // this resource+action narrowed to the single gated action (keeping the
        // entry's constraints), so the approval and the transaction token are
        // scoped to the operation being approved, not the whole entry.
        const requested = view.authority_set
          .filter((e) => e.resource === CANONICAL_RESOURCE && e.actions.includes(mapping.action))
          .map((e) => ({ ...e, actions: [mapping.action] })) as unknown as JsonValue[];
        const digest = parameterDigest(effective);
        const signed = await signChallenge(
          {
            txn: randomUUID(),
            authorization_details: requested,
            parameter_digest: digest,
            mission: token.missionClaim,
            cnf: { jkt: token.cnfJkt },
            iss: CANONICAL_RESOURCE,
            aud: signer.asIssuer,
            reason: "action_approval_required",
            ...(signer.lifetimeSeconds !== undefined ? { lifetimeSeconds: signer.lifetimeSeconds } : {}),
            ...(token.act !== undefined ? { act: token.act as unknown as JsonValue } : {}),
          },
          signer.sign,
          signer.kid,
          signer.alg ?? "ES256",
        );
        result.challenge = {
          error: TXN_AUTHORIZATION_REQUIRED,
          transaction_challenge: signed.challenge,
          pending: {
            txn: signed.txn,
            resource: CANONICAL_RESOURCE,
            challengeJti: signed.jti,
            mission: token.missionClaim,
            action: mapping.action,
            parameterDigest: digest,
            authorizationDetails: requested,
            cnfJkt: token.cnfJkt,
            // @spec txn-authorization#challenge-redemption — the verified
            // subject, under the SAME rule the Transaction Authorization Server
            // mints `sub` by: the credential's OWN `sub`, in the issuing
            // Authorization Server's namespace. The origin principal, where the
            // Origin Principal profile applies, stays issuer-qualified inside
            // the `mission` claim and is covered by the mission-invariants
            // equality check -- never flattened into a local subject. The
            // retained operation and the token that comes back must agree.
            subject: token.sub,
          },
        };
      }
      // @spec I-D.draft-zehavi-oauth-rar-metadata §4 (insufficient_authorization
      // grain, additive to the grains above): only on a GENUINE out_of_authority
      // denial -- the (resource, action) pair is absent from the Mission's
      // Authority Set entirely, not merely denied for THIS target object
      // (deriveContextualTuples/FGA can also return out_of_authority when the
      // entry exists but the specific object is excluded) -- propose the
      // missing entry back. Deliberately NOT emitted for authority_contained:
      // that is the family's monotonic trust ratchet (@spec containment);
      // handing back "here's how to ask again" for a deliberately narrowed
      // capability would contradict restore-only-via-Expansion.
      if (
        decision.context.denial_reason === "out_of_authority" &&
        !view.authority_set.some((e) => e.resource === CANONICAL_RESOURCE && e.actions.includes(mapping.action))
      ) {
        result.insufficient_authorization = buildInsufficientAuthorization([
          { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: [mapping.action] },
        ]);
      }
      return result;
    }
    return {
      permitted: true,
      decision,
      ...(effective ? { effective } : {}),
      ...(listVendorScope ? { list_vendor_scope: listVendorScope } : {}),
    };
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
      emitter: { id: CANONICAL_RESOURCE, role: "pep" },
    });
  }
}

export function sourceDigestOf(serverCard: unknown): string {
  return `sha-256:${createHash("sha256").update(JSON.stringify(serverCard), "utf8").digest("base64url")}`;
}

export { TOOL_ACTIONS };
