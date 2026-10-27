/**
 * MCP-shaped resource server for the payments estate. Streamable-HTTP MCP
 * transport is the production swap (O-33); this exposes tools/list and
 * tools/call over JSON with the full PEP pipeline, which is what the core
 * enforcement tier (M4) requires. RFC 9728 PRM is published.
 */

import {
  AAT_ALGORITHMS,
  AAT_TYP,
  aatToolId,
  aatToPlainJson,
  authorizationDetailsEqual,
  type CredentialAuthorityEntry,
  type DpopProofReplay,
  establishOperationTarget,
  isIdempotencyKey,
  mediaTypeOf,
  type MissionAatChain,
  MISSION_TXN_TOKEN_TYP,
  missionInvariantsEqual,
  newDpopProofReplay,
  parseCredentialAuthority,
  readTxnMissionClaim,
  verifyAatPresentation,
  verifyMissionAatChain,
  type IssuerKeysFetch,
} from "@mission/core";
import {
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  type JWTPayload,
  jwtVerify,
} from "jose";
import type { ActObject } from "@mission/actor-chain";
import {
  type AudienceContext,
  type AudienceValidation,
  executionLeaseMaxSeconds,
  executionLeaseMs,
  loadRuntimePosture,
  REVERSIBLE_WRITE_CLASS,
  reversibleWriteControlFor,
  reversibleWriteDeclarationFor,
  reversibleWriteRetentionSeconds,
  RUNTIME_POSTURE,
  type Decision,
  type MissionView,
  type RuntimePosture,
} from "@mission/pdp";

import {
  type ActionApprovalInput,
  type ActionMapping,
  CANONICAL_RESOURCE,
  type CompensatedEffect,
  type DecisionEvidenceGap,
  type EnforceResult,
  type ExecutionAttempt,
  type InsufficientAuthorization,
  type LoadedView,
  loadCheckedView,
  type MissionBoundTokenFacts,
  paymentsBoundaryContext,
  type MissionReference,
  type OrdinaryTokenFacts,
  type ValidatedBoundary,
  type Pep,
  recipientParams,
  type RequestSignals,
  type SuppressOutcome,
  type TokenFacts,
  TOOL_ACTIONS,
  type TxnCredential,
  type WriteReservationScope,
} from "./pep.js";
import { type DpopPresentation, DpopReplayUnavailableError, verifyDpopProof } from "./dpop.js";
import { type IntrospectionSettings, TokenInactiveError, TokenIntrospector } from "./introspection.js";
import { aatKeyThumbprint, readAttenuationRootClaims, readMissionAccessClaims } from "./token-verifier.js";
import { type AatPresentation, AatPresentationRefused } from "./aat-presentation.js";
import { parseOriginalArguments } from "./invocation-arguments.js";
import {
  type KeyAlgorithms,
  type KeyResolver,
  type KeyRole,
  type KeyRoles,
  type RefreshingRoleKeys,
  refreshingRoleKeyResolvers,
  roleKeyResolvers,
} from "./key-roles.js";
import {
  openTxnStores,
  type TxnConsumeOutcome,
  type TxnConsumptionStore,
  type TxnPendingStore,
} from "./txn-store.js";
import { defaultRemittanceAddress, type PaymentsStore } from "./payments-store.js";
import type { CommitResult, Connectors } from "./connectors.js";
import type { EvidenceStore, ExecutionEvidence, ExecutionEvidenceInput } from "./evidence.js";
import type { OperatorAlertSink } from "./outcome-reconciler.js";
import { operationKey, type TransactionEngine } from "./transaction.js";
import { recordRedeemingAttempt } from "./redemption-status.js";
import { buildEffectiveParams, type EffectiveParams, parameterDigest } from "./effective-params.js";
import {
  CONSUMED_PERMIT_RETENTION_MARGIN_MS,
  type ExecutionAttemptRecord,
  type WriteEffectOutcome,
  type WriteReservation,
  type WriteReservationStore,
} from "./write-reservations.js";

/** Called only after this path's signature, issuer/chain and expiry checks. */
function verifiedCredentialRef(payload: JWTPayload): { issuer?: string; expires_at?: string } {
  return {
    ...(typeof payload.iss === "string" ? { issuer: payload.iss } : {}),
    ...(typeof payload.exp === "number" ? { expires_at: new Date(payload.exp * 1000).toISOString() } : {}),
  };
}

/**
 * @spec runtime-oauth#token-validation (#853, D487): a verified credential
 * whose `aud` does not name the enforcement boundary the PEP establishes, or
 * a boundary that cannot be established. Refused before any claim becomes a
 * decision input.
 */
export class TokenAudienceError extends Error {
  constructor(readonly reason: string) {
    super(`token audience refused: ${reason}`);
    this.name = "TokenAudienceError";
  }
}

/**
 * @spec authority-server#mapping-contract (#818): the one credential format an
 * estate route (`ordinaryOnly`) accepts: an RFC 9068 JWT access token, `typ`
 * `at+jwt`, with the string `sub`, `client_id` and `jti` and the numeric `exp`
 * and `iat` the profile requires, and a `scope` string when present. Signature,
 * issuer, audience, `cnf` and the proof are checked before this. A credential in
 * any other format throws: it is refused, not interpreted.
 */
/**
 * @spec authority-server#mission-join (#818 slice 3): the token profile an
 * introspected opaque access token is validated under, as the boundary's
 * audience rule names profiles (an alias declared for it applies).
 */
export const INTROSPECTED_TOKEN_PROFILE = "token-introspection";

/** A compact JWS: three dot-separated segments whose first decodes as a protected header. */
function isCompactJws(token: string): boolean {
  if (token.split(".").length !== 3) return false;
  try {
    decodeProtectedHeader(token);
    return true;
  } catch {
    return false;
  }
}

function assertEstateAccessToken(typ: unknown, payload: JWTPayload): void {
  if (typeof typ !== "string" || typ.toLowerCase() !== "at+jwt") throw new Error("unsupported credential format");
  for (const claim of ["sub", "client_id", "jti"] as const) {
    if (typeof payload[claim] !== "string" || payload[claim] === "") throw new Error(`token missing ${claim}`);
  }
  if (typeof payload.exp !== "number" || typeof payload.iat !== "number") throw new Error("token missing exp or iat");
  if (payload.scope !== undefined && typeof payload.scope !== "string") throw new Error("token scope is not a string");
}

/**
 * @spec txn-authorization#transaction-token — a transaction token authorizes
 * exactly the challenged operation and MUST NOT be accepted as a general
 * Mission-bound access token for any other purpose. Its `typ` is read before
 * anything else, so it is refused outright rather than parsed on a best-effort
 * basis: every other claim on it (issuer, audience, `cnf`, the `mission`
 * claim) would otherwise satisfy ordinary token validation.
 */
function refuseTransactionToken(accessToken: string): void {
  if (decodeProtectedHeader(accessToken).typ === MISSION_TXN_TOKEN_TYP) {
    throw new Error("a transaction token is not a Mission-bound access token");
  }
}

/**
 * @spec authzen#response-context: a permit's decision conditions
 * (`parameter_digest`/`valid_until`/`use_limit`) live NESTED under
 * `decision.context.conditions`, never as flat top-level members. Every
 * digest reverification site reads through this one accessor so the nesting
 * is never repeated ad hoc.
 */
function permitConditions(decision: Decision | undefined): Record<string, unknown> | undefined {
  return decision?.context.conditions as Record<string, unknown> | undefined;
}

/**
 * @spec runtime#single-use-identifiers, authzen#response-context `use_limit`
 * (#1080, #1136 review, D317): what a permit's `use_limit` asks of the write
 * path, resolved once for the unkeyed and the keyed write alike, so neither
 * can ignore a limit it receives. `undefined` when the permit carries none;
 * `error` names the Execution Evidence `error` that refuses it; otherwise the
 * single use is metered and its consumed record kept until `retainUntilMs`.
 *
 * | Case | Result |
 * |---|---|
 * | no `use_limit` | `undefined` |
 * | `use_limit` other than 1 (this PEP meters single use only) | `condition_unrecognized` |
 * | `use_limit: 1` with no resolvable `valid_until` | `permit_expired` |
 * | `use_limit: 1` | `valid_until` plus {@link CONSUMED_PERMIT_RETENTION_MARGIN_MS} |
 */
function singleUseCondition(
  attempt: ExecutionAttempt,
  decision: Decision | undefined,
): { error: string } | { retainUntilMs: number } | undefined {
  const useLimit = permitConditions(decision)?.use_limit;
  if (useLimit === undefined) return undefined;
  if (useLimit !== 1) return { error: "condition_unrecognized" };
  const validUntilMs =
    typeof attempt.permitValidUntil === "string" ? Date.parse(attempt.permitValidUntil) : Number.NaN;
  if (!Number.isFinite(validUntilMs)) return { error: "permit_expired" };
  return { retainUntilMs: validUntilMs + CONSUMED_PERMIT_RETENTION_MARGIN_MS };
}

/** The caller-visible reason for a single-use refusal's Execution Evidence `error`. */
function singleUseRefusalReason(error: string): string {
  return error === "condition_unrecognized" ? "unrecognized_condition" : error;
}

export interface ToolDef {
  name: string;
  description: string;
  action: string;
}

/**
 * @spec runtime#compound-actions — `check_transfer`, `hold_transfer` and
 * `execute_wire_transfer` are the preflight, prepare and commit crossings of
 * ONE compound action, sharing the `payments:payment.execute` identifier and
 * one `{invoice_id}` argument schema, so they also share one normalized
 * effect form and one `parameter_digest`. The phase is what separates their
 * permits; see `TOOL_ACTIONS` for the Operation Profile that assigns it.
 */
export const TOOLS: ToolDef[] = [
  { name: "list_invoices", description: "List invoices", action: "payments:invoice.list" },
  { name: "get_invoice", description: "Read one invoice", action: "payments:invoice.read" },
  { name: "lookup_vendor", description: "Look up a vendor", action: "payments:vendor.read" },
  { name: "schedule_payment", description: "Schedule a payment", action: "payments:payment.schedule" },
  { name: "cancel_scheduled_payment", description: "Cancel a scheduled payment", action: "payments:payment.schedule.cancel" },
  { name: "check_transfer", description: "Check whether a wire transfer is feasible, reserving nothing", action: "payments:payment.execute" },
  { name: "hold_transfer", description: "Place a hold for a wire transfer", action: "payments:payment.execute" },
  { name: "execute_wire_transfer", description: "Execute a wire transfer", action: "payments:payment.execute" },
  { name: "reverse_wire_transfer", description: "Reverse a committed wire transfer", action: "payments:payment.reverse" },
  { name: "send_remittance_email", description: "Send remittance advice", action: "payments:remittance.send" },
];

/**
 * @spec runtime#execution-reverification — the explicit connector operation
 * each committing tool releases its effect through.
 *
 * A ternary on one tool name used to decide this, so every other name reaching
 * the commit point sent an email: adding a served tool to the compound action
 * would have silently mis-executed. The mapping is exhaustive over the tools
 * the Operation Profile gives a high-consequence class (pinned by the
 * catalog/profile consistency test), and a tool with no entry throws before
 * any state is taken rather than falling through to another connector.
 */
const CONNECTOR_OPERATIONS: Record<
  string,
  (input: {
    connectors: Connectors;
    opKey: string;
    effective: EffectiveParams;
    permitId: string;
    missionId: string;
    /**
     * @spec runtime#compound-actions (#252): the committed effect a
     * compensate crossing offsets, as the PEP established it from verified
     * evidence before the decision request. Absent on every other crossing.
     */
    compensates?: CompensatedEffect;
  }) => CommitResult
> = {
  execute_wire_transfer: ({ connectors, opKey, effective, permitId, missionId }) =>
    connectors.postWire({
      opKey,
      invoiceId: effective.invoice_id,
      vendorId: effective.vendor_id,
      payeeAccount: effective.payee_account,
      amount: effective.amount.amount,
      currency: effective.amount.currency,
      permitId,
      missionId,
    }),
  // @spec runtime#compound-actions (#252): the compensate crossing offsets the
  // one committed wire its Decision linked, named by the wire's operation key
  // (bound in the reversal's parameter digest) and evaluation identifier, with
  // the amount, currency and payee the Decision evaluated and bound; the
  // connector refuses them unless they equal the wire's record. Never an agent
  // argument. With no established link there is nothing to offset.
  reverse_wire_transfer: ({ connectors, opKey, effective, permitId, missionId, compensates }) =>
    compensates && effective.reverses !== undefined
      ? connectors.reverseWire({
          opKey,
          reversedOpKey: effective.reverses,
          reversedPermitId: compensates.evaluationId,
          amount: effective.amount.amount,
          currency: effective.amount.currency,
          payeeAccount: effective.payee_account,
          permitId,
          missionId,
        })
      : { committed: false, deduped: false, refusal: "wire_not_committed" },
  send_remittance_email: ({ connectors, opKey, effective, permitId, missionId }) =>
    connectors.sendEmail({
      opKey,
      invoiceId: effective.invoice_id,
      // @spec resource-access#initial-common-constraints (#1266): exactly the
      // recipients the decision evaluated: the routed set the digest binds,
      // or the vendor's default address.
      to: (effective.recipients ?? [defaultRemittanceAddress(effective.vendor_id)]).join(", "),
      permitId,
      missionId,
    }),
};

/** The committing tools this server serves a connector operation for. */
export const CONNECTOR_TOOLS: readonly string[] = Object.keys(CONNECTOR_OPERATIONS);

/**
 * @spec runtime#idempotency (#918): the reversible effect each keyed write
 * releases, run inside the reservation's one local transaction. An explicit
 * per-tool mapping, as for the connector operations: a keyed write with no
 * entry throws before any state is taken. Neither effect calls a connector or
 * moves money, and nothing reads a schedule to pay: `execute_wire_transfer`
 * keeps its own Decision, single-use permit and D28 redemption.
 */
const REVERSIBLE_WRITE_EFFECTS: Record<
  string,
  (input: {
    store: WriteReservationStore;
    attempt: ExecutionAttempt;
    token: TokenFacts;
    effective: EffectiveParams;
    invoiceVersion: number;
    parameterDigest: string;
    nowMs: number;
  }) => WriteEffectOutcome
> = {
  schedule_payment: ({ store, attempt, token, effective, invoiceVersion, parameterDigest, nowMs }) =>
    store.insertSchedule({
      mission: attempt.mission,
      subject: token.sub,
      invoice: {
        id: effective.invoice_id,
        version: invoiceVersion,
        vendor_id: effective.vendor_id,
        payee_account: effective.payee_account,
      },
      amount: effective.amount,
      parameterDigest,
      evaluationId: attempt.evaluationId,
      nowMs,
    }),
  cancel_scheduled_payment: ({ store, attempt, effective, nowMs }) =>
    store.cancelActiveSchedule({
      mission: attempt.mission,
      invoiceId: effective.invoice_id,
      evaluationId: attempt.evaluationId,
      nowMs,
    }),
};

/** The keyed reversible writes this server serves an effect for. */
export const REVERSIBLE_WRITE_TOOLS: readonly string[] = Object.keys(REVERSIBLE_WRITE_EFFECTS);

/**
 * @spec runtime#permit-binding, runtime#idempotency, runtime#single-use-identifiers
 * (#918, #1080, D333): every `consequential_write` this server serves is
 * covered by a permit-lifetime control the statement selects for it
 * ({@link reversibleWriteControlFor}), a control this server enforces on the
 * tool's own write path, with the enforcing store configured and owned by the
 * declared owner. Anything else is an unsafe topology, refused at startup
 * rather than discovered at the first duplicate or replay:
 *
 * | Selected control | Supported where | Owner the store must have |
 * |---|---|---|
 * | `validity_window_plus_idempotency_key` | a keyed tool with a declared reversible effect | `reservation_owner` |
 * | `single_use_decision_identifier` | an unkeyed tool | `consumed_identifier_owner` |
 */
function assertPermitLifetimeCoverage(statement: RuntimePosture, store: WriteReservationStore | undefined): void {
  for (const [tool, mapping] of Object.entries(TOOL_ACTIONS)) {
    if (mapping.actionClass !== REVERSIBLE_WRITE_CLASS) continue;
    const control = reversibleWriteControlFor(statement, mapping.actionClass, mapping.action);
    if (!control) throw new Error(`no permit-lifetime control declaration covers ${tool}`);
    const keyed = mapping.idempotencyKey === true;
    if (keyed !== (control.permit_lifetime_control === "validity_window_plus_idempotency_key")) {
      throw new Error(
        `${tool} is served on the ${keyed ? "keyed" : "unkeyed"} write path, which does not enforce ${control.permit_lifetime_control}`,
      );
    }
    if (!store) throw new Error(`${tool}'s ${control.permit_lifetime_control} control has no configured enforcing store`);
    if (control.permit_lifetime_control === "validity_window_plus_idempotency_key") {
      if (control.reservation_owner !== store.owner) {
        throw new Error(`${tool}'s reservation domain is owned by ${control.reservation_owner}, not ${store.owner}`);
      }
      if (!REVERSIBLE_WRITE_EFFECTS[tool]) throw new Error(`no reversible effect is declared for tool ${tool}`);
    } else if (control.consumed_identifier_owner !== store.owner) {
      throw new Error(
        `${tool}'s consumed-identifier domain is owned by ${control.consumed_identifier_owner}, not ${store.owner}`,
      );
    }
  }
}

/**
 * @spec runtime-evidence#execution-evidence-object `error`: deployment-
 * defined values for the refusals a keyed reversible write makes before any
 * effect: the two its effect makes before it changes anything, and
 * `actor_unkeyable`, an actor with no stable identity to scope the key on
 * (#1016 review). None is in the closed set, whose values each name a
 * narrower condition (`consumption_unavailable` is an unreachable store), so
 * each is a collision-resistant name under a namespace this deployment
 * controls (the RFC 7519 Section 4.2 guidance the member cites). The
 * caller-visible diagnostic is the short name.
 */
export const REVERSIBLE_WRITE_REFUSAL_ERRORS: Readonly<Record<string, string>> = Object.freeze({
  schedule_not_found: "https://payments.demo/execution-errors/schedule_not_found",
  schedule_exists: "https://payments.demo/execution-errors/schedule_exists",
  actor_unkeyable: "https://payments.demo/execution-errors/actor_unkeyable",
});

/**
 * The Execution Evidence `error` for a wire the ledger refused because the
 * invoice is already settled (#1270): a collision-resistant name, for the same
 * reason as the reversible-write refusals above. The caller-visible diagnostic
 * is `already_settled`.
 */
export const SETTLEMENT_REFUSAL_ERROR = "https://payments.demo/execution-errors/already_settled";

/**
 * @spec runtime#compound-actions (#252): the Execution Evidence `error` for a
 * reversal the ledger refused with no effect, by the connector's refusal: the
 * linked wire is not a committed entry, the reversal's amount, currency or
 * payee differs from the wire's record, or it is already reversed. Each is a
 * collision-resistant name for the reason {@link SETTLEMENT_REFUSAL_ERROR} is;
 * the caller-visible diagnostic is the short name.
 */
export const CONNECTOR_REFUSAL_ERRORS: Readonly<Record<NonNullable<CommitResult["refusal"]>, string>> = Object.freeze({
  already_settled: SETTLEMENT_REFUSAL_ERROR,
  wire_not_committed: "https://payments.demo/execution-errors/wire_not_committed",
  reversal_mismatch: "https://payments.demo/execution-errors/reversal_mismatch",
  already_reversed: "https://payments.demo/execution-errors/already_reversed",
});

/**
 * @spec authzen#execution-evidence-requirement (#1640, D770 ruling 4): the
 * Execution Evidence `error` for a result the PEP withheld because its
 * `completed` record could not be recorded before disclosure. Computing a
 * result discloses nothing, so the permit's final disposition is a
 * suppression, under a collision-resistant name for the same reason as the
 * refusals above. The caller-visible diagnostic is `evidence_unavailable`.
 * The transaction tier refuses under it too when its pre-effect attempt
 * record cannot be written (#821).
 */
export const EVIDENCE_UNAVAILABLE_ERROR = "https://payments.demo/execution-errors/evidence_unavailable";

/**
 * @spec runtime#evidence (pre-effect durability) (#821, D814): the classes
 * whose connector effect is released only after a durable attempt record:
 * the irreversible and external-commitment effects the transaction tier
 * commits.
 */
const PRE_EFFECT_ATTEMPT_CLASSES: ReadonlySet<string> = new Set(["irreversible_action", "external_commitment"]);

/**
 * Test-only failpoints on the keyed reversible-write path (#918): the awaited
 * reverification, where concurrent in-process attempts interleave after each
 * found the pair free; inside the one local transaction (a throw rolls the
 * effect and the reservation back together); and after its commit but before
 * the response. The unkeyed write path (#1080) honors `atReverification` alone,
 * where concurrent presentations of one single-use permit interleave after
 * admission and before its redemption. `atRetrieval` (D342) holds a retrieval
 * after its permit-use check and before it consumes a single-use permit.
 */
export interface ReversibleWriteFailpoints {
  atReverification?: () => Promise<void>;
  atRetrieval?: () => Promise<void>;
  insideTransaction?: () => void;
  afterCommit?: () => void;
}

/**
 * The dispatch path a tool call takes, shared by both MCP transports so they
 * cannot route differently. Only the `transaction-assurance` tier reaches the
 * single-use permit, lease and connector path; a consequential write (a
 * reservation, hold, draft or schedule, and its cancellation) takes the write
 * path, whatever else it is; everything else takes the read path, where the
 * PEP still refuses or denies an unknown or ungranted tool. A tier tool on a
 * server with no transaction tier takes the write path, so it reaches a
 * Decision rather than a read.
 */
export function dispatchPathFor(
  mapping: ActionMapping | undefined,
  hasTransactionTier: boolean,
): "transaction" | "write" | "read" {
  if (mapping?.tier === "transaction-assurance") return hasTransactionTier ? "transaction" : "write";
  if (mapping?.actionClass === REVERSIBLE_WRITE_CLASS) return "write";
  return "read";
}

/** A write-path verdict. `deduped` marks a retained result released to a retry under its key. */
export interface WriteToolResult {
  ok: boolean;
  result?: unknown;
  deduped?: boolean;
  denial_reason?: string;
  refusal_reason?: string;
  /** Present on a refusal of a keyed write: whether a later retry under the same key can succeed. */
  next_action?: "retry" | "none";
  insufficient_authorization?: InsufficientAuthorization;
  /**
   * @spec authzen#execution-evidence-requirement (#1640, D770 ruling 4):
   * present only when a keyed write's effect committed and its `completed`
   * Execution Evidence could not be recorded. Never a refusal: the effect
   * stands. Its result is withheld; a retry under the same key retrieves it.
   */
  gap?: DispositionGap;
  /**
   * @spec authzen#obligation-processing (#1640, D770 ruling 6): present on a
   * denial whose Decision Evidence did not verify. The authenticated decision
   * still stands, and its obligations were still performed.
   */
  evidence_gap?: DecisionEvidenceGap;
}

/**
 * Why a released effect's `completed` Execution Evidence does not exist: its
 * emission failed after one retry, or no effective parameter digest could be
 * observed for a parameter-bound permit, or no effective context digest for a
 * context-bound one (#773).
 */
export type DispositionGap = Extract<SuppressOutcome, { recorded: false }>["gap"];

export interface McpServerDeps {
  /** Trusted assembly's effective topology declaration, never a tool input. */
  enforcementScopeStatement?: RuntimePosture;
  pep: Pep;
  payments: PaymentsStore;
  loadView: (ref: MissionReference) => LoadedView | undefined;
  /** The issuer's keys as a fixed set; or give `jwksUri`, never both. */
  jwks?: { keys: Record<string, unknown>[] };
  /**
   * @spec #831 C2: the issuer's `jwks_uri`, from metadata the deployment has
   * validated. Its keys are held through `IssuerKeys` (`@mission/core`): each
   * role's pinned `kid`s only, refreshed within the freshness the issuer
   * declares, so a rotation is followed without a restart once `keyRoles`
   * lists the new `kid`. Exactly one of `jwks` and `jwksUri` is given.
   */
  jwksUri?: string;
  /** Tests: the clock and fetch the `jwksUri` key holder uses. */
  issuerKeysOptions?: { now?: () => number; fetch?: IssuerKeysFetch };
  /**
   * @spec #831 C2 (D825): the per-role algorithm policy, applied the same way
   * to a fixed set and to a `jwksUri`. A role not listed accepts whatever its
   * pinned key admits.
   */
  keyAlgorithms?: KeyAlgorithms;
  /**
   * @spec runtime-oauth#token-validation (#825, D312) — the `kid`s trusted
   * for each token class, configured locally. Access tokens and attenuation
   * roots resolve from `jwks` (or `jwksUri`), transaction tokens from
   * `txnTokenJwks` (or `txnTokenJwksUri`), each only among its own role's
   * keys. Never defaulted: a shared JWKS and distinct `typ` strings do not
   * enforce key purpose.
   */
  keyRoles: KeyRoles;
  issuer: string;
  /**
   * @spec authority-server#limitations, #high-consequence-binding (#818):
   * `issuer` is an estate authorization server that is NOT a Mission Issuer:
   * it issues ordinary OAuth tokens only. Every credential this server
   * verifies is then ordinary; one carrying a `mission` claim is refused,
   * never read as Mission-bound, so an estate token cannot pose as a
   * Mission-bound credential on any route this server serves. The published
   * metadata then omits `mission_bound_authorization_required`. Default
   * false: `issuer` is the Mission Issuer, unchanged.
   */
  ordinaryOnly?: boolean;
  /**
   * @spec authority-server#mission-join rule 8 (#818 slice 3; RFC 7662): an
   * estate route (`ordinaryOnly`) that also accepts OPAQUE access tokens,
   * validating each by introspection at `issuer` (`introspection.ts`). A
   * compact JWS still takes the JWT path. Absent: opaque tokens are refused,
   * as before.
   */
  introspection?: IntrospectionSettings;
  /** Transaction-assurance tier (M5); omit for a core-tier-only server. */
  transaction?: { engine: TransactionEngine; connectors: Connectors; evidence: EvidenceStore };
  /**
   * AROP Transaction Challenge (RS side): the AS's txn public JWKS (as-txn key)
   * and issuer, used to validate a presented txn-token. Omit to disable the
   * hybrid txn-token path.
   */
  txnTokenJwks?: { keys: Record<string, unknown>[] };
  /** @spec #831 C2: the transaction-token issuer's `jwks_uri`, held like `jwksUri`; never with `txnTokenJwks`. */
  txnTokenJwksUri?: string;
  asIssuer?: string;
  /**
   * @spec txn-authorization#two-phase-expiry (key discovery) — this resource's
   * PUBLISHED txn-challenge key material and the metadata members that point at
   * it. A Transaction Authorization Server resolves this resource's challenge
   * keys from `jwksUri` and nowhere else.
   */
  txnChallenge?: {
    /** Absolute URI published as `txn_challenge_jwks_uri`. */
    jwksUri: string;
    /** Path this server answers the JWKS on (the `jwksUri` path component). */
    jwksPath: string;
    /** Published as `txn_challenge_signing_alg_values_supported`. */
    signingAlgValuesSupported: string[];
    /** The PUBLIC half of the challenge-signing key(s). */
    jwks: { keys: Record<string, unknown>[] };
  };
  /**
   * @spec txn-authorization#offline-verification — the retained pending
   * operations and the `txn` consumption domain. Injectable so replicas that
   * can execute the same operation share ONE database (consumption must be
   * linearizable across all of them); defaulted to this replica's own
   * in-memory stores.
   */
  txnStores?: { pending: TxnPendingStore; consumption: TxnConsumptionStore };
  /**
   * @spec RFC 9449 §11.1 — the DPoP proof `jti` replay window. Injectable so a
   * deployment can share one across replicas fronted as one resource; defaulted
   * to this replica's own (D27).
   */
  dpopReplay?: DpopProofReplay;
  /**
   * @spec runtime#idempotency (#918): this PEP's reservation and retention
   * store for keyed reversible writes, a durable single-writer file named in
   * configuration. @spec runtime#single-use-identifiers (#1080): the same
   * file records the consumed identifiers of single-use permits. Never
   * defaulted, and REQUIRED (D333): the server does not start without it,
   * since every served `consequential_write` needs its control's enforcing
   * store ({@link assertPermitLifetimeCoverage}). A store that later cannot be
   * written refuses `consumption_unavailable` and executes nothing.
   */
  writeReservations?: WriteReservationStore;
  /**
   * @spec runtime-evidence#execution-evidence-object (#821): where an
   * evidence emission failure on the transaction tier is alerted, the
   * deployment's declared operator sink. Absent, the caller's `gap` is the
   * only report.
   */
  alerts?: OperatorAlertSink;
}

/**
 * The transaction-tier verdict. @spec txn-authorization#resource-challenge —
 * `error` and `transaction_challenge` are the upstream wire members, carried
 * verbatim on the tool-result surface; there is no bespoke challenge envelope
 * and no endpoint hint (the client discovers the Transaction Authorization
 * Server through `transaction_authorization_endpoint` in AS metadata).
 */
/**
 * @spec txn-authorization#offline-verification — the outcome of verifying a
 * presented transaction credential. On success the request's TokenFacts are
 * derived FROM the transaction token, so the challenged operation runs under
 * that credential alone; on failure the profile's refusal reason says which
 * check the credential failed.
 */
export type VerifiedTxnCredential =
  | { ok: true; facts: MissionBoundTokenFacts }
  | { ok: false; refusal_reason: string };

export interface TransactionToolResult {
  ok: boolean;
  result?: unknown;
  denial_reason?: string;
  refusal_reason?: string;
  deduped?: boolean;
  access_request?: EnforceResult["access_request"];
  error?: string;
  transaction_challenge?: string;
  insufficient_authorization?: InsufficientAuthorization;
  /**
   * @spec runtime-evidence#execution-evidence-object (#1104, #821): a
   * disposition record that could not be recorded after one retry. With no
   * `refusal_reason`, the connector effect committed and its `completed`
   * record is missing: `result` describes the effect that stands. Beside a
   * `refusal_reason`, nothing executed and the refusal's `suppressed` record
   * is missing. The operator is alerted either way.
   */
  gap?: "emission_failed";
  /** @spec authzen#obligation-processing (#1640, D770 ruling 6): a denial whose Decision Evidence did not verify. */
  evidence_gap?: DecisionEvidenceGap;
}

export class McpPaymentsServer {
  get capabilityCatalog() { return this.deps.pep.capabilityCatalog; }
  /** Keys pinned to the access-token role (@spec runtime-oauth#token-validation, D312). */
  private resolveAccessKey: KeyResolver;
  /** Keys pinned to the attenuation-root role. */
  private resolveRootKey: KeyResolver;
  /** Keys pinned to the transaction-token role; absent when the txn tier is off. */
  private resolveTxnKey?: KeyResolver;
  /** @spec #831 C2 (D825): the reload of a `jwksUri` server's trusted configuration, in place. */
  private readonly refreshing?: RefreshingRoleKeys;
  /** @spec txn-authorization#offline-verification — the retained pending operations. */
  private readonly txnPending: TxnPendingStore;
  /** @spec txn-authorization#offline-verification — the `txn` consumption domain. */
  private readonly txnConsumption: TxnConsumptionStore;
  /** @spec RFC 9449 §11.1 — this resource's DPoP proof `jti` replay window. */
  private readonly dpopReplay: DpopProofReplay;
  /** @spec RFC 7662 (#818 slice 3): the estate route's introspection adapter, when configured. */
  private readonly introspector?: TokenIntrospector;
  /** The snapshot path's pinned resolvers over the fixed key sets. */
  private snapshotResolvers(roles: KeyRoles, algorithms: KeyAlgorithms | undefined): Record<KeyRole, KeyResolver> {
    return roleKeyResolvers(
      roles,
      { jwks: this.deps.jwks as { keys: Record<string, unknown>[] }, txnTokenJwks: this.deps.txnTokenJwks },
      algorithms,
    );
  }

  /**
   * @spec #831 C2 (D825): reload the trusted configuration while serving:
   * the `kid`s pinned to each role, and the algorithm policy. It takes effect
   * at the next verification; a configuration that pins one `kid` to two
   * roles, or gives one key two roles, is refused and the one in force stays.
   * A `jwksUri` server replaces its trust in place; a fixed-set server
   * rebuilds its pins over the same sets.
   */
  reloadKeyRoles(roles: KeyRoles, algorithms?: KeyAlgorithms): void {
    const pinned = this.refreshing ? (this.refreshing.setRoles(roles, algorithms), this.refreshing) : this.snapshotResolvers(roles, algorithms);
    this.resolveAccessKey = pinned.accessToken;
    this.resolveRootKey = pinned.attenuationRoot;
    if (this.resolveTxnKey) this.resolveTxnKey = pinned.transactionToken;
  }

  constructor(private readonly deps: McpServerDeps) {
    if (deps.enforcementScopeStatement) deps.enforcementScopeStatement = loadRuntimePosture(deps.enforcementScopeStatement);
    if ((deps.jwks === undefined) === (deps.jwksUri === undefined)) {
      throw new Error("McpPaymentsServer: give exactly one of jwks and jwksUri");
    }
    if (deps.txnTokenJwks !== undefined && deps.txnTokenJwksUri !== undefined) {
      throw new Error("McpPaymentsServer: give txnTokenJwks or txnTokenJwksUri, not both");
    }
    if ((deps.jwksUri === undefined) !== (deps.txnTokenJwksUri === undefined) && deps.txnTokenJwks !== undefined) {
      throw new Error("McpPaymentsServer: a jwksUri server takes txnTokenJwksUri, not txnTokenJwks");
    }
    if (deps.jwksUri !== undefined) {
      this.refreshing = refreshingRoleKeyResolvers(
        deps.keyRoles,
        { jwksUri: deps.jwksUri, txnTokenJwksUri: deps.txnTokenJwksUri },
        { ...(deps.issuerKeysOptions ?? {}), ...(deps.keyAlgorithms ? { algorithms: deps.keyAlgorithms } : {}) },
      );
    }
    const pinned = this.refreshing ?? this.snapshotResolvers(deps.keyRoles, deps.keyAlgorithms);
    this.resolveAccessKey = pinned.accessToken;
    this.resolveRootKey = pinned.attenuationRoot;
    if (deps.txnTokenJwks || deps.txnTokenJwksUri) this.resolveTxnKey = pinned.transactionToken;
    const stores = deps.txnStores ?? openTxnStores();
    this.txnPending = stores.pending;
    this.txnConsumption = stores.consumption;
    this.dpopReplay = deps.dpopReplay ?? newDpopProofReplay();
    if (deps.introspection) {
      // Introspection reads an estate token's facts; only an estate route,
      // whose issuer mints no Mission-bound credential, accepts one this way.
      if (!deps.ordinaryOnly) throw new Error("introspection is configured only on an ordinaryOnly (estate) route");
      this.introspector = new TokenIntrospector(deps.introspection, deps.issuer);
    }
    assertPermitLifetimeCoverage(deps.enforcementScopeStatement ?? RUNTIME_POSTURE, deps.writeReservations);
  }

  /**
   * @spec RFC 9449 §4.3 — the ONE proof check every credential class this
   * resource accepts runs, against this replica's replay window.
   */
  private async verifyPresentation(
    accessToken: string,
    expectedJkt: string,
    pop: DpopPresentation,
  ): Promise<void> {
    await verifyDpopProof({
      proof: pop.proof,
      accessToken,
      expectedJkt,
      htu: pop.htu,
      htm: pop.htm,
      replay: this.dpopReplay,
    });
  }

  /**
   * @spec runtime-oauth#token-validation (#853, D487): the audience check
   * every credential class runs after its signature and issuer verify. The
   * PEP establishes the boundary from its declaration; `aud` (a string or an
   * array, by membership) must name it directly or through an alias the
   * declaration scopes to this verified issuer and this credential's `typ`
   * media type. `aud` never selects the boundary.
   *
   * Returns the boundary and statement version it validated against, which
   * the caller carries on the credential's facts (`validatedBoundary`): the
   * PEP decides only at that boundary and version, and refuses the request
   * when a cutover moved either before the decision.
   */
  private requireAudience(payload: JWTPayload, typ: unknown, issuer: string): ValidatedBoundary {
    const checked = this.validateAudience(payload.aud, { issuer, tokenProfile: mediaTypeOf(typ) ?? "" });
    if (!checked.ok) throw new TokenAudienceError(checked.reason);
    return { boundary: checked.boundary, version: checked.version };
  }

  /**
   * The PEP's own audience rule, over the boundary context it establishes
   * its boundary from. A server assembled with no PEP (token validation
   * alone) reads the published statement's context instead.
   */
  private validateAudience(aud: unknown, context: AudienceContext): AudienceValidation {
    return this.deps.pep ? this.deps.pep.validateAudience(aud, context) : paymentsBoundaryContext().validateAudience(aud, context);
  }

  /**
   * @spec authority-server#mission-join, mission#protected-resource-metadata
   * (#1531, D741): the RFC 9728 metadata of a MAS Join route served under its
   * own resource identifier. A join admits an ordinary credential, so the
   * route's metadata names `resource` and does not declare Mission-bound-only
   * acceptance; every other member is this resource's.
   */
  joinRouteMetadata(resource: string): Record<string, unknown> {
    const { mission_bound_authorization_required: _omitted, ...metadata } = this.protectedResourceMetadata();
    return { ...metadata, resource };
  }

  /** RFC 9728 Protected Resource Metadata. */
  protectedResourceMetadata(): Record<string, unknown> {
    const txn = this.deps.txnChallenge;
    return {
      resource: CANONICAL_RESOURCE,
      authorization_servers: [this.deps.issuer],
      bearer_methods_supported: ["dpop"],
      // @spec mission#protected-resource-metadata: an ordinary-only route
      // accepts tokens with no `mission` claim, so it does not advertise
      // Mission-bound-only acceptance (#818).
      ...(this.deps.ordinaryOnly ? {} : { mission_bound_authorization_required: true }),
      // @spec resource-access#protected-resource-metadata (#1266): exactly the
      // keys this resource enforces: against its own authoritative facts, and
      // through its PDP the action-bound approval requirement (step 8) and a
      // Discharge condition (step 5b), so a client predicts no fail-closed
      // mismatch that would not happen.
      mission_constraints_supported: [
        "max_amount",
        "vendors",
        "requires_action_approval",
        "terminal_when",
        "resource_issued_after",
        "resource_issued_before",
        "tenant",
        "time_window",
        "recipient_domain",
        "data_classification",
        "allowed_tools",
      ],
      // Deployment-local publication, not a new protocol baseline member.
      enforcement_scope_statement: this.deps.enforcementScopeStatement ?? RUNTIME_POSTURE,
      // @spec txn-authorization#two-phase-expiry — key discovery rides the
      // upstream metadata: this is where a TAS resolves this resource's
      // challenge-signing keys, and nowhere else.
      ...(txn
        ? {
            txn_challenge_jwks_uri: txn.jwksUri,
            txn_challenge_signing_alg_values_supported: txn.signingAlgValuesSupported,
          }
        : {}),
    };
  }

  /** The published txn-challenge JWKS, or undefined when none is configured. */
  txnChallengeJwks(): { keys: Record<string, unknown>[] } | undefined {
    return this.deps.txnChallenge?.jwks;
  }

  /** The path {@link txnChallengeJwks} is served on. */
  txnChallengeJwksPath(): string | undefined {
    return this.deps.txnChallenge?.jwksPath;
  }

  /**
   * @spec mission#rs-enforcement — the ONE verification step every DPoP-bound
   * credential presented over HTTP passes through, whichever class it turns
   * out to be: a transaction token refused outright, the signature, issuer
   * and audience verified against this resource's own trusted keys, `cnf.jkt`
   * required, and the request's DPoP proof bound both to that key and to this
   * token (`ath`). It returns the VERIFIED payload, so a caller that must tell
   * one credential class from another branches on verified claims and never on
   * a caught error string.
   */
  private async verifyDpopBoundToken(
    accessToken: string,
    dpopProof: string,
    htu: string,
    htm: string,
  ): Promise<{ payload: JWTPayload; typ: unknown; cnfJkt: string; validated: ValidatedBoundary }> {
    refuseTransactionToken(accessToken);
    const { payload, protectedHeader } = await jwtVerify(accessToken, this.resolveAccessKey, {
      issuer: this.deps.issuer,
    });
    const validated = this.requireAudience(payload, protectedHeader.typ, this.deps.issuer);
    const cnf = payload.cnf as { jkt?: string } | undefined;
    if (!cnf?.jkt) throw new Error("token missing cnf.jkt");
    // Verify the DPoP proof and bind it to the token's cnf.jkt AND to the token
    // itself (`ath`), under the same verifier the transaction path uses.
    await this.verifyPresentation(accessToken, cnf.jkt, { proof: dpopProof, htu, htm });
    return { payload, typ: protectedHeader.typ, cnfJkt: cnf.jkt, validated };
  }

  /**
   * The Mission-bound facts of an already signature-verified payload, under
   * the ordinary Mission access-token profile (@spec runtime-oauth#token-
   * validation, #825): `typ` `at+jwt`, the RFC 9068 claim set with types, the
   * `mission` claim and the credential's own `authorization_details`. A claim
   * that is missing or not the profiled shape THROWS here: it is a refusal,
   * never a credential silently demoted to the ordinary class. A proof of
   * possession is not part of this: each transport verifies its own.
   */
  private missionBoundFactsFrom(payload: JWTPayload, typ: unknown, validated: ValidatedBoundary): MissionBoundTokenFacts {
    // @spec authority-server#limitations (#818), mission#rs-requirements item
    // 6 (#1503): an estate issuer that is not a Mission Issuer mints no
    // Mission-bound credential, so a `mission` claim under it is refused
    // rather than trusted: trusting its ordinary tokens is not enough.
    if (this.deps.ordinaryOnly) throw new Error("this route's issuer is not a Mission Issuer");
    // @spec cross-domain#mission-subject — readTxnMissionClaim (inside the
    // profile) validates the REQUIRED invariants and, when present, the
    // closed {iss, sub} shape of the origin principal; a present-but-malformed
    // `subject` is a refusal here, not a silently dropped member.
    const claims = readMissionAccessClaims(typ, payload, Math.floor(Date.now() / 1000));
    const mission = claims.mission;
    // @spec mission#rs-requirements item 6 (#1503): this resource adopts no
    // cross-domain profile, so the Mission's issuer is the verified `iss`.
    // A mismatch is refused here, before any Mission lookup or decision.
    if (mission.issuer !== payload.iss) throw new Error("token iss != mission.issuer");
    return {
      sub: claims.sub,
      clientId: claims.clientId,
      // @spec authzen#pdp-request rule 10 — this resource's own verified
      // issuer, never the mission's origin issuer.
      iss: this.deps.issuer,
      credential: verifiedCredentialRef(payload),
      ...(payload.act ? { act: payload.act as ActObject } : {}),
      mission: {
        id: mission.id,
        issuer: mission.issuer,
        // @spec mission#the-mission-claim (#702) — NOT on the baseline claim;
        // carried only when the source token's own profile added it.
        ...(mission.authority_hash !== undefined ? { authority_hash: mission.authority_hash } : {}),
        ...(mission.subject ? { subject: mission.subject } : {}),
      },
      missionClaim: mission,
      cnfJkt: claims.cnfJkt,
      // @spec runtime#input-authority (#825) — the credential's own authority,
      // evaluated as its own bound and never replaced by the Mission's.
      credentialAuthority: claims.credentialAuthority,
      jti: claims.jti,
      ...(payload.identity_continuation_handle
        ? { identityContinuationHandle: payload.identity_continuation_handle as string }
        : {}),
      validatedBoundary: validated,
    };
  }

  /**
   * @spec authority-server#mission-join (#557) — the ordinary facts of an
   * already-verified payload carrying NO `mission` claim. `scope` is carried
   * verbatim: it is rule 8 bound 1's input, the authority the acting
   * credential holds as issued.
   */
  private ordinaryFactsFrom(payload: JWTPayload, cnfJkt: string, validated: ValidatedBoundary): OrdinaryTokenFacts {
    return {
      sub: payload.sub as string,
      clientId: payload.client_id as string,
      // @spec authzen#pdp-request rule 10 — this resource's own verified
      // issuer, never a claim on the (nonexistent) mission.
      iss: this.deps.issuer,
      credential: verifiedCredentialRef(payload),
      ...(payload.act ? { act: payload.act as ActObject } : {}),
      cnfJkt,
      ...(typeof payload.scope === "string" ? { scope: payload.scope } : {}),
      ...(payload.jti ? { jti: payload.jti as string } : {}),
      validatedBoundary: validated,
    };
  }

  /**
   * Validate a DPoP-bound access token, returning TokenFacts.
   * @spec mission#rs-enforcement: enforce from the token (cnf, mission claim).
   */
  async validateToken(accessToken: string, dpopProof: string, htu: string, htm: string): Promise<MissionBoundTokenFacts> {
    const { payload, typ, validated } = await this.verifyDpopBoundToken(accessToken, dpopProof, htu, htm);
    return this.missionBoundFactsFrom(payload, typ, validated);
  }

  /**
   * @spec authority-server#mission-join (#557) — validates an ORDINARY DPoP-
   * bound OAuth credential (issuer, audience, `cnf.jkt`, DPoP proof: all the
   * SAME checks {@link validateToken} performs) that carries NO `mission`
   * claim at all. Returns `TokenFacts` with `mission` absent, `sub`/
   * `clientId` from the credential's own authenticated claims. This method
   * assumes its caller already knows the credential's class; a gateway route
   * that must decide the class from the credential itself calls
   * {@link validateGatewayCredential}, which verifies once and branches on
   * the verified `mission` claim. {@link validateToken} itself is UNCHANGED and
   * still rejects a no-claim token outright, so an existing Mission-bound
   * route configured to call it keeps doing exactly that. `Pep.enforce`
   * separately refuses `unknown_mission` when `PepDeps.masJoin` is not
   * configured, so a gateway calling this method without ALSO configuring
   * the PEP for the baseline Join gets a working validator with no usable
   * permit, never a silently unbounded one.
   *
   * Not wired for the MCP-mediated transport ({@link validateMissionToken})
   * or {@link validateCredential}: a documented remainder, not a silent gap
   * -- those stay Mission-bound-only.
   */
  async validateOrdinaryToken(accessToken: string, dpopProof: string, htu: string, htm: string): Promise<OrdinaryTokenFacts> {
    const { payload, cnfJkt, validated } = await this.verifyDpopBoundToken(accessToken, dpopProof, htu, htm);
    return this.ordinaryFactsFrom(payload, cnfJkt, validated);
  }

  /**
   * @spec authority-server#mission-join (#557) — the credential validator a
   * GATEWAY route uses: it verifies the presented credential exactly once
   * ({@link verifyDpopBoundToken}) and then branches on the VERIFIED payload's
   * `mission` claim presence. Branching on a verified claim is what keeps the
   * two classes apart honestly: a caught error string from a Mission-bound
   * validator would also match a bad signature, an expired token, or a failed
   * proof, so a route that fell back on one would admit as ordinary exactly
   * the credentials it must refuse.
   *
   * `admitsOrdinary` is the route's own configuration. False (a Mission-bound
   * route): a credential with no `mission` claim is refused here, the same
   * outcome {@link validateToken} produces. True (a MAS-governed route): it is
   * returned as {@link OrdinaryTokenFacts} for the baseline Join, which the
   * PEP still gates on its own `PepDeps.masJoin` configuration.
   *
   * A `mission` claim that is present but not the profiled shape is a refusal
   * on either setting: presence decides the class, and the class then verifies
   * strictly, so stripping or corrupting a claim never downgrades a
   * Mission-bound credential into a joinable ordinary one.
   */
  async validateGatewayCredential(
    accessToken: string,
    pop: DpopPresentation,
    admitsOrdinary: boolean,
  ): Promise<TokenFacts> {
    // @spec authority-server#mission-join (#818 slice 3; RFC 7662): on an
    // estate route that introspects, an opaque token's facts come from the
    // estate's introspection response instead of a verified signature.
    if (this.introspector && admitsOrdinary && !isCompactJws(accessToken)) {
      return this.introspectedFactsFrom(this.introspector, accessToken, pop);
    }
    const { payload, typ, cnfJkt, validated } = await this.verifyDpopBoundToken(accessToken, pop.proof, pop.htu, pop.htm);
    if (payload.mission !== undefined) return this.missionBoundFactsFrom(payload, typ, validated);
    if (!admitsOrdinary) throw new Error("token missing mission claim");
    // @spec authority-server#mapping-contract (#818): an estate route accepts
    // exactly one credential format, an RFC 9068 JWT access token. Anything
    // else is refused here rather than read on a best-effort basis.
    if (this.deps.ordinaryOnly) assertEstateAccessToken(typ, payload);
    return this.ordinaryFactsFrom(payload, cnfJkt, validated);
  }

  /**
   * @spec authority-server#mission-join rule 8 (#818 slice 3; RFC 7662): the
   * ordinary facts of an opaque estate token, from its introspection: the same
   * audience rule as a JWT (`aud` must name this boundary), the request's DPoP
   * proof bound to the introspected `cnf.jkt` and to this token (`ath`), and
   * the facts built exactly as the JWT path builds them, qualified by this
   * route's own issuer (the estate), never by a value the response supplies.
   */
  private async introspectedFactsFrom(
    introspector: TokenIntrospector,
    accessToken: string,
    pop: DpopPresentation,
  ): Promise<OrdinaryTokenFacts> {
    const introspected = await introspector.introspect(accessToken);
    const payload: JWTPayload = {
      iss: this.deps.issuer,
      sub: introspected.sub,
      client_id: introspected.clientId,
      aud: introspected.aud,
      exp: introspected.exp,
      ...(introspected.scope !== undefined ? { scope: introspected.scope } : {}),
    };
    const validated = this.requireAudience(payload, INTROSPECTED_TOKEN_PROFILE, this.deps.issuer);
    await this.verifyPresentation(accessToken, introspected.cnfJkt, pop);
    // Admission re-reads the clock after its awaits: a token that expired
    // while it was being introspected or its proof checked is refused here,
    // not only at the PDP's own credential-expiry check (#1400 review).
    if (introspected.exp * 1000 <= introspector.clock().getTime()) {
      throw new TokenInactiveError("expired while being admitted");
    }
    return this.ordinaryFactsFrom(payload, introspected.cnfJkt, validated);
  }

  /**
   * Increment-1 mediated-channel credential validation: a documented
   * simplification of {@link validateToken}. Over the in-process MCP transport
   * there is no HTTP request to bind a DPoP proof to (no htu/htm), so this
   * validates the mission access token's signature (jwks), issuer, audience and
   * mission claim and carries the token's `cnf.jkt` into TokenFacts. Live DPoP
   * proof-of-possession over MCP is out of scope for increment 1. The credential
   * still crosses IN the MCP request (in `_meta`) and TokenFacts is derived from
   * a validated token here, never passed through untouched.
   * @spec draft-mcguinness-mission-harness (mediated execution environment)
   */
  async validateMissionToken(accessToken: string): Promise<MissionBoundTokenFacts> {
    refuseTransactionToken(accessToken);
    const { payload, protectedHeader } = await jwtVerify(accessToken, this.resolveAccessKey, {
      issuer: this.deps.issuer,
    });
    const validated = this.requireAudience(payload, protectedHeader.typ, this.deps.issuer);
    // The same claim profile as the HTTP path; no proof is claimed, because
    // this transport delivers none (the documented limitation above).
    const facts = this.missionBoundFactsFrom(payload, protectedHeader.typ, validated);
    return {
      ...facts,
      ...(payload.client_instance_id ? { clientInstanceId: payload.client_instance_id as string } : {}),
    };
  }

  /**
   * @spec txn-authorization#transaction-token, #offline-verification — the
   * SINGLE OAuth credential a request presents, resolved to TokenFacts.
   *
   * The protected-header `typ` is read BEFORE anything else and decides which
   * class of credential this is: `mission-txn-token+jwt` is the retry of a
   * challenged operation and takes the transaction-credential path below;
   * everything else takes the ordinary path, which still refuses a transaction
   * token outright. There is no second credential and no side channel: a
   * transaction token authorizes the operation this resource challenged for and
   * is never accepted as a general Mission-bound access token.
   *
   * `pop` carries the request's DPoP proof where the transport has an HTTP
   * request to bind one to; the in-process mediated channel omits it, exactly
   * as {@link validateMissionToken} documents for the ordinary class.
   */
  async validateCredential(accessToken: string, pop?: DpopPresentation): Promise<TokenFacts> {
    if (decodeProtectedHeader(accessToken).typ === MISSION_TXN_TOKEN_TYP) {
      const verified = await this.verifyTransactionCredential(accessToken, pop);
      if (!verified.ok) throw new Error(`transaction credential refused: ${verified.refusal_reason}`);
      return verified.facts;
    }
    return pop
      ? this.validateToken(accessToken, pop.proof, pop.htu, pop.htm)
      : this.validateMissionToken(accessToken);
  }

  /**
   * @spec txn-authorization#offline-verification — verify a presented
   * transaction credential locally, in the order the profile fixes:
   *
   *  1. exact `typ`, trusted issuer and signature, intended `aud` (a singleton,
   *     this resource), and the REQUIRED typed claims. An unknown `typ` -- an
   *     ordinary Mission-bound access token, or any other JWT -- never reaches
   *     here (the caller branches on `typ`) and is rejected outright by the
   *     verifier besides;
   *  2. `cnf` proof by the CURRENT presenter, under the same DPoP discipline
   *     the ordinary credential path uses;
   *  3. equality of the `mission` invariants, the operation
   *     `authorization_details`, `cnf`, the subject and `parameter_digest` with
   *     the pending operation this resource RETAINED when it challenged --
   *     never with the token's own account of the operation.
   *
   * The operation-scoped half of step 3 (the action this credential is good
   * for, and the digest RECOMPUTED from the request's own parameters) needs the
   * tool and arguments, so it runs at the call site
   * ({@link verifyChallengedOperation}); step 5 (current local policy,
   * entitlement and Mission state) is the PEP/PDP path the caller runs next,
   * and step 6 (atomic first use) is taken at the commit point.
   */
  async verifyTransactionCredential(
    txnToken: string,
    pop?: DpopPresentation,
  ): Promise<VerifiedTxnCredential> {
    if (!this.resolveTxnKey || !this.deps.asIssuer) return { ok: false, refusal_reason: "txn_not_configured" };
    // @spec txn-authorization#offline-verification step 2 — proof of possession
    // is not optional for a transaction credential. It authorizes an
    // irreversible operation under a key the challenge committed to; accepting
    // it without a proof would make it a BEARER token for that operation. A
    // transport with no request to bind a proof to therefore cannot carry one
    // at all -- it is refused here rather than admitted unproven.
    if (!pop) return { ok: false, refusal_reason: "txn_pop_required" };
    let payload: Record<string, unknown>;
    try {
      // The TAS's token-signing key is trusted through pre-established
      // federation metadata (this JWKS), never through the request.
      ({ payload } = (await jwtVerify(txnToken, this.resolveTxnKey, {
        issuer: this.deps.asIssuer,
        typ: MISSION_TXN_TOKEN_TYP,
      })) as { payload: Record<string, unknown> });
    } catch {
      return { ok: false, refusal_reason: "txn_invalid" };
    }
    // `aud` names this resource's enforcement boundary (@spec
    // runtime-oauth#boundary-audience, #853, D487), and is a SINGLETON: a
    // list is not this profile, which keeps its rule, stricter than the
    // access token's membership rule.
    const audience = this.validateAudience(payload.aud, { issuer: this.deps.asIssuer, tokenProfile: MISSION_TXN_TOKEN_TYP });
    if (!audience.ok) return { ok: false, refusal_reason: "txn_invalid" };
    const cnf = payload.cnf as { jkt?: string } | undefined;
    if (
      typeof payload.aud !== "string" ||
      typeof payload.jti !== "string" ||
      typeof payload.iat !== "number" ||
      typeof payload.exp !== "number" ||
      typeof payload.sub !== "string" ||
      typeof payload.client_id !== "string" ||
      typeof payload.txn !== "string" ||
      typeof payload.parameter_digest !== "string" ||
      typeof cnf?.jkt !== "string"
    ) {
      return { ok: false, refusal_reason: "txn_invalid" };
    }
    const mission = readTxnMissionClaim(payload.mission);
    if (!mission) return { ok: false, refusal_reason: "txn_invalid" };

    // 2. Proof by the CURRENT presenter: this request's proof, under the key
    //    the credential itself is bound to and naming THIS credential (`ath`).
    try {
      await this.verifyPresentation(txnToken, cnf.jkt, pop);
    } catch (e) {
      // @spec runtime-evidence#pre-decision-refusal, #1173 (D375): replay state
      // at capacity is a transient refusal, not a proof verdict.
      if (e instanceof DpopReplayUnavailableError) return { ok: false, refusal_reason: "state_unavailable" };
      return { ok: false, refusal_reason: "txn_cnf_mismatch" };
    }

    // 3. Against the RETAINED pending operation.
    const pending = this.txnPending.get(CANONICAL_RESOURCE, payload.txn);
    if (!pending) return { ok: false, refusal_reason: "txn_unknown" };
    if (pending.cnfJkt !== cnf.jkt) return { ok: false, refusal_reason: "txn_cnf_mismatch" };
    if (!missionInvariantsEqual(payload.mission, pending.mission)) {
      return { ok: false, refusal_reason: "txn_mission_mismatch" };
    }
    if (!authorizationDetailsEqual(payload.authorization_details, pending.authorizationDetails)) {
      return { ok: false, refusal_reason: "txn_authority_mismatch" };
    }
    // @spec runtime#input-authority (#825) — the operation entry this
    // credential carries is its own authority bound.
    let credentialAuthority: readonly CredentialAuthorityEntry[];
    try {
      credentialAuthority = parseCredentialAuthority(payload.authorization_details);
    } catch {
      return { ok: false, refusal_reason: "txn_invalid" };
    }
    if (payload.parameter_digest !== pending.parameterDigest) {
      return { ok: false, refusal_reason: "txn_parameter_mismatch" };
    }
    // The verified effective subject the challenge was issued for; the origin
    // principal where the Origin Principal profile applies.
    if (payload.sub !== pending.subject) return { ok: false, refusal_reason: "txn_subject_mismatch" };

    // The request runs under THESE claims: subject, client, Mission, actor and
    // presenter key all come from the verified transaction token, so an
    // approval obtained for one Mission cannot carry an operation on another.
    const txn: TxnCredential = {
      txn: payload.txn,
      jti: payload.jti,
      iatS: payload.iat,
      expS: payload.exp,
      parameterDigest: payload.parameter_digest,
    };
    return {
      ok: true,
      facts: {
        sub: payload.sub,
        clientId: payload.client_id,
        // @spec authzen#pdp-request rule 10 — this resource's own verified
        // issuer: the subject the challenge was opened for is a principal in
        // ITS namespace regardless of which credential class retrieved it.
        iss: this.deps.issuer,
        credential: verifiedCredentialRef(payload),
        ...(payload.act ? { act: payload.act as ActObject } : {}),
        mission: {
          id: mission.id,
          issuer: mission.issuer,
          // @spec mission#the-mission-claim (#702) — NOT on the baseline
          // claim; carried only when the source token's own profile added it.
          ...(mission.authority_hash !== undefined ? { authority_hash: mission.authority_hash } : {}),
          ...(mission.subject ? { subject: mission.subject } : {}),
        },
        missionClaim: mission,
        cnfJkt: cnf.jkt,
        credentialAuthority,
        jti: payload.jti,
        txn,
        validatedBoundary: { boundary: audience.boundary, version: audience.version },
      },
    };
  }

  /**
   * @spec attenuation#mission-binding-check, AAT -02 Sections 7 and 8 (#1756
   * slice B3, D882, D902)
   *
   * Validate the attenuation presentation a `tools/call` carries and derive
   * TokenFacts whose credential authority is the LEAF's tools and
   * `mission_constraints`. The transport calls this with the invocation's
   * original arguments text, before the call reaches the intake seam
   * ({@link Pep.intake}), which checks that the text describes exactly the
   * arguments dispatched.
   *
   * 1. The substrate's verification (`verifyAatPresentation`): the chain,
   *    the proof of possession under the leaf's `cnf.jwk`, the invoked tool
   *    identifier (`aat_tool`, the operation's target and action) and its
   *    arguments as written (`hta`), and the presentation audience. The trust
   *    anchor is the key that verifies the root among this resource's keys
   *    pinned to the attenuation-root role, bound to the Authorization
   *    Server's issuer. The audiences are this enforcement boundary and its
   *    aliases. A tool with side effects tracks the proof's `jti`, through
   *    the DPoP replay cache's atomic admit; a full cache refuses retryably.
   * 2. The Mission layer (`verifyMissionAatChain`): the root's `mission`,
   *    with `iss` equal to `mission.issuer` and to the anchor's issuer, the
   *    same `mission` on every token, per-hop `aud` nesting, and
   *    `mission_constraints` on every token, exactly one value per tool,
   *    narrowed per hop, no key this resource does not understand.
   *
   * A substrate PERMIT alone never authorizes: the leaf's authority becomes
   * the credential bound the PEP enforces against the facts it establishes,
   * the leaf's `resource_contract` included, on the existing enforce path.
   * `sub` and `client_id` are the issuer-signed root's; a derived token's
   * identity claims carry no authority (AAT -02 Section 3.3, #1758).
   *
   * The kill switch (Mission `active` on every presentation) is NOT checked
   * here: it is the existing PEP->PDP state gate on the per-action enforce()
   * path (the returned TokenFacts drives that path), which fails closed on
   * non-active or unestablished Mission state.
   *
   * Throws {@link AatPresentationRefused}, or {@link DpopReplayUnavailableError}
   * when the replay state is at capacity. A refusal after the substrate
   * PERMIT is recorded ({@link Pep.refusePresentation}).
   */
  async validateAatPresentation(
    presentation: AatPresentation,
    tool: string,
    argumentsJson: string,
  ): Promise<MissionBoundTokenFacts> {
    // @spec mission#rs-requirements item 6 (#1503): a root carries a `mission`
    // claim, which an estate route's issuer is not trusted to issue.
    if (this.deps.ordinaryOnly) throw new AatPresentationRefused("this route's issuer is not a Mission Issuer");
    const mapping = this.deps.pep?.toolAction(tool) ?? TOOL_ACTIONS[tool];
    if (mapping === undefined) throw new AatPresentationRefused(`no operation ${JSON.stringify(tool)}`);
    const original = parseOriginalArguments(argumentsJson);
    if (original === undefined) throw new AatPresentationRefused("the invocation arguments are not a JSON object");
    // @spec attenuation#root-mapping: the tool identifier is the operation's
    // target, as its contract establishes it, and its action.
    const target = establishOperationTarget(mapping.target, aatToPlainJson(original) as Record<string, unknown>);
    if (!target.ok) throw new AatPresentationRefused("the operation target cannot be established");
    const toolId = aatToolId(target.target, mapping.action);

    // The trust anchor: the attenuation-root-role key that verifies the root,
    // through the same pinned resolver (role, `kid` and algorithm policy) the
    // other credential classes use.
    let anchorJwk: Record<string, unknown>;
    try {
      const { key } = await jwtVerify(presentation.aat_chain[0] as string, this.resolveRootKey, {
        issuer: this.deps.issuer,
        typ: AAT_TYP,
        algorithms: [...AAT_ALGORITHMS],
      });
      anchorJwk = (await exportJWK(key)) as Record<string, unknown>;
    } catch {
      throw new AatPresentationRefused("the root does not verify under this resource's attenuation-root keys");
    }

    const nowS = Math.floor(Date.now() / 1000);
    const sideEffecting = mapping.actionClass !== "consequential_read";
    const permit = verifyAatPresentation({
      chain: presentation.aat_chain,
      pop: presentation.aat_pop,
      tool: toolId,
      argsJson: argumentsJson,
      trustAnchors: [{ issuer: this.deps.issuer, jwk: anchorJwk }],
      now: nowS,
      policy: {
        audiences: this.presentedAudiences(presentation),
        requireChainAud: true,
        replay: { trackJti: sideEffecting, admit: (jti) => this.admitPopJti(jti) },
      },
    });
    if (permit.verdict === "DENY") throw new AatPresentationRefused(`AAT -02 step ${permit.step}: ${permit.reason}`);

    // The Mission layer, over the chain the substrate verified.
    const rootClaims = permit.root.claims;
    const claimed = {
      ...(typeof rootClaims.sub === "string" ? { sub: rootClaims.sub, iss: this.deps.issuer } : {}),
      ...(typeof (rootClaims.mission as { id?: unknown } | undefined)?.id === "string"
        ? { missionId: (rootClaims.mission as { id: string }).id }
        : {}),
    };
    const refuse = async (reason: "invalid_credential" | "mission_claim_missing", why: string): Promise<never> => {
      await this.deps.pep?.refusePresentation(tool, reason, claimed);
      throw new AatPresentationRefused(why);
    };
    if (!Object.hasOwn(rootClaims, "mission")) {
      return refuse("mission_claim_missing", "the root carries no mission claim");
    }
    let root: ReturnType<typeof readAttenuationRootClaims>;
    let missionLayer: MissionAatChain;
    let validated: ValidatedBoundary;
    try {
      root = readAttenuationRootClaims(permit.root.header.typ, rootClaims as JWTPayload, nowS);
      missionLayer = verifyMissionAatChain(permit.chain, permit.anchorIssuer);
      // @spec runtime-oauth#token-validation (#853, D487): the boundary the
      // root was validated against, which the PEP decides at.
      validated = this.requireAudience(rootClaims as JWTPayload, permit.root.header.typ, this.deps.issuer);
    } catch (e) {
      return refuse("invalid_credential", (e as Error).message);
    }

    // @spec cross-domain#mission-subject — the root's origin principal,
    // where the profile applies, carried unchanged into TokenFacts the same
    // way as the other credential classes.
    const missionClaim = readTxnMissionClaim(rootClaims.mission);
    return {
      // @spec attenuation#mission-binding-check, AAT -02 Section 3.3 (#1758):
      // the subject is the issuer-signed root's, which the root profile
      // requires. A child's `sub` is whatever its holder wrote and carries no
      // authority, so it never becomes the decision, idempotency or recorded
      // subject.
      sub: root.sub,
      clientId: root.clientId,
      iss: this.deps.issuer,
      credential: verifiedCredentialRef(permit.leaf.claims as JWTPayload),
      mission: {
        ...missionLayer.mission,
        ...(missionClaim?.subject ? { subject: missionClaim.subject } : {}),
      },
      ...(missionClaim ? { missionClaim } : {}),
      // The sender constraint is the leaf's key: its RFC 7638 thumbprint.
      cnfJkt: aatKeyThumbprint((permit.leaf.claims.cnf as { jwk: Record<string, unknown> }).jwk),
      credentialAuthority: missionLayer.credentialAuthority,
      validatedBoundary: validated,
    };
  }

  /**
   * @spec AAT -02 Section 8 steps 6c and 7d, runtime-oauth#token-validation
   * (#853, D487): the audience identifiers this enforcement point accepts
   * from a presentation, as exact strings: each value the presentation's
   * tokens and proof name that this boundary's audience rule accepts for the
   * Authorization Server's `aat+jwt` tokens (the boundary or a declared
   * alias). A value it does not accept is left out, so a token naming only
   * another resource is refused by the substrate.
   */
  private presentedAudiences(presentation: AatPresentation): string[] {
    const named = new Set<string>();
    for (const token of [...presentation.aat_chain, presentation.aat_pop]) {
      let claims: JWTPayload;
      try {
        claims = decodeJwt(token);
      } catch {
        continue;
      }
      const values = [claims.aud, (claims as { aat_aud?: unknown }).aat_aud].flat();
      for (const v of values) if (typeof v === "string") named.add(v);
    }
    return [...named].filter(
      (v) => this.validateAudience(v, { issuer: this.deps.issuer, tokenProfile: AAT_TYP }).ok,
    );
  }

  /**
   * @spec AAT -02 Section 7.3 and step 7i: the proof `jti` check-and-record,
   * on this replica's DPoP replay cache (its own namespace there, so a PoP
   * and a DPoP proof never collide). A cache at its bound refuses retryably,
   * as a DPoP proof's does.
   */
  private admitPopJti(jti: string): boolean {
    const admission = this.dpopReplay.admit(`aat-pop:${jti}`);
    if (admission.admitted) return true;
    if (admission.reason === "full") throw new DpopReplayUnavailableError(admission.retryAfterS);
    return false;
  }

  /** Whether the transaction-assurance tier (M5) is configured on this server. */
  hasTransactionTier(): boolean {
    return this.deps.transaction !== undefined;
  }

  /**
   * Mission-scoped tools/list (@spec least exposure, D22/E): only tools whose
   * action is within the mission's authority are shown.
   */
  toolsList(token: TokenFacts): ToolDef[] {
    // @spec authority-server#mission-join (#557): the baseline-Join gateway
    // path is not wired into least-exposure tool listing (a documented
    // remainder); an ordinary credential with no `mission` claim sees no
    // tools here rather than the full unfiltered set.
    if (!token.mission) return [];
    const loaded = loadCheckedView(this.deps.loadView, { id: token.mission.id, issuer: token.mission.issuer });
    if (!loaded) return [];
    const granted = new Set(loaded.view.authority_set.flatMap((e) => e.actions));
    // Several tools can share one action identifier (@spec
    // runtime#compound-actions), so every crossing of a granted action is
    // listed: least exposure is per ACTION, and hiding one phase of a granted
    // compound action would hide a crossing the Mission is authorized for.
    return TOOLS.filter((t) => granted.has(t.action));
  }

  /**
   * Read-only tool call: enforce then execute. For a `bindsVendorScope`
   * read (list_invoices), `beforeReverify` is a test hook to mutate Mission
   * state in the decision->execute window, mirroring {@link callWriteTool}'s
   * hook of the same name for the write path's TOCTOU reverification.
   */
  async callReadTool(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
    beforeReverify?: () => void,
    signals?: RequestSignals,
  ): Promise<{
    ok: boolean;
    result?: unknown;
    denial_reason?: string;
    refusal_reason?: string;
    insufficient_authorization?: InsufficientAuthorization;
    evidence_gap?: DecisionEvidenceGap;
  }> {
    if (token.txn) return { ok: false, refusal_reason: "txn_action_mismatch" };
    // @spec runtime#idempotency (#918): a keyed reversible write's effect is
    // reachable only through its reservation, so a caller that sends one down
    // the read path is served by the write path, never by an unreserved effect.
    // @spec runtime#single-use-identifiers (#1080): so is every other
    // reversible write, whose single-use permit only the write path redeems.
    // The write path runs its own intake.
    if (this.deps.pep.toolAction(tool)?.actionClass === REVERSIBLE_WRITE_CLASS) {
      return this.callWriteTool(tool, args, token, beforeReverify, signals);
    }
    // @spec operation-profile-payments-v1 intake (D316): every later step,
    // execution included, uses the normalized arguments.
    const intake = await this.deps.pep.intake(tool, args, token, signals?.invocation);
    if (!intake.ok) return { ok: false, refusal_reason: intake.refusal_reason };
    args = intake.args;
    const res = await this.deps.pep.enforce(tool, args, token, undefined, signals);
    if (!res.permitted) {
      return {
        ok: false,
        ...(res.denial_reason ? { denial_reason: res.denial_reason } : {}),
        ...(res.refusal_reason ? { refusal_reason: res.refusal_reason } : {}),
        ...(res.insufficient_authorization ? { insufficient_authorization: res.insufficient_authorization } : {}),
        ...(res.evidence_gap ? { evidence_gap: res.evidence_gap } : {}),
      };
    }
    // @spec runtime-evidence#execution-evidence-object (#786): the permit's
    // own disposition context, built by the PEP after its Decision Evidence
    // was retained. Absent on a permit is unreachable; fail closed.
    const attempt = res.attempt;
    if (!attempt) return { ok: false, refusal_reason: "state_unavailable" };
    // @spec runtime#compound-actions — admission: the phase MUST be compared
    // at every crossing, not only at one that reaches a connector. A read
    // crossing releases no external effect and still refuses a permit bound
    // to another phase, and it refuses an expired permit before it reads
    // anything.
    const admitted = await this.deps.pep.verifyPermitAtUse(attempt);
    if (!admitted.ok) return { ok: false, refusal_reason: admitted.error };
    beforeReverify?.();
    const capability = await this.deps.pep.reverifyCapability(
      res.capabilitySnapshot,
      token,
      this.deps.pep.toolAction(tool)?.action ?? tool,
      attempt,
    );
    if (!capability.ok) return { ok: false, refusal_reason: capability.error };
    let listDigest: string | undefined;
    if (res.listEffective) {
      // @spec runtime#read-binding: reverify the bound list read's
      // normalized parameters immediately before execution, exactly as
      // callWriteTool/callTransactionTool already do for a write.
      const digest = permitConditions(res.decision)?.parameter_digest as string | undefined;
      if (!digest) {
        // A bound read whose permit carries no digest condition binds
        // nothing, so the PEP cannot confirm the parameters it is about to
        // use are the ones authorized: the same parameter-binding failure,
        // refused rather than executed on an unbound scope.
        await this.deps.pep.suppressExecution(attempt, "parameter_mismatch");
        return { ok: false, refusal_reason: "parameter_mismatch" };
      }
      const bound = await this.deps.pep.reverifyList(res.listEffective, digest, token, attempt);
      if (!bound.ok) return { ok: false, refusal_reason: bound.error };
      listDigest = bound.effectiveParameterDigest;
    }
    // The whole seam again after the awaited capability and parameter reads,
    // immediately before release: the permit can expire and the Operation
    // Profile can stop placing this crossing while one of them is pending, so
    // the admission call above is not the last word on either.
    const live = await this.deps.pep.verifyPermitAtUse(attempt);
    if (!live.ok) return { ok: false, refusal_reason: live.error };
    const result = this.execute(tool, args, res.list_vendor_scope, res.listEffective?.members?.map((m) => m.id));
    // @spec authzen#execution-evidence-requirement (#1640, D744 ruling 2): the
    // read's completed disposition, recorded before its result is returned.
    const recorded = await this.deps.pep.completeExecution(
      attempt,
      listDigest !== undefined ? { effectiveParameterDigest: listDigest } : {},
    );
    if (!recorded.recorded) return this.withholdUnevidenced(attempt);
    return { ok: true, result };
  }

  /**
   * @spec authzen#execution-evidence-requirement (#1640, D770 ruling 4): a
   * result whose `completed` record could not be recorded is never returned.
   * Computing it disclosed nothing, so the permit's final disposition is a
   * suppression, recorded where the evidence path still accepts one, and the
   * caller receives no protected data. Only an effect that already committed
   * (a keyed write's local transaction, the transaction tier's connector) is
   * reported as a gap instead, and even then without its result.
   */
  private async withholdUnevidenced(attempt: ExecutionAttempt): Promise<{ ok: false; refusal_reason: string }> {
    await this.deps.pep.suppressExecution(attempt, EVIDENCE_UNAVAILABLE_ERROR);
    return { ok: false, refusal_reason: "evidence_unavailable" };
  }

  /** @spec runtime#idempotency (#918): the Operation Profile keys this tool as a reversible write. */
  private isKeyedReversibleWrite(tool: string): boolean {
    const mapping = this.deps.pep.toolAction(tool);
    return mapping?.idempotencyKey === true && mapping.actionClass === REVERSIBLE_WRITE_CLASS;
  }

  /**
   * Write tool call, two-phase for TOCTOU (@spec operation-profile): enforce
   * (decision) -> reverify effective params against fresh store state -> execute.
   * `beforeReverify` is a test hook to mutate state in the decision->execute window.
   *
   * @spec runtime#idempotency (#918): a keyed reversible write adds two steps
   * after the Decision, kept apart: retrieval of a retained result
   * ({@link releaseRetained}), authorized by THIS attempt's own permit and never
   * by the permit the result was first produced under, then admission and the
   * effect ({@link admitReversibleWrite}). `failpoints` are test-only.
   */
  async callWriteTool(
    tool: string,
    args: Record<string, unknown>,
    token: TokenFacts,
    beforeReverify?: () => void,
    signals?: RequestSignals,
    failpoints?: ReversibleWriteFailpoints,
  ): Promise<WriteToolResult> {
    if (token.txn) return { ok: false, refusal_reason: "txn_action_mismatch" };
    // @spec operation-profile-payments-v1 intake (D316), as in callReadTool.
    const intake = await this.deps.pep.intake(tool, args, token, signals?.invocation);
    if (!intake.ok) return { ok: false, refusal_reason: intake.refusal_reason };
    args = intake.args;
    const res = await this.deps.pep.enforce(tool, args, token, undefined, signals);
    if (!res.permitted || !res.effective || !res.decision) {
      return {
        ok: false,
        ...(res.denial_reason ? { denial_reason: res.denial_reason } : {}),
        ...(res.refusal_reason ? { refusal_reason: res.refusal_reason } : {}),
        ...(res.insufficient_authorization ? { insufficient_authorization: res.insufficient_authorization } : {}),
        ...(res.evidence_gap ? { evidence_gap: res.evidence_gap } : {}),
      };
    }
    if (this.isKeyedReversibleWrite(tool)) {
      return this.callKeyedReversibleWrite(tool, token, res, beforeReverify, failpoints);
    }
    const attempt = res.attempt;
    if (!attempt) return { ok: false, refusal_reason: "state_unavailable" };
    // Admission, ahead of every awaited read (@spec runtime#compound-actions).
    const admitted = await this.deps.pep.verifyPermitAtUse(attempt);
    if (!admitted.ok) return { ok: false, refusal_reason: admitted.error };
    beforeReverify?.();
    await failpoints?.atReverification?.();
    // A moved catalog snapshot is its own error, not a parameter mismatch:
    // check it first so the caller-visible reason matches the record.
    const capability = await this.deps.pep.reverifyCapability(
      res.capabilitySnapshot,
      token,
      res.effective.action,
      attempt,
    );
    if (!capability.ok) return { ok: false, refusal_reason: capability.error };
    const digest = permitConditions(res.decision)?.parameter_digest as string;
    const bound = await this.deps.pep.reverify(res.effective, digest, token, attempt);
    if (!bound.ok) return { ok: false, refusal_reason: bound.error };
    // The whole seam again immediately before release: both the clock and the
    // Operation Profile can have moved during the reads above.
    const live = await this.deps.pep.verifyPermitAtUse(attempt);
    if (!live.ok) return { ok: false, refusal_reason: live.error };
    // @spec runtime#single-use-identifiers (#1080, D317): a single-use permit
    // is redeemed last, after every check that could refuse it, so an earlier
    // refusal never burns it; redemption and release are synchronous, with no
    // await between them.
    const singleUse = this.takeSingleUse(attempt, res.decision);
    if (singleUse !== undefined) return this.refuseSingleUse(attempt, singleUse);
    const result = this.execute(tool, args);
    // @spec authzen#execution-evidence-requirement (#1640, D744 ruling 2): the
    // write's completed disposition, over the parameters reverification just
    // confirmed. The hold stores nothing, so a record that cannot be written
    // withholds the result (D770 ruling 4); the single use stays consumed.
    const recorded = await this.deps.pep.completeExecution(attempt, {
      ...(bound.effectiveParameterDigest !== undefined ? { effectiveParameterDigest: bound.effectiveParameterDigest } : {}),
      // @spec runtime-evidence#execution-evidence-object (#773): the context
      // reverification re-established before the effect, never one recomputed
      // after it, when the effect itself can move a declared fact.
      ...(bound.effectiveEvaluationContextDigest !== undefined
        ? { effectiveEvaluationContextDigest: bound.effectiveEvaluationContextDigest }
        : {}),
    });
    if (!recorded.recorded) return this.withholdUnevidenced(attempt);
    return { ok: true, result };
  }

  /**
   * @spec runtime#single-use-identifiers, authzen#response-context `use_limit`
   * (#1080, D317): "the PEP owns the consumed-identifier store and refuses a
   * re-presented consumed `evaluation_id`". Where the permit carries
   * `use_limit`, take its single use in this PEP's durable store and return
   * nothing; otherwise return the Execution Evidence `error` that refuses it:
   *
   * | Case | `error` |
   * |---|---|
   * | `use_limit` other than 1 (this PEP meters single use only) | `condition_unrecognized` |
   * | no store configured, or the store cannot be written | `consumption_unavailable` |
   * | the identifier is already consumed | `permit_consumed` |
   *
   * A permit with no `use_limit` returns nothing and touches no store. The
   * record is retained until the permit's `valid_until` plus
   * {@link CONSUMED_PERMIT_RETENTION_MARGIN_MS}. Synchronous, so the caller
   * releases the effect with no await after the redemption.
   */
  private takeSingleUse(attempt: ExecutionAttempt, decision: Decision): string | undefined {
    const condition = singleUseCondition(attempt, decision);
    if (condition === undefined) return undefined;
    if ("error" in condition) return condition.error;
    const store = this.deps.writeReservations;
    if (!store) return "consumption_unavailable";
    try {
      const first = store.consumePermit({
        evaluationId: attempt.evaluationId,
        action: attempt.action,
        executionId: attempt.executionId,
        retainUntilMs: condition.retainUntilMs,
      });
      return first ? undefined : "permit_consumed";
    } catch {
      return "consumption_unavailable";
    }
  }

  /** A single-use refusal, through the one post-permit writer: nothing executes. */
  private async refuseSingleUse(attempt: ExecutionAttempt, error: string): Promise<WriteToolResult> {
    await this.deps.pep.suppressExecution(attempt, error);
    return { ok: false, refusal_reason: singleUseRefusalReason(error) };
  }

  /**
   * @spec runtime#idempotency (#918, D223): a keyed reversible write after
   * its Decision. Retrieval first, read-only: a retained record of the
   * (scope, key) pair is resolved by {@link releaseRetained} and admits
   * nothing. With none, the attempt goes to admission and the effect.
   *
   * @spec runtime#single-use-identifiers (#1136 review, D317, D342): a permit
   * carrying a `use_limit` this PEP cannot meter is refused before either;
   * `use_limit: 1` is consumed by whichever of retrieval or admission the
   * attempt reaches.
   */
  private async callKeyedReversibleWrite(
    tool: string,
    token: TokenFacts,
    res: EnforceResult,
    beforeReverify: (() => void) | undefined,
    failpoints: ReversibleWriteFailpoints | undefined,
  ): Promise<WriteToolResult> {
    const attempt = res.attempt;
    if (!attempt) return { ok: false, refusal_reason: "state_unavailable" };
    const singleUse = singleUseCondition(attempt, res.decision);
    if (singleUse && "error" in singleUse) return this.refuseSingleUse(attempt, singleUse.error);
    if (res.writeReservationUnkeyable) return this.actorUnkeyable(attempt);
    const pair = this.reservationPair(res);
    if (!pair) return this.reservationUnavailable(attempt);
    let found: WriteReservation | undefined;
    try {
      found = pair.store.lookup(pair.scope.scopeDigest, pair.key, pair.scope.lineageScopeDigests);
    } catch {
      return this.reservationUnavailable(attempt);
    }
    if (found) {
      return this.releaseRetained(
        attempt,
        pair.scope,
        found,
        singleUse ? { store: pair.store, retainUntilMs: singleUse.retainUntilMs } : undefined,
        failpoints,
      );
    }
    return this.admitReversibleWrite(tool, token, res, beforeReverify, failpoints);
  }

  /**
   * @spec runtime#idempotency (#918): the store, the pair and the published
   * retention a keyed reversible write needs. `undefined` when any is
   * missing, which refuses: a key the PDP let through malformed, a store that
   * is not configured, or a statement that publishes no retention for this
   * operation all leave exactly-once unestablished. An actor with no stable
   * identity is refused before this, as its own condition
   * ({@link actorUnkeyable}).
   */
  private reservationPair(
    res: EnforceResult,
  ): { store: WriteReservationStore; scope: WriteReservationScope; key: string; retentionMs: number } | undefined {
    const store = this.deps.writeReservations;
    const scope = res.writeReservation;
    const key = scope?.idempotencyKey;
    const attempt = res.attempt;
    if (!store || !scope || !attempt || !isIdempotencyKey(key)) return undefined;
    const statement = this.deps.enforcementScopeStatement ?? RUNTIME_POSTURE;
    const declared = reversibleWriteDeclarationFor(
      statement,
      this.deps.pep.toolAction(attempt.tool)?.actionClass,
      attempt.action,
    );
    const seconds = declared ? reversibleWriteRetentionSeconds(statement, declared) : undefined;
    if (!declared || declared.reservation_owner !== store.owner || seconds === undefined) return undefined;
    return { store, scope, key, retentionMs: seconds * 1000 };
  }

  /**
   * @spec runtime-evidence#execution-evidence-object `consumption_unavailable`:
   * the store this PEP takes the single winner in could not be reached, so
   * exactly-once could not be established. Nothing executes, and the PEP
   * never retries the effect on its own.
   */
  private async reservationUnavailable(attempt: ExecutionAttempt): Promise<WriteToolResult> {
    await this.deps.pep.suppressExecution(attempt, "consumption_unavailable");
    return { ok: false, refusal_reason: "consumption_unavailable" };
  }

  /**
   * @spec runtime#idempotency (#918, #1016 review): the attempt's actor has
   * no stable identity to scope its key on (an instance-profiled leaf with no
   * client), so no (scope, key) pair exists to reserve and the write is
   * refused before any effect, through the one post-permit writer, under this
   * deployment's own error name: the store was reachable, so this is not
   * `consumption_unavailable`. Retrying the same request cannot succeed.
   */
  private async actorUnkeyable(attempt: ExecutionAttempt): Promise<WriteToolResult> {
    await this.deps.pep.suppressExecution(attempt, REVERSIBLE_WRITE_REFUSAL_ERRORS.actor_unkeyable as string);
    return { ok: false, refusal_reason: "actor_unkeyable", next_action: "none" };
  }

  /**
   * @spec runtime#idempotency (#918, D223): retrieval, separate from
   * admission. A retained record resolves without any effect:
   *
   * | Record | Disposition (#808 writer) | Caller sees |
   * |---|---|---|
   * | completed, same operation identity | `operation_already_claimed` | `{ok, deduped, result}`, the original response |
   * | any, different operation identity | `operation_identity_conflict` | refusal, `next_action: none` |
   * | reserved, same operation identity | `operation_already_claimed` | `duplicate_suppressed`, `next_action: retry` |
   *
   * What authorizes the release is THIS attempt's own permit: a current
   * positive Decision for the same action and resource, whose (scope, key)
   * pair matched, held to {@link Pep.verifyPermitAtUse} before anything is
   * disclosed. The permit the record was first produced under is never
   * consulted, so a retry after that permit expired retrieves through its own
   * fresh Decision, and the expired permit itself admits nothing: an effect
   * needs the current attempt's permit at {@link admitReversibleWrite}.
   *
   * The disposition record is awaited before anything is disclosed, so the
   * permit is compared once more, synchronously and on a fresh clock read,
   * after that write: an attempt whose permit expired during it discloses
   * nothing, not the retained result and not which kind of record the key
   * holds. Its one disposition is already recorded, so that last comparison
   * records nothing further.
   *
   * @spec runtime#single-use-identifiers (#1080, D342): retrieval is a use of
   * a single-use permit. A permit carrying `use_limit: 1` names, in
   * `singleUse`, the store admission meters it in and the retention of its
   * record. After the permit-use check and before the disposition or
   * anything else is disclosed, its identifier is consumed there in one
   * atomic insert: one already consumed, by an effect or by an earlier
   * retrieval, is refused `permit_consumed`, and a store that cannot be
   * written refuses `consumption_unavailable`; neither discloses the record.
   * A later retrieval takes a fresh Decision. Retrieval still admits no
   * operation and runs no effect.
   */
  private async releaseRetained(
    attempt: ExecutionAttempt,
    scope: WriteReservationScope,
    retained: WriteReservation,
    singleUse: { store: WriteReservationStore; retainUntilMs: number } | undefined,
    failpoints: ReversibleWriteFailpoints | undefined,
  ): Promise<WriteToolResult> {
    const current = await this.deps.pep.verifyPermitAtUse(attempt);
    if (!current.ok) return { ok: false, refusal_reason: current.error };
    if (failpoints?.atRetrieval) await failpoints.atRetrieval();
    if (singleUse) {
      let first: boolean;
      try {
        first = singleUse.store.consumePermit({
          evaluationId: attempt.evaluationId,
          action: attempt.action,
          executionId: attempt.executionId,
          retainUntilMs: singleUse.retainUntilMs,
        });
      } catch {
        return this.reservationUnavailable(attempt);
      }
      if (!first) return this.refuseSingleUse(attempt, "permit_consumed");
    }
    const conflict = retained.operationIdentity !== scope.operationIdentity;
    await this.deps.pep.suppressExecution(attempt, conflict ? "operation_identity_conflict" : "operation_already_claimed");
    const atRelease = this.deps.pep.permitUseFailure(attempt);
    if (atRelease !== undefined) return { ok: false, refusal_reason: atRelease };
    if (conflict) return { ok: false, refusal_reason: "operation_identity_conflict", next_action: "none" };
    if (retained.state === "reserved") {
      // An outcome this PEP cannot establish: never executed again, and only
      // reconciliation resolves it.
      return { ok: false, refusal_reason: "duplicate_suppressed", next_action: "retry" };
    }
    return { ok: true, deduped: true, result: retained.result };
  }

  /**
   * @spec runtime#idempotency, runtime#execution-reverification (#918, D223):
   * admission and the effect of a keyed reversible write, under the attempt
   * `res` carries. The permit is held to {@link Pep.verifyPermitAtUse} before
   * and after the awaited reverification, then reserve, effect and completion
   * commit in one local transaction with no await inside it. An expired
   * permit, this attempt's or one replayed from an earlier attempt, is
   * refused `permit_expired` here and admits no effect.
   *
   * Public as the effect step's own seam: it is what an attempt replayed past
   * its Decision reaches, and it re-checks everything that attempt needs.
   *
   * @spec runtime#single-use-identifiers (#1136 review, D317): a `use_limit`
   * the permit carries is metered here, never ignored. One this PEP cannot
   * meter is refused first; `use_limit: 1` is taken inside the reservation's
   * transaction, as the last check before the effect
   * ({@link WriteReservationStore.reserve}), so a consumed identifier, under
   * any idempotency key, is refused `permit_consumed` and runs no effect.
   */
  async admitReversibleWrite(
    tool: string,
    token: TokenFacts,
    res: EnforceResult,
    beforeReverify?: () => void,
    failpoints?: ReversibleWriteFailpoints,
  ): Promise<WriteToolResult> {
    const attempt = res.attempt;
    if (!attempt || !res.effective || !res.decision) return { ok: false, refusal_reason: "state_unavailable" };
    const effect = REVERSIBLE_WRITE_EFFECTS[tool];
    if (!effect) throw new Error(`no reversible effect is declared for tool ${tool}`);
    const admitted = await this.deps.pep.verifyPermitAtUse(attempt);
    if (!admitted.ok) return { ok: false, refusal_reason: admitted.error };
    const singleUse = singleUseCondition(attempt, res.decision);
    if (singleUse && "error" in singleUse) return this.refuseSingleUse(attempt, singleUse.error);
    if (res.writeReservationUnkeyable) return this.actorUnkeyable(attempt);
    const pair = this.reservationPair(res);
    if (!pair) return this.reservationUnavailable(attempt);
    beforeReverify?.();
    await failpoints?.atReverification?.();
    const capability = await this.deps.pep.reverifyCapability(
      res.capabilitySnapshot,
      token,
      res.effective.action,
      attempt,
    );
    if (!capability.ok) return { ok: false, refusal_reason: capability.error };
    const digest = permitConditions(res.decision)?.parameter_digest as string;
    const bound = await this.deps.pep.reverify(res.effective, digest, token, attempt);
    if (!bound.ok) return { ok: false, refusal_reason: bound.error };
    const live = await this.deps.pep.verifyPermitAtUse(attempt);
    if (!live.ok) return { ok: false, refusal_reason: live.error };

    // One local transaction, and no await from here to its commit.
    const effective = res.effective;
    const invoiceVersion = this.deps.payments.getInvoice(effective.invoice_id)?.version;
    let outcome: ReturnType<WriteReservationStore["reserve"]>;
    try {
      if (invoiceVersion === undefined) throw new Error("the permit's invoice no longer resolves");
      outcome = pair.store.reserve(
        {
          scope: pair.scope.scope,
          scopeDigest: pair.scope.scopeDigest,
          lineageScopeDigests: pair.scope.lineageScopeDigests,
          idempotencyKey: pair.key,
          action: attempt.action,
          operationIdentity: pair.scope.operationIdentity,
          evaluationId: attempt.evaluationId,
          executionId: attempt.executionId,
          retentionMs: pair.retentionMs,
          ...(singleUse ? { singleUse } : {}),
        },
        (nowMs) =>
          effect({ store: pair.store, attempt, token, effective, invoiceVersion, parameterDigest: digest, nowMs }),
        failpoints?.insideTransaction ? { inside: failpoints.insideTransaction } : {},
      );
    } catch {
      return this.reservationUnavailable(attempt);
    }
    if (outcome.kind === "existing") {
      // @spec runtime#single-use-identifiers (D342): the concurrent-existing
      // fallback consumes the permit too; the reservation read above it in the
      // transaction consumed nothing.
      return this.releaseRetained(
        attempt,
        pair.scope,
        outcome.reservation,
        singleUse ? { store: pair.store, retainUntilMs: singleUse.retainUntilMs } : undefined,
        failpoints,
      );
    }
    if (outcome.kind === "consumed") return this.refuseSingleUse(attempt, "permit_consumed");
    if (outcome.kind === "refused") {
      await this.deps.pep.suppressExecution(
        attempt,
        REVERSIBLE_WRITE_REFUSAL_ERRORS[outcome.refusal] ?? "consumption_unavailable",
      );
      return { ok: false, refusal_reason: outcome.refusal, next_action: "none" };
    }
    failpoints?.afterCommit?.();
    // @spec authzen#execution-evidence-requirement (#1640, D744 ruling 2): the
    // committed write's completed disposition. The effect stands whatever the
    // emission does, so a record that cannot be written is reported as a gap,
    // never a refusal, and its result is withheld (D770 ruling 4): a retry
    // under the key retrieves it under that retry's own permit and record.
    const recorded = await this.deps.pep.completeExecution(attempt, {
      ...(bound.effectiveParameterDigest !== undefined ? { effectiveParameterDigest: bound.effectiveParameterDigest } : {}),
      // @spec runtime-evidence#execution-evidence-object (#773): the context
      // reverification re-established before the effect, never one recomputed
      // after it, when the effect itself can move a declared fact.
      ...(bound.effectiveEvaluationContextDigest !== undefined
        ? { effectiveEvaluationContextDigest: bound.effectiveEvaluationContextDigest }
        : {}),
    });
    if (!recorded.recorded) return { ok: false, gap: recorded.gap };
    return { ok: true, result: outcome.result };
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
    signals?: RequestSignals,
  ): Promise<TransactionToolResult> {
    const tx = this.deps.transaction;
    if (!tx) throw new Error("transaction tier not configured");

    // @spec operation-profile-payments-v1 intake (D316), before the
    // transaction-token check below reads `invoice_id`, so the challenged
    // operation's digest is recomputed from the normalized arguments too.
    const intake = await this.deps.pep.intake(tool, args, token, signals?.invocation);
    if (!intake.ok) return { ok: false, refusal_reason: intake.refusal_reason };
    args = intake.args;

    // @spec txn-authorization#offline-verification — where the credential IS a
    // transaction token, it is matched against the operation THIS resource
    // retained when it issued the challenge, with no call to the Transaction
    // Authorization Server on the request path. The resource reads no approval
    // object off the token: the action-approval context below is derived only
    // from the typed verified claims.
    let derivedApproval: ActionApprovalInput | undefined;
    let consumedTxn: string | undefined;
    if (token.txn) {
      const verified = await this.verifyChallengedOperation(token.txn, tool, args);
      if (!verified.ok) return { ok: false, refusal_reason: verified.refusal_reason };
      derivedApproval = verified.approval;
      consumedTxn = token.txn.txn;
    }

    const res = await this.deps.pep.enforce(tool, args, token, derivedApproval, signals);
    // @spec txn-authorization#offline-verification — the resource RETAINS the
    // pending operation when it issues the challenge; the later transaction
    // token is matched against THAT record, never against its own assertions.
    if (res.challenge) this.txnPending.put(res.challenge.pending);
    if (!res.permitted || !res.effective || !res.decision || !res.resolvedMission) {
      return {
        ok: false,
        ...(res.denial_reason ? { denial_reason: res.denial_reason } : {}),
        ...(res.refusal_reason ? { refusal_reason: res.refusal_reason } : {}),
        ...(res.access_request ? { access_request: res.access_request } : {}),
        ...(res.challenge
          ? {
              error: res.challenge.error,
              transaction_challenge: res.challenge.transaction_challenge,
            }
          : {}),
        ...(res.insufficient_authorization ? { insufficient_authorization: res.insufficient_authorization } : {}),
        ...(res.evidence_gap ? { evidence_gap: res.evidence_gap } : {}),
      };
    }
    // @spec authority-server#mission-join (#557) — the governing Mission for
    // everything past the permit, never `token.mission` directly: on the
    // baseline-Join path `token.mission` stays absent even after a permit,
    // since the credential itself never carried the claim.
    const resolvedMission = res.resolvedMission;
    const digest = permitConditions(res.decision)?.parameter_digest as string;
    const permitId = res.decision.context.decision_id as string;
    const profile = this.deps.pep.toolAction(tool);
    // @spec runtime#idempotency — the operation key carries the crossing's
    // phase where the profile declares one, so two crossings sharing an action
    // identifier and a parameter digest claim DISTINCT keys. Computed once and
    // used by every consumer keyed on operation identity below: redemption,
    // the operation state machine, the connector's own idempotency key, the
    // single-use transaction consumption lookup, and Execution Evidence.
    const opKey = operationKey(resolvedMission.id, res.effective.action, digest, profile?.phase);
    const attempt = res.attempt;
    if (!attempt) return { ok: false, refusal_reason: "state_unavailable" };

    // @spec runtime#compound-actions — admission, BEFORE `redeemPermit`.
    // Redemption is keyed on the operation identity and inserts a row that is
    // never rolled back on refusal, so a wrong-phase or expired presentation
    // checked after it would burn the claim and leave the legitimate crossing
    // reporting `permit_consumed`. Nothing here touches the store.
    const admitted = await this.deps.pep.verifyPermitAtUse(attempt);
    if (!admitted.ok) return this.surfaced(attempt, admitted.disposition, { ok: false, refusal_reason: admitted.error });

    // @spec runtime#execution-reverification — the connector operation this
    // crossing commits, resolved before any state is taken: an explicit
    // per-tool mapping, so a newly served tool name can never fall through to
    // another tool's connector. Unreachable by construction (only a tool the
    // Operation Profile gives a high-consequence class routes here, and the
    // consistency test pins that set against this mapping); a configuration
    // that broke that pairing throws here, before a redemption or a lease.
    const commitEffect = CONNECTOR_OPERATIONS[tool];
    if (!commitEffect) throw new Error(`no connector operation is declared for tool ${tool}`);

    // @spec runtime#execution-reverification — the execution lease comes from
    // the deployment's PUBLISHED maximum for this action class (the
    // Enforcement Scope Statement's `transaction_assurance` declaration, the
    // same object `protectedResourceMetadata()` publishes) and is capped by
    // the permit's own `valid_until`. A local lease never extends
    // authorization, and no bound at either end yields no lease at all.
    const leaseStartMs = tx.engine.nowMs();
    const leaseExpiresAtMs =
      leaseStartMs +
      executionLeaseMs({
        nowMs: leaseStartMs,
        publishedMaxSeconds: executionLeaseMaxSeconds(
          this.deps.enforcementScopeStatement ?? RUNTIME_POSTURE,
          profile?.actionClass,
        ),
        permitValidUntilMs:
          typeof attempt.permitValidUntil === "string" ? Date.parse(attempt.permitValidUntil) : undefined,
      });

    // Single-use permit redemption (D28). @spec
    // runtime-evidence#execution-evidence-object (#786): the two failures are
    // distinct records. Re-presenting the SAME evaluation identifier is
    // `permit_consumed`; a fresh permit for an operation identity already
    // claimed is `operation_already_claimed`. The caller-visible diagnostic
    // stays `permit_consumed` for both: the operation was already claimed
    // either way, and only the signed record needs the distinction. No
    // `advance` here, deliberately: the operation row under this key belongs
    // to the EARLIER attempt, and abandoning it would rewrite that attempt's
    // state.
    const redeem = tx.engine.redeemPermit({
      permitId,
      opKey,
      missionId: resolvedMission.id,
      action: res.effective.action,
      leaseExpiresAtMs,
    });
    if (!redeem.ok) {
      // A lease that could not be set up took no redemption and opened no
      // operation row, so it is not a duplicate: the permit's own window had
      // closed by the time a lease was derived from it.
      if (redeem.reason === "lease_setup_failed") {
        return this.refuseSuppressed(attempt, "permit_expired", { refusal_reason: "permit_expired" });
      }
      return this.refuseSuppressed(
        attempt,
        redeem.reason === "operation_already_claimed" ? "operation_already_claimed" : "permit_consumed",
        { refusal_reason: "permit_consumed" },
      );
    }
    // @spec runtime#idempotency (#917): this attempt now holds the single
    // use, so how it ends is the outcome of the permit's idempotency claim.
    // The redemption store records WHICH attempt, in this same synchronous
    // step, so only this attempt's failure can ever settle the claim (#1016).
    attempt.redeemed = true;
    recordRedeemingAttempt(tx.engine, permitId, attempt.executionId);

    beforeCommit?.();

    // @spec runtime#evidence (pre-effect durability) (#821, D814): before the
    // final checks and the effect. This attempt's operation identity (its
    // execution identity, operation key and evaluation) and the retained
    // Decision Evidence that authorizes it are committed to this PEP's
    // durable file, so a crash after the effect leaves an operation whose
    // disposition can be recovered, never one nothing names. Written ahead of
    // the checks, so a slow write is followed by them rather than by the
    // effect (#821 review). A write that fails prevents the effect: the
    // action is refused and nothing executes.
    let attemptRecord: ExecutionAttemptRecord | undefined;
    if (PRE_EFFECT_ATTEMPT_CLASSES.has(profile?.actionClass ?? "")) {
      try {
        if (!this.deps.writeReservations || !attempt.decisionEvidence) throw new Error("no pre-effect attempt record");
        attemptRecord = this.deps.writeReservations.recordAttempt({
          executionId: attempt.executionId,
          opKey,
          evaluationId: permitId,
          missionId: resolvedMission.id,
          action: res.effective.action,
          decisionEvidence: attempt.decisionEvidence,
        });
      } catch {
        const refused = await this.refuseSuppressed(attempt, EVIDENCE_UNAVAILABLE_ERROR, {
          refusal_reason: "evidence_unavailable",
        });
        tx.engine.advance(opKey, "abandoned");
        return refused;
      }
    }

    // A moved catalog snapshot is its own error, not a parameter mismatch.
    const capability = await this.deps.pep.reverifyCapability(
      res.capabilitySnapshot,
      token,
      res.effective.action,
      attempt,
    );
    if (!capability.ok) {
      tx.engine.advance(opKey, "abandoned");
      return this.surfaced(attempt, capability.disposition, { ok: false, refusal_reason: capability.error });
    }
    // The execution lease is its OWN gate with its own error. It used to sit
    // as an `||` operand ahead of reverification, so an expired lease
    // short-circuited: nothing was recorded and the caller was told
    // `parameter_mismatch`, which was false. This gate is about an
    // ALREADY-STARTED attempt: how long the local lease lets it run, capped by
    // the published maximum and the permit's validity. Whether the permit may
    // still initiate an effect at all is the separate question the pre-effect
    // seam answers below and at admission above.
    if (!tx.engine.leaseValid(opKey)) {
      const refused = await this.refuseSuppressed(attempt, "permit_expired", { refusal_reason: "permit_expired" });
      tx.engine.advance(opKey, "abandoned");
      return refused;
    }
    // TOCTOU re-verify inside the lease, before commit. A compensate crossing
    // (#252) re-derives its form from the committed wire's record, not the
    // invoice as it reads now.
    const bound = res.compensates
      ? await this.deps.pep.reverifyCompensation(res.effective, digest, token, attempt, res.compensates)
      : await this.deps.pep.reverify(res.effective, digest, token, attempt);
    if (!bound.ok) {
      tx.engine.advance(opKey, "abandoned");
      return this.surfaced(attempt, bound.disposition, { ok: false, refusal_reason: bound.error });
    }

    // @spec runtime#execution-reverification — the last check of all, after
    // every awaited read and before anything irreversible: the single use
    // taken below and the connector commit after it. A permit that expired,
    // or a crossing the Operation Profile stopped placing, while the
    // capability or parameter reads were pending initiates nothing, and its
    // refusal is a suppressed disposition, not a consumed txn.
    const live = await this.deps.pep.verifyPermitAtUse(attempt);
    if (!live.ok) {
      tx.engine.advance(opKey, "abandoned");
      return this.surfaced(attempt, live.disposition, { ok: false, refusal_reason: live.error });
    }

    // @spec txn-authorization#offline-verification — atomic first use of the
    // resource-scoped `txn`, LINEARIZABLE across every replica that can execute
    // this operation and committed BEFORE the irreversible effect. A second,
    // distinct token jti for an already-consumed txn is the same replay: it is
    // refused as duplicate_suppressed and never executed as a new attempt. If
    // the consumption store is unavailable the resource fails CLOSED.
    if (consumedTxn !== undefined) {
      let outcome: TxnConsumeOutcome;
      try {
        outcome = this.txnConsumption.consume(CANONICAL_RESOURCE, consumedTxn, opKey);
      } catch {
        const refused = await this.refuseSuppressed(attempt, "consumption_unavailable", {
          refusal_reason: "consumption_unavailable",
        });
        tx.engine.advance(opKey, "abandoned");
        return refused;
      }
      if (!outcome.first) {
        const prior = outcome.record;
        // A DIFFERENT operation under an already-consumed txn, or a txn whose
        // effect already committed, is a replay: refused, never executed as a
        // new attempt.
        //
        // @spec runtime-evidence#execution-evidence-object (#786): the record
        // names which duplicate this is. A different operation identity under
        // the same single-use identifier is `operation_identity_conflict`; the
        // same operation whose effect already committed is a fresh permit for
        // an operation identity already claimed, `operation_already_claimed`.
        // Neither is `permit_consumed`, which is reserved for re-presenting
        // one evaluation identifier. The caller-visible diagnostic stays
        // `duplicate_suppressed`, the reason the transaction-authorization
        // profile mandates on the wire for this refusal, and it is NOT the
        // PDP denial reason of the same name.
        if (prior.state === "effect_committed" || prior.opKey !== opKey) {
          const refused = await this.refuseSuppressed(
            attempt,
            prior.opKey !== opKey ? "operation_identity_conflict" : "operation_already_claimed",
            { refusal_reason: "duplicate_suppressed" },
          );
          tx.engine.advance(opKey, "abandoned");
          return refused;
        }
        // Otherwise this is THIS operation, consumed but never committed: a
        // crash landed in the window between taking the single use and the
        // effect. Refusing it as a duplicate would strand an operation that
        // never happened. It RESUMES instead -- the connector commit below is
        // idempotent by `op_key`, so at most one effect exists either way.
      }
    }

    // @spec runtime#execution-reverification, runtime#evidence (#821 review):
    // nothing slow sits between the last comparison and the effect. The
    // durable attempt record is written before the checks above; the `txn`
    // consumption cannot move ahead of them, so the permit and the lease are
    // compared once more, synchronously on a fresh clock read, with no await
    // before the connector call. A permit or lease that ran out while a store
    // was being written releases nothing.
    const atRelease = this.deps.pep.permitUseFailure(attempt) ?? (tx.engine.leaseValid(opKey) ? undefined : "permit_expired");
    if (atRelease !== undefined) {
      const refused = await this.refuseSuppressed(attempt, atRelease, { refusal_reason: atRelease });
      tx.engine.advance(opKey, "abandoned");
      return refused;
    }

    // Commit point (D36): connector accepts with the idempotency key. The
    // operation is resolved from the explicit per-tool mapping above, never
    // from a ternary whose else-branch would email on any unrecognized name.
    const invoice = this.deps.payments.getInvoice(res.effective.invoice_id);
    const commit = commitEffect({
      connectors: tx.connectors,
      opKey,
      effective: res.effective,
      permitId,
      missionId: resolvedMission.id,
      ...(res.compensates ? { compensates: res.compensates } : {}),
    });
    // @spec runtime#security-considerations (#1270): the resource refused a
    // second settlement of the invoice with no effect, so this is affirmative
    // non-execution under the deployment's collision-resistant error, the
    // same disposition as the reversible writes' `schedule_exists`. A
    // reversal the ledger refused (#252) disposes the same way, under its own
    // error.
    if (!commit.committed) {
      const refusal = commit.refusal ?? "already_settled";
      const refused = await this.refuseSuppressed(attempt, CONNECTOR_REFUSAL_ERRORS[refusal], { refusal_reason: refusal });
      tx.engine.advance(opKey, "abandoned");
      return refused;
    }
    tx.engine.advance(opKey, "connector_committed");
    // The effect is durable, so the consumption row says so. A failure to write
    // it leaves the row at `consumed`, which is exactly the resumable state: a
    // later presentation of the same txn under the same operation re-runs the
    // idempotent commit and settles it, and no second effect can exist.
    if (consumedTxn !== undefined) {
      try {
        this.txnConsumption.commit(CANONICAL_RESOURCE, consumedTxn);
      } catch {
        /* self-healing on the resume path above */
      }
    }

    // Execution Evidence, then reconciliation state.
    // @spec runtime-evidence#execution-evidence-object (issue #649):
    // `outcome` is `completed` whether or not the connector commit itself was
    // a dedup of an already-committed effect (`commit.deduped`): either way
    // the action's final disposition IS completed, and the spec's outcome
    // enum has no distinct "deduped" value (dedup is delivery/idempotency
    // bookkeeping, not an execution outcome). `commit.deduped` stays on the
    // caller's own return value (`ok: true, deduped`) below, unchanged.
    // Both parameter-digest members are the SAME `digest`: `reverify()`
    // above already re-confirmed the effective parameters match what the
    // permit authorized before this commit point, the binding-held case.
    //
    // @spec authority-server#mission-join (#557): `mission_id` is
    // `resolvedMission.id`, never `token.mission.id` -- a baseline-Join
    // credential carries no `mission` claim at all, and this write path
    // (execute_wire_transfer / send_email) is reachable on that path too.
    const result = { executed: true, invoice_id: res.effective.invoice_id, op_key: opKey, payee: invoice?.payee_account };
    const completed: ExecutionEvidenceInput = {
      permitId,
      opKey,
      // One execution identity per disposition attempt, the completed
      // disposition included (#786): an emission retry reuses it and is
      // deduplicated rather than retained twice.
      execution_id: attempt.executionId,
      evaluation_id: permitId,
      mission_id: resolvedMission.id,
      // @spec runtime#permit-binding (#853, D487): the boundary the permit
      // was decided at, as every disposition record of it carries.
      audience: attempt.audience,
      authorized_parameter_digest: digest,
      effective_parameter_digest: digest,
      // @spec runtime-evidence#execution-evidence-object (#773): the context
      // pair of a covered crossing. The authorized member mirrors the linked
      // Decision Evidence; the effective one is the context `reverify()`
      // re-established and found equal before this commit point, an
      // observation it made, never a copy of the authorized digest.
      ...(attempt.authorizedEvaluationContextDigest !== undefined
        ? {
            authorized_evaluation_context_digest: attempt.authorizedEvaluationContextDigest,
            ...(bound.effectiveEvaluationContextDigest !== undefined
              ? { effective_evaluation_context_digest: bound.effectiveEvaluationContextDigest }
              : {}),
          }
        : {}),
      outcome: "completed",
      // @spec authzen#obligation-processing (#1640): the obligations this
      // permit's PEP fulfilled before release.
      ...(attempt.obligationOutcomes ? { obligation_outcomes: attempt.obligationOutcomes } : {}),
      // @spec runtime-evidence#evidence-extensions `work_item` (#815): the
      // work item the PEP attributed to this request.
      ...(attempt.workItem ? { work_item: attempt.workItem } : {}),
      // #821: the instant the attempt was recorded before its effect, as a
      // late record from reconciliation carries it too.
      ...(attemptRecord ? { attempted_at: new Date(attemptRecord.attemptedAtMs).toISOString() } : {}),
      ...(token.jti
        ? {
            hop_reference: {
              jti: token.jti,
              mission_id: resolvedMission.id,
              ...(token.identityContinuationHandle
                ? { continuation_handle: token.identityContinuationHandle }
                : {}),
            },
          }
        : {}),
    };
    let executed: ExecutionEvidence | undefined;
    for (let tries = 0; tries < 2 && executed === undefined; tries += 1) {
      try {
        executed = await tx.evidence.recordExecution(CANONICAL_RESOURCE, "executor", completed);
      } catch {
        /* one retry, on the SAME execution identity: a retained record is
           returned rather than duplicated, so this cannot double-emit. */
      }
    }
    if (executed === undefined) {
      // @spec runtime-evidence#execution-evidence-object (#1104): the effect
      // stands and its record does not exist. This is not a refusal, so it
      // carries no `refusal_reason`: the caller is told the effect committed
      // and its evidence is missing. Nothing here executes again. The
      // operation stays `connector_committed` and the PDP claim unsettled,
      // so the key stays refused and reconciliation settles the claim from
      // the connector ledger (#1103). The operator is alerted now (#821).
      this.alertUnrecorded(attempt, "completed_disposition_unrecorded");
      return { ok: false, gap: "emission_failed", deduped: commit.deduped, result };
    }
    tx.engine.advance(opKey, "evidence_emitted");
    // @spec runtime#idempotency (#917, owner ruling 2026-10-02): the completed
    // record settles the PDP's claim, so the key stays refused as completed
    // through the horizon. D36's state machine is unchanged by this: the
    // settlement is a notification, not a step the effect waits on.
    await this.deps.pep.settleClaim(executed.content);
    tx.engine.advance(opKey, "reconciled");

    return { ok: true, deduped: commit.deduped, result };
  }

  /**
   * @spec runtime-evidence#execution-evidence-object (#786, #821): a
   * transaction-tier refusal after the permit, disposed through the one
   * post-permit writer. A suppressed record that could not be written is
   * surfaced, never dropped ({@link surfaced}).
   */
  private async refuseSuppressed(
    attempt: ExecutionAttempt,
    error: string,
    refusal: { refusal_reason: string },
  ): Promise<TransactionToolResult> {
    const disposition = await this.deps.pep.suppressExecution(attempt, error);
    return this.surfaced(attempt, disposition, { ok: false, ...refusal });
  }

  /**
   * @spec runtime-evidence#execution-evidence-object (#821): a refusal whose
   * suppressed disposition could not be recorded says so. The refusal stands
   * and nothing executed; the caller's result also carries
   * `gap: "emission_failed"`, and the operator is alerted, as for a completed
   * record that could not be written after its effect.
   */
  private surfaced(
    attempt: ExecutionAttempt,
    disposition: SuppressOutcome,
    result: TransactionToolResult,
  ): TransactionToolResult {
    if (disposition.recorded) return result;
    this.alertUnrecorded(attempt, "suppressed_disposition_unrecorded");
    return { ...result, gap: "emission_failed" };
  }

  /** One operator alert for a disposition record that could not be written: identifiers and a fixed cause only. */
  private alertUnrecorded(attempt: ExecutionAttempt, cause: string): void {
    try {
      this.deps.alerts?.alert({
        kind: "evidence_emission_failed",
        evaluation_id: attempt.evaluationId,
        mission_id: attempt.mission.id,
        cause,
        at: new Date(this.deps.transaction?.engine.nowMs() ?? Date.now()).toISOString(),
      });
    } catch {
      /* a failing sink never changes the result */
    }
  }

  /**
   * @spec txn-authorization#offline-verification — the operation-scoped half of
   * the verification, taken where the tool and its arguments are known: the
   * credential is good for the CHALLENGED operation and nothing else, so a call
   * whose action or RECOMPUTED `parameter_digest` is not the retained
   * operation's is refused. The digest is recomputed from authoritative store
   * state, never read off the token.
   */
  private async verifyChallengedOperation(
    credential: TxnCredential,
    tool: string,
    args: Record<string, unknown>,
  ): Promise<{ ok: true; approval: ActionApprovalInput } | { ok: false; refusal_reason: string }> {
    const pending = this.txnPending.get(CANONICAL_RESOURCE, credential.txn);
    if (!pending) return { ok: false, refusal_reason: "txn_unknown" };
    if (TOOL_ACTIONS[tool]?.action !== pending.action) {
      return { ok: false, refusal_reason: "txn_action_mismatch" };
    }
    const recomputed = await this.recomputeParameterDigest(tool, args, pending.mission);
    if (
      recomputed === undefined ||
      recomputed !== pending.parameterDigest ||
      credential.parameterDigest !== recomputed
    ) {
      return { ok: false, refusal_reason: "txn_parameter_mismatch" };
    }

    // A txn whose EFFECT already committed is a replay whatever token jti
    // carries it. A txn merely `consumed` is not decidable here: it may be this
    // very request resuming after a crash between consumption and the effect,
    // and only the commit point holds both operation keys. The authoritative,
    // atomic decision is taken there; this read only lets the resource answer
    // the settled case with the right reason instead of a later one.
    try {
      if (this.txnConsumption.get(CANONICAL_RESOURCE, credential.txn)?.state === "effect_committed") {
        return { ok: false, refusal_reason: "duplicate_suppressed" };
      }
    } catch {
      return { ok: false, refusal_reason: "consumption_unavailable" };
    }

    // The action-approval context the PDP re-evaluates is derived ONLY from
    // these typed, verified claims: the token carries no approval object.
    // @spec authzen#context-approval (#249): the approved Resource is the
    // challenged operation this resource retained, so its contract reference
    // is the one the approval was given under.
    const approvedContract = (pending.authorizationDetails[0] as { resource_contract?: unknown } | undefined)
      ?.resource_contract;
    return {
      ok: true,
      approval: {
        id: `txn:${credential.jti}`,
        approved_at: new Date(credential.iatS * 1000).toISOString(),
        approved_until: new Date(credential.expS * 1000).toISOString(),
        parameter_digest: recomputed,
        ...(approvedContract !== undefined ? { resource: { properties: { resource_contract: approvedContract } } } : {}),
      },
    };
  }

  /**
   * @spec runtime (parameter binding) — recompute the operation's digest from
   * authoritative store state, exactly as the enforcement path does. The token
   * is matched against THIS value, never against a digest it supplies.
   *
   * @spec runtime#compound-actions, txn-authorization#offline-verification
   * (#252, #1693, D889): a compensate crossing's form is the committed wire's
   * reversal form, so it is rebuilt from the compensation link the PEP
   * establishes again from its retained, verified evidence for the challenged
   * Mission, and from that wire's ledger record; never the invoice form, and
   * never the vendor the invoice names now.
   */
  private async recomputeParameterDigest(
    tool: string,
    args: Record<string, unknown>,
    mission: { id: string; issuer: string },
  ): Promise<string | undefined> {
    const mapping = TOOL_ACTIONS[tool];
    if (!mapping?.needsInvoice) return undefined;
    if (mapping.compensates) return await this.deps.pep.compensationParameterDigest(tool, args, mission);
    // @spec resource-access#resource-matching (#1276): the operation target
    // the enforcement path establishes, from the same trusted contract and
    // the same validated arguments.
    const target = this.deps.pep.operationTargetFor(tool, args);
    if (!target.ok) return undefined;
    const invoice = this.deps.payments.getInvoice(String(args.invoice_id ?? ""));
    const vendor = invoice ? this.deps.payments.getVendor(invoice.vendor_id) : undefined;
    if (!invoice || !vendor) return undefined;
    const bound = recipientParams(mapping.reachesRecipients === true, this.deps.payments, vendor.id);
    if (!bound) return undefined;
    return parameterDigest(
      buildEffectiveParams({ action: mapping.action, invoice, vendor, resource: target.target, ...bound }),
    );
  }

  /**
   * @spec runtime#read-binding — `listVendorScope` is the PEP's bound result
   * scope for `list_invoices` (`Pep.enforceInner`'s `bindsVendorScope`
   * branch): the vendor ids the permitted read is limited to, for an
   * unconstrained entry every vendor the store held invoices for at the
   * decision. The store filter on `args.vendor_id` stays as a first pass;
   * this filter is the actual binding enforcement, applied regardless of
   * what the caller asked for, and an absent scope returns nothing.
   * `listMemberIds` (@spec resource-access#initial-common-constraints, #1266)
   * are the invoices whose own facts the decision evaluated, when it bound
   * them; no other invoice is returned.
   */
  private execute(
    tool: string,
    args: Record<string, unknown>,
    listVendorScope?: string[],
    listMemberIds?: string[],
  ): unknown {
    switch (tool) {
      case "list_invoices": {
        const invoices = this.deps.payments.listInvoices(args.vendor_id ? String(args.vendor_id) : undefined);
        const scope = listVendorScope ?? [];
        return invoices.filter(
          (inv) => scope.includes(inv.vendor_id) && (listMemberIds === undefined || listMemberIds.includes(inv.id)),
        );
      }
      case "get_invoice":
        return this.deps.payments.getInvoice(String(args.invoice_id));
      case "lookup_vendor":
        return this.deps.payments.getVendor(String(args.vendor_id));
      // @spec runtime#compound-actions — the preflight crossing: a
      // feasibility answer with no reservation and no external effect.
      case "check_transfer": {
        const invoiceId = String(args.invoice_id);
        const invoice = this.deps.payments.getInvoice(invoiceId);
        // A settled invoice is not payable again (#1270).
        const settled = this.deps.transaction?.connectors.settled(invoiceId) ?? false;
        return { feasible: invoice?.status === "payable" && !settled, invoice_id: invoiceId };
      }
      // The prepare crossing: a hold, which is state and never authority for
      // the commit crossing.
      case "hold_transfer":
        return { held: true, invoice_id: String(args.invoice_id) };
      default:
        return { ok: true };
    }
  }
}

export { TOOL_ACTIONS };
