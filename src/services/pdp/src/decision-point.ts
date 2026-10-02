/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-object,
 * #decision-evidence-integrity; draft-mcguinness-mission-runtime.md#agent-isolated-evidence-emission
 * (issue #741, PR #753 review): where the Decision Evidence emission path is
 * bound.
 *
 * The emitter is constructed HERE, inside the PDP's own construction, and is
 * reachable only through the closure {@link DecisionPoint.decide} holds. It
 * is never a member of any object an enforcement component receives. A PEP
 * gets two things: this decision function, and the verification material
 * ({@link DecisionEvidenceVerification}) it needs to verify and retain what
 * comes back. So the only Decision Evidence a PEP can obtain is a record
 * this PDP built from a decision this PDP reached.
 *
 * The distinction is the whole point of the emission condition. An
 * enforcement component holding an emitter does not need the raw signing key
 * to mint an arbitrary record: `emit` accepts the Mission, subject, resource,
 * action, audience, decision, conditions, and denial reason from its caller
 * and signs them under the decision point's identity. Handing the PEP a
 * decision function instead leaves it the caller of a decision, never the
 * author of a record.
 */

import { generateKeyPairSync, randomUUID } from "node:crypto";
import { createDecisionEvidenceEmitter, type DecisionEvidenceEmitter } from "./decision-evidence.js";
import { type DecisionFn, type EvaluateOptions, evaluate } from "./evaluate.js";
import type {
  ClaimRequester,
  ClaimResolution,
  ConsumptionStatusFn,
  IdempotencyClaimDomain,
  SettlementResult,
  UnresolvedClaim,
} from "./idempotency-claims.js";
import type { EvidenceKeyLike, EvidenceSigningKey } from "./runtime-evidence-integrity.js";

/**
 * @spec runtime#idempotency (#917, owner ruling 2026-10-02): what an
 * executing PEP may tell the claim domain, over the same decision channel it
 * asks for decisions on, scoped to the authenticated requester. It settles
 * and reconciles claims from authenticated Execution Evidence or from its own
 * redemption store; it cannot release a claim, and it never redeems through
 * the PDP.
 */
export interface ClaimChannel {
  /** The redeeming attempt's PEP-signed Execution Evidence. Idempotent on `execution_id`. */
  settle(record: unknown): Promise<SettlementResult>;
  /** This requester's unresolved claims, for the declared reconciler. */
  listUnresolved(): Promise<UnresolvedClaim[]>;
  /** Resolve one unresolved claim. */
  reconcile(evaluationId: string, resolution: ClaimResolution): Promise<SettlementResult>;
}

/** The channel a decision point without a claim domain offers: nothing settles. */
const NO_CLAIM_CHANNEL: ClaimChannel = {
  settle: async () => ({ accepted: false, reason: "no_claim_domain" }),
  listUnresolved: async () => [],
  reconcile: async () => ({ accepted: false, reason: "no_claim_domain" }),
};

/** The claim channel over one domain, bound to one authenticated requester. */
export function claimChannelFor(claims: IdempotencyClaimDomain | undefined, requester: ClaimRequester): ClaimChannel {
  if (!claims) return NO_CLAIM_CHANNEL;
  return {
    settle: (record) => claims.settle(requester, record),
    listUnresolved: async () => claims.listUnresolved(requester),
    reconcile: (evaluationId, resolution) => claims.reconcile(requester, evaluationId, resolution),
  };
}

/**
 * What a relying PEP registers to verify (and then retain) the Decision
 * Evidence this decision point emits: the published `kid` and its public key,
 * plus the `emitter.id` and enforcement scope the key is published FOR. The
 * verifier binds all four ({{decision-evidence-integrity}}); a `kid`-only
 * registration is exactly the wildcard that binding exists to prevent.
 */
export interface DecisionEvidenceVerification {
  kid: string;
  publicKey: EvidenceKeyLike;
  emitterId: string;
  audience: string;
}

export interface DecisionPointConfig {
  /**
   * This decision point's Decision Evidence emission path: its ES256 signing
   * identity, the public half a relying PEP verifies with, the `emitter.id`
   * it names, and the enforcement scope its key is published for. Absent, the
   * decision point emits no Decision Evidence, and a PEP that requires one
   * refuses the action rather than executing an unevidenced decision.
   */
  evidence?: {
    signer: EvidenceSigningKey;
    verificationKey: EvidenceKeyLike;
    emitterId: string;
    audience: string;
  };
  /**
   * @spec runtime#idempotency (#917): this decision point's Exact
   * idempotency claim domain, bound here exactly as the evidence path is and
   * for the same reason: an enforcement component that could supply one
   * could choose the domain its own requests are claimed in. Absent, the
   * decision point declares no domain and refuses every high-consequence
   * permit.
   */
  claims?: IdempotencyClaimDomain;
}

export interface DecisionPoint {
  /** The only decision-side capability an enforcement component receives. */
  decide: DecisionFn;
  /** Published alongside `decide`, so the PEP that holds one can verify what the other returns. */
  evidenceVerification?: DecisionEvidenceVerification;
  /**
   * @spec runtime#idempotency (#917): the decision channel's seam: `decide`
   * bound to one authenticated requester and that requester's read-only
   * consumption-status capability. Only trusted assembly and the channel call
   * this; a PEP receives the function it returns.
   */
  decideAs?: (requester: ClaimRequester, consumptionStatus?: ConsumptionStatusFn) => DecisionFn;
  /** @spec runtime#idempotency (#917): settlement and reconciliation for one authenticated requester. */
  claimsFor?: (requester: ClaimRequester) => ClaimChannel;
}

/**
 * Bind one emission path, one claim domain and one requester to one decision
 * function. The returned function strips any `evidence`, `claims`,
 * `requester` or `consumptionStatus` a caller's options object carries before
 * applying this decision point's own: {@link DecisionOptions} omits the
 * members, but an options object built elsewhere and widened is still
 * structurally assignable, so they are removed rather than merely
 * overwritten. None of them can be supplied, replaced, or suppressed from the
 * enforcement side.
 */
function bindDecide(
  emitter: DecisionEvidenceEmitter | undefined,
  claims: IdempotencyClaimDomain | undefined,
  requester: ClaimRequester,
  consumptionStatus?: ConsumptionStatusFn,
): DecisionFn {
  return async (req, opts) => {
    const forwarded = { ...opts } as EvaluateOptions;
    delete forwarded.evidence;
    delete forwarded.claims;
    delete forwarded.requester;
    delete forwarded.consumptionStatus;
    if (emitter) forwarded.evidence = emitter;
    if (claims) forwarded.claims = claims;
    forwarded.requester = requester;
    if (consumptionStatus) forwarded.consumptionStatus = consumptionStatus;
    return evaluate(req, forwarded);
  };
}

/**
 * The requester a decision point's plain `decide` answers to: a co-resident
 * caller that no channel authenticated. Its epoch is fresh per decision
 * point and it has no consumption-status capability, so a retransmission can
 * never be returned to it; every other guarantee of the claim holds.
 */
function unboundRequester(): ClaimRequester {
  return { pep_id: "co-resident", pep_epoch: `co-resident:${randomUUID()}` };
}

/** Construct a co-resident PDP: one decision function, bound once to one emission path. */
export function createDecisionPoint(
  config: DecisionPointConfig & Required<Pick<DecisionPointConfig, "evidence">>,
): Required<DecisionPoint>;
export function createDecisionPoint(
  config?: DecisionPointConfig,
): DecisionPoint & Required<Pick<DecisionPoint, "decideAs" | "claimsFor">>;
export function createDecisionPoint(config: DecisionPointConfig = {}): DecisionPoint {
  const emitter = config.evidence
    ? createDecisionEvidenceEmitter({
        signer: config.evidence.signer,
        emitterId: config.evidence.emitterId,
        audience: config.evidence.audience,
      })
    : undefined;
  return {
    decide: bindDecide(emitter, config.claims, unboundRequester()),
    decideAs: (requester, consumptionStatus) => bindDecide(emitter, config.claims, requester, consumptionStatus),
    claimsFor: (requester) => claimChannelFor(config.claims, requester),
    ...(config.evidence
      ? {
          evidenceVerification: {
            kid: config.evidence.signer.kid,
            publicKey: config.evidence.verificationKey,
            emitterId: config.evidence.emitterId,
            audience: config.evidence.audience,
          },
        }
      : {}),
  };
}

/**
 * A decision point with a fresh, per-process ES256 emission key, for a demo,
 * eval, or test process with no published key infrastructure of its own.
 *
 * {@link EphemeralDecisionPoint.emitter} is a PDP-SIDE seam: a test standing
 * in for a PDP that already decided needs to mint the record that PDP would
 * have emitted, on the same emitter (and so the same sequence counters) its
 * `decide` uses. Enforcement wiring takes `decide` and `evidenceVerification`
 * and never this.
 *
 * `claims` binds a claim domain exactly as {@link createDecisionPoint} does;
 * absent, this decision point declares none and refuses high-consequence
 * permits.
 */
export interface EphemeralDecisionPoint extends DecisionPoint {
  evidenceVerification: DecisionEvidenceVerification;
  emitter: DecisionEvidenceEmitter;
  decideAs: NonNullable<DecisionPoint["decideAs"]>;
  claimsFor: NonNullable<DecisionPoint["claimsFor"]>;
}

export function createEphemeralDecisionPoint(options: {
  emitterId: string;
  audience: string;
  kid?: string;
  claims?: IdempotencyClaimDomain;
}): EphemeralDecisionPoint {
  const { emitterId, audience, kid = "ephemeral-pdp", claims } = options;
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const emitter = createDecisionEvidenceEmitter({ signer: { kid, key: privateKey }, emitterId, audience });
  return {
    decide: bindDecide(emitter, claims, unboundRequester()),
    decideAs: (requester, consumptionStatus) => bindDecide(emitter, claims, requester, consumptionStatus),
    claimsFor: (requester) => claimChannelFor(claims, requester),
    evidenceVerification: { kid, publicKey, emitterId, audience },
    emitter,
  };
}
