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

import { generateKeyPairSync } from "node:crypto";
import { createDecisionEvidenceEmitter, type DecisionEvidenceEmitter } from "./decision-evidence.js";
import { type DecisionFn, type EvaluateOptions, evaluate } from "./evaluate.js";
import type { EvidenceKeyLike, EvidenceSigningKey } from "./runtime-evidence-integrity.js";

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
}

export interface DecisionPoint {
  /** The only decision-side capability an enforcement component receives. */
  decide: DecisionFn;
  /** Published alongside `decide`, so the PEP that holds one can verify what the other returns. */
  evidenceVerification?: DecisionEvidenceVerification;
}

/**
 * Bind one emission path to one decision function. The returned function
 * strips any `evidence` a caller's options object carries before applying
 * this decision point's own: {@link DecisionOptions} omits the member, but an
 * options object built elsewhere and widened is still structurally
 * assignable, so it is removed rather than merely overwritten. The emission
 * path therefore cannot be supplied, replaced, or suppressed from the
 * enforcement side.
 */
function bindDecide(emitter: DecisionEvidenceEmitter | undefined): DecisionFn {
  return async (req, opts) => {
    const forwarded = { ...opts } as EvaluateOptions;
    delete forwarded.evidence;
    if (emitter) forwarded.evidence = emitter;
    return evaluate(req, forwarded);
  };
}

/** Construct a co-resident PDP: one decision function, bound once to one emission path. */
export function createDecisionPoint(config: Required<DecisionPointConfig>): Required<DecisionPoint>;
export function createDecisionPoint(config?: DecisionPointConfig): DecisionPoint;
export function createDecisionPoint(config: DecisionPointConfig = {}): DecisionPoint {
  const emitter = config.evidence
    ? createDecisionEvidenceEmitter({
        signer: config.evidence.signer,
        emitterId: config.evidence.emitterId,
        audience: config.evidence.audience,
      })
    : undefined;
  return {
    decide: bindDecide(emitter),
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
 */
export interface EphemeralDecisionPoint extends DecisionPoint {
  evidenceVerification: DecisionEvidenceVerification;
  emitter: DecisionEvidenceEmitter;
}

export function createEphemeralDecisionPoint(options: {
  emitterId: string;
  audience: string;
  kid?: string;
}): EphemeralDecisionPoint {
  const { emitterId, audience, kid = "ephemeral-pdp" } = options;
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const emitter = createDecisionEvidenceEmitter({ signer: { kid, key: privateKey }, emitterId, audience });
  return {
    decide: bindDecide(emitter),
    evidenceVerification: { kid, publicKey, emitterId, audience },
    emitter,
  };
}
