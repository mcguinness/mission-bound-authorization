/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-integrity
 * (issue #649, #741): a fresh, per-process ES256 signing identity for every
 * runtime-evidence emitter this deployment operates: the PEP's own roles
 * (`pep`, `executor`, `receipt_issuer`), for a demo, eval, or test process
 * with no persistent, published key infrastructure of its own, plus the
 * enforcement-side halves of the PDP boundary.
 *
 * No `pdp` signing key is generated, held, or returned here (#741, PR #753
 * review). The PDP's key and its emission path belong to the decision point
 * (`@mission/pdp`'s `createEphemeralDecisionPoint`); this bundle carries only
 * what an enforcement component may hold: {@link EphemeralEvidenceKeys.decide}
 * to ask for a decision, and the PDP's PUBLIC verification key in
 * {@link EphemeralEvidenceKeys.verification} to verify what comes back.
 *
 * NOT a substitute for real key management: a production deployment
 * publishes a durable JWKS per role and supplies its own
 * `EvidenceSigningConfig` (a `kid` resolvable in that published set, backed
 * by a key with a real retention and rotation story). This generates a NEW,
 * unpublished keypair on every call, so nothing outside the SAME process
 * (and the `verification` keys returned alongside) can ever verify a record
 * it signs.
 */

import { generateKeyPairSync } from "node:crypto";
import {
  createEphemeralDecisionPoint,
  type DecisionEvidenceVerification,
  type DecisionFn,
  type EvidenceKeyResolver,
} from "@mission/pdp";
import {
  buildEvidenceKeyResolver,
  type EvidenceSigningConfig,
  type EvidenceVerificationKey,
} from "./evidence.js";
import { CANONICAL_RESOURCE } from "./pep.js";

const STORE_ROLES = ["pep", "executor", "receipt_issuer"] as const;
type StoreRole = (typeof STORE_ROLES)[number];

export interface EphemeralEvidenceKeys {
  /** Pass directly to `new EvidenceStore(signing, resolver)`: the roles this PEP emits under. */
  signing: EvidenceSigningConfig;
  /** One entry per role (the PDP's included), bound to `emitterId` and, for every role but `receipt_issuer`, `audience`. */
  verification: EvidenceVerificationKey[];
  /** The resolver over {@link verification}: `new EvidenceStore(signing, resolver)`. */
  resolver: EvidenceKeyResolver;
  /**
   * The PDP decision entry point (#741, PR #753 review): pass to
   * `PepDeps.decide`. The emission path behind it is closed over inside the
   * decision point, so this member exposes no way to emit.
   */
  decide: DecisionFn;
}

export interface CreateEphemeralEvidenceKeysOptions {
  roles?: readonly StoreRole[];
  /**
   * The exact `emitter.id` registered for every generated key
   * ({{decision-evidence-integrity}}, #739 review point 1: a verifier MUST
   * bind the key to the component named in the record's `emitter` member),
   * and the id the Decision Evidence emitter names. Defaults to this
   * deployment's canonical resource, which is what its PEP and PDP actually
   * emit under, so a resolver built from `verification` verifies genuinely
   * signed records rather than a placeholder.
   */
  emitterId?: string;
  /**
   * The audience registered for `pep`/`executor` and for the PDP's key
   * (REQUIRED there per {@link EvidenceVerificationKey}; `receipt_issuer`
   * stays audience-unbound regardless of this option, matching its own key's
   * type). Defaults, like `emitterId`, to this deployment's canonical
   * resource: the audience its decision requests actually carry.
   */
  audience?: string;
  /**
   * The PDP this bundle's `decide` and `pdp` verification key come from. A
   * test standing in for a decision point that already decided constructs one
   * itself (`createEphemeralDecisionPoint`), keeps its PDP-side emitter, and
   * passes it here so this bundle's resolver verifies exactly what it emits.
   * Absent, a decision point is constructed here and its emission path is
   * unreachable from anywhere.
   */
  decisionPoint?: { decide: DecisionFn; evidenceVerification: DecisionEvidenceVerification };
}

/**
 * Generate one ES256 keypair per role. Each role gets its OWN keypair and
 * `kid`, so a verifier's key-to-role binding ({{decision-evidence-integrity}})
 * is genuinely exercised rather than trivially satisfied by one key reused
 * everywhere. The decision point's PUBLIC key appears in `verification` (so
 * the PEP can verify what the PDP emitted) and its private half appears
 * nowhere in this bundle.
 */
export function createEphemeralEvidenceKeys(
  options: CreateEphemeralEvidenceKeysOptions = {},
): EphemeralEvidenceKeys {
  const { roles = STORE_ROLES, emitterId = CANONICAL_RESOURCE, audience = CANONICAL_RESOURCE } = options;
  const signing: EvidenceSigningConfig = {};
  const verification: EvidenceVerificationKey[] = [];
  for (const role of roles) {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const kid = `ephemeral-${role}`;
    signing[role] = { kid, key: privateKey };
    verification.push(
      role === "receipt_issuer"
        ? { kid, publicKey, role, emitterId }
        : { kid, publicKey, role, emitterId, audience },
    );
  }
  const point: { decide: DecisionFn; evidenceVerification: DecisionEvidenceVerification } =
    options.decisionPoint ?? createEphemeralDecisionPoint({ emitterId, audience });
  verification.push({ ...point.evidenceVerification, role: "pdp" });
  return {
    signing,
    verification,
    resolver: buildEvidenceKeyResolver(verification),
    decide: point.decide,
  };
}
