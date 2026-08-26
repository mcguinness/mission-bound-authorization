/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-integrity
 * (issue #649): a fresh, per-process ES256 signing identity for every
 * `EvidenceStore` emitter role (`pdp`, `pep`, `executor`, `receipt_issuer`),
 * for a demo, eval, or test process with no persistent, published key
 * infrastructure of its own.
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
import type { EvidenceSigningConfig, EvidenceVerificationKey } from "./evidence.js";

const ALL_ROLES = ["pdp", "pep", "executor", "receipt_issuer"] as const;
type EvidenceRole = (typeof ALL_ROLES)[number];

export interface EphemeralEvidenceKeys {
  /** Pass directly to `new EvidenceStore(signing)`. */
  signing: EvidenceSigningConfig;
  /** One entry per role, bound to `emitterId` (and, for every role but `receipt_issuer`, `audience`) per {@link createEphemeralEvidenceKeys}'s options. */
  verification: EvidenceVerificationKey[];
}

export interface CreateEphemeralEvidenceKeysOptions {
  roles?: readonly EvidenceRole[];
  /**
   * The exact `emitter.id` registered for every generated key
   * ({{decision-evidence-integrity}}, #739 review point 1: a verifier MUST
   * bind the key to the component named in the record's `emitter` member).
   * Callers exercising `buildEvidenceKeyResolver` against records a real
   * PEP/PDP signed MUST pass the same id that emitted those records (this
   * deployment's convention is `CANONICAL_RESOURCE`); the default here is
   * an arbitrary placeholder, adequate only when nothing checks it.
   */
  emitterId?: string;
  /**
   * The audience registered for `pdp`/`pep`/`executor` keys (REQUIRED
   * there per {@link EvidenceVerificationKey}; `receipt_issuer` stays
   * audience-unbound regardless of this option, matching its own key's
   * type). Same caveat as `emitterId`: pass the real request audience when
   * verifying genuinely signed records.
   */
  audience?: string;
}

/**
 * Generate one ES256 keypair per role (default: all four). Each role gets
 * its OWN keypair and `kid`, so a verifier's key-to-role binding
 * ({{decision-evidence-integrity}}) is genuinely exercised rather than
 * trivially satisfied by one key reused everywhere. `emitterId`/`audience`
 * default to fixed placeholders: fine for a caller that only ever uses the
 * `signing` half (most callers, which never build a resolver at all), but a
 * caller that DOES build a {@link buildEvidenceKeyResolver} from
 * `verification` and checks it against real signed records MUST supply the
 * values that match what those records actually carry (#739 review point
 * 1's whole point is that a resolver no longer wildcards these).
 */
export function createEphemeralEvidenceKeys(
  options: CreateEphemeralEvidenceKeysOptions = {},
): EphemeralEvidenceKeys {
  const {
    roles = ALL_ROLES,
    emitterId = "ephemeral-emitter.example.com",
    audience = "https://ephemeral-audience.example.com",
  } = options;
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
  return { signing, verification };
}
