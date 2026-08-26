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
  /** One entry per role, `audience` unbound (matches any audience) for convenience; build a narrower resolver directly when a test needs to exercise scope/audience binding. */
  verification: EvidenceVerificationKey[];
}

/**
 * Generate one ES256 keypair per role (default: all four). Each role gets
 * its OWN keypair and `kid`, so a verifier's key-to-role binding
 * ({{decision-evidence-integrity}}) is genuinely exercised rather than
 * trivially satisfied by one key reused everywhere.
 */
export function createEphemeralEvidenceKeys(
  roles: readonly EvidenceRole[] = ALL_ROLES,
): EphemeralEvidenceKeys {
  const signing: EvidenceSigningConfig = {};
  const verification: EvidenceVerificationKey[] = [];
  for (const role of roles) {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const kid = `ephemeral-${role}`;
    signing[role] = { kid, key: privateKey };
    verification.push({ kid, publicKey, role });
  }
  return { signing, verification };
}
