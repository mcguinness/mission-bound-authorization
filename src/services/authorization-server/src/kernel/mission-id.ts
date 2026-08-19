import { randomBytes } from "node:crypto";

/**
 * @spec mission#mission-identifier, mission-substrate#reference
 * (unguessability): the single Mission Reference minting helper. Every
 * `msn_` minting site (approve, expansion, template instantiation,
 * child-delegation) MUST draw its id from this helper rather than construct
 * one inline, so the entropy source and byte count are asserted in exactly
 * one place instead of once per call site.
 *
 * The unguessability row's floor is >=128 bits of entropy; this draws
 * {@link MISSION_ID_ENTROPY_BYTES} (144 bits) from a cryptographically
 * secure random source, base64url-encoded.
 */
export const MISSION_ID_ENTROPY_BYTES = 18;

/**
 * `source` is injectable ONLY so the entropy-source contract itself (which
 * function is drawn from, and how many bytes are requested) can be tested
 * directly; every production call site uses the default and never passes
 * one.
 */
export function newMissionId(source: (size: number) => Buffer = randomBytes): string {
  return `msn_${source(MISSION_ID_ENTROPY_BYTES).toString("base64url")}`;
}
