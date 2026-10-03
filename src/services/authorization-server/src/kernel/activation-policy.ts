/**
 * @spec mission#standing-consent-bases — the activation policy registry: the
 * policies this Mission Issuer evaluates to adjudicate a standing-consent
 * activation (a template Dispatch, a policy-adjudicated child creation), each
 * with the exact snapshot it evaluates.
 *
 * The consented object (a template's `dispatch_policy`, an Authority Set
 * entry's `child_creation_policy`) commits a policy as an activation policy
 * reference `{id, version, digest}`. Before each activation the issuer
 * recomputes `digest` over the snapshot it holds for that `id` and refuses the
 * activation when the version or digest differs: editing a policy's content,
 * even under an unchanged version, never adjudicates an activation the human
 * did not consent to. The registry is the reference implementation's retained
 * snapshot store; it holds the current snapshot per `id`, not a history.
 */
import { type ActivationPolicyRef, activationPolicyDigest } from "@mission/core";

/** One registered policy: its current version and the exact snapshot evaluated. */
export interface RegisteredActivationPolicy {
  version: string;
  /** The snapshot's media type. */
  content_type: string;
  /** The snapshot's exact content (UTF-8). */
  content: string;
}

/** The deployment's activation policies, keyed by policy `id`. */
export type ActivationPolicyRegistry = Readonly<Record<string, RegisteredActivationPolicy>>;

/**
 * Mint the reference a consented object commits, from the snapshot this issuer
 * holds for `id` at `version`. Undefined when no such policy is registered at
 * that version: the issuer cannot commit content it does not hold.
 */
export function mintActivationPolicyRef(
  iss: string,
  registry: ActivationPolicyRegistry | undefined,
  id: string,
  version: string,
): ActivationPolicyRef | undefined {
  const policy = registry && Object.hasOwn(registry, id) ? registry[id] : undefined;
  if (!policy || policy.version !== version) return undefined;
  return { id, version, digest: activationPolicyDigest(iss, policy) };
}

/**
 * @spec mission#standing-consent-bases — before an activation, recompute the
 * digest over the snapshot this issuer would evaluate for `ref.id`. True only
 * when that snapshot exists at `ref.version` and its digest equals
 * `ref.digest`; an unregistered policy, a changed version, or changed content
 * under the same version is a mismatch.
 */
export function activationPolicyMatches(
  iss: string,
  registry: ActivationPolicyRegistry | undefined,
  ref: ActivationPolicyRef,
): boolean {
  const current = mintActivationPolicyRef(iss, registry, ref.id, ref.version);
  return current !== undefined && current.digest === ref.digest;
}
