/**
 * @spec runtime#idempotency, authzen#parameter-digest (`idempotency_key`):
 * the (idempotency scope, `idempotency_key`) pair a high-consequence claim
 * (the PDP's, #917) or a reversible-write reservation (the enforcing PEP's,
 * #918) is keyed on.
 *
 * One fixed-member scope object, shared by both owners so the two cannot
 * drift to private encodings: every dimension is present, `null` where it
 * does not apply, so an absent dimension never collides with a value, and the
 * digest is the JCS canonical digest of that object, so JSON string escaping
 * keeps the tuple unambiguous where a concatenation would not.
 */

import { canonicalDigest, type JsonValue } from "./canonicalize.js";

/**
 * @spec authzen#parameter-digest: the Operation Profile key format: 16 to
 * 128 characters of `ALPHA / DIGIT / "-" / "_"`.
 */
export const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

/** A well-formed `idempotency_key`; anything else is not a key at all. */
export function isIdempotencyKey(value: unknown): value is string {
  return typeof value === "string" && IDEMPOTENCY_KEY_PATTERN.test(value);
}

/**
 * @spec runtime#idempotency: "The idempotency scope is, at minimum, the
 * Mission, the subject and the actor, the audience, the action, and the
 * resource", and "Where compound-action phases share an action identifier,
 * the idempotency scope MUST include the phase". A deployment publishes the
 * list in its Enforcement Scope Statement; every name here is a dimension of
 * the fixed scope object below, in its member order.
 */
export const IDEMPOTENCY_SCOPE_DIMENSIONS = [
  "mission",
  "subject",
  "actor",
  "audience",
  "action",
  "resource",
  "phase",
] as const;

export type IdempotencyScopeDimension = (typeof IDEMPOTENCY_SCOPE_DIMENSIONS)[number];

/**
 * @spec runtime#idempotency: "Volatile members MUST NOT be added to the
 * scope." The members a request carries that change between retries of one
 * intended execution: a published scope naming one of these is refused at
 * load, never encoded.
 */
export const VOLATILE_SCOPE_MEMBERS = [
  "client_instance_id",
  "act_chain",
  "freshness",
  "approval",
  "timestamp",
] as const;

export function isScopeDimension(value: unknown): value is IdempotencyScopeDimension {
  return (
    typeof value === "string" && (IDEMPOTENCY_SCOPE_DIMENSIONS as readonly string[]).includes(value)
  );
}

export function isVolatileScopeMember(value: unknown): boolean {
  return typeof value === "string" && (VOLATILE_SCOPE_MEMBERS as readonly string[]).includes(value);
}

/**
 * The fixed-member idempotency scope. `actor.act` is the immediate (leaf)
 * delegate only, and only when that leaf names a delegate rather than a
 * client instance ({@link idempotencyScopeActor}): the rest of the chain is
 * volatile.
 */
export interface IdempotencyScope {
  mission: { iss: string; id: string };
  subject: { iss: string | null; sub: string };
  actor: { client_id: string | null; act: { iss: string; sub: string } | null };
  audience: string;
  action: string;
  resource: { type: string; id: string };
  phase: string | null;
}

/** The actor members of a validated decision request, as the scope reads them. */
export interface ScopeActorInput {
  client_id?: string;
  act?: ReadonlyArray<{ iss?: unknown; sub?: unknown; sub_profile?: unknown }>;
}

/** The `sub_profile` token marking an `act` entry that names a client instance. */
const CLIENT_INSTANCE_PROFILE = "client_instance";

/** Whether an `act` entry names a client instance (its space-delimited `sub_profile` carries `client_instance`). */
export function namesClientInstance(entry: { sub_profile?: unknown }): boolean {
  return (
    typeof entry.sub_profile === "string" &&
    entry.sub_profile.split(" ").includes(CLIENT_INSTANCE_PROFILE)
  );
}

/**
 * @spec runtime#idempotency ("Volatile members MUST NOT be added to the
 * scope"), oauth-mission#delegated-instance-context: the stable actor
 * identity a scope is keyed on, or `undefined` when none can be established.
 *
 * - No delegation (`act` absent): the client alone.
 * - The leaf names a delegate (its `sub_profile` carries no
 *   `client_instance`): the client and that delegate's `{iss, sub}`, so a
 *   genuinely different delegate is a different scope.
 * - The leaf names a client instance: an instance's identity is volatile
 *   (the same reason `client_instance_id` is excluded), and instance
 *   evidence does not establish a delegate. The stable identity is the
 *   client the instance belongs to, so `act` is `null` and another instance
 *   of the same client is the same scope. Without a `client_id` there is no
 *   stable identity to key on: `undefined`, and the caller refuses.
 *
 * Shared by every owner of a (scope, key) record, the PDP claim (#917) and
 * the PEP reservation (#918), so they derive the actor identically.
 */
export function idempotencyScopeActor(
  actor: ScopeActorInput | undefined,
): IdempotencyScope["actor"] | undefined {
  const clientId =
    typeof actor?.client_id === "string" && actor.client_id.length > 0 ? actor.client_id : null;
  const leaf = actor?.act?.[actor.act.length - 1];
  if (!leaf) return { client_id: clientId, act: null };
  if (typeof leaf.iss !== "string" || typeof leaf.sub !== "string") return undefined;
  if (namesClientInstance(leaf))
    return clientId === null ? undefined : { client_id: clientId, act: null };
  return { client_id: clientId, act: { iss: leaf.iss, sub: leaf.sub } };
}

/**
 * The canonical JSON form of a scope: built member by member from the typed
 * object, so a caller's widened object cannot carry an extra member into the
 * digest.
 */
export function canonicalIdempotencyScope(scope: IdempotencyScope): JsonValue {
  return {
    mission: { iss: scope.mission.iss, id: scope.mission.id },
    subject: { iss: scope.subject.iss, sub: scope.subject.sub },
    actor: {
      client_id: scope.actor.client_id,
      act: scope.actor.act === null ? null : { iss: scope.actor.act.iss, sub: scope.actor.act.sub },
    },
    audience: scope.audience,
    action: scope.action,
    resource: { type: scope.resource.type, id: scope.resource.id },
    phase: scope.phase,
  };
}

/** `scope_digest`: the JCS canonical digest of the fixed-member scope. */
export function idempotencyScopeDigest(scope: IdempotencyScope): string {
  return canonicalDigest(canonicalIdempotencyScope(scope));
}
