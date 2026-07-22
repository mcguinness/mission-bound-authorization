/**
 * @spec actor-profile#actor-object-structure
 * @spec actor-profile#delegation-chains
 * @spec authzen#context-actor
 *
 * The bridge between the token's nested `act` claim (outermost = immediate
 * actor, innermost = first actor authorized by the subject) and the AuthZEN
 * `context.actor.act` array (ordered root to leaf). Shared by the AS, PDP,
 * and PEPs (decisions D31, D5). Per D31 the PEP flattens; the PDP validates
 * shape and consistency.
 */

/** A nested `act` object per RFC 8693 as profiled by actor-profile. */
export interface ActObject {
  sub: string;
  iss: string;
  sub_profile?: string;
  act?: ActObject;
  cnf?: Record<string, unknown>;
  // instance/agent members ride along (CIA-CORE / ai-agent-instance)
  [k: string]: unknown;
}

/** A flattened chain entry (no nesting); order is root-to-leaf in the array. */
export type FlatActEntry = Omit<ActObject, "act">;

/**
 * Entity-profile allowlists, position-keyed (O-26 / entity-profiles rev 01).
 * `sub_profile` inside an `act` node uses the Actor Profile usage location.
 */
export const ACTOR_SUB_PROFILE_VALUES = new Set(["user", "service", "ai_agent", "client_instance"]);
export const SUBJECT_SUB_PROFILE_VALUES = new Set(["user", "device", "service", "ai_agent"]);
const PROFILE_TOKEN = /^[A-Za-z0-9._-]+$/;

export const DEFAULT_MAX_DEPTH = 4;

export class ActorChainError extends Error {}

/** Split a space-delimited sub_profile into its tokens (case preserved). */
export function parseSubProfile(value: string | undefined): string[] {
  if (value === undefined) return [];
  return value.split(" ").filter((t) => t.length > 0);
}

/**
 * Flatten a nested `act` claim into a root-to-leaf array.
 * The nested claim is outermost-first (leaf first); the array is root-first,
 * so this reverses. Returns [] when there is no `act` claim.
 */
export function flattenActChain(act: ActObject | undefined): FlatActEntry[] {
  const leafFirst: FlatActEntry[] = [];
  let node: ActObject | undefined = act;
  const guard = new Set<ActObject>();
  while (node) {
    if (guard.has(node)) throw new ActorChainError("cyclic act chain");
    guard.add(node);
    const { act: inner, ...entry } = node;
    leafFirst.push(entry);
    node = inner;
  }
  return leafFirst.reverse();
}

/**
 * Validate a nested `act` claim per the profile: each hop MUST carry `sub`
 * and `iss`; `sub_profile` values (when present) MUST be Actor-Profile
 * registered or collision-resistant private; depth MUST NOT exceed the
 * local maximum. `client_profile` MUST NOT appear inside an `act` node.
 */
export function validateActChain(
  act: ActObject | undefined,
  opts: { maxDepth?: number } = {},
): FlatActEntry[] {
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;
  const flat = flattenActChain(act);
  if (flat.length > maxDepth) {
    throw new ActorChainError(`delegation depth ${flat.length} exceeds local maximum ${maxDepth}`);
  }
  for (const entry of flat) {
    if (typeof entry.sub !== "string" || entry.sub.length === 0) {
      throw new ActorChainError("act entry missing required sub");
    }
    if (typeof entry.iss !== "string" || entry.iss.length === 0) {
      throw new ActorChainError("act entry missing required iss (actor-profile)");
    }
    if ("client_profile" in entry) {
      throw new ActorChainError("client_profile MUST NOT appear inside an act object");
    }
    for (const token of parseSubProfile(entry.sub_profile as string | undefined)) {
      if (!PROFILE_TOKEN.test(token)) {
        throw new ActorChainError(`invalid sub_profile token: ${token}`);
      }
      // Unknown-but-syntactically-valid values are preserved, not rejected
      // (entity-profiles pass-through rule). Registered values are a subset.
    }
  }
  return flat;
}

export interface ContextActor {
  client_id?: string;
  client_instance_id?: string;
  act?: FlatActEntry[];
}

/**
 * Build the AuthZEN `context.actor` from a validated token (PEP-side, D31).
 * `act` is omitted when there is no delegation (self-acting).
 */
export function buildContextActor(input: {
  clientId?: string;
  clientInstanceId?: string;
  act?: ActObject;
  maxDepth?: number;
}): ContextActor {
  const out: ContextActor = {};
  if (input.clientId !== undefined) out.client_id = input.clientId;
  if (input.clientInstanceId !== undefined) out.client_instance_id = input.clientInstanceId;
  const chain = validateActChain(input.act, { maxDepth: input.maxDepth ?? DEFAULT_MAX_DEPTH });
  if (chain.length > 0) out.act = chain;
  return out;
}

/**
 * PDP-side shape/consistency validation of a supplied context.actor (D31):
 * non-empty entries, iss/sub per entry, root consistent with subject, leaf
 * consistent with client_instance_id when both are present.
 */
export function validateContextActor(actor: ContextActor, opts: { subject?: string } = {}): void {
  if (!actor.act || actor.act.length === 0) return;
  for (const entry of actor.act) {
    if (typeof entry.iss !== "string" || typeof entry.sub !== "string") {
      throw new ActorChainError("context.actor.act entry missing iss/sub");
    }
  }
  const leaf = actor.act[actor.act.length - 1];
  if (
    actor.client_instance_id !== undefined &&
    leaf !== undefined &&
    parseSubProfile(leaf.sub_profile as string | undefined).includes("client_instance") &&
    leaf.sub !== actor.client_instance_id
  ) {
    throw new ActorChainError("leaf act.sub inconsistent with client_instance_id");
  }
}

/**
 * Construct a new chain by installing `newActor` as the immediate (outermost)
 * actor over a validated inbound chain (@spec actor-profile: new outermost act,
 * inbound chain preserved verbatim beneath). Returns the nested claim.
 */
export function extendChain(
  newActor: FlatActEntry & { sub: string; iss: string },
  inbound: ActObject | undefined,
): ActObject {
  return { ...newActor, ...(inbound ? { act: inbound } : {}) };
}
