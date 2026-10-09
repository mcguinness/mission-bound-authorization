/**
 * @spec mission#lifecycle, mission#termination: the pure lifecycle views the
 * kernel reads through: the stored-row normalizer (persisted truth, no clock)
 * and the expiry observation (the time view every gate and emitter uses).
 *
 * Two layers stay separate. {@link normalizeStoredLifecycle} turns what a row
 * holds into `active`, `suspended` or `terminated` with its recorded
 * {@link Termination}; it never applies the clock, because every
 * compare-and-set binds the stored state. {@link observeExpiry} applies the
 * clock: from `expires_at`, a Mission still `active` or `suspended` is
 * `terminated` with reason `expired` for every decision, whether or not that
 * transition has been persisted.
 */

import { COMMIT_IS_EFFECT_REASONS } from "@mission/core";
import type { LifecycleCommit, MissionRecord, MissionState, Termination } from "./types.js";

/**
 * @spec mission#termination (transition-period reading): the terminal state
 * values a record, event or signed artifact committed before the termination
 * vocabulary can hold, and the reason each reads as (`cascaded` as
 * `parent_terminated`). A read-side view only: never re-emitted or re-signed.
 */
export const LEGACY_TERMINAL_REASONS: ReadonlyMap<string, string> = new Map([
  ["revoked", "revoked"],
  ["expired", "expired"],
  ["completed", "completed"],
  ["superseded", "superseded"],
  ["cascaded", "parent_terminated"],
]);

/** The reason a terminated row reads as when its stored termination is unreadable. */
export const UNKNOWN_TERMINATION_REASON = "unknown";

const STRING_MEMBERS = ["terminated_at", "successor", "parent", "origin", "origin_reason", "carried_to"] as const;

/**
 * Parse a stored or received `termination` value: an object with a non-empty
 * string `reason`, keeping each well-typed known member and dropping any
 * other. Undefined when malformed. Never fills a member in.
 */
export function parseTermination(value: unknown): Termination | undefined {
  let v = value;
  if (typeof v === "string") {
    try {
      v = JSON.parse(v);
    } catch {
      return undefined;
    }
  }
  if (v === null || typeof v !== "object" || Array.isArray(v)) return undefined;
  const t = v as Record<string, unknown>;
  if (typeof t.reason !== "string" || t.reason === "") return undefined;
  const out: Termination = { reason: t.reason };
  for (const member of STRING_MEMBERS) {
    const m = t[member];
    if (typeof m === "string" && m !== "") out[member] = m;
  }
  if (typeof t.version === "number" && Number.isSafeInteger(t.version) && t.version >= 1) {
    out.version = t.version;
  }
  return out;
}

/**
 * @spec mission#termination: the lifecycle a stored row reads as, fail
 * closed. `active` and `suspended` read as themselves while no termination is
 * stored. `terminated` reads its stored termination; a missing or malformed
 * one reads as reason {@link UNKNOWN_TERMINATION_REASON} with no other
 * member. A legacy terminal value reads as `terminated` with that reason,
 * folding the legacy `successor` / `carried_to` columns and, for `cascaded`,
 * the record's own lineage parent into the termination; a member the row
 * never retained stays absent (no invented `terminated_at` or `version`).
 * Any other stored value reads as `terminated` with the raw value as its
 * reason: never active, never suspended.
 */
export function normalizeStoredLifecycle(row: {
  state: unknown;
  terminationJson?: unknown;
  successor?: unknown;
  carriedTo?: unknown;
  parentId?: unknown;
  /** The retained state version of the transition that committed the legacy terminal state. */
  version?: unknown;
  /** The record's `expires_at`, the effective instant of an `expired` termination. */
  expiresAt?: unknown;
  /** The retained commit time, used only for a reason whose commit is its effect. */
  committedAt?: unknown;
}): { state: MissionState; termination?: Termination } {
  const stored = row.terminationJson == null ? undefined : row.terminationJson;
  if ((row.state === "active" || row.state === "suspended") && stored === undefined) {
    return { state: row.state };
  }
  if (row.state === "terminated" || row.state === "active" || row.state === "suspended") {
    // A termination is written only with `terminated`; one stored beside any
    // other state is inconsistent and reads terminated (fail closed).
    return {
      state: "terminated",
      termination: parseTermination(stored) ?? { reason: UNKNOWN_TERMINATION_REASON },
    };
  }
  if (typeof row.state !== "string" || row.state === "") {
    return { state: "terminated", termination: { reason: UNKNOWN_TERMINATION_REASON } };
  }
  const legacy = LEGACY_TERMINAL_REASONS.get(row.state);
  if (legacy === undefined) return { state: "terminated", termination: { reason: row.state } };
  const termination: Termination = { reason: legacy };
  if (legacy === "superseded" && typeof row.successor === "string" && row.successor !== "") {
    termination.successor = row.successor;
  }
  if (legacy === "parent_terminated") {
    if (typeof row.parentId === "string" && row.parentId !== "") termination.parent = row.parentId;
    if (typeof row.carriedTo === "string" && row.carriedTo !== "") termination.carried_to = row.carriedTo;
  }
  // Retained facts only (#705, D359 owner rulings): the committing
  // transition's state version; for `expired`, the record's `expires_at`;
  // and a retained commit time only where the commit is the effect. Nothing
  // else is filled in.
  if (typeof row.version === "number" && Number.isSafeInteger(row.version) && row.version >= 1) {
    termination.version = row.version;
  }
  if (legacy === "expired") {
    if (typeof row.expiresAt === "string" && row.expiresAt !== "") termination.terminated_at = row.expiresAt;
  } else if (COMMIT_IS_EFFECT_REASONS.has(legacy) && typeof row.committedAt === "string" && row.committedAt !== "") {
    termination.terminated_at = row.committedAt;
  }
  return { state: "terminated", termination };
}

/**
 * @spec mission#lifecycle: the expiry observation. A record `active` or
 * `suspended` at or after its `expires_at` is observed `terminated` with
 * `{reason: "expired", terminated_at: expires_at}` (no `version` until the
 * transition commits). A record already `terminated` is returned unchanged:
 * expiry never replaces a recorded cause or its references.
 */
export function observeExpiry(record: MissionRecord, nowMs: number): MissionRecord {
  if ((record.state === "active" || record.state === "suspended") && Date.parse(record.expires_at) <= nowMs) {
    return {
      ...record,
      state: "terminated",
      termination: { reason: "expired", terminated_at: record.expires_at },
    };
  }
  return record;
}

/**
 * @spec child-delegation#cascade: the `parent_terminated` termination a
 * child of `parent` takes when `parent` terminates: `parent` is the immediate
 * parent, `terminated_at` the parent's own (the cascade propagates one
 * instant), and `origin` / `origin_reason` name the ancestor whose
 * termination started the cascade (provenance only). A member the parent's
 * termination does not hold is omitted, never invented: a parent recorded
 * without `terminated_at` (a legacy termination) gives a child termination
 * without one, and the child's commit time is recorded on its commit, never
 * as `terminated_at`.
 */
export function parentTerminatedTermination(parent: { id: string; termination?: Termination }): Termination {
  const pt = parent.termination;
  const at = pt?.terminated_at;
  const inherited = pt?.reason === "parent_terminated";
  const origin = inherited ? pt?.origin : parent.id;
  const originReason = inherited ? pt?.origin_reason : pt?.reason;
  return {
    reason: "parent_terminated",
    ...(at ? { terminated_at: at } : {}),
    parent: parent.id,
    ...(origin ? { origin } : {}),
    ...(originReason ? { origin_reason: originReason } : {}),
  };
}

/**
 * @spec mission#termination (transition-period reading): a lifecycle commit
 * persisted before the termination vocabulary (outbox payload version 1),
 * normalized in memory: a legacy terminal `state` reads as `terminated` with
 * that reason, and the top-level `successor` / `carried_to` fold into its
 * `termination`. The stored bytes are never rewritten. A commit already in
 * the current vocabulary is returned unchanged.
 */
export function normalizeLegacyCommit<C extends LifecycleCommit>(commit: C): C {
  const raw = commit as C & { successor?: unknown; carried_to?: unknown };
  const { successor, carried_to: carriedTo, ...rest } = raw;
  const state = rest.state as unknown;
  if (state === "active" || state === "suspended" || state === "terminated") {
    if (successor === undefined && carriedTo === undefined) return commit;
    return rest as unknown as C;
  }
  // `prior_state` is never terminal (a terminated Mission commits no further
  // transition), so it passes through unchanged.
  const normalized = normalizeStoredLifecycle({
    state,
    successor,
    carriedTo,
    version: rest.version,
    expiresAt: rest.expires_at,
    committedAt: rest.committed_at,
  });
  return {
    ...rest,
    state: normalized.state,
    ...(normalized.termination ? { termination: normalized.termination } : {}),
  } as unknown as C;
}
