import { RUNTIME_SCOPE_CONFIG } from "@mission/demo-data";
import { type EnforcementScopeStatement, validateEnforcementScopeStatement } from "./enforcement-scope.js";

export const RUNTIME_CLASSES = ["consequential_read", "consequential_write", "irreversible_action", "external_commitment", "privileged_administration"] as const;
type ActionClass = typeof RUNTIME_CLASSES[number];
type ClassBound = { max_staleness_seconds: number; recovery_objective_seconds: number; beyond_bound: "deny" };
export type RuntimePosture = EnforcementScopeStatement & {
  state_source: EnforcementScopeStatement["state_source"] & {
    mission_max_stale_seconds: number;
    per_class: Record<ActionClass, ClassBound>;
    unknown_action_class: "deny";
    availability_consequence: string;
    replication: "none";
    break_glass: "absent";
  };
};
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const positive = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
function freeze<T>(v: T): T {
  if (v !== null && typeof v === "object") { for (const child of Object.values(v)) freeze(child); Object.freeze(v); }
  return v;
}

/** @spec runtime#runtime-operational, status#status-operational — executable,
 * published deployment policy, not evidence of implementing optional modes. */
export function loadRuntimePosture(input: unknown): RuntimePosture {
  const findings = validateEnforcementScopeStatement(input);
  if (findings.length) throw new Error(`invalid runtime posture: ${JSON.stringify(findings)}`);
  const state = (input as EnforcementScopeStatement).state_source as unknown as Record<string, unknown>;
  const fail = (why: string): never => { throw new Error(`invalid runtime posture: ${why}`); };
  if (state.pdp_unavailability_posture !== "deny") fail("only deny is implemented; bounded permit reuse is not available");
  if (!positive(state.mission_max_stale_seconds)) fail("mission_max_stale_seconds must be a positive integer");
  if (!positive(state.max_staleness_seconds) || state.max_staleness_seconds > (state.mission_max_stale_seconds as number)) fail("state bound exceeds issuer ceiling");
  if (state.unknown_action_class !== "deny" || state.replication !== "none" || state.break_glass !== "absent") fail("unsupported unknown-class, replication, or emergency mode");
  if (typeof state.availability_consequence !== "string" || !state.availability_consequence.trim()) fail("availability consequence missing");
  if (!object(state.per_class)) fail("per-class bounds missing");
  const classes = state.per_class as Record<string, unknown>;
  if (Object.keys(classes).some(k => !RUNTIME_CLASSES.includes(k as ActionClass))) fail("unknown class declaration");
  for (const name of RUNTIME_CLASSES) {
    const value = classes[name];
    if (!object(value) || !positive(value.max_staleness_seconds) || value.max_staleness_seconds > (state.max_staleness_seconds as number)
      || !positive(value.recovery_objective_seconds) || value.beyond_bound !== "deny") fail(`invalid class bound: ${name}`);
  }
  return freeze(structuredClone(input) as RuntimePosture);
}

export const RUNTIME_POSTURE = loadRuntimePosture(RUNTIME_SCOPE_CONFIG);

/**
 * @spec runtime#ride-through — missing class is the existing consequential-read
 * default; unknown labels refuse (zero bound) rather than inheriting the least
 * restrictive class.
 */
export function postureStalenessBound(posture: RuntimePosture, actionClass: string | undefined): number {
  const name = actionClass ?? "consequential_read";
  return Object.hasOwn(posture.state_source.per_class, name)
    ? posture.state_source.per_class[name as ActionClass].max_staleness_seconds : 0;
}
