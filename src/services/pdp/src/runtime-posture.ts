import { RUNTIME_SCOPE_CONFIG } from "@mission/demo-data";
import { type EnforcementScopeStatement, validateEnforcementScopeStatement } from "./enforcement-scope.js";

/**
 * The action classes this deployment declares a freshness posture for: the
 * six runtime action classes of `runtime#classification` plus the freshness
 * table's `audit_only` row. `mediated_scope.action_classes` is a narrower,
 * separate declaration (what the deployment claims runtime enforcement for);
 * a row here is a freshness-table row, not an enforcement claim.
 */
export const RUNTIME_CLASSES = ["non_consequential", "consequential_read", "consequential_write", "irreversible_action", "external_commitment", "privileged_administration", "audit_only"] as const;
type ActionClass = typeof RUNTIME_CLASSES[number];
type BoundedClass = { freshness_posture: "bounded"; max_staleness_seconds: number; recovery_objective_seconds: number; beyond_bound: "deny" };
type UnboundedClass = { freshness_posture: "none" };
type ClassDeclaration = BoundedClass | UnboundedClass;
export type RuntimePosture = EnforcementScopeStatement & {
  state_source: EnforcementScopeStatement["state_source"] & {
    mission_max_stale_seconds: number;
    per_class: Record<ActionClass, ClassDeclaration>;
    unknown_action_class: "deny";
    availability_consequence: string;
    replication: "none";
    break_glass: "absent";
  };
};

/**
 * @spec runtime#state-freshness — the resolved freshness posture for one
 * action class. `bounded` carries the declared window in seconds; `none` is
 * the draft's "No active freshness required" row, an explicit posture and
 * never a zero or absent bound; `undeclared` is a label the deployment's
 * policy does not declare, which is a request fault, not a freshness fact.
 */
export type StalenessBound =
  | { kind: "bounded"; seconds: number }
  | { kind: "none" }
  | { kind: "undeclared" };

/** Fail-fast load-time configuration error (demo-data's ConfigError style). */
export class PostureConfigError extends Error {
  constructor(why: string) {
    super(`invalid runtime posture: ${why}`);
    this.name = "ConfigError";
  }
}

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
  if (findings.length) throw new PostureConfigError(JSON.stringify(findings));
  const state = (input as EnforcementScopeStatement).state_source as unknown as Record<string, unknown>;
  const fail = (why: string): never => { throw new PostureConfigError(why); };
  if (state.pdp_unavailability_posture !== "deny") fail("only deny is implemented; bounded permit reuse is not available");
  if (!positive(state.mission_max_stale_seconds)) fail("mission_max_stale_seconds must be a positive integer");
  if (!positive(state.max_staleness_seconds) || state.max_staleness_seconds > (state.mission_max_stale_seconds as number)) fail("state bound exceeds issuer ceiling");
  if (state.unknown_action_class !== "deny" || state.replication !== "none" || state.break_glass !== "absent") fail("unsupported unknown-class, replication, or emergency mode");
  if (typeof state.availability_consequence !== "string" || !state.availability_consequence.trim()) fail("availability consequence missing");
  if (!object(state.per_class)) fail("per-class bounds missing");
  const classes = state.per_class as Record<string, unknown>;
  // A class key the code does not declare a posture for is a configuration
  // error refused here, never a label the PDP meets for the first time at
  // decision time.
  for (const key of Object.keys(classes)) {
    if (!RUNTIME_CLASSES.includes(key as ActionClass)) fail(`undeclared action class: ${key}`);
  }
  for (const name of RUNTIME_CLASSES) {
    const value = classes[name];
    if (!object(value)) fail(`invalid class declaration: ${name}`);
    const declared = value as Record<string, unknown>;
    // Every declared class states its freshness posture. `none` carries no
    // window, and a class that claims a bound supplies a positive one inside
    // the state bound: a class lacking a bound where one is required refuses
    // at load rather than resolving to zero.
    if (declared.freshness_posture === "none") {
      if (declared.max_staleness_seconds !== undefined || declared.beyond_bound !== undefined) fail(`class with no active freshness carries a bound: ${name}`);
      continue;
    }
    if (declared.freshness_posture !== "bounded") fail(`class declares no freshness posture: ${name}`);
    if (!positive(declared.max_staleness_seconds) || (declared.max_staleness_seconds as number) > (state.max_staleness_seconds as number)
      || !positive(declared.recovery_objective_seconds) || declared.beyond_bound !== "deny") fail(`invalid class bound: ${name}`);
  }
  return freeze(structuredClone(input) as RuntimePosture);
}

export const RUNTIME_POSTURE = loadRuntimePosture(RUNTIME_SCOPE_CONFIG);

/**
 * @spec runtime#ride-through, runtime#state-freshness — the declared
 * freshness posture for one action class. A missing class label is the
 * existing consequential-read default. Every declared class resolves to the
 * posture the deployment published: a window, or explicitly no active
 * freshness requirement (the draft's Audit-only row). A label outside the
 * declared set resolves to `undeclared`, which the decision point refuses;
 * it never inherits the least restrictive class and is never reported as a
 * staleness fact.
 */
export function postureStalenessBound(posture: RuntimePosture, actionClass: string | undefined): StalenessBound {
  const name = actionClass ?? "consequential_read";
  if (!Object.hasOwn(posture.state_source.per_class, name)) return { kind: "undeclared" };
  const declared = posture.state_source.per_class[name as ActionClass];
  return declared.freshness_posture === "none"
    ? { kind: "none" }
    : { kind: "bounded", seconds: declared.max_staleness_seconds };
}
