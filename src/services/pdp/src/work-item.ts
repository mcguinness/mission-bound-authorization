/**
 * @spec harness#work-item-identity, authzen#context-work-item,
 * authzen#decision-conditions `work_item`, runtime-evidence#evidence-extensions
 * `work_item` (#815): the qualified work-item identifier on the decision path.
 *
 * A harness assigns the identifier, binds it to one Mission and attaches it
 * as two extension members of the propagated Mission reference. The PEP takes
 * it only from that attachment, and only where the Enforcement Scope
 * Statement names the harness that issued it as the attacher for the client
 * the PEP authenticated; it then rides the decision request as
 * `context.work_item`, the permit's `work_item` condition, and Decision and
 * Execution Evidence. This module holds the one reader each of those sites
 * applies, and the statement's work-item declaration.
 */

import { canonicalize, type JsonValue } from "@mission/core";

/**
 * @spec authzen#context-work-item: "An object with exactly two members, both
 * strings: `issuer`, the URI of the harness that issued the identifier, and
 * `id`, that harness's identifier for the work item."
 */
export interface WorkItemRef {
  issuer: string;
  id: string;
}

const WORK_ITEM_ID_MAX = 256;
const WORK_ITEM_ISSUER_MAX = 512;

/**
 * The value as a work item, or `undefined` when it is not exactly an object
 * with two non-empty, bounded string members `issuer` and `id`. Never
 * repairs a value: a member too many, too few, or of another type is not a
 * work item.
 */
export function parseWorkItem(value: unknown): WorkItemRef | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 2 || !keys.includes("issuer") || !keys.includes("id")) return undefined;
  const { issuer, id } = record;
  if (typeof issuer !== "string" || typeof id !== "string") return undefined;
  if (issuer.length === 0 || id.length === 0) return undefined;
  if (issuer.length > WORK_ITEM_ISSUER_MAX || id.length > WORK_ITEM_ID_MAX) return undefined;
  return { issuer, id };
}

/**
 * @spec authzen#decision-conditions `work_item`: the executing PEP's
 * comparison at use. Both absent holds; one present without the other, a
 * malformed one, or two that differ in either member fails.
 */
export function sameWorkItem(a: unknown, b: unknown): boolean {
  if (a === undefined && b === undefined) return true;
  const x = parseWorkItem(a);
  const y = parseWorkItem(b);
  if (!x || !y) return false;
  return canonicalize(x as unknown as JsonValue) === canonicalize(y as unknown as JsonValue);
}

/**
 * The statement extension name and claim. A reference-statement
 * representation, not a Runtime wire member: the runtime profile's statement
 * records which party attaches a work item and the classes a deployment
 * claims work-item attribution for.
 */
export const WORK_ITEM_ATTRIBUTION_EXTENSION = "work_item_attribution";

/**
 * @spec harness#work-item-identity: the statement's work-item declaration.
 * `attachers` maps each authenticated client to the harness the statement
 * names as its work-item attacher; `claimedClasses` holds the action classes
 * the statement claims work-item attribution (the `work-item-attributed`
 * composition) for, and is empty unless `claims` names the extension. A
 * declaration without the claim still names attachers: their work items are
 * carried, and Mission-level attribution is all the deployment claims.
 */
export interface WorkItemAttribution {
  attachers: ReadonlyMap<string, string>;
  claimedClasses: ReadonlySet<string>;
}

/** A statement declaring nothing: no attacher, no claimed class. */
export const NO_WORK_ITEM_ATTRIBUTION: WorkItemAttribution = Object.freeze({
  attachers: new Map<string, string>(),
  claimedClasses: new Set<string>(),
});

function objectOf(v: unknown): Record<string, unknown> | undefined {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

/**
 * Read the work-item declaration from an Enforcement Scope Statement, refusing
 * at load (throwing) a declaration that cannot be read in full: an attacher
 * missing its client or harness, one client mapped to two harnesses, a covered
 * class outside `mediated_scope.action_classes`, or a claim with no attacher
 * or no covered class. A statement with no declaration declares nothing.
 */
export function readWorkItemAttribution(statement: unknown): WorkItemAttribution {
  const stmt = objectOf(statement) ?? {};
  const claims = Array.isArray(stmt.claims) ? (stmt.claims as unknown[]) : [];
  const claimed = claims.includes(WORK_ITEM_ATTRIBUTION_EXTENSION);
  const decl = objectOf(objectOf(stmt.extensions)?.[WORK_ITEM_ATTRIBUTION_EXTENSION]);
  if (!decl) {
    if (claimed) throw new Error(`${WORK_ITEM_ATTRIBUTION_EXTENSION} is claimed but carries no declaration`);
    return NO_WORK_ITEM_ATTRIBUTION;
  }
  const attachers = new Map<string, string>();
  for (const raw of Array.isArray(decl.attachers) ? (decl.attachers as unknown[]) : []) {
    const a = objectOf(raw);
    const clientId = a?.client_id;
    const harness = a?.harness;
    if (typeof clientId !== "string" || clientId === "" || typeof harness !== "string" || harness === "") {
      throw new Error(`${WORK_ITEM_ATTRIBUTION_EXTENSION}: an attacher names no client_id or no harness`);
    }
    const prior = attachers.get(clientId);
    if (prior !== undefined && prior !== harness) {
      throw new Error(`${WORK_ITEM_ATTRIBUTION_EXTENSION}: client ${clientId} names two harnesses`);
    }
    attachers.set(clientId, harness);
  }
  const mediated = Array.isArray(objectOf(stmt.mediated_scope)?.action_classes)
    ? (objectOf(stmt.mediated_scope)?.action_classes as unknown[])
    : [];
  const covered = Array.isArray(decl.covered_classes) ? (decl.covered_classes as unknown[]) : [];
  for (const c of covered) {
    if (typeof c !== "string" || !mediated.includes(c)) {
      throw new Error(`${WORK_ITEM_ATTRIBUTION_EXTENSION}: covered class ${String(c)} is outside mediated_scope.action_classes`);
    }
  }
  if (claimed && (attachers.size === 0 || covered.length === 0)) {
    throw new Error(`${WORK_ITEM_ATTRIBUTION_EXTENSION} is claimed with no attacher or no covered class`);
  }
  return {
    attachers,
    claimedClasses: claimed ? new Set(covered as string[]) : new Set<string>(),
  };
}
