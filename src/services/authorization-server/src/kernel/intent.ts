/**
 * @spec mission#submission-via-par
 * @spec mission#mission-intent
 * Mission Intent intake: strict parse (duplicate member names rejected),
 * closed top level, required members, bounded size, proposed_authority
 * resources contained in the Intent's resources.
 */

import { DuplicateMemberError, type JsonValue, parseStrictJson } from "@mission/core";
import type { AuthorityEntry, MissionIntent } from "./types.js";

const TOP_LEVEL = new Set([
  "goal",
  "resources",
  "expires_at",
  "constraints",
  "proposed_authority",
  "success_criteria",
  "purpose",
  "controls",
]);

const MAX_INTENT_BYTES = 65536;
const MAX_ARRAY_LEN = 64;
const MAX_GOAL_CHARS = 4096;

export class IntentError extends Error {
  constructor(
    readonly code: "invalid_request" | "invalid_authorization_details",
    message: string,
  ) {
    super(message);
  }
}

export function validateMissionIntent(raw: string): MissionIntent {
  if (Buffer.byteLength(raw, "utf8") > MAX_INTENT_BYTES) {
    throw new IntentError("invalid_request", "mission_intent exceeds size bound");
  }
  let parsed: JsonValue;
  try {
    parsed = parseStrictJson(raw);
  } catch (e) {
    if (e instanceof DuplicateMemberError) {
      throw new IntentError("invalid_request", e.message);
    }
    throw new IntentError("invalid_request", "mission_intent must be valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new IntentError("invalid_request", "mission_intent must be a JSON object");
  }
  const obj = parsed as Record<string, JsonValue>;

  // Closed top level (@spec mission#submission-via-par).
  for (const key of Object.keys(obj)) {
    if (!TOP_LEVEL.has(key)) {
      throw new IntentError("invalid_request", `unknown top-level member: ${key}`);
    }
  }

  const goal = obj.goal;
  if (typeof goal !== "string" || goal.length === 0 || goal.length > MAX_GOAL_CHARS) {
    throw new IntentError("invalid_request", "goal is required (string, <= 4096 chars)");
  }
  const resources = obj.resources;
  if (!isStringArray(resources) || resources.length === 0 || resources.length > MAX_ARRAY_LEN) {
    throw new IntentError("invalid_request", "resources is required (non-empty string array)");
  }
  for (const r of resources) {
    if (!isAbsoluteUri(r)) throw new IntentError("invalid_request", `resource is not an absolute URI: ${r}`);
  }
  const expiresAt = obj.expires_at;
  if (typeof expiresAt !== "string" || Number.isNaN(Date.parse(expiresAt))) {
    throw new IntentError("invalid_request", "expires_at is required (RFC 3339 date-time)");
  }

  for (const member of ["constraints", "success_criteria"] as const) {
    const v = obj[member];
    if (v !== undefined && (!isStringArray(v) || v.length > MAX_ARRAY_LEN)) {
      throw new IntentError("invalid_request", `${member} must be a string array`);
    }
  }
  if (obj.purpose !== undefined && typeof obj.purpose !== "string") {
    throw new IntentError("invalid_request", "purpose must be a string");
  }

  const controls = obj.controls;
  if (controls !== undefined) {
    if (controls === null || typeof controls !== "object" || Array.isArray(controls)) {
      throw new IntentError("invalid_request", "controls must be an object");
    }
    const md = (controls as Record<string, JsonValue>).max_derivations;
    if (md !== undefined && (typeof md !== "number" || !Number.isInteger(md) || md < 1)) {
      // @spec mission#mission-intent: max_derivations below 1 -> invalid_request
      throw new IntentError("invalid_request", "max_derivations must be an integer >= 1");
    }
  }

  const proposed = obj.proposed_authority;
  if (proposed !== undefined) {
    if (!Array.isArray(proposed) || proposed.length > MAX_ARRAY_LEN) {
      throw new IntentError("invalid_request", "proposed_authority must be an array");
    }
    for (const entry of proposed) {
      validateProposedEntry(entry, resources);
    }
  }

  return obj as unknown as MissionIntent;
}

function validateProposedEntry(entry: JsonValue, resources: string[]): void {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    throw new IntentError("invalid_request", "proposed_authority entries must be objects");
  }
  const e = entry as Record<string, JsonValue>;
  if (e.type !== "mission_resource_access") {
    throw new IntentError("invalid_authorization_details", `unsupported authorization details type: ${String(e.type)}`);
  }
  if (typeof e.resource !== "string") {
    throw new IntentError("invalid_request", "proposed_authority entry requires resource");
  }
  // @spec mission#mission-intent: each entry's resource MUST be among resources.
  if (!resources.includes(e.resource)) {
    throw new IntentError("invalid_request", `proposed_authority resource not among Intent resources: ${e.resource}`);
  }
  if (!isStringArray(e.actions) || e.actions.length === 0) {
    throw new IntentError("invalid_request", "proposed_authority entry requires actions");
  }
}

function isStringArray(v: JsonValue | undefined): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

function isAbsoluteUri(v: string): boolean {
  try {
    const u = new URL(v);
    return u.protocol.length > 0;
  } catch {
    return false;
  }
}
