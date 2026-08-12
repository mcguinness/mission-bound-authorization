/**
 * @spec mission#authorization-derivation, mission#other-types
 * @spec I-D.draft-zehavi-oauth-rar-metadata (authorization_details_types_metadata_endpoint)
 *
 * The AS's single source of truth for which `authorization_details` types it
 * advertises/supports, each with its published JSON Schema. Both the AS
 * metadata endpoint (provider.ts) and the authority-proposal intake check
 * (intent.ts, @spec mission#authority-proposal) consult the SAME key set
 * exported here, so "an entry whose type is not an advertised type"
 * (@spec mission#other-types) cannot drift out of sync with what the metadata
 * endpoint actually publishes.
 */

import type { JsonValue } from "@mission/core";

/** @spec mission#authorization-derivation — the sole type this AS derives. */
export const MISSION_RESOURCE_ACCESS_TYPE = "mission_resource_access" as const;

/** draft-zehavi-oauth-rar-metadata §5 — one type's published metadata entry. */
export interface AuthorizationDetailsTypeMetadata {
  version?: string;
  description?: string;
  documentation_uri?: string;
  /** Mutually exclusive with schema_uri (draft-zehavi §5); this AS always inlines `schema`. */
  schema: Record<string, JsonValue>;
  examples?: JsonValue[];
}

/**
 * @spec mission#authorization-derivation — the JSON Schema for one
 * `mission_resource_access` authorization_details object (the type's
 * normative definition remains {{type-registration}}; this is its
 * machine-readable form). `constraints` covers the Common Constraints
 * structure (@spec mission#common-constraints): `max_amount`/`vendors` are
 * shaped explicitly (the two this derivation engine narrows, see derive.ts);
 * other registered Common Constraint keys are left open
 * (`additionalProperties: true`) since the schema describes wire SHAPE, not
 * which keys this engine implements narrowing for. draft-zehavi §5: the
 * schema "MUST restrict the `type` attribute" — done via `const` below.
 */
export const MISSION_RESOURCE_ACCESS_SCHEMA: Record<string, JsonValue> = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "urn:ietf:params:oauth:authorization-details-type:mission_resource_access",
  title: "Mission Resource Access",
  type: "object",
  properties: {
    type: { const: MISSION_RESOURCE_ACCESS_TYPE },
    resource: { type: "string", format: "uri" },
    actions: { type: "array", items: { type: "string" }, minItems: 1 },
    constraints: {
      type: "object",
      description: "Common Constraints (@spec mission#common-constraints)",
      properties: {
        max_amount: {
          type: "object",
          properties: { amount: { type: "string" }, currency: { type: "string" } },
          required: ["amount", "currency"],
          additionalProperties: false,
        },
        vendors: { type: "array", items: { type: "string" } },
      },
      additionalProperties: true,
    },
    delegation: {
      type: "object",
      description: "@spec attenuation#delegation, child-delegation#fanout",
      properties: {
        max_depth: { type: "integer", minimum: 0 },
        allowed_delegates: {
          type: "array",
          items: {
            type: "object",
            properties: { sub: { type: "string" }, sub_profile: { type: "string" } },
            additionalProperties: true,
          },
        },
        // @spec child-delegation#fanout — the per-entry child-creation controls.
        // `allowed_child_actors` is the same matcher shape as `allowed_delegates`
        // (shared vocabulary); both are now schema-covered so neither rides on
        // additionalProperties.
        children: {
          type: "object",
          description: "@spec child-delegation#fanout — per-entry child-creation controls",
          properties: {
            max_children: { type: "integer", minimum: 0 },
            max_child_depth: { type: "integer", minimum: 1 },
            allowed_child_actors: {
              type: "array",
              items: {
                type: "object",
                properties: { sub: { type: "string" }, sub_profile: { type: "string" } },
                additionalProperties: true,
              },
            },
            child_creation_policy: { type: "string" },
          },
          additionalProperties: true,
        },
      },
      required: ["max_depth"],
      additionalProperties: true,
    },
  },
  required: ["type", "resource", "actions"],
  additionalProperties: true,
};

/**
 * draft-zehavi-oauth-rar-metadata §5 response body: a JSON object keyed by
 * authorization_details type identifier. The key set here IS
 * `authorization_details_types_supported` (@spec mission#other-types) — the
 * endpoint enriches that list with schemas, it does not add to it.
 */
export const AUTHORIZATION_DETAILS_TYPES_METADATA: Readonly<Record<string, AuthorizationDetailsTypeMetadata>> = {
  [MISSION_RESOURCE_ACCESS_TYPE]: {
    version: "1",
    description:
      "A Mission's Authority Set entry: one (resource, actions[]) grant plus its Common Constraints and delegation policy. A client MAY submit entries of this type on the standard authorization_details parameter alongside mission_intent, as a proposal subject to derivation (@spec mission#authority-proposal); granted entries on issued tokens are issuer-derived, never the submission carried through by right.",
    documentation_uri: "https://github.com/mcguinness/mission-bound-authorization",
    schema: MISSION_RESOURCE_ACCESS_SCHEMA,
    examples: [
      {
        type: MISSION_RESOURCE_ACCESS_TYPE,
        resource: "https://payments.example/mcp",
        actions: ["payments:invoice.read"],
      },
    ],
  },
};

/**
 * The advertised/supported authorization_details type identifiers — the SAME
 * set the metadata endpoint publishes and the authority-proposal intake check
 * (intent.ts) consults. Single source of truth (@spec mission#other-types):
 * an entry of a type not in this set is refused, never silently carried.
 */
export const SUPPORTED_AUTHORIZATION_DETAILS_TYPES: ReadonlySet<string> = new Set(
  Object.keys(AUTHORIZATION_DETAILS_TYPES_METADATA),
);

/** The full endpoint response body (draft-zehavi §5). */
export function authorizationDetailsTypesMetadata(): Record<string, AuthorizationDetailsTypeMetadata> {
  return AUTHORIZATION_DETAILS_TYPES_METADATA;
}

/**
 * Schema-conformance check for one `mission_resource_access` object
 * (draft-zehavi §5: the published schema "MUST validate exactly one
 * authorization details object"). Hand-rolled (no JSON Schema engine is a
 * dependency of this workspace) but mirrors MISSION_RESOURCE_ACCESS_SCHEMA
 * structurally member-for-member; returns a violation description on the
 * first mismatch, else undefined. Callers MUST check the type is advertised
 * (SUPPORTED_AUTHORIZATION_DETAILS_TYPES) before calling this — it assumes
 * `type` is already `mission_resource_access` and does not re-check it.
 */
export function validateMissionResourceAccessSchema(entry: unknown): string | undefined {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
    return "authorization_details entry must be an object";
  }
  const e = entry as Record<string, unknown>;
  if (typeof e.resource !== "string") return "resource must be a string";
  if (!Array.isArray(e.actions) || e.actions.length === 0 || !e.actions.every((a) => typeof a === "string")) {
    return "actions must be a non-empty array of strings";
  }
  if (e.constraints !== undefined) {
    if (e.constraints === null || typeof e.constraints !== "object" || Array.isArray(e.constraints)) {
      return "constraints must be an object";
    }
    const c = e.constraints as Record<string, unknown>;
    if (c.max_amount !== undefined) {
      if (
        c.max_amount === null ||
        typeof c.max_amount !== "object" ||
        Array.isArray(c.max_amount) ||
        typeof (c.max_amount as Record<string, unknown>).amount !== "string" ||
        typeof (c.max_amount as Record<string, unknown>).currency !== "string"
      ) {
        return "constraints.max_amount must be an object with string amount and currency";
      }
    }
    if (c.vendors !== undefined) {
      if (!Array.isArray(c.vendors) || !c.vendors.every((v) => typeof v === "string")) {
        return "constraints.vendors must be an array of strings";
      }
    }
  }
  if (e.delegation !== undefined) {
    if (e.delegation === null || typeof e.delegation !== "object" || Array.isArray(e.delegation)) {
      return "delegation must be an object";
    }
    const d = e.delegation as Record<string, unknown>;
    if (typeof d.max_depth !== "number" || !Number.isInteger(d.max_depth) || d.max_depth < 0) {
      return "delegation.max_depth must be a non-negative integer";
    }
    if (d.allowed_delegates !== undefined) {
      const err = validateMatcherList(d.allowed_delegates, "delegation.allowed_delegates");
      if (err) return err;
    }
    // @spec child-delegation#fanout — the per-entry `children` controls, including
    // the `allowed_child_actors` matcher list (same shape as allowed_delegates).
    if (d.children !== undefined) {
      if (d.children === null || typeof d.children !== "object" || Array.isArray(d.children)) {
        return "delegation.children must be an object";
      }
      const ch = d.children as Record<string, unknown>;
      if (
        ch.max_children !== undefined &&
        (typeof ch.max_children !== "number" || !Number.isInteger(ch.max_children) || ch.max_children < 0)
      ) {
        return "delegation.children.max_children must be a non-negative integer";
      }
      if (
        ch.max_child_depth !== undefined &&
        (typeof ch.max_child_depth !== "number" ||
          !Number.isInteger(ch.max_child_depth) ||
          ch.max_child_depth < 1)
      ) {
        return "delegation.children.max_child_depth must be a positive integer";
      }
      if (ch.child_creation_policy !== undefined && typeof ch.child_creation_policy !== "string") {
        return "delegation.children.child_creation_policy must be a string";
      }
      if (ch.allowed_child_actors !== undefined) {
        const err = validateMatcherList(ch.allowed_child_actors, "delegation.children.allowed_child_actors");
        if (err) return err;
      }
    }
  }
  return undefined;
}

/**
 * Shared structural check for a delegate-matcher list (`allowed_delegates` /
 * `allowed_child_actors`): an array of objects each with optional string `sub` /
 * `sub_profile`. Returns a violation description or undefined. Mirrors the
 * runtime matcher's shape ({@link DelegateMatcher}).
 */
function validateMatcherList(value: unknown, path: string): string | undefined {
  if (!Array.isArray(value)) return `${path} must be an array`;
  for (const m of value) {
    if (m === null || typeof m !== "object" || Array.isArray(m)) {
      return `${path} entries must be objects`;
    }
    const mm = m as Record<string, unknown>;
    if (mm.sub !== undefined && typeof mm.sub !== "string") return `${path}.sub must be a string`;
    if (mm.sub_profile !== undefined && typeof mm.sub_profile !== "string") {
      return `${path}.sub_profile must be a string`;
    }
  }
  return undefined;
}
