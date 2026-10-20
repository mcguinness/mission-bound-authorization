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

import {
  delegateMatcherListViolation,
  entryDelegateMatcherViolation,
  isAbsoluteUri,
  isActivationPolicyRef,
  isImplementedCommonConstraint,
  refusedEntryMember,
  SUPPORTED_CONSTRAINT_KEYS,
  type JsonValue,
  validCommonConstraint,
} from "@mission/core";

/** @spec mission#authorization-derivation — the sole type this AS derives. */
export const MISSION_RESOURCE_ACCESS_TYPE = "mission_resource_access" as const;

/**
 * @spec resource-access#resource-access-type, resource-access#entry-validation
 * (#1376): one `actions` value, matched as a whole: an action identifier
 * (`[A-Za-z0-9_.:-]+`), or an action family, an identifier followed by `.*`.
 * Anchored and without the `m` flag, so a character outside the grammar
 * anywhere in the value, a trailing newline included, fails it.
 */
export const ACTION_VALUE = /^[A-Za-z0-9_.:-]+(?:\.\*)?$/;

/**
 * @spec resource-access#matching-allowed-delegates, child-delegation#fanout
 * (#1373): one delegate matcher, the item of both `allowed_delegates` and
 * `allowed_child_actors`. Closed to `sub` and `sub_profile`, at least one
 * present, each a non-empty string: the published form of the shared rule
 * {@link validateMissionResourceAccessSchema} applies
 * (`delegateMatcherListViolation`).
 */
const DELEGATE_MATCHER_SCHEMA: Record<string, JsonValue> = {
  type: "object",
  properties: { sub: { type: "string", minLength: 1 }, sub_profile: { type: "string", minLength: 1 } },
  minProperties: 1,
  additionalProperties: false,
};

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
 * structure (@spec mission#common-constraints), its member set CLOSED
 * (`additionalProperties: false`) to exactly {@link SUPPORTED_CONSTRAINT_KEYS}
 * (issue #784): every initial Mission Resource Access Common Constraint
 * (`max_amount`, `requires_action_approval`, and the seven of #1266, whose
 * shared semantics are in `@mission/core`'s common-constraints.ts),
 * `terminal_when`, and `vendors`, a deployment-defined key this engine also
 * narrows though the common registry does not carry it. A `constraints`
 * member outside that set (a Common Constraint registered later, or any other
 * key) is refused here rather than admitted and then silently dropped by
 * derivation: this schema describes exactly what the engine supports.
 * draft-zehavi §5: the schema "MUST restrict the `type` attribute" — done via
 * `const` below.
 *
 * @spec resource-access#entry-validation (#1278, D457): `locations` is
 * prohibited by name (`"locations": false`), not by closing the top level:
 * `additionalProperties` stays `true`, so a member another specification
 * defines for this type (such as `capability_sources`) remains possible.
 * {@link validateMissionResourceAccessSchema} enforces the same prohibition.
 */
export const MISSION_RESOURCE_ACCESS_SCHEMA: Record<string, JsonValue> = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "urn:ietf:params:oauth:authorization-details-type:mission_resource_access",
  title: "Mission Resource Access",
  type: "object",
  properties: {
    type: { const: MISSION_RESOURCE_ACCESS_TYPE },
    resource: { type: "string", format: "uri" },
    // @spec resource-access#entry-validation (#1278): this type does not use
    // the RFC 9396 common `locations` field; its presence, whatever its value,
    // fails the schema.
    locations: false,
    // @spec resource-access#entry-validation (#1376): non-empty, each value an
    // action identifier or an action family ({@link ACTION_VALUE}).
    actions: { type: "array", items: { type: "string", pattern: ACTION_VALUE.source }, minItems: 1 },
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
        // @spec txn-authorization#applicability — monotonic-OR gate; `false`
        // is equivalent to omission (derive.ts).
        requires_action_approval: { type: "boolean" },
        // @spec discharge#terminal-when — the completion-condition constraint. Its
        // member set is CLOSED (additionalProperties: false): condition identity
        // is byte equality of the canonical form, which `condition_digest`
        // digests, so an unrecognized member would silently change identity.
        terminal_when: {
          type: "array",
          minItems: 1,
          items: {
            type: "object",
            properties: { event_type: { type: "string" }, discharge_authority: { type: "string" } },
            required: ["event_type"],
            additionalProperties: false,
          },
        },
        // @spec resource-access#initial-common-constraints (#1266): RFC 3339
        // date-time values compared as UTC instants (common-constraints.ts).
        resource_issued_after: { type: "string", format: "date-time" },
        resource_issued_before: { type: "string", format: "date-time" },
        // Exact string comparison against the resource's own tenant record.
        tenant: { type: "string", minLength: 1 },
        // At least one bound; an absent bound is unbounded on its side.
        time_window: {
          type: "object",
          properties: {
            not_before: { type: "string", format: "date-time" },
            not_after: { type: "string", format: "date-time" },
          },
          minProperties: 1,
          additionalProperties: false,
        },
        // A DNS name; compared case-insensitively on whole labels.
        recipient_domain: { type: "string", format: "hostname" },
        // Exact-string labels; an empty list admits no data.
        data_classification: { type: "array", items: { type: "string", minLength: 1 } },
        // Exact-string tool identities; an empty list admits no tool.
        allowed_tools: { type: "array", items: { type: "string", minLength: 1 } },
      },
      // @spec mission#derivation-policy (issue #784) — CLOSED to
      // SUPPORTED_CONSTRAINT_KEYS: an unsupported key is refused at intake,
      // not admitted then dropped at derivation.
      additionalProperties: false,
    },
    delegation: {
      type: "object",
      description: "@spec attenuation#delegation, child-delegation#fanout",
      properties: {
        max_depth: { type: "integer", minimum: 0 },
        allowed_delegates: { type: "array", items: DELEGATE_MATCHER_SCHEMA },
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
            allowed_child_actors: { type: "array", items: DELEGATE_MATCHER_SCHEMA },
            child_creation_policy: {
              type: "object",
              properties: {
                id: { type: "string" },
                version: { type: "string" },
                digest: { type: "string", pattern: "^sha-256:[A-Za-z0-9_-]{43}$" },
              },
              required: ["id", "version", "digest"],
              additionalProperties: false,
            },
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
  // @spec resource-access#entry-validation (#1278, D457): the schema's
  // `"locations": false`, enforced by presence before any other member is
  // read, so `[]`, `null` or a malformed value is refused like a populated
  // array.
  const refused = refusedMemberViolation(entry);
  if (refused) return refused;
  const e = entry as Record<string, unknown>;
  if (typeof e.resource !== "string") return "resource must be a string";
  // @spec resource-access#entry-validation (#1310, D480): the schema's
  // `format: "uri"`, enforced with the shared RFC 3986 check; the value is
  // kept as submitted.
  if (!isAbsoluteUri(e.resource)) {
    return `resource ${JSON.stringify(e.resource)} is not an RFC 3986 absolute URI`;
  }
  // @spec resource-access#resource-matching (#1264, D446): this authorization
  // server implements `exact` resource matching only. Any other value is
  // refused at intake, never admitted and then rebuilt as an exact entry.
  if (e.resource_match !== undefined && e.resource_match !== "exact") {
    return `resource_match ${JSON.stringify(e.resource_match)} is not supported; this authorization server implements exact resource matching only`;
  }
  if (!Array.isArray(e.actions) || e.actions.length === 0 || !e.actions.every((a) => typeof a === "string")) {
    return "actions must be a non-empty array of strings";
  }
  // @spec resource-access#entry-validation (#1376): each value matches the
  // action grammar as a whole, so an identifier the namespace cannot carry
  // is refused at intake rather than admitted and never matched.
  const malformedAction = e.actions.find((a) => !ACTION_VALUE.test(a));
  if (malformedAction !== undefined) {
    return `actions value ${JSON.stringify(malformedAction)} is neither an action identifier nor an action family`;
  }
  if (e.constraints !== undefined) {
    if (e.constraints === null || typeof e.constraints !== "object" || Array.isArray(e.constraints)) {
      return "constraints must be an object";
    }
    const c = e.constraints as Record<string, unknown>;
    // @spec mission#derivation-policy (issue #784) — the member set is CLOSED
    // to SUPPORTED_CONSTRAINT_KEYS (the SAME declaration {@link
    // isAuthorityEntry} enforces at the config-load boundary): an entry
    // carrying a constraint this engine cannot compare is refused here,
    // never admitted and then silently dropped by derivation's fixed
    // four-key rebuild.
    for (const key of Object.keys(c)) {
      if (!(SUPPORTED_CONSTRAINT_KEYS as readonly string[]).includes(key)) {
        return `constraints carries unsupported key '${key}'`;
      }
    }
    if (c.requires_action_approval !== undefined && typeof c.requires_action_approval !== "boolean") {
      return "constraints.requires_action_approval must be a boolean";
    }
    // @spec resource-access#initial-common-constraints (#1266): each
    // implemented Common Constraint's value syntax, from the shared table the
    // config loader, derivation and the resource server also read.
    for (const key of Object.keys(c)) {
      if (isImplementedCommonConstraint(key) && !validCommonConstraint(key, c[key])) {
        return `constraints.${key} is malformed`;
      }
    }
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
    // @spec discharge#terminal-when — one or more completion conditions, each a
    // CLOSED { event_type, discharge_authority? } object (identity is the canonical
    // form of exactly these members). The `discharge_authority` charset and its
    // resolution against the issuer-held mapping are checked at derivation and
    // record creation (@spec discharge#discharge-authority), not here: this is the
    // wire-shape gate the published schema describes.
    if (c.terminal_when !== undefined) {
      if (!Array.isArray(c.terminal_when) || c.terminal_when.length === 0) {
        return "constraints.terminal_when must be a non-empty array of completion conditions";
      }
      for (const condition of c.terminal_when) {
        if (condition === null || typeof condition !== "object" || Array.isArray(condition)) {
          return "constraints.terminal_when entries must be objects";
        }
        const cc = condition as Record<string, unknown>;
        if (typeof cc.event_type !== "string") {
          return "constraints.terminal_when entries need a string event_type";
        }
        if (cc.discharge_authority !== undefined && typeof cc.discharge_authority !== "string") {
          return "constraints.terminal_when discharge_authority must be a string";
        }
        for (const k of Object.keys(cc)) {
          if (k !== "event_type" && k !== "discharge_authority") {
            return `constraints.terminal_when entries carry no member '${k}'`;
          }
        }
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
    // @spec resource-access#matching-allowed-delegates (#1373): the shared
    // matcher rule, applied before derivation can rebuild a matcher without a
    // member it does not recognize.
    if (d.allowed_delegates !== undefined) {
      const err = delegateMatcherListViolation(d.allowed_delegates, "delegation.allowed_delegates");
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
      if (ch.child_creation_policy !== undefined && !isActivationPolicyRef(ch.child_creation_policy)) {
        return "delegation.children.child_creation_policy must be an activation policy reference (id, version, digest)";
      }
      if (ch.allowed_child_actors !== undefined) {
        const err = delegateMatcherListViolation(
          ch.allowed_child_actors,
          "delegation.children.allowed_child_actors",
        );
        if (err) return err;
      }
    }
  }
  return undefined;
}

/**
 * @spec resource-access#entry-validation (#1278, D457): the violation for a
 * `mission_resource_access` entry carrying a member this type refuses by
 * name ({@link refusedEntryMember}: `locations`), or undefined. Shared by the
 * schema check above and by the token-exchange and deferred intakes that read
 * requested entries without it, each refusing `invalid_authorization_details`.
 */
export function refusedMemberViolation(entry: unknown): string | undefined {
  const member = refusedEntryMember(entry);
  return member === undefined
    ? undefined
    : `${member} must be absent: the ${MISSION_RESOURCE_ACCESS_TYPE} type does not use this RFC 9396 common field`;
}

/**
 * {@link refusedMemberViolation} over a requested `authorization_details`
 * array, for an intake that reads requested entries without the schema check:
 * the first `mission_resource_access` entry carrying a refused member yields
 * the violation. Entries of another type are left to the intake's own checks,
 * since the refusal applies only to this type.
 */
export function refusedMemberInRequest(entries: readonly unknown[]): string | undefined {
  for (const entry of entries) {
    if ((entry as { type?: unknown } | null)?.type !== MISSION_RESOURCE_ACCESS_TYPE) continue;
    const violation = refusedMemberViolation(entry);
    if (violation) return violation;
  }
  return undefined;
}

/**
 * @spec resource-access#matching-allowed-delegates, child-delegation#fanout
 * (#1373): the shared delegate-matcher rule over a requested
 * `authorization_details` array, for the same intakes as
 * {@link refusedMemberInRequest}: the first `mission_resource_access` entry
 * whose `allowed_delegates` or `allowed_child_actors` carries a malformed
 * matcher yields the violation (`entryDelegateMatcherViolation`, which applies
 * `delegateMatcherListViolation`). Each intake's subset check reads a matcher's
 * `sub` and `sub_profile` only, so a matcher carrying another member would be
 * admitted, then issued either rebuilt without the member (a projection) or
 * carrying a member no enforcement point reads (the deferred grant).
 */
export function malformedMatcherInRequest(entries: readonly unknown[]): string | undefined {
  for (const entry of entries) {
    if ((entry as { type?: unknown } | null)?.type !== MISSION_RESOURCE_ACCESS_TYPE) continue;
    const violation = entryDelegateMatcherViolation(entry);
    if (violation) return violation;
  }
  return undefined;
}
