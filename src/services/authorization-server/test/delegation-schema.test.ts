/**
 * The published RAR metadata schema (@spec draft-zehavi-oauth-rar-metadata Section 5)
 * for `mission_resource_access` covers BOTH delegation vocabularies: the core
 * `allowed_delegates` and the child-delegation `delegation.children.allowed_child_actors`.
 * Neither rides on `additionalProperties` any longer. This exercises both the
 * declarative schema (structure) and the hand-rolled structural validator.
 */

import { describe, expect, it } from "vitest";
import {
  MISSION_RESOURCE_ACCESS_SCHEMA,
  MISSION_RESOURCE_ACCESS_TYPE,
  validateMissionResourceAccessSchema,
} from "../src/index.js";

const base = {
  type: MISSION_RESOURCE_ACCESS_TYPE,
  resource: "https://erp.example.com/mcp",
  actions: ["invoices.read"],
};

describe("MISSION_RESOURCE_ACCESS_SCHEMA — delegation.children is schema-covered", () => {
  it("declares delegation.children with its four members (allowed_child_actors, ...)", () => {
    const schema = MISSION_RESOURCE_ACCESS_SCHEMA as Record<string, never>;
    const delegation = (schema.properties as Record<string, never>).delegation as Record<string, never>;
    const children = (delegation.properties as Record<string, never>).children as Record<string, never>;
    const props = children.properties as Record<string, unknown>;
    expect(Object.keys(props).sort()).toEqual(
      ["allowed_child_actors", "child_creation_policy", "max_child_depth", "max_children"].sort(),
    );
  });
});

describe("validateMissionResourceAccessSchema — allowed_child_actors validation", () => {
  it("accepts a well-formed delegation.children with allowed_child_actors matchers", () => {
    expect(
      validateMissionResourceAccessSchema({
        ...base,
        delegation: {
          max_depth: 2,
          allowed_delegates: [{ sub_profile: "ai_agent" }],
          children: {
            max_children: 5,
            max_child_depth: 2,
            allowed_child_actors: [{ sub_profile: "ai_agent" }, { sub: "subagent-1" }],
            child_creation_policy: "urn:policy:child-drawdown:v1",
          },
        },
      }),
    ).toBeUndefined();
  });

  it("rejects a non-array allowed_child_actors", () => {
    expect(
      validateMissionResourceAccessSchema({
        ...base,
        delegation: { max_depth: 2, children: { allowed_child_actors: "ai_agent" } },
      }),
    ).toMatch(/allowed_child_actors must be an array/);
  });

  it("rejects a non-string sub_profile inside allowed_child_actors", () => {
    expect(
      validateMissionResourceAccessSchema({
        ...base,
        delegation: { max_depth: 2, children: { allowed_child_actors: [{ sub_profile: 42 }] } },
      }),
    ).toMatch(/allowed_child_actors\.sub_profile must be a string/);
  });

  it("rejects a non-object delegation.children and a bad max_child_depth", () => {
    expect(
      validateMissionResourceAccessSchema({ ...base, delegation: { max_depth: 2, children: [] } }),
    ).toMatch(/delegation\.children must be an object/);
    expect(
      validateMissionResourceAccessSchema({
        ...base,
        delegation: { max_depth: 2, children: { max_child_depth: 0 } },
      }),
    ).toMatch(/max_child_depth must be a positive integer/);
  });

  it("still validates allowed_delegates (unchanged, via the shared matcher check)", () => {
    expect(
      validateMissionResourceAccessSchema({
        ...base,
        delegation: { max_depth: 2, allowed_delegates: [{ sub: 7 }] },
      }),
    ).toMatch(/allowed_delegates\.sub must be a string/);
  });
});
