/**
 * @spec resource-access#qualified-narrowing, mission#transformation-capabilities
 * (#1377, D1025): the shipped transformation-capability declaration, and the
 * loader that refuses to start on a declaration this server cannot validate.
 */
import { readFileSync } from "node:fs";
import { narrowingDomainDigest } from "@mission/core";
import { describe, expect, it } from "vitest";
import { loadTransformationCapabilities, TRANSFORMATION_CAPABILITIES } from "../src/index.js";

const CONFIG = new URL("../../../config/", import.meta.url);
const read = (path: string) => readFileSync(new URL(path, CONFIG), "utf8");
const SHIPPED = read("transformation-capabilities.json");
const DOMAIN_PATH = "narrowing-domains/mission-resource-access-2026-10-29.json";
const DOMAIN = JSON.parse(read(DOMAIN_PATH)) as Record<string, unknown>;
const declaredValue = (): { domain: { id: string; digest: string } } =>
  (
    JSON.parse(SHIPPED) as {
      types: { mission_resource_access: { narrowing: { domain: { id: string; digest: string } } } };
    }
  ).types.mission_resource_access.narrowing;

/** The shipped file with its narrowing value replaced, and domain documents served from `docs`. */
function load(narrowing: unknown, docs: Record<string, unknown> = { [DOMAIN_PATH]: DOMAIN }) {
  const config = JSON.parse(SHIPPED) as {
    types: { mission_resource_access: Record<string, unknown> };
  };
  config.types.mission_resource_access.narrowing = narrowing;
  return loadTransformationCapabilities(JSON.stringify(config), (path) => {
    if (!(path in docs)) throw new Error(`no ${path}`);
    return JSON.stringify(docs[path]);
  });
}

describe("the shipped transformation-capability declaration (@spec resource-access#qualified-narrowing)", () => {
  it("declares narrowing for mission_resource_access as a qualified value naming the reference's narrowing domain, and nothing else", () => {
    expect(Object.keys(TRANSFORMATION_CAPABILITIES.declared)).toEqual(["mission_resource_access"]);
    expect(
      Object.keys(TRANSFORMATION_CAPABILITIES.declared.mission_resource_access ?? {}).sort(),
    ).toEqual(["delegation", "narrowing", "projection"]);
    expect(TRANSFORMATION_CAPABILITIES.delegation).toBe(true);
    expect(TRANSFORMATION_CAPABILITIES.projection).toBe(true);
    const { narrowing } = TRANSFORMATION_CAPABILITIES;
    expect(narrowing.kind).toBe("domain");
    if (narrowing.kind !== "domain") return;
    expect(narrowing.digest).toBe(narrowingDomainDigest(DOMAIN as never));
    expect(narrowing.domain.resource_match).toEqual(["exact", "prefix"]);
    expect(narrowing.domain.limitations).toEqual(["delegate-matcher-identity"]);
  });
});

describe("the loader refuses to start on a declaration it cannot validate (@spec resource-access#qualified-narrowing)", () => {
  it("refuses a mismatched digest, an unknown member, an unavailable document and a malformed document", () => {
    const value = declaredValue();
    expect(load(value).narrowing.kind).toBe("domain");
    expect(() =>
      load({ domain: { ...value.domain, digest: narrowingDomainDigest({ other: true }) } }),
    ).toThrow(/digest/);
    expect(() => load({ ...value, scope: "all" })).toThrow(/no member 'scope'/);
    expect(() => load(value, {})).toThrow(/no /);
    const malformed = { ...DOMAIN, resource_match: ["glob"] };
    expect(() =>
      load(
        { domain: { ...value.domain, digest: narrowingDomainDigest(malformed as never) } },
        { [DOMAIN_PATH]: malformed },
      ),
    ).toThrow(/resource_match/);
  });

  it("refuses a domain listing a constraints key whose rules this implementation does not implement", () => {
    const value = declaredValue();
    const claiming = { ...DOMAIN, constraints: [...(DOMAIN.constraints as string[]), "x_region"] };
    expect(() =>
      load(
        { domain: { ...value.domain, digest: narrowingDomainDigest(claiming as never) } },
        { [DOMAIN_PATH]: claiming },
      ),
    ).toThrow(/x_region/);
  });

  it("resolves delegation and projection only from an explicit true: omitted or false is undeclared", () => {
    const shipped = JSON.parse(SHIPPED) as {
      types: { mission_resource_access: Record<string, unknown> };
    };
    const variant = (members: Record<string, unknown>) => {
      const config = structuredClone(shipped);
      const entry = config.types.mission_resource_access;
      delete entry.delegation;
      delete entry.projection;
      Object.assign(entry, members);
      return loadTransformationCapabilities(JSON.stringify(config), (path) =>
        JSON.stringify(path === DOMAIN_PATH ? DOMAIN : {}),
      );
    };
    for (const members of [{}, { delegation: false, projection: false }]) {
      const caps = variant(members);
      expect(caps.delegation, JSON.stringify(members)).toBe(false);
      expect(caps.projection, JSON.stringify(members)).toBe(false);
    }
    const declared = variant({ delegation: true, projection: true });
    expect(declared.delegation).toBe(true);
    expect(declared.projection).toBe(true);
    expect(() => variant({ delegation: "yes" })).toThrow(/delegation must be a boolean/);
  });

  it("keeps true and false, and an absent narrowing member declares nothing", () => {
    expect(load(true).narrowing.kind).toBe("full");
    expect(load(false).narrowing.kind).toBe("undeclared");
    expect(load(undefined).narrowing.kind).toBe("undeclared");
  });
});
