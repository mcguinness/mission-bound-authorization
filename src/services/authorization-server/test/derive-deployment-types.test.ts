/**
 * @spec mission#other-types, mission#proposal-derivation, mission#subset
 * (#2019 review): derivation and the source-ceiling gate hold each entry to
 * its own type's rules. An entry of a deployment-defined type is held to that
 * type's documented definition and compared by equality; every other entry to
 * the built-in `mission_resource_access` rules and relation. So a valid entry
 * of one type never refuses a derivation for another type's request, and an
 * invalid entry of either type is still refused under its own type's rules.
 *
 * Pure, in-memory, no network.
 */

import { generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import { assertWithinSourceCeiling } from "../src/kernel/authority-source.js";
import {
  type AuthorityEntry,
  type DeploymentDefinedTypes,
  deriveAuthoritySetWithProvenance,
  IntentError,
  type MissionIntent,
  MissionKernel,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";
import { FAR_EXPIRES_AT } from "./relative-expiry.helper.js";

const R = "https://r.example/mcp";
const TYPE = "urn:example:records";

/** A deployment-defined type: the four members it shares with the built-in type, and an optional non-empty `tenant_id` of its own. */
const TYPES: DeploymentDefinedTypes = {
  [TYPE]: {
    metadata: { schema: { type: "object" } },
    validate(entry) {
      const extra = Object.keys(entry).find((m) => !["type", "resource", "resource_match", "actions", "tenant_id"].includes(m));
      if (extra !== undefined) return `${extra} is not a member of ${TYPE}`;
      if (entry.tenant_id !== undefined && (typeof entry.tenant_id !== "string" || entry.tenant_id.length === 0)) {
        return "tenant_id must be a non-empty string";
      }
      return undefined;
    },
  },
};

const READ: AuthorityEntry = { type: "mission_resource_access", resource: R, actions: ["res.read", "res.list"] };
/** The type's entry carrying `tenant_id`, which the built-in rules refuse as an unsupported member. */
const TENANT = { type: TYPE, resource: R, actions: ["res.read"], tenant_id: "acme" } as unknown as AuthorityEntry;
const intent: MissionIntent = { goal: "g", target_resources: [R], expires_at: FAR_EXPIRES_AT };

function derive(ceiling: readonly AuthorityEntry[], proposal: readonly AuthorityEntry[]): AuthorityEntry[] {
  return deriveAuthoritySetWithProvenance(
    intent,
    { policy_version: "p", ceiling },
    proposal,
    undefined,
    undefined,
    undefined,
    undefined,
    TYPES,
  ).entries;
}

function refusal(run: () => unknown): string | undefined {
  try {
    run();
  } catch (e) {
    if (e instanceof IntentError) return e.code;
    throw e;
  }
  return undefined;
}

describe("derivation holds each ceiling and proposal entry to its own type's rules (#2019 review; @spec mission#other-types, mission#proposal-derivation)", () => {
  it("a mission_resource_access proposal derives under the built-in rules beside a deployment-defined ceiling entry carrying a member of its own", () => {
    const narrower: AuthorityEntry = { ...READ, actions: ["res.read"] };
    expect(derive([READ, TENANT], [narrower])).toEqual([narrower]);
  });

  it("a proposal of the deployment-defined type equal to its ceiling entry is retained unchanged in the same mixed ceiling", () => {
    expect(derive([READ, TENANT], [structuredClone(TENANT)])).toEqual([TENANT]);
  });

  it("a ceiling entry failing its own type's rules refuses the derivation invalid_authorization_details: a mission_resource_access entry carrying tenant_id under the built-in rules, and a deployment-defined entry under its own definition", () => {
    const builtInWithTenant = { ...READ, tenant_id: "acme" } as unknown as AuthorityEntry;
    const emptyTenant = { ...TENANT, tenant_id: "" } as unknown as AuthorityEntry;
    expect(refusal(() => derive([READ, builtInWithTenant], [READ]))).toBe("invalid_authorization_details");
    expect(refusal(() => derive([READ, emptyTenant], [READ]))).toBe("invalid_authorization_details");
    // A proposed entry of either type failing its own rules is refused the same way.
    expect(refusal(() => derive([READ, TENANT], [builtInWithTenant]))).toBe("invalid_authorization_details");
    expect(refusal(() => derive([READ, TENANT], [emptyTenant]))).toBe("invalid_authorization_details");
  });
});

describe("an approval adds no built-in member to a deployment-defined entry (#2019 review; @spec mission#transformation-capabilities, resource-access#resource-contract)", () => {
  it("where configuration requires a resource_contract for the built-in type's entry at a resource, the deployment-defined entry there is derived without one, as approved", async () => {
    const { privateKey: statusKey } = await generateKeyPair("ES256", { extractable: true });
    // The shipped payments contract requires a reference for this action at this resource.
    const payments = "http://localhost:4403/mcp";
    const execute: AuthorityEntry = { type: "mission_resource_access", resource: payments, actions: ["payments:payment.execute"] };
    const records = { type: TYPE, resource: payments, actions: ["payments:payment.execute"] } as unknown as AuthorityEntry;
    const ceiling = [execute, records];
    const kernel = new MissionKernel({
      issuer: "https://as.test",
      policy: { policy_version: "p", ceiling } as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(ceiling, ["agent"], ["bob"]),
      statusKey,
      statusKid: "as-status",
      deploymentTypes: TYPES,
    });
    const paymentsIntent: MissionIntent = { goal: "g", target_resources: [payments], expires_at: FAR_EXPIRES_AT };
    const [built] = kernel.derive(paymentsIntent, [execute]);
    expect(built?.resource_contract).toBeDefined();
    expect(kernel.derive(paymentsIntent, [structuredClone(records)])).toEqual([records]);
  });
});

describe("the source-ceiling gate compares each entry under its own type (#2019 review; @spec mission#authority-sources, mission#subset)", () => {
  const source = (ceiling: readonly AuthorityEntry[]) => ({
    id: "src",
    type: "user_delegated" as const,
    clients: ["agent"],
    activators: ["bob"],
    ceiling,
  });
  /** The type's entry with the built-in members only, so the built-in relation could read it. */
  const BROAD = { type: TYPE, resource: R, actions: ["res.read", "res.list"] } as unknown as AuthorityEntry;
  const NARROW = { type: TYPE, resource: R, actions: ["res.read"] } as unknown as AuthorityEntry;

  it("a deployment-defined entry lies within the source ceiling only by equality, while a mission_resource_access entry beside it is compared under the built-in relation", () => {
    const gate = (set: readonly AuthorityEntry[]) =>
      refusal(() => assertWithinSourceCeiling(source([READ, BROAD, TENANT]), set, TYPES));
    expect(gate([BROAD, TENANT])).toBeUndefined();
    expect(gate([{ ...READ, actions: ["res.read"] }])).toBeUndefined();
    // Narrower under the built-in relation, but no relation is known for the type.
    expect(gate([NARROW])).toBe("access_denied");
  });
});
