/**
 * @spec capability-binding#capability-source-binding — the COMMITTED per-action
 * shape: where bindings enter (the validating server's resolution, attached in
 * `approve` before `authority_hash`), what refuses, and how the subset rule
 * treats them. Presentation and decision-time comparison are separate changes.
 */

import { authorityHash, type CapabilitySourceBinding, capabilitySourceDigest, catalogDigest, extractMcpToolDefinition } from "@mission/core";
import { CATALOG_SERVICES, DERIVATION_POLICY, TRUSTED_TOOL_CATALOGS } from "@mission/demo-data";
import { TOOLS } from "@mission/mcp-payments";
import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  attachCapabilitySources,
  type AuthorityEntry,
  type CapabilitySourceResolution,
  IntentError,
  isSubsetEntry,
  isSubsetSet,
  MissionKernel,
  projectThroughEffective,
  validateAuthorityProposal,
  validateMissionIntent,
} from "../src/index.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const READ_ACTION = "payments:invoice.read";
const WRITE_ACTION = "payments:payment.schedule";

const CATALOG = TRUSTED_TOOL_CATALOGS.find((c) => c.service_id === "payments")!;

const bindingFor = (action: string, operationRef: string): CapabilitySourceBinding => ({
  action,
  tool_id: `mcp://payments.test/tools/${operationRef}`,
  source_uri: "https://payments.test/.well-known/mcp",
  source_digest: capabilitySourceDigest({ name: operationRef, description: "x" }),
  operation_ref: operationRef,
});

const resolution = (action: string, operationRef: string): CapabilitySourceResolution => ({
  resource: RESOURCE,
  action,
  binding: bindingFor(action, operationRef),
});

let kernel: MissionKernel;
beforeAll(async () => {
  const { privateKey } = await generateKeyPair("ES256");
  kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    statusKey: privateKey,
    statusKid: "as-status",
  });
});

let seq = 0;
const approve = (resolutions?: CapabilitySourceResolution[]) =>
  kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Pay Acme invoices",
        target_resources: [RESOURCE],
        expires_at: "2027-01-01T00:00:00Z",
      }),
    ),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-cap-${(seq += 1)}`,
    ...(resolutions ? { capabilityResolution: resolutions } : {}),
  });

const entryFor = (record: { authority_set: AuthorityEntry[] }, action: string) =>
  record.authority_set.find((e) => e.actions.includes(action)) as AuthorityEntry;

describe("Kernel.approve: bindings enter before authority_hash", () => {
  it("attaches nothing when no action resolves as catalog-sourced", () => {
    const record = approve();
    for (const entry of record.authority_set) {
      // The member is ABSENT, never an empty array: JCS commits an empty
      // array, so attaching one everywhere would move every authority_hash.
      expect("capability_sources" in entry).toBe(false);
    }
    expect(record.authority_hash).toBe(authorityHash(ISS, record.authority_set as never));
  });

  it("commits the attached bindings: authority_hash moves and reproduces", () => {
    const bare = approve();
    const bound = approve([resolution(READ_ACTION, "get_invoice")]);
    expect(entryFor(bound, READ_ACTION).capability_sources).toEqual([
      bindingFor(READ_ACTION, "get_invoice"),
    ]);
    expect(bound.authority_hash).toBe(authorityHash(ISS, bound.authority_set as never));
    expect(bound.authority_hash).not.toBe(bare.authority_hash);
  });

  it("binds per action: a mixed entry carries bindings for its catalog-sourced actions only", () => {
    const record = approve([resolution(READ_ACTION, "get_invoice")]);
    const readEntry = entryFor(record, READ_ACTION);
    expect(readEntry.actions.length).toBeGreaterThan(1);
    expect(readEntry.capability_sources?.map((b) => b.action)).toEqual([READ_ACTION]);
    // The money-carrying entry for the same resource stays first-party here.
    expect("capability_sources" in entryFor(record, WRITE_ACTION)).toBe(false);
  });

  it("permits several tool_id values for one action", () => {
    const extra = {
      ...resolution(READ_ACTION, "get_invoice"),
      binding: { ...bindingFor(READ_ACTION, "get_invoice"), tool_id: "mcp://payments.test/tools/get_invoice_v2" },
    };
    const record = approve([resolution(READ_ACTION, "get_invoice"), extra]);
    expect(entryFor(record, READ_ACTION).capability_sources).toHaveLength(2);
  });

  it("commits a reproducible order whatever order the resolution arrives in", () => {
    const a = resolution(READ_ACTION, "get_invoice");
    const b = resolution("payments:invoice.list", "list_invoices");
    expect(approve([a, b]).authority_hash).toBe(approve([b, a]).authority_hash);
  });

  it("refuses an unresolvable catalog-sourced action rather than approving it unbound", () => {
    expect(() => approve([{ resource: RESOURCE, action: READ_ACTION }])).toThrow(IntentError);
    expect(() => approve([{ resource: RESOURCE, action: READ_ACTION }])).toThrow(
      /could not be resolved/,
    );
  });

  it("refuses a resolution naming an action the derived Authority Set does not carry", () => {
    expect(() => approve([resolution("payments:ledger.write", "write_ledger")])).toThrow(
      /the derived Authority Set does not carry/,
    );
  });

  it("refuses a binding whose action disagrees with the resolution's", () => {
    const mismatched: CapabilitySourceResolution = {
      resource: RESOURCE,
      action: READ_ACTION,
      binding: bindingFor(WRITE_ACTION, "schedule_payment"),
    };
    expect(() => approve([mismatched])).toThrow(/names action/);
  });

  it("refuses a repeated (action, tool_id) pair on one entry", () => {
    const dup = {
      ...resolution(READ_ACTION, "get_invoice"),
      binding: { ...bindingFor(READ_ACTION, "get_invoice"), operation_ref: "other" },
    };
    expect(() => approve([resolution(READ_ACTION, "get_invoice"), dup])).toThrow(
      /duplicate capability source/,
    );
  });

  it("refuses an unrecognized digest algorithm prefix", () => {
    const bad = {
      ...resolution(READ_ACTION, "get_invoice"),
      binding: { ...bindingFor(READ_ACTION, "get_invoice"), source_digest: "sha-512:AAAA" },
    };
    expect(() => approve([bad])).toThrow(/unrecognized source_digest algorithm prefix/);
  });
});

describe("attachCapabilitySources: addressing", () => {
  it("attaches one resolution to every derived entry sharing the resource and action", () => {
    const entries: AuthorityEntry[] = [
      { type: "mission_resource_access", resource: RESOURCE, actions: [READ_ACTION] },
      { type: "mission_resource_access", resource: RESOURCE, actions: [READ_ACTION, WRITE_ACTION] },
      { type: "mission_resource_access", resource: "https://other.test/mcp", actions: [READ_ACTION] },
    ];
    const out = attachCapabilitySources(entries, [resolution(READ_ACTION, "get_invoice")]);
    expect(out[0]?.capability_sources).toHaveLength(1);
    expect(out[1]?.capability_sources).toHaveLength(1);
    expect("capability_sources" in (out[2] as AuthorityEntry)).toBe(false);
  });

  it("returns the input unchanged when there is no resolution", () => {
    const entries: AuthorityEntry[] = [
      { type: "mission_resource_access", resource: RESOURCE, actions: [READ_ACTION] },
    ];
    expect(attachCapabilitySources(entries)).toBe(entries);
    expect(attachCapabilitySources(entries, [])).toBe(entries);
  });
});

describe("derivation: a proposal can never introduce a binding", () => {
  it("drops capability_sources carried on an untrusted proposal", () => {
    const proposal = validateAuthorityProposal(
      JSON.stringify([
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: [READ_ACTION],
          capability_sources: [bindingFor(READ_ACTION, "get_invoice")],
        },
      ]),
      [RESOURCE],
    );
    const derived = kernel.derive(
      validateMissionIntent(
        JSON.stringify({
          goal: "Pay Acme invoices",
          target_resources: [RESOURCE],
          expires_at: "2027-01-01T00:00:00Z",
        }),
      ),
      proposal,
    );
    expect(derived.length).toBeGreaterThan(0);
    for (const entry of derived) expect("capability_sources" in entry).toBe(false);
  });
});

describe("isSubsetEntry: monotonic derivation of recorded bindings", () => {
  const granted: AuthorityEntry = {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: [READ_ACTION, WRITE_ACTION],
    capability_sources: [bindingFor(READ_ACTION, "get_invoice")],
  };

  it("retains the action with its binding byte-identical", () => {
    expect(isSubsetEntry({ ...granted }, granted)).toBe(true);
  });

  it("drops the catalog-sourced action entirely (strictly narrower)", () => {
    expect(
      isSubsetEntry(
        { type: "mission_resource_access", resource: RESOURCE, actions: [WRITE_ACTION] },
        granted,
      ),
    ).toBe(true);
  });

  it("refuses retaining the action with the binding dropped", () => {
    expect(
      isSubsetEntry(
        { type: "mission_resource_access", resource: RESOURCE, actions: [READ_ACTION] },
        granted,
      ),
    ).toBe(false);
  });

  it("refuses an altered binding", () => {
    const altered: AuthorityEntry = {
      ...granted,
      capability_sources: [
        { ...bindingFor(READ_ACTION, "get_invoice"), source_digest: "sha-256:AAAA" },
      ],
    };
    expect(isSubsetEntry(altered, granted)).toBe(false);
  });

  it("refuses introducing a binding the grantor lacks", () => {
    const grantorNone: AuthorityEntry = {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: [READ_ACTION],
    };
    const candidate: AuthorityEntry = {
      ...grantorNone,
      capability_sources: [bindingFor(READ_ACTION, "get_invoice")],
    };
    expect(isSubsetEntry(candidate, grantorNone)).toBe(false);
    expect(isSubsetEntry(candidate, granted)).toBe(true);
    expect(
      isSubsetEntry(
        { ...granted, capability_sources: [bindingFor(READ_ACTION, "get_invoice_v2")] },
        granted,
      ),
    ).toBe(false);
  });

  it("is unaffected when neither side records a binding", () => {
    const plain: AuthorityEntry = {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: [READ_ACTION],
    };
    expect(isSubsetEntry(plain, plain)).toBe(true);
  });
});

describe("projectThroughEffective: recorded bindings keep the subset property", () => {
  const bound: AuthorityEntry = {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: [READ_ACTION, WRITE_ACTION],
    capability_sources: [bindingFor(READ_ACTION, "get_invoice")],
  };

  it("carries bindings both sides recorded, and stays a subset of both", () => {
    const result = projectThroughEffective([bound], [bound]);
    expect(result).toHaveLength(1);
    expect(result[0]?.capability_sources).toEqual(bound.capability_sources);
    expect(isSubsetSet(result, [bound])).toBe(true);
  });

  it("drops a binding whose action the projection narrows away", () => {
    const narrowed: AuthorityEntry = { ...bound, actions: [WRITE_ACTION] };
    const result = projectThroughEffective([bound], [narrowed]);
    expect(result[0]?.actions).toEqual([WRITE_ACTION]);
    expect("capability_sources" in (result[0] as AuthorityEntry)).toBe(false);
    expect(isSubsetSet(result, [bound])).toBe(true);
    expect(isSubsetSet(result, [narrowed])).toBe(true);
  });

  it("drops a pairing whose two sides disagree on a retained action's binding", () => {
    const other: AuthorityEntry = {
      ...bound,
      capability_sources: [bindingFor(READ_ACTION, "get_invoice_v2")],
    };
    expect(projectThroughEffective([bound], [other])).toEqual([]);
    const unbound: AuthorityEntry = {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: [READ_ACTION, WRITE_ACTION],
    };
    expect(projectThroughEffective([bound], [unbound])).toEqual([]);
  });
});

describe("trusted catalog configuration", () => {
  it("marks only the payments service trusted", () => {
    expect(CATALOG_SERVICES.filter((s) => s.trusted).map((s) => s.id)).toEqual(["payments"]);
  });

  it("loads the payments tool-catalog fixture for the trusted service only", () => {
    expect(TRUSTED_TOOL_CATALOGS.map((c) => c.service_id)).toEqual(["payments"]);
    expect(CATALOG.source_uri).toContain("/.well-known/mcp");
  });

  it("serves the same tool names the MCP server does, so a resolver has real bytes", () => {
    expect(CATALOG.tool_names).toEqual(TOOLS.map((t) => t.name));
  });

  it("extracts a per-capability definition from the fixture's exact octets", () => {
    const definition = extractMcpToolDefinition(CATALOG.text, "schedule_payment");
    expect(capabilitySourceDigest(definition)).toMatch(/^sha-256:/);
    // The whole-catalog digest is over the retrieved bytes, so it differs from
    // any per-capability digest taken from within them.
    expect(catalogDigest(CATALOG.text)).not.toBe(capabilitySourceDigest(definition));
  });
});
