/**
 * @spec capability-binding#capability-source-binding — the COMMITTED per-action
 * shape: where bindings enter (the validating server's resolution, attached in
 * `approve` before `authority_hash`), what refuses, and how the subset rule
 * treats them. Presentation and decision-time comparison are separate changes.
 */

import { authorityHash, type CapabilitySourceBinding, capabilitySourceDigest, capabilitySourceIdentity, catalogDigest, extractMcpToolDefinition, isSubsetSetIgnoringCapabilitySources } from "@mission/core";
import { CATALOG_SERVICES, DERIVATION_POLICY, TRUSTED_TOOL_CATALOGS } from "@mission/demo-data";
import { TOOLS } from "@mission/mcp-payments";
import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  attachCapabilitySources,
  type AuthorityEntry,
  type CapabilitySourceResolution,
  createChildMission,
  createExpansion,
  createTemplate,
  deriveAttenuationRoot,
  deriveCrossOrgRoot,
  mapAuthorityToTools,
  dispatchFromTemplate,
  IntentError,
  isSubsetEntry,
  isSubsetSet,
  MissionKernel,
  type MissionRecord,
  projectThroughEffective,
  TemplateStore,
  validateAuthorityProposal,
  validateMissionIntent,
} from "../src/index.js";
import { aiAgents } from "./actor-profiles.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const READ_ACTION = "payments:invoice.read";
const WRITE_ACTION = "payments:payment.schedule";

// A first-party action of the SAME ceiling entry as READ_ACTION, so a derived
// set can retain the entry while dropping the catalog-sourced action.
const VENDOR_ACTION = "payments:vendor.read";
const CHILD_ACTOR = "subagent-capability";
const EXP = "2027-01-01T00:00:00Z";

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
    // The suite approves as `ap-agent` under approver `bob`, and its template
    // dispatches to the `worker` recipient: gate 1 resolves both, gate 2 names
    // the Approver each path actually activates with, and gate 3's ceiling is
    // this suite's own derivation ceiling.
    authoritySourceCatalog: testAuthoritySourceCatalog(
      DERIVATION_POLICY.ceiling,
      ["ap-agent", "worker"],
      ["bob"],
    ),
    statusKey: privateKey,
    statusKid: "as-status",
    // The child-creation suite below delegates to this AS-asserted `ai_agent`.
    actorProfiles: aiAgents(CHILD_ACTOR),
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

  it("attaches effective bindings to a bare wire candidate without widening either authority", () => {
    const { capability_sources: _drop, ...wire } = bound;
    const result = projectThroughEffective([wire], [bound]);
    expect(result).toEqual([bound]);
    expect(isSubsetSet(result, [bound])).toBe(true);
    expect(isSubsetSet(result, [wire])).toBe(false); // issuer lineage stays strict
    expect(isSubsetSetIgnoringCapabilitySources(result, [wire])).toBe(true);
    expect(isSubsetSetIgnoringCapabilitySources(result, [bound])).toBe(true);
  });
});

describe("wire-bound attenuation over recorded authority", () => {
  it("permits both root paths without putting recorded bindings on the AAT tools wire shape", async () => {
    const record = approve([resolution(READ_ACTION, "get_invoice")]);
    const { privateKey } = await generateKeyPair("ES256");
    const requestedTools = mapAuthorityToTools(record.authority_set);
    const common = { missionId: record.id, aud: RESOURCE, clientId: "ap-agent", cnfJkt: "test-key", requestedTools };
    const root = await deriveAttenuationRoot(kernel, privateKey, "root", common);
    expect(root.tools).toEqual(requestedTools);
    const crossOrg = await deriveCrossOrgRoot(kernel, privateKey, "root", {
      ...common, actor: { iss: ISS, sub: "ap-agent" }, mappingVersion: "test-v1",
    });
    expect(crossOrg.tools).toEqual(requestedTools);
    expect(JSON.stringify(root.tools)).not.toContain("capability_sources");
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

// ---------------------------------------------------------------------------
// The DERIVED paths. `Kernel.approve` is where a binding first enters; child
// creation, template dispatch, and expansion create a Mission from an EXISTING
// one and never resolve, so each inherits the grantor's recorded bindings.
// ---------------------------------------------------------------------------

/** Two bindings for ONE catalog-sourced action, so "every binding" is testable. */
const TWO_TOOLS: CapabilitySourceResolution[] = [
  resolution(READ_ACTION, "get_invoice"),
  {
    resource: RESOURCE,
    action: READ_ACTION,
    binding: {
      ...bindingFor(READ_ACTION, "get_invoice"),
      tool_id: "mcp://payments.test/tools/get_invoice_v2",
    },
  },
];

/** A proposal on the payments resource, restating the ceiling's vendors. */
const proposalOf = (actions: string[]): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions,
    constraints: { vendors: ["acme"] },
  },
];

const intentOf = (goal: string) =>
  validateMissionIntent(
    JSON.stringify({ goal, target_resources: [RESOURCE], expires_at: EXP }),
  );

/** The canonical bytes of an entry's recorded bindings: byte-identity, not shape. */
const identitiesOf = (entry: AuthorityEntry) =>
  entry.capability_sources?.map(capabilitySourceIdentity);

const hashCovers = (record: MissionRecord) =>
  record.authority_hash === authorityHash(record.issuer, record.authority_set as never);

describe("child creation inherits the parent's recorded bindings", () => {
  let parent: MissionRecord;
  let parentEntry: AuthorityEntry;
  beforeAll(() => {
    parent = approve(TWO_TOOLS);
    parentEntry = entryFor(parent, READ_ACTION);
  });

  const createChild = (actions: string[], seqTag: string) =>
    createChildMission(kernel, {
      parentId: parent.id,
      intent: intentOf(`Extract Acme invoices ${seqTag}`),
      proposedAuthority: proposalOf(actions),
      childActor: { sub: CHILD_ACTOR, sub_profile: "ai_agent" },
    });

  it("carries every parent binding byte-identically onto a retained action", () => {
    const { child } = createChild([READ_ACTION], "retain");
    const childEntry = entryFor(child, READ_ACTION);
    expect(parentEntry.capability_sources).toHaveLength(2);
    expect(childEntry.capability_sources).toEqual(parentEntry.capability_sources);
    expect(identitiesOf(childEntry)).toEqual(identitiesOf(parentEntry));
  });

  it("keeps the child a subset of the parent, which a dropped binding would refuse", () => {
    const { child } = createChild([READ_ACTION], "subset");
    expect(isSubsetSet(child.authority_set, parent.authority_set)).toBe(true);
    // The counterfactual the review named: the same child WITHOUT the inherited
    // bindings is correctly undelegable.
    const unbound = child.authority_set.map(({ capability_sources: _drop, ...rest }) => rest);
    expect(isSubsetSet(unbound, parent.authority_set)).toBe(false);
  });

  it("drops the bindings of an action the child does not retain", () => {
    const { child } = createChild([VENDOR_ACTION], "drop");
    const childEntry = entryFor(child, VENDOR_ACTION);
    expect(childEntry.actions).toEqual([VENDOR_ACTION]);
    expect("capability_sources" in childEntry).toBe(false);
    expect(isSubsetSet(child.authority_set, parent.authority_set)).toBe(true);
  });

  it("commits the inherited bindings under the child authority_hash", () => {
    const { child } = createChild([READ_ACTION], "hash");
    expect(hashCovers(child)).toBe(true);
    const { child: bare } = createChild([VENDOR_ACTION], "hash-bare");
    expect(child.authority_hash).not.toBe(bare.authority_hash);
  });
});

describe("template dispatch inherits the ceiling's recorded bindings", () => {
  const CEILING: AuthorityEntry[] = [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: [READ_ACTION, VENDOR_ACTION],
      constraints: { vendors: ["acme"] },
      capability_sources: TWO_TOOLS.map((r) => r.binding as CapabilitySourceBinding),
    },
  ];

  let store: TemplateStore;
  let templateId: string;
  let seq = 0;
  beforeAll(() => {
    store = new TemplateStore();
    templateId = createTemplate(store, {
      template_version: "tmpl-cap-1",
      issuer: ISS,
      approver: { iss: ISS, sub: "bob" },
      ceiling: CEILING,
      dispatch_policy: "capability-binding-test",
      dispatchers: ["orchestrator"],
      recipients: ["worker"],
      per_instance_lifetime_s: 3600,
      max_active: 10,
      rate_per_min: 20,
      approval_event_id: "tmpl-cap-consent",
      expires_at: EXP,
    }, kernel.authoritySourceOptions()).id;
  });

  const dispatch = (actions: string[]) =>
    dispatchFromTemplate(kernel, store, {
      templateId,
      dispatchEventId: `dsp-cap-${(seq += 1)}`,
      dispatcher: "orchestrator",
      recipient: "worker",
      intent: intentOf("reconcile Acme"),
      proposedAuthority: proposalOf(actions),
      subject: { iss: ISS, sub: "alice" },
      policyVersion: DERIVATION_POLICY.policy_version,
    });

  it("carries every ceiling binding byte-identically onto a retained action", () => {
    const instance = dispatch([READ_ACTION]).mission;
    const entry = entryFor(instance, READ_ACTION);
    expect(entry.capability_sources).toEqual(CEILING[0]?.capability_sources);
    expect(identitiesOf(entry)).toEqual(identitiesOf(CEILING[0] as AuthorityEntry));
    // The double intersection still holds against BOTH ceilings.
    expect(isSubsetSet(instance.authority_set, CEILING)).toBe(true);
  });

  it("drops the bindings of an action the instance does not retain", () => {
    const instance = dispatch([VENDOR_ACTION]).mission;
    const entry = entryFor(instance, VENDOR_ACTION);
    expect("capability_sources" in entry).toBe(false);
    expect(isSubsetSet(instance.authority_set, CEILING)).toBe(true);
  });

  it("commits the inherited bindings under the instance authority_hash", () => {
    const bound = dispatch([READ_ACTION]).mission;
    const bare = dispatch([VENDOR_ACTION]).mission;
    expect(hashCovers(bound)).toBe(true);
    expect(bound.authority_hash).not.toBe(bare.authority_hash);
  });
});

describe("expansion inherits the predecessor's recorded bindings", () => {
  let seq = 0;
  const expand = (predecessorId: string, actions: string[]) =>
    createExpansion(kernel, {
      predecessorId,
      intent: intentOf("Pay Acme invoices (widened)"),
      proposedAuthority: proposalOf(actions),
      approver: { iss: ISS, sub: "bob" },
      approvalEventId: `apev-succ-cap-${(seq += 1)}`,
      approvedUntil: EXP,
    });

  it("carries every predecessor binding byte-identically onto a retained action", () => {
    const predecessor = approve(TWO_TOOLS);
    const { successor } = expand(predecessor.id, [READ_ACTION]);
    const entry = entryFor(successor, READ_ACTION);
    expect(entry.capability_sources).toEqual(
      entryFor(predecessor, READ_ACTION).capability_sources,
    );
    expect(identitiesOf(entry)).toEqual(identitiesOf(entryFor(predecessor, READ_ACTION)));
    // Expansion has no subset gate of its own, so the property is asserted here.
    expect(isSubsetSet(successor.authority_set, predecessor.authority_set)).toBe(true);
  });

  it("drops the bindings of an action the successor does not retain", () => {
    const predecessor = approve(TWO_TOOLS);
    const { successor } = expand(predecessor.id, [VENDOR_ACTION]);
    expect("capability_sources" in entryFor(successor, VENDOR_ACTION)).toBe(false);
    expect(isSubsetSet(successor.authority_set, predecessor.authority_set)).toBe(true);
  });

  it("restores a contained action with the binding the predecessor recorded", () => {
    const predecessor = approve(TWO_TOOLS);
    kernel.contain(predecessor.id, {
      event: {
        type: "tainted_read",
        source: "https://siem.example/detections",
        observed_at: new Date().toISOString(),
        event_id: `taint-cap-${(seq += 1)}`,
      },
      remove: [{ resource: RESOURCE, actions: [READ_ACTION] }],
    });
    // The grantor is the predecessor's APPROVED set: containment does not
    // propagate to a successor, and the restored action keeps its binding
    // rather than being emitted unbound.
    const { successor } = expand(predecessor.id, [READ_ACTION]);
    expect(entryFor(successor, READ_ACTION).capability_sources).toEqual(
      entryFor(predecessor, READ_ACTION).capability_sources,
    );
  });

  it("commits the inherited bindings under the successor authority_hash", () => {
    const predecessor = approve(TWO_TOOLS);
    const bound = expand(predecessor.id, [READ_ACTION]).successor;
    const bare = expand(predecessor.id, [VENDOR_ACTION]).successor;
    expect(hashCovers(bound)).toBe(true);
    expect(bound.authority_hash).not.toBe(bare.authority_hash);
  });
});
