import { authorityHash, capabilitySourceDigest, extractMcpToolDefinition, type AuthorityEntry } from "@mission/core";
import { CATALOG_SERVICES, DERIVATION_POLICY, TRUSTED_TOOL_CATALOGS } from "@mission/demo-data";
import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { trustedCapabilityResolver } from "../src/adapters/capability-resolver.js";
import { attachCapabilitySources, createExpansion, createTemplate, dispatchFromTemplate, MissionKernel, TemplateStore, validateMissionIntent } from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const catalog = TRUSTED_TOOL_CATALOGS.find(c => c.service_id === "payments")!;
const resource = catalog.resource;
const read = "payments:invoice.read", vendor = "payments:vendor.read";
const proposal = (actions: string[]): AuthorityEntry[] => [{ type: "mission_resource_access", resource, actions, constraints: { vendors: ["acme"] } }];
const intent = validateMissionIntent(JSON.stringify({ goal: "Reconcile invoices", target_resources: [resource], expires_at: "2027-01-01T00:00:00Z" }));
let key: CryptoKey;
beforeAll(async () => { key = (await generateKeyPair("ES256")).privateKey; });
const build = (resolver = trustedCapabilityResolver()) => new MissionKernel({
  issuer: "https://as.test", policy: DERIVATION_POLICY as never, statusKey: key, statusKid: "status",
  authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["ap-agent", "worker"], ["bob"]),
  capabilityResolver: resolver,
});
const approve = (kernel: MissionKernel, actions: string[] = [read]) => kernel.approve({
  intent, proposedAuthority: proposal(actions), clientId: "ap-agent", subject: { iss: "https://as.test", sub: "alice" },
  approver: { iss: "https://as.test", sub: "bob" }, approvalEventId: crypto.randomUUID(),
});

describe("trusted capability recording", () => {
  it("records source_digest and never a catalog_digest; the selected definition is the trust unit", () => {
    const resolved = trustedCapabilityResolver().resolve(proposal([read]));
    expect(resolved[0]?.binding?.source_digest).toBe(capabilitySourceDigest(extractMcpToolDefinition(catalog.text, "get_invoice")));
    expect(resolved[0]?.binding).not.toHaveProperty("catalog_digest");
    const kernel = build();
    const record = approve(kernel);
    expect(record.authority_set[0]?.capability_sources).toEqual(resolved.map(r => r.binding));
    expect(record.authority_hash).toBe(authorityHash(record.issuer, record.authority_set as never));
  });

  it("ignores a proposed digest and never retrieves its client-controlled URI", () => {
    const kernel = build();
    const malicious = proposal([read]);
    malicious[0]!.capability_sources = [{ action: read, tool_id: "attacker", source_uri: "https://attacker.test", source_digest: "bad", operation_ref: "bad" }];
    const record = kernel.approve({ intent, proposedAuthority: malicious, clientId: "ap-agent", subject: { iss: "https://as.test", sub: "alice" }, approver: { iss: "https://as.test", sub: "bob" }, approvalEventId: "malicious" });
    expect(record.authority_set[0]?.capability_sources?.[0]?.source_uri).toBe(catalog.source_uri);
  });

  it("leaves untrusted resources unclaimed but refuses an unresolved action on a trusted resource", () => {
    const resolver = trustedCapabilityResolver();
    expect(resolver.resolve([{ ...proposal([read])[0]!, resource: "https://first-party.test" }])).toEqual([]);
    const unresolved = resolver.resolve(proposal(["unmapped-action"]));
    expect(unresolved).toEqual([{ resource, action: "unmapped-action" }]);
    expect(() => attachCapabilitySources(proposal(["unmapped-action"]), unresolved)).toThrow(/could not be resolved/);
    for (const text of ["{", '{"tools":[]}', '{"tools":[{"name":"get_invoice","name":"spoof"}]}']) {
      expect(() => approve(build(trustedCapabilityResolver([{ ...catalog, text }])))).toThrow(/could not be resolved/);
    }
  });

  it("resolves mixed actions individually and records a fresh expansion action without refreshing its predecessor binding", () => {
    const catalogs = [{ ...catalog }];
    const kernel = build(trustedCapabilityResolver(catalogs));
    const predecessor = approve(kernel);
    const old = predecessor.authority_set[0]!.capability_sources![0]!;
    catalogs[0]!.text = catalog.text.replace("Read one invoice", "Changed after original approval");
    const { successor } = createExpansion(kernel, { predecessorId: predecessor.id, intent, proposedAuthority: proposal([read, vendor]), approver: { iss: "https://as.test", sub: "bob" }, approvalEventId: "expand", approvedUntil: "2027-01-01T00:00:00Z" });
    const bindings = successor.authority_set.flatMap(e => e.capability_sources ?? []);
    expect(bindings.find(b => b.action === read)).toEqual(old);
    expect(bindings.find(b => b.action === vendor)?.operation_ref).toBe("lookup_vendor");
    expect(bindings).toHaveLength(2);
  });

  it("resolves the consented template ceiling before hashing and drawdown inherits it", () => {
    const kernel = build(), store = new TemplateStore();
    const template = createTemplate(store, { template_version: "1", issuer: "https://as.test", approver: { iss: "https://as.test", sub: "bob" }, ceiling: proposal([read]), dispatch_policy: "test", dispatchers: ["orchestrator"], recipients: ["worker"], per_instance_lifetime_s: 3600, max_active: 10, rate_per_min: 20, approval_event_id: "template", expires_at: "2027-01-01T00:00:00Z" }, kernel.authoritySourceOptions());
    expect(template.ceiling[0]?.capability_sources).toHaveLength(1);
    const { mission } = dispatchFromTemplate(kernel, store, { templateId: template.id, dispatchEventId: "draw", dispatcher: "orchestrator", recipient: "worker", intent, proposedAuthority: proposal([read]), subject: { iss: "https://as.test", sub: "alice" }, policyVersion: DERIVATION_POLICY.policy_version });
    expect(mission.authority_set[0]?.capability_sources).toEqual(template.ceiling[0]?.capability_sources);
  });
});
