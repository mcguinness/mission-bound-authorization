import { catalogDigest, capabilitySourceDigest, extractMcpToolDefinition } from "@mission/core";
import { TRUSTED_TOOL_CATALOGS, DERIVATION_POLICY, AUTHORITY_SOURCES } from "@mission/demo-data";
import { MissionKernel, validateMissionIntent } from "@mission/authorization-server";
import { trustedCapabilityResolver } from "../../authorization-server/src/adapters/capability-resolver.js";
import { generateKeyPair } from "jose";
import type { EvaluationRequest, Fga, MissionView } from "@mission/pdp";
import { describe, expect, it } from "vitest";
import { CANONICAL_RESOURCE, createEphemeralEvidenceKeys, EvidenceStore, McpPaymentsServer, PaymentsStore, PaymentsToolCatalog, Pep, TOOLS, parameterDigest, type TokenFacts } from "../src/index.js";
import { startResourceMetadataServer } from "../src/resource-metadata.js";

const text = TRUSTED_TOOL_CATALOGS.find(c => c.service_id === "payments")!.text;
const token: TokenFacts = { sub: "alice", clientId: "ap-agent", mission: { id: "msn_catalog", issuer: "https://as.test", authority_hash: "sha-256:test" }, cnfJkt: "key" };
function fixture(source: () => string = () => text) {
  const payments = new PaymentsStore();
  payments.seed([{ id: "acme", name: "Acme", status: "approved" }], [{ id: "inv-1", vendor_id: "acme", amount: "100.00", currency: "USD", payee_account: "acct", status: "payable" }]);
  const keys = createEphemeralEvidenceKeys();
  const evidence = new EvidenceStore(keys.signing, keys.resolver);
  const view: MissionView = { id: token.mission.id, issuer: token.mission.issuer, authority_hash: token.mission.authority_hash!, state: "active", version: 1,
    authority_set: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: TOOLS.map(t => t.action), constraints: { vendors: ["acme"] } }],
    subject: { iss: token.mission.issuer, sub: "alice" }, client_id: "ap-agent" };
  const loadView = () => ({ view, freshness: { observed_at: new Date().toISOString(), source: "load_view" } });
  const requests: EvaluationRequest[] = [];
  const catalog = new PaymentsToolCatalog(source);
  const pep = new Pep({ payments, evidence, capabilityCatalog: catalog, decide: async (...args) => {
    requests.push(args[0]); return keys.decide(...args);
  }, fga: { checkWithContext: async () => true } as unknown as Fga, modelId: "test", loadView, instanceEpoch: "epoch", allowedFreshnessSources: new Set(["load_view"]) });
  const server = new McpPaymentsServer({ pep, payments, loadView, jwks: { keys: [] }, issuer: token.mission.issuer });
  return { pep, server, evidence, requests, catalog, view, payments };
}

describe("one catalog snapshot from discovery to invocation", () => {
  it("a served definition edited after real approval denies capability_drift and retains the compared evidence", async () => {
    const key = (await generateKeyPair("ES256")).privateKey;
    const kernel = new MissionKernel({ issuer: "https://as.test", policy: DERIVATION_POLICY as never, authoritySourceCatalog: AUTHORITY_SOURCES as never, capabilityResolver: trustedCapabilityResolver(), statusKey: key, statusKid: "status" });
    const record = kernel.approve({ intent: validateMissionIntent(JSON.stringify({ goal: "Read invoice", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-01-01T00:00:00Z" })), proposedAuthority: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"], constraints: { vendors: ["acme"] } }], subject: { iss: "https://as.test", sub: "alice" }, approver: { iss: "https://as.test", sub: "bob" }, clientId: "ap-agent", approvalEventId: "catalog-e2e" });
    let current = text;
    const f = fixture(() => current);
    Object.assign(f.view, { id: record.id, authority_hash: record.authority_hash, authority_set: record.authority_set });
    const credential = { ...token, mission: { id: record.id, issuer: record.issuer, authority_hash: record.authority_hash } };
    expect((await f.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, credential)).ok).toBe(true);
    current = text.replace("Read one invoice", "A different operation definition");
    expect(await f.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, credential)).toEqual({ ok: false, denial_reason: "capability_drift" });
    const retained = f.evidence.forMission(record.id).filter(e => e.kind === "decision");
    expect(retained).toHaveLength(2);
    expect(retained[0]?.content.capability_source?.source_digest).toBe(record.authority_set[0]?.capability_sources?.[0]?.source_digest);
    expect(retained[1]?.content.denial_reason).toBe("capability_drift");
    expect(retained[1]?.content.capability_source?.source_digest).toBe(capabilitySourceDigest(extractMcpToolDefinition(current, "get_invoice")));
  });

  it("serves exact discovery octets and selects tools/list definitions from the same source", async () => {
    const f = fixture();
    const listener = await startResourceMetadataServer(() => f.server);
    try {
      expect(await (await fetch(`${listener.origin}/.well-known/mcp`)).text()).toBe(text);
      const definitions = f.server.capabilityCatalog.toolDefinitions(f.server.toolsList(token).map(t => t.name));
      expect(definitions).toEqual(JSON.parse(text).tools);
    } finally { await listener.close(); }
  });

  it("gets binding and snapshot identity from one read, even if the next read changes", () => {
    let reads = 0;
    const changed = text.replace("Read one invoice", "New definition");
    const catalog = new PaymentsToolCatalog(() => ++reads === 1 ? text : changed);
    const first = catalog.resolve("get_invoice");
    expect(reads).toBe(1);
    expect(first.catalog_sourced).toBe(true);
    if (!first.catalog_sourced) throw new Error("fixture");
    expect(first.snapshot.id).toBe(catalogDigest(text));
    expect(first.binding.source_digest).toBe(capabilitySourceDigest(extractMcpToolDefinition(text, "get_invoice")));
    expect(catalog.resolve("get_invoice")).not.toEqual(first);
  });

  it("presents the current per-tool binding even on a Mission with no recorded member", async () => {
    const f = fixture();
    expect(f.view.authority_set[0]).not.toHaveProperty("capability_sources");
    expect((await f.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token)).permitted).toBe(true);
    const binding = (f.requests[0]!.context as unknown as { capability_source: unknown }).capability_source;
    const resolution = f.catalog.resolve("get_invoice");
    expect(resolution.catalog_sourced && binding).toEqual(resolution.catalog_sourced && resolution.binding);
    expect(binding).not.toHaveProperty("action");
    expect(binding).not.toHaveProperty("catalog_digest");
    expect(f.catalog.resolve("non-catalog-operation")).toEqual({ catalog_sourced: false });
  });

  it.each(["unreachable", "malformed", "missing-tool"])("refuses %s before any PDP call and retains a Refusal Record", async failure => {
    const f = fixture(() => {
      if (failure === "unreachable") throw new Error("offline");
      return failure === "malformed" ? "{" : '{"tools":[]}';
    });
    const result = await f.pep.enforce("get_invoice", { invoice_id: "inv-1" }, token);
    expect(result).toMatchObject({ permitted: false, refusal_reason: "capability_source_unresolvable" });
    expect(f.requests).toHaveLength(0);
    expect(f.evidence.forMission(token.mission.id)).toMatchObject([{ kind: "refusal", content: { denial_reason: "capability_source_unresolvable" } }]);
  });

  it("refuses a changed snapshot before a read executes", async () => {
    let current = text;
    const f = fixture(() => current);
    const result = await f.server.callReadTool("get_invoice", { invoice_id: "inv-1" }, token, () => { current = text + "\n"; });
    expect(result).toEqual({ ok: false, refusal_reason: "capability_source_unresolvable" });
    expect(result).not.toHaveProperty("result");
  });

  it("carries the snapshot into write and list effective operations and refuses a post-decision change", async () => {
    let current = text;
    const f = fixture(() => current);
    const write = await f.pep.enforce("schedule_payment", { invoice_id: "inv-1" }, token);
    const list = await f.pep.enforce("list_invoices", {}, token);
    expect(write.permitted).toBe(true); expect(list.permitted).toBe(true);
    expect(write.effective?.capability_snapshot).toEqual(write.capabilitySnapshot);
    expect(list.listEffective?.capability_snapshot).toEqual(list.capabilitySnapshot);
    current = text.replace("Read one invoice", "Changed while deciding");
    expect(await f.pep.reverify(write.effective!, parameterDigest(write.effective!), token)).toBe(false);
    expect(await f.pep.reverifyList(list.listEffective!, parameterDigest(list.listEffective!), token)).toBe(false);
  });
});
