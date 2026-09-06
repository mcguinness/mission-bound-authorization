/** One exact-octet source for discovery, tools/list and decision presentation. */
import { capabilitySourceDigest, catalogDigest, extractMcpToolDefinition, type CapabilitySourceBinding } from "@mission/core";
import { CATALOG_SERVICES, TRUSTED_TOOL_CATALOGS } from "@mission/demo-data";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

export type PresentedCapability = Omit<CapabilitySourceBinding, "action">;
export interface CapabilitySnapshot { tool: string; id: string }
export interface CapabilityCatalog {
  text(): string;
  toolDefinitions(names: readonly string[]): Tool[];
  resolve(tool: string): { catalog_sourced: false } | { catalog_sourced: true; binding: PresentedCapability; snapshot: CapabilitySnapshot };
}

export class PaymentsToolCatalog implements CapabilityCatalog {
  constructor(private readonly catalogSource: () => string = () => {
    const catalog = TRUSTED_TOOL_CATALOGS.find(c => c.service_id === "payments");
    if (!catalog) throw new Error("payments catalog unavailable");
    return catalog.text;
  }) {}

  text(): string { return this.catalogSource(); }

  toolDefinitions(names: readonly string[]): Tool[] {
    const text = this.text(); // one read for the whole list
    return names.map(name => extractMcpToolDefinition(text, name) as unknown as Tool);
  }

  resolve(tool: string): ReturnType<CapabilityCatalog["resolve"]> {
    const service = CATALOG_SERVICES.find(s => s.id === "payments");
    if (!service?.actions?.some(a => a.tool_name === tool)) return { catalog_sourced: false };
    if (!service.server_card_uri) throw new Error("payments source URI unavailable");
    const text = this.text(); // binding AND snapshot identity from this one read
    const definition = extractMcpToolDefinition(text, tool);
    return { catalog_sourced: true,
      binding: { tool_id: `mcp://payments.demo/tools/${tool}`, source_uri: service.server_card_uri,
        source_digest: capabilitySourceDigest(definition), operation_ref: tool },
      snapshot: { tool, id: catalogDigest(text) },
    };
  }
}
