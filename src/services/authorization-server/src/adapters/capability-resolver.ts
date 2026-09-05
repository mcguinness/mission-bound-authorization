/** Trusted, synchronous snapshot adapter; never follows a client-supplied URI. */
import { capabilitySourceDigest, extractMcpToolDefinition } from "@mission/core";
import { CATALOG_SERVICES, TRUSTED_TOOL_CATALOGS, type CatalogServiceSeed, type TrustedToolCatalog } from "@mission/demo-data";
import type { CapabilitySourceResolver, CapabilitySourceResolution } from "../kernel/capability-binding.js";

export function trustedCapabilityResolver(
  catalogs: readonly TrustedToolCatalog[] = TRUSTED_TOOL_CATALOGS,
  services: readonly CatalogServiceSeed[] = CATALOG_SERVICES,
): CapabilitySourceResolver {
  return {
    resolve(entries) {
      const resolutions: CapabilitySourceResolution[] = [];
      const seen = new Set<string>();
      for (const entry of entries) {
        const service = services.find(s => s.resource === entry.resource && s.trusted);
        if (!service) continue; // first-party/unclaimed source
        const catalog = catalogs.find(c => c.service_id === service.id && c.resource === entry.resource);
        for (const action of entry.actions) {
          const key = JSON.stringify([entry.resource, action]);
          if (seen.has(key)) continue;
          seen.add(key);
          const resolution: CapabilitySourceResolution = { resource: entry.resource, action };
          try {
            const tool = service.actions?.find(a => a.id === action)?.tool_name;
            if (!catalog || !tool) throw new Error("trusted source has no action definition");
            const definition = extractMcpToolDefinition(catalog.text, tool);
            resolution.binding = {
              action, tool_id: `mcp://${service.id}.demo/tools/${tool}`,
              source_uri: catalog.source_uri,
              source_digest: capabilitySourceDigest(definition), operation_ref: tool,
            };
            // The selected definition, not the whole catalog, is the trust unit.
          } catch { /* present without binding means fail closed at establishment */ }
          resolutions.push(resolution);
        }
      }
      return resolutions;
    },
  };
}
