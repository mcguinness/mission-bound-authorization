/**
 * Trusted, synchronous snapshot adapter; never follows a client-supplied URI.
 *
 * @spec capability-binding#conformance — the validating server's recording
 * duty: `tool_id`, `source_uri`, `source_digest` and `operation_ref` for every
 * catalog-sourced action, resolved at derivation. This deployment's trust unit
 * is the selected capability definition, so no `catalog_digest` is recorded.
 */
import { capabilitySourceDigest, entryOverlapsResource, extractMcpToolDefinition } from "@mission/core";
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
        // @spec resource-access#resource-matching (#1440): every trusted
        // service whose resource tree overlaps the entry, through the shared
        // matcher ({@link entryOverlapsResource}): the service the entry
        // names, the service a finer or `prefix` entry beneath it reaches, and
        // each service within a `prefix` entry's base. Pairing by string
        // equality would read a finer entry's catalog-sourced action as
        // first-party and approve it unbound. An entry no trusted service
        // overlaps is a first-party or unclaimed source.
        for (const service of services.filter(s => s.trusted && entryOverlapsResource(entry, s.resource))) {
          // A trusted catalog belongs to its service by the service's own
          // identifier: both are configured service identifiers, so equality is exact.
          const catalog = catalogs.find(c => c.service_id === service.id && c.resource === service.resource);
          for (const action of entry.actions) {
            const declared = service.actions?.find(a => a.id === action);
            // @spec runtime#compound-actions: an action whose phases share one
            // identifier serves SEVERAL tools, so it resolves one binding per
            // (action, tool): `normalizeCapabilitySources` keys uniqueness on
            // the (action, tool_id) pair, and the PDP's committed-binding check
            // is membership over that set, so the crossing's own tool must be
            // among the recorded bindings rather than collapsed into one.
            const tools = declared?.tools?.map(t => t.tool_name) ?? (declared?.tool_name !== undefined ? [declared.tool_name] : []);
            // An unresolvable action still yields ONE resolution with no
            // binding, which is what fails the derivation closed.
            for (const tool of tools.length ? tools : [undefined]) {
              const key = JSON.stringify([entry.resource, service.id, action, tool ?? null]);
              if (seen.has(key)) continue;
              seen.add(key);
              const resolution: CapabilitySourceResolution = { resource: entry.resource, action };
              try {
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
        }
      }
      return resolutions;
    },
  };
}
