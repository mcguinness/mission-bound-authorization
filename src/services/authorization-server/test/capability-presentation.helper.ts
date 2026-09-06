/** Direct-PDP scenario fixtures emulate the PEP's CURRENT catalog presentation,
 * never copy a Mission's recorded digest (which would make drift tautological). */
import { PaymentsToolCatalog, TOOLS } from "@mission/mcp-payments";

export function capabilityPresentationFor(action: string) {
  const tool = TOOLS.find(t => t.action === action);
  if (!tool) return {};
  const resolved = new PaymentsToolCatalog().resolve(tool.name);
  return resolved.catalog_sourced ? { capability_source: resolved.binding } : {};
}
