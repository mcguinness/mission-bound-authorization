/**
 * @spec capability-binding#capability-approval (#1447, D584): what an approval
 * rendering presents about each catalog-sourced action's source binding, in
 * terms the Approver can act on: the tool or operation identity, what invoking
 * it authorizes (the tool's own description, read from the trusted catalog in
 * the very definition the binding's digest commits, and rendered as inert
 * text), its source and publisher, and that a later change to its definition
 * is refused. The exact machine binding stays on the entry the approval
 * commits; a digest or URI alone is never the account.
 */
import { type AuthorityEntry, capabilitySourceDigest, type CapabilitySourceBinding, extractMcpToolDefinition, type JsonValue } from "@mission/core";
import { CATALOG_SERVICES, TRUSTED_TOOL_CATALOGS, type TrustedToolCatalog } from "@mission/demo-data";
import { IntentError } from "../kernel/intent.js";

/** One bound action, as the approval page presents it. */
export interface BindingDisclosure {
  resource: string;
  binding: CapabilitySourceBinding;
  /** The tool's own description, from the definition the binding commits; absent only for an inherited binding the catalog no longer serves. */
  description?: string;
  /** The deployment's configured name for the source. */
  sourceName?: string;
  /** Kept from the Mission an expansion widens, approved there, rather than bound by this approval. */
  inherited: boolean;
}

const sameBinding = (a: CapabilitySourceBinding, b: CapabilitySourceBinding) =>
  a.action === b.action &&
  a.tool_id === b.tool_id &&
  a.source_uri === b.source_uri &&
  a.source_digest === b.source_digest &&
  a.operation_ref === b.operation_ref &&
  a.catalog_digest === b.catalog_digest;

/**
 * The disclosure of every binding the entries carry. A binding this approval
 * makes is shown only with the definition its digest commits: one whose
 * definition the trusted catalog does not serve refuses the rendering, so no
 * Approver consents to a binding they could not read. A binding inherited from
 * `inheritedFrom` (the approved set of the Mission an expansion widens) was
 * approved there; it is shown as kept, with its description where the catalog
 * still serves that definition.
 */
export function bindingDisclosures(
  entries: readonly AuthorityEntry[],
  inheritedFrom: readonly AuthorityEntry[] = [],
  catalogs: readonly TrustedToolCatalog[] = TRUSTED_TOOL_CATALOGS,
): BindingDisclosure[] {
  const out: BindingDisclosure[] = [];
  for (const entry of entries) {
    for (const binding of entry.capability_sources ?? []) {
      const inherited = inheritedFrom.some((e) => e.capability_sources?.some((b) => sameBinding(b, binding)));
      const catalog = catalogs.find((c) => c.source_uri === binding.source_uri);
      let description: string | undefined;
      if (catalog) {
        try {
          const definition = extractMcpToolDefinition(catalog.text, binding.operation_ref);
          if (capabilitySourceDigest(definition) === binding.source_digest) {
            const text = (definition as { description?: JsonValue }).description;
            if (typeof text === "string") description = text;
          }
        } catch {
          description = undefined;
        }
      }
      if (description === undefined && !inherited) {
        throw new IntentError(
          "invalid_authorization_details",
          `the trusted catalog does not serve the definition the binding of ${binding.action} commits; render the request again`,
        );
      }
      const service = catalog ? CATALOG_SERVICES.find((s) => s.id === catalog.service_id) : undefined;
      out.push({
        resource: entry.resource,
        binding,
        ...(description !== undefined ? { description } : {}),
        ...(service?.display_name ? { sourceName: service.display_name } : {}),
        inherited,
      });
    }
  }
  return out;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/** The page section for these disclosures; empty when nothing is bound. */
export function renderBindingDisclosures(disclosures: readonly BindingDisclosure[]): string {
  if (!disclosures.length) return "";
  const items = disclosures.map(({ resource, binding, description, sourceName, inherited }) => {
    const authorizes =
      description !== undefined
        ? `${inherited ? "Kept from the Mission being widened, where it was approved. " : ""}Invoking it: <q class="binding-description">${escapeHtml(description)}</q> (the tool's own description, from its catalog).`
        : "Kept from the Mission being widened, where it was approved. The trusted catalog no longer serves that definition, so a call to the changed tool is refused.";
    return `<li class="capability-binding" data-action="${escapeHtml(binding.action)}" data-tool-id="${escapeHtml(binding.tool_id)}" data-operation-ref="${escapeHtml(binding.operation_ref)}" data-source-digest="${escapeHtml(binding.source_digest)}">
<p class="binding-identity">Action <code>${escapeHtml(binding.action)}</code> on <code>${escapeHtml(resource)}</code> invokes the tool <code>${escapeHtml(binding.operation_ref)}</code> (<code>${escapeHtml(binding.tool_id)}</code>).</p>
<p class="binding-authorizes">${authorizes}</p>
<p class="binding-source">Source: the trusted catalog at <code>${escapeHtml(binding.source_uri)}</code>${sourceName ? `, configured here as <q>${escapeHtml(sourceName)}</q>` : ""}.</p>
<p class="binding-publisher">Publisher: unknown; this server has not established one.</p>
<p class="binding-drift">A later change to this tool's definition is refused.</p>
</li>`;
  });
  return `<h2>Tools these actions are bound to</h2>
<ul class="capability-bindings">
${items.join("\n")}
</ul>`;
}
