/**
 * @spec attenuation#root-mapping (#1756, D902, D904): what this resource
 * server declares to the Mission Issuer about the operations an Attenuating
 * Agent Token tool identifier names, for the root mapping
 * (`mapAuthorityToCeiling` in the authorization server).
 *
 * A tool identifier `<resource>#<action>` names every payments tool whose
 * action is `action`, at this resource's canonical identifier: every tool of
 * the shipped profile is performed under the service contract, so its
 * operation target is that identifier. Each operation's arguments are the
 * trusted tool catalog's input schema, required as the schema requires them.
 *
 * The facts each operation establishes are the ones this PEP establishes
 * from its own records before it decides, and enforces against a
 * credential's constraints ({@link Pep.enforce}): every vendor the operation
 * reaches (`vendors`), and the invoice amount of an amount-bearing action
 * (`max_amount`). No other constraint key is declared, so an entry carrying
 * one is not mapped to a tool: the Mission Issuer omits it rather than carry
 * a restriction this declaration does not claim the PEP enforces.
 */

import { type AttenuationOperation, type AttenuationOperations, aatToolId } from "@mission/core";
import { isAmountBearingAction } from "@mission/demo-data";
import { CANONICAL_RESOURCE, type ActionMapping, TOOL_ACTIONS } from "./pep.js";
import { PaymentsToolCatalog } from "./tool-catalog.js";

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** The constraint keys whose facts this PEP establishes for `mapping`'s operation. */
function establishedFacts(mapping: ActionMapping): string[] {
  const facts: string[] = [];
  if (mapping.needsInvoice || mapping.bindsVendorScope === true || mapping.targetsVendor === true) facts.push("vendors");
  if (mapping.needsInvoice && isAmountBearingAction(mapping.action)) facts.push("max_amount");
  return facts;
}

/** One tool's declared operation: its input schema's arguments and the facts it establishes. */
function operationOf(name: string, mapping: ActionMapping, catalog: PaymentsToolCatalog): AttenuationOperation | undefined {
  const schema = (catalog.toolDefinitions([name])[0] as { inputSchema?: unknown } | undefined)?.inputSchema;
  if (!isObject(schema) || !isObject(schema.properties)) return undefined;
  const required = Array.isArray(schema.required) ? schema.required : [];
  const args: Record<string, { required: boolean }> = {};
  for (const arg of Object.keys(schema.properties)) args[arg] = { required: required.includes(arg) };
  return { name, arguments: args, establishes: establishedFacts(mapping) };
}

/**
 * The payments resource server's declaration: for a tool identifier at this
 * resource, one operation per tool whose action it names, or undefined when
 * it names none (or a tool's schema cannot be read, which declares nothing
 * for that action rather than part of it).
 */
export function paymentsAttenuationOperations(
  catalog: PaymentsToolCatalog = new PaymentsToolCatalog(),
): AttenuationOperations {
  return (resource, action) => {
    if (resource !== CANONICAL_RESOURCE) return undefined;
    const ops: AttenuationOperation[] = [];
    for (const [name, mapping] of Object.entries(TOOL_ACTIONS)) {
      if (mapping.action !== action) continue;
      const op = operationOf(name, mapping, catalog);
      if (op === undefined) return undefined;
      ops.push(op);
    }
    return ops.length > 0 ? ops : undefined;
  };
}

/**
 * @spec attenuation#root-mapping: the tool identifier this resource computes
 * for an invocation of the payments tool `name`, as the holder signs it in
 * the proof's `aat_tool`: the operation's target and action.
 */
export function paymentsAatToolId(name: string): string {
  const mapping = TOOL_ACTIONS[name];
  if (mapping === undefined) throw new Error(`no payments tool ${JSON.stringify(name)}`);
  return aatToolId(CANONICAL_RESOURCE, mapping.action);
}
