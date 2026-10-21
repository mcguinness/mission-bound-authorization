/**
 * @spec resource-access#resource-contract (#249, D553): approval-time
 * assembly and validation of an entry's `resource_contract` reference, from
 * the trusted configuration the resource declares
 * ({@link ResourceContractDeclarations}), never from client input.
 *
 * "The authorization server assembles the reference from trusted resource or
 * deployment configuration, which states whether an entry's `resource`
 * requires a reference and which contract version is current for it. A
 * `resource_contract` a client proposes is a proposal, never an authoritative
 * declaration. Before approval, the authorization server:
 *
 * - MUST refuse, with the `invalid_authorization_details` error code, a
 *   proposed entry whose `resource_contract` does not equal, member for
 *   member, the reference of a contract its configuration names as current
 *   for the entry's `resource` and that defines every action and action
 *   family the entry lists; and
 * - MUST, where its configuration requires a reference for the entry's
 *   `resource` and the proposal carries none, record the current contract's
 *   reference in the entry, so that the Approver approves the entry with it."
 *
 * A deployment with no declarations configures no current contract, so every
 * proposed reference is refused and none is required: the member is refused,
 * never dropped.
 */

import { type ResourceContractDeclarations, resourceContractViolation } from "@mission/core";
import { IntentError } from "./intent.js";
import type { AuthorityEntry } from "./types.js";

function refuse(message: string): never {
  throw new IntentError("invalid_authorization_details", message);
}

/**
 * The first bullet, at proposal intake (PAR and every other proposal
 * intake): a proposed reference that is not the configured current one for
 * its entry refuses the whole proposal before anything is derived.
 */
export function assertProposedContractsCurrent(
  proposal: readonly AuthorityEntry[],
  contracts: ResourceContractDeclarations,
): void {
  for (const entry of proposal) {
    const ref = entry.resource_contract;
    if (ref === undefined) continue;
    const violation = resourceContractViolation(ref);
    if (violation !== undefined) refuse(violation);
    if (!contracts.isCurrentFor(entry, ref)) {
      refuse(
        "resource_contract is not a contract this authorization server's configuration names as current for the entry's resource and defining every action it lists",
      );
    }
  }
}

/**
 * Both bullets, on the derived entries a fresh approval renders and commits:
 * a carried reference must be the current one, and where configuration
 * requires a reference and the entry carries none, the one current reference
 * is recorded in it. A requirement no single current contract meets (none
 * defines every action the entry lists, or more than one applies) refuses
 * rather than choosing. Order-preserving and one entry out per entry in, so
 * per-entry provenance stays index-aligned.
 */
export function assembleResourceContracts(
  entries: readonly AuthorityEntry[],
  contracts: ResourceContractDeclarations,
): AuthorityEntry[] {
  return entries.map((entry) => {
    const config = contracts.forEntry(entry);
    if (entry.resource_contract !== undefined) {
      if (!contracts.isCurrentFor(entry, entry.resource_contract)) {
        refuse(
          "resource_contract is not a contract this authorization server's configuration names as current for the entry's resource and defining every action it lists",
        );
      }
      return entry;
    }
    if (!config.required) return entry;
    const [current, ...more] = config.current;
    if (current === undefined || more.length > 0) {
      refuse(
        "configuration requires a resource_contract for the entry's resource and names no single current contract defining every action it lists",
      );
    }
    return { ...entry, resource_contract: current };
  });
}

/**
 * @spec resource-access#resource-contract: "Every derivation, narrowing, and
 * delegation of the entry preserves it exactly", and "a reference that does
 * not resolve there authorizes nothing". Every derivation checks a carried
 * reference against the declarations as preserved, not re-assembled: a
 * superseded version within its retention stands, while an unknown, retired,
 * changed or out-of-retention reference refuses.
 */
export function assertCarriedContractsResolvable(
  entries: readonly AuthorityEntry[],
  contracts: ResourceContractDeclarations,
  now: Date,
): void {
  for (const entry of entries) {
    const violation = contracts.carriedViolation(entry, now);
    if (violation !== undefined) refuse(violation);
  }
}
