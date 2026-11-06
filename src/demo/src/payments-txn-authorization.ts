/**
 * The payments deployment's Transaction Authorization Server configuration:
 * one definition for every composition whose AS serves the payments
 * resource's action-bound approvals, in process (`composeStack`) or in its own
 * process (`as-native-separated/as-server.ts`, #1101).
 */

import {
  type buildAuthorizationServer,
  contractOperationProfiles,
  type OperationProfileRegistry,
} from "@mission/authorization-server";
import { TOPOLOGY, USERS } from "@mission/demo-data";
import { CANONICAL_RESOURCE } from "@mission/mcp-payments";
import { type MissionView, relationForAction } from "@mission/pdp";

export type TransactionAuthorizationOptions = NonNullable<Parameters<typeof buildAuthorizationServer>[0]["transactionAuthorization"]>;

export function paymentsTransactionAuthorization(input: {
  challengeIssuers: TransactionAuthorizationOptions["challengeIssuers"];
  ars: TransactionAuthorizationOptions["ars"];
  /** The AS's own read of a Mission it holds, for the fresh decision at completion. */
  viewFor: (missionId: string) => MissionView | undefined;
}): TransactionAuthorizationOptions & { operationProfiles: OperationProfileRegistry } {
  const { challengeIssuers, ars, viewFor } = input;
  const txnTopo = TOPOLOGY.txnChallenge.payments;
  return {
    challengeIssuers,
    ars,
    // @spec txn-authorization#two-phase-expiry — the pending workflow's own
    // lifetime and the deployment maximum for an issued transaction token
    // are INDEPENDENT of the challenge's admission window.
    workflowLifetimeSeconds: txnTopo.workflowLifetimeSeconds,
    maxTokenLifetimeSeconds: txnTopo.maxTokenLifetimeSeconds,
    maxApprovalAgeSeconds: TOPOLOGY.ttls.maxApprovalAgeSeconds,
    // @spec txn-authorization#resource-challenge — the Operation Profiles
    // this deployment recognizes. The payments resource challenges with the
    // family's own `mission_resource_access` entry, so that profile governs
    // its operations; an entry naming any other type is refused at
    // admission rather than read structurally.
    // #249, #1846: one profile under each version the payments contract
    // declares, named by its own document, the current one registered and
    // the others retained, so a supported older reference resolves to its
    // own profile and a retired one is refused by resolution.
    operationProfiles: contractOperationProfiles(CANONICAL_RESOURCE),
    // @spec txn-authorization#challenge-redemption step 7 — the deployment's
    // entitlement and resource-policy decision, run FRESH at completion
    // against LIVE state. A completed approval is context here, never a
    // bypass: each of these denies on its own, after an approval, whenever
    // the input no longer holds -- the Mission is no longer active, the
    // containment overlay has narrowed the entry away, the deployment does
    // not recognize the action, the entry has no vendor scope left, or the
    // local subject is no longer an entitled account.
    freshDecision: async (input) => {
      const view = viewFor(input.missionId);
      if (!view || view.state !== "active") return { decision: "deny", reason: "mission_inactive" };
      const entry = view.authority_set.find(
        (e) => e.resource === input.resource && e.actions.includes(input.action),
      );
      if (!entry) return { decision: "deny", reason: "out_of_authority" };
      const contained = view.containment?.contained.some(
        (c) => c.resource === input.resource && (c.actions === undefined || c.actions.includes(input.action)),
      );
      if (contained) return { decision: "deny", reason: "authority_contained" };
      if (!relationForAction(input.action)) return { decision: "deny", reason: "unknown_action" };
      if (!entry.constraints?.vendors?.length) return { decision: "deny", reason: "no_vendor_scope" };
      // Principal entitlement, from the deployment's own identity config:
      // the DESTINATION-LOCAL subject must still be an account this estate
      // carries. Where the Origin Principal profile applies the decision
      // also receives `originPrincipal`, issuer-qualified and separate; a
      // local account list is never matched against a foreign namespace.
      if (!USERS.some((u) => u.sub === input.subject)) {
        return { decision: "deny", reason: "entitlement_denied" };
      }
      return { decision: "permit" };
    },
  };
}
