/**
 * @spec runtime#input-resource-policy (#828): where the demo's independently
 * administered Resource policy lives, and how it is provisioned.
 *
 * The policy is a set of stored OpenFGA entitlements the PDP reads with no
 * Mission input. Two ways to reach the store, and no default between them:
 *
 * - `attach`: a configured store and model. Startup reads the model back and
 *   verifies it; nothing is created or written, so a revocation made before
 *   the restart is exactly what the next decision reads.
 * - `bootstrap: "development"`: a DEVELOPMENT OPERATION. A fresh store is
 *   created and seeded with `config/seed/resource-policy.json` plus the
 *   payments store's own invoice ownership. Nothing in it is derived from a
 *   Mission approval or a token.
 */

import { Fga, FgaDomainAdmin, principalObject } from "@mission/pdp";
import { RESOURCE_POLICY_SEED } from "@mission/demo-data";

type TupleKey = { user: string; relation: string; object: string };

export type ResourcePolicyStore = { attach: { storeId: string; modelId: string } } | { bootstrap: "development" };

/**
 * The demo entrypoints' choice: attach when `OPENFGA_STORE_ID` and
 * `OPENFGA_MODEL_ID` name a store, else bootstrap a development store (and
 * print its ids, so a restart can attach to it).
 */
export function resourcePolicyStoreFromEnv(env: NodeJS.ProcessEnv = process.env): ResourcePolicyStore {
  const storeId = env.OPENFGA_STORE_ID;
  const modelId = env.OPENFGA_MODEL_ID;
  if (storeId && modelId) return { attach: { storeId, modelId } };
  if (storeId || modelId) throw new Error("set both OPENFGA_STORE_ID and OPENFGA_MODEL_ID to attach, or neither");
  return { bootstrap: "development" };
}

export async function openResourcePolicyStore(
  connection: { apiUrl: string; presharedKey: string; caCertPath?: string },
  store: ResourcePolicyStore,
): Promise<{ fga: Fga; modelId: string; storeId: string; development: boolean }> {
  if ("attach" in store) {
    const fga = await Fga.attach({ ...connection, storeId: store.attach.storeId, authorizationModelId: store.attach.modelId });
    return { fga, modelId: store.attach.modelId, storeId: store.attach.storeId, development: false };
  }
  if (store.bootstrap !== "development") throw new Error("a Resource-policy store must be attached or bootstrapped for development");
  const conn = await Fga.bootstrap(connection);
  return { ...conn, development: true };
}

/**
 * The development grants: each seeded entitlement for its subject under
 * `issuer` (the issuer-local mapping), and each invoice's owning vendor as
 * the payments store records it.
 */
export function developmentResourcePolicyTuples(issuer: string, invoices: ReadonlyArray<{ id: string; vendor_id: string }>): TupleKey[] {
  return [
    ...RESOURCE_POLICY_SEED.map((e) => ({
      user: principalObject({ iss: issuer, sub: e.sub }),
      relation: e.relation,
      object: `vendor:${e.vendor}`,
    })),
    ...invoices.map((inv) => ({ user: `vendor:${inv.vendor_id}`, relation: "vendor", object: `invoice:${inv.id}` })),
  ];
}

export async function seedDevelopmentResourcePolicy(
  fga: Fga,
  issuer: string,
  invoices: ReadonlyArray<{ id: string; vendor_id: string }>,
): Promise<void> {
  await new FgaDomainAdmin(fga).grant(developmentResourcePolicyTuples(issuer, invoices));
}
