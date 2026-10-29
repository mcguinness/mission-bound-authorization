/**
 * oidc-provider 9.10.0 (pinned exactly in package.json) ships no `exports`
 * map, so its grant modules are importable by path; @types/oidc-provider 9.5
 * does not declare them. This declares the one module the Deferred Mission
 * Approval wiring wraps (adapters/deferred-mission-approval.ts): the
 * authorization_code grant's handler and its parameter set, which the
 * provider's own initialization extends in place with `resource` and
 * `authorization_details`.
 */
declare module "oidc-provider/lib/actions/grants/authorization_code.js" {
  import type { KoaContextWithOIDC } from "oidc-provider";
  export const handler: (ctx: KoaContextWithOIDC) => Promise<void>;
  export const parameters: Set<string>;
  export const grantType: "authorization_code";
}

/**
 * @spec mission#approval-event (step 7) (#1863): the provider's in-memory
 * adapter, which the reference AS's `adapter` factory (approval-hold.ts)
 * keeps for every model and wraps for `AuthorizationCode`.
 */
declare module "oidc-provider/lib/adapters/memory_adapter.js" {
  import type { Adapter } from "oidc-provider";
  export default class MemoryAdapter implements Adapter {
    constructor(model: string);
    upsert: Adapter["upsert"];
    find: Adapter["find"];
    findByUserCode: Adapter["findByUserCode"];
    findByUid: Adapter["findByUid"];
    consume: Adapter["consume"];
    destroy: Adapter["destroy"];
    revokeByGrantId: Adapter["revokeByGrantId"];
  }
}
