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
