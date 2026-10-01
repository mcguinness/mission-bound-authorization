/**
 * Deployment capability controls for the reference AS assembly.
 *
 * The issuance profile itself (PAR, the authorization code with PKCE,
 * DPoP-bound JWT access tokens, refresh, scope projection, the approval
 * interaction, the `authorization_details` types metadata, and introspection)
 * is always on and is not listed here. Each capability below is a surface a
 * deployment may leave out. An assembly built with no capability set enables
 * every one of them, which is the full reference provider.
 *
 * A disabled capability refuses with the standard error its path already uses
 * when it is not configured: an unregistered grant type answers
 * `unsupported_grant_type`, a disabled token-exchange profile or lifecycle
 * operation answers `invalid_request`, an unconfigured endpoint answers 501
 * `temporarily_unavailable`, and an absent route answers 404.
 */
export type ProviderCapability =
  /** RFC 8693 exchange with `request_refresh_token` (async-delegation). */
  | "async-delegation"
  /** Child creation (exchange to a JWT grant) and the child's RFC 7523 jwt-bearer redemption. */
  | "child-delegation"
  /** ICA subject token to a continuation ID-JAG (cross-domain projection). */
  | "continuation"
  /** Cross-organization chain exchange (Chain Presentation subject token). */
  | "cross-org"
  /** Expansion exchange (exchange to a Mission access token). */
  | "expansion"
  /** The AROP deferred grant (DTR). */
  | "deferred"
  /** Mission Templates: the dispatch grant and the template admin routes. */
  | "templates"
  /** The lifecycle `contain` operation and protected-event ingestion. */
  | "containment"
  /** The lifecycle `discharge` operation. */
  | "discharge"
  /** The lifecycle `revoke` operation. */
  | "lifecycle-revoke"
  /** The lifecycle `suspend`, `resume` and `complete` operations. */
  | "lifecycle-extended"
  /** The signed Mission Status operation (`GET /missions/{id}/status`). */
  | "status"
  /** The Mission Status List fetch (`GET /statuslist/{id}`). */
  | "status-list"
  /** The transaction authorization endpoint. */
  | "transaction-authorization"
  /** The dev-only ordinary-token route. */
  | "dev-token"
  /** OIDC: `openid` and the OIDC scope values, userinfo, and RP-initiated logout. */
  | "oidc"
  /** RFC 7009 token revocation. */
  | "token-revocation"
  /** The `mission_attenuation_supported` metadata member. */
  | "attenuation"
  /** The `service_catalog_endpoint` metadata member. */
  | "service-catalog";

/** Every capability, in declaration order. */
export const ALL_PROVIDER_CAPABILITIES: readonly ProviderCapability[] = [
  "async-delegation",
  "child-delegation",
  "continuation",
  "cross-org",
  "expansion",
  "deferred",
  "templates",
  "containment",
  "discharge",
  "lifecycle-revoke",
  "lifecycle-extended",
  "status",
  "status-list",
  "transaction-authorization",
  "dev-token",
  "oidc",
  "token-revocation",
  "attenuation",
  "service-catalog",
];

/** The token-exchange profiles; the exchange grant is registered when any is on. */
export const TOKEN_EXCHANGE_CAPABILITIES: readonly ProviderCapability[] = [
  "async-delegation",
  "child-delegation",
  "continuation",
  "cross-org",
  "expansion",
];

/**
 * Whether `capability` is enabled. An absent set enables everything (the full
 * reference provider).
 */
export function capabilityEnabled(
  opts: { capabilities?: ReadonlySet<ProviderCapability> | undefined },
  capability: ProviderCapability,
): boolean {
  return opts.capabilities === undefined || opts.capabilities.has(capability);
}
