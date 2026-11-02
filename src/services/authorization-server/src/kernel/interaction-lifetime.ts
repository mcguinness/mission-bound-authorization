/**
 * Authorization interaction lifetime (seconds): the oidc-provider `Interaction`
 * TTL the provider configures (oidc-provider's own default). A decision on an
 * interaction arrives only within it, so the kernel prunes an approval
 * reservation once it is older than this plus the clock skew (#1922). Its own
 * module so the kernel and the provider read one value.
 */
export const INTERACTION_TTL_S = 60 * 60;

/**
 * oidc-provider's `clockTolerance` (seconds), the value the provider configures
 * (oidc-provider's own default): an interaction is still accepted this long
 * past its expiry, so the skew a reservation is kept for is never less (#1922).
 */
export const PROVIDER_CLOCK_TOLERANCE_S = 15;
