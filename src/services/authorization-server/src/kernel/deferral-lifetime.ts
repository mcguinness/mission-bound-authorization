/**
 * Deferral lifetime (seconds): the advertised expires_in; a poll after this is
 * expired_token. Its own module so the creation-idempotency store, which
 * deferred.ts imports, can read it without an import cycle.
 */
export const DEFERRAL_EXPIRES_IN = 600;
