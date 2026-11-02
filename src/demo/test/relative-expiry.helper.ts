/**
 * Fixture expiries for tests on the real clock (#1968, D1133): each is a fixed
 * distance ahead of the clock when this module loads, in whole seconds, so no
 * fixture expires because the host's date moved on. Computed once, so every
 * use in a test file names the same instant. They keep the order of the
 * fixtures they serve: EARLIER_EXPIRES_AT before FIXTURE_EXPIRES_AT before
 * LATER_EXPIRES_AT. A file on a controlled clock derives its instants from
 * that clock instead.
 */
export function daysFromNow(days: number): string {
  return new Date(Math.ceil(Date.now() / 1000) * 1000 + days * 86_400_000).toISOString().replace(".000Z", "Z");
}

/** An expiry 30 days ahead: one that falls before the default fixture expiry. */
export const EARLIER_EXPIRES_AT = daysFromNow(30);

/** The default fixture expiry, 61 days ahead. */
export const FIXTURE_EXPIRES_AT = daysFromNow(61);

/** An expiry 212 days ahead: a ceiling or template that outlives the default fixture expiry. */
export const LATER_EXPIRES_AT = daysFromNow(212);
