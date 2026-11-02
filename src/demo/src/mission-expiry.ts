/**
 * The demo's default Mission expiry (#1976, D1141): a fixed distance after the
 * owning clock's current instant (the stack's, AS's or MAS's kernel clock), in
 * whole seconds, so the demo never submits an Intent whose `expires_at` the
 * host's date has already passed. A caller that supplies its own expiry keeps
 * it.
 */

const DAY_MS = 86_400_000;

/** How long a demo Mission lives by default. */
export const DEMO_MISSION_LIFETIME_DAYS = 61;

/** An RFC 3339 `expires_at` `days` after `now`, rounded up to whole seconds. */
export function defaultMissionExpiry(now: Date, days: number = DEMO_MISSION_LIFETIME_DAYS): string {
  return new Date(Math.ceil(now.getTime() / 1000) * 1000 + days * DAY_MS).toISOString().replace(".000Z", "Z");
}
