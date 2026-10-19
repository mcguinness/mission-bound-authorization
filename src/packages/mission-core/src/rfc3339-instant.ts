/**
 * @spec resource-access#value-space-comparison: RFC 3339 date-time values
 * compared as the instants they denote after normalization to UTC, so two
 * representations of one instant that differ only in timezone offset or in
 * trailing subsecond zeros are equal.
 *
 * Strict and exact. The grammar is RFC 3339's `date-time` (a date-only value,
 * an RFC 2822 string or any other form `Date.parse` happens to accept is
 * refused), every calendar field is range-checked, and the fractional part is
 * kept as digits rather than rounded to milliseconds, so two instants that
 * differ below a millisecond still compare unequal. A leap second (`:60`) is
 * refused: this module cannot place it on the UTC timeline without guessing.
 */

const DATE_TIME =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:([Zz])|([+-])(\d{2}):(\d{2}))$/;

/** An instant: whole seconds since the epoch, and the fractional digits with trailing zeros removed. */
export interface Instant {
  readonly seconds: bigint;
  readonly fraction: string;
}

/** The instant an RFC 3339 `date-time` string denotes, or `undefined` when the value is not one. */
export function parseRfc3339Instant(value: unknown): Instant | undefined {
  if (typeof value !== "string") return undefined;
  const m = DATE_TIME.exec(value);
  if (!m) return undefined;
  const [year, month, day, hour, minute, second] = m.slice(1, 7).map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  if (month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59) {
    return undefined;
  }
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  // A day past the month's end rolls over; refuse it rather than accept the roll.
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return undefined;
  }
  let offsetSeconds = 0;
  if (m[8] === undefined) {
    const offsetHours = Number(m[10]);
    const offsetMinutes = Number(m[11]);
    if (offsetHours > 23 || offsetMinutes > 59) return undefined;
    offsetSeconds = (offsetHours * 60 + offsetMinutes) * 60 * (m[9] === "-" ? -1 : 1);
  }
  const seconds = BigInt(date.getTime() / 1000) - BigInt(offsetSeconds);
  return { seconds, fraction: (m[7] ?? "").replace(/0+$/, "") };
}

/** True when `value` is an RFC 3339 `date-time` this module can place on the UTC timeline. */
export function isRfc3339Instant(value: unknown): value is string {
  return parseRfc3339Instant(value) !== undefined;
}

/** -1, 0 or 1 as `a` is before, at or after `b`. */
export function compareInstants(a: Instant, b: Instant): -1 | 0 | 1 {
  if (a.seconds !== b.seconds) return a.seconds < b.seconds ? -1 : 1;
  const width = Math.max(a.fraction.length, b.fraction.length);
  const fa = a.fraction.padEnd(width, "0");
  const fb = b.fraction.padEnd(width, "0");
  if (fa === fb) return 0;
  return fa < fb ? -1 : 1;
}

/** The instant of an epoch-millisecond reading (a trusted clock), exactly. */
export function instantFromMs(ms: number): Instant {
  const whole = Math.floor(ms / 1000);
  const millis = ms - whole * 1000;
  return { seconds: BigInt(whole), fraction: String(millis).padStart(3, "0").replace(/0+$/, "") };
}

/** The latest epoch millisecond at or before `instant`: a ceiling never later than the instant. */
export function instantFloorMs(instant: Instant): number {
  return Number(instant.seconds) * 1000 + Number(instant.fraction.slice(0, 3).padEnd(3, "0"));
}
