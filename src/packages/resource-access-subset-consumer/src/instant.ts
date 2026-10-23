// RFC 3339 date-time values and their comparison as instants
// (resource-access#initial-common-constraints: "a date-time string as defined
// in RFC3339"; resource-access#value-space-comparison: "compared as the
// instants they denote after normalization to UTC").
//
// Parsed by hand from the RFC 3339 section 5.6 grammar rather than with
// Date.parse, which accepts forms outside that grammar and cannot represent a
// leap second or more than millisecond precision.

// RFC 3339 section 5.6: full-date "T" full-time, time-secfrac = "." 1*DIGIT,
// time-offset = "Z" / ("+" / "-") time-hour ":" time-minute. ABNF literals are
// case-insensitive, so "t" and "z" are admitted (RFC 3339 section 5.6 NOTE).
const DATE_TIME =
  /^([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?(?:([Zz])|([+-])([0-9]{2}):([0-9]{2}))$/;

/**
 * An instant on the UTC time line. `seconds` counts non-leap seconds since
 * 1970-01-01T00:00:00Z; `leap` marks the inserted second 23:59:60 UTC, which
 * follows every instant of the 23:59:59 second it shares `seconds` with;
 * `fraction` is the subsecond digit string with trailing zeros removed.
 */
export interface Instant {
  readonly seconds: bigint;
  readonly leap: boolean;
  readonly fraction: string;
}

function digits(text: string): number {
  // Small integer fields (year, month, ...) built from ASCII digits.
  let value = 0;
  for (const ch of text) value = value * 10 + (ch.charCodeAt(0) - 48);
  return value;
}

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

// Days from 1970-01-01 to the given proleptic Gregorian date (RFC 3339
// section 5.6 uses the Gregorian calendar).
function daysFromCivil(year: number, month: number, day: number): bigint {
  const y = BigInt(month <= 2 ? year - 1 : year);
  const era = (y >= 0n ? y : y - 399n) / 400n;
  const yoe = y - era * 400n;
  const m = BigInt(month);
  const doy = (153n * (m > 2n ? m - 3n : m + 9n) + 2n) / 5n + BigInt(day) - 1n;
  const doe = yoe * 365n + yoe / 4n - yoe / 100n + doy;
  return era * 146097n + doe - 719468n;
}

/**
 * Parse an RFC 3339 date-time. Returns undefined for any string outside the
 * grammar or with an out-of-range field (RFC 3339 section 5.7). A second of 60
 * is admitted only where it falls at 23:59:60 UTC, the one place RFC 3339
 * section 5.7 places a leap second; this consumer has no leap-second table, so
 * it does not check that the date carried one.
 */
export function parseInstant(value: unknown): Instant | undefined {
  if (typeof value !== "string") return undefined;
  const m = DATE_TIME.exec(value);
  if (!m) return undefined;
  const [, ys, mos, ds, hs, mis, ss, frac, zulu, sign, ohs, oms] = m;
  if (ys === undefined || mos === undefined || ds === undefined) return undefined;
  if (hs === undefined || mis === undefined || ss === undefined) return undefined;
  const year = digits(ys);
  const month = digits(mos);
  const day = digits(ds);
  const hour = digits(hs);
  const minute = digits(mis);
  const second = digits(ss);
  if (month < 1 || month > 12) return undefined;
  if (day < 1 || day > daysInMonth(year, month)) return undefined;
  if (hour > 23 || minute > 59 || second > 60) return undefined;
  let offsetMinutes = 0;
  if (zulu === undefined) {
    if (sign === undefined || ohs === undefined || oms === undefined) return undefined;
    const oh = digits(ohs);
    const om = digits(oms);
    if (oh > 23 || om > 59) return undefined;
    offsetMinutes = (sign === "-" ? -1 : 1) * (oh * 60 + om);
  }
  const leap = second === 60;
  // Local wall-clock seconds, then shifted to UTC by the offset.
  const localSeconds =
    daysFromCivil(year, month, day) * 86400n +
    BigInt(hour * 3600 + minute * 60 + (leap ? 59 : second));
  const seconds = localSeconds - BigInt(offsetMinutes * 60);
  if (leap) {
    // The leap second is 23:59:60 UTC: the UTC second it follows is 23:59:59.
    const utcSecondOfDay = ((seconds % 86400n) + 86400n) % 86400n;
    if (utcSecondOfDay !== 86399n) return undefined;
  }
  return { seconds, leap, fraction: (frac ?? "").replace(/0+$/, "") };
}

/** Compare two instants: negative, zero or positive as a is before, at, or after b. */
export function compareInstant(a: Instant, b: Instant): number {
  if (a.seconds !== b.seconds) return a.seconds < b.seconds ? -1 : 1;
  if (a.leap !== b.leap) return a.leap ? 1 : -1;
  const scale = Math.max(a.fraction.length, b.fraction.length);
  const x = BigInt(a.fraction.padEnd(scale, "0") || "0");
  const y = BigInt(b.fraction.padEnd(scale, "0") || "0");
  if (x < y) return -1;
  if (x > y) return 1;
  return 0;
}
