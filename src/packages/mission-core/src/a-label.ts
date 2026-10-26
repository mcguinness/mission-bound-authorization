/**
 * @spec resource-access#entry-validation (#1376, D858): the structural checks
 * on a `recipient_domain` label carrying the `xn--` prefix, which Resource
 * Access requires to be an A-label as RFC 5890 Section 2.3.2.1 defines it.
 *
 * Checked, as RFC 5891 Sections 4.2.3 and 5.4 give the structure: compared
 * case-insensitively, the ASCII label decodes under Punycode (RFC 3492) and
 * encodes back to itself; the decoded U-label holds a non-ASCII character,
 * is in NFC and in lower case as decoded (never repaired), does not begin
 * with a combining mark, and meets the hyphen restrictions.
 *
 * Not checked, a stated residual (D858): the code-point classes of RFC 5892
 * (RFC 5891 Section 4.2.2), the contextual rules (Section 4.2.3.3) and the
 * Bidi rule (Section 4.2.3.4, RFC 5893). A label only those refuse, such as
 * `xn--n3h` (U+2603, DISALLOWED), is admitted.
 */

const ACE_PREFIX = "xn--";

// RFC 3492 Section 5 parameters.
const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 0x80;
// RFC 3492 Section 6.4: a decoder detects overflow against its integer width.
const MAX_INT = 0x7fffffff;
const MAX_CODE_POINT = 0x10ffff;
const HYPHEN = 0x2d;

/** RFC 3492 Section 6.1. */
function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : Math.floor(delta / 2);
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - T_MIN) * T_MAX) / 2) {
    d = Math.floor(d / (BASE - T_MIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - T_MIN + 1) * d) / (d + SKEW));
}

function threshold(k: number, bias: number): number {
  return k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
}

/** A lower-case basic code point's digit value (`a`-`z` 0 to 25, `0`-`9` 26 to 35), or BASE for any other. */
function digitValue(c: number): number {
  if (c >= 0x61 && c <= 0x7a) return c - 0x61;
  if (c >= 0x30 && c <= 0x39) return c - 0x30 + 26;
  return BASE;
}

function digitChar(d: number): string {
  return String.fromCharCode(d < 26 ? 0x61 + d : 0x30 + d - 26);
}

/**
 * RFC 3492 Section 6.2 decoding of a lower-case Punycode string, or
 * `undefined` for a malformed one: a non-basic or invalid digit, a truncated
 * integer, an overflow, or a code point that is out of range or a surrogate.
 * Never throws.
 */
export function punycodeDecode(input: string): number[] | undefined {
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;
  const b = Math.max(input.lastIndexOf("-"), 0);
  const output: number[] = [];
  for (let j = 0; j < b; j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) return undefined;
    output.push(c);
  }
  let pos = b > 0 ? b + 1 : 0;
  while (pos < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (pos >= input.length) return undefined;
      const digit = digitValue(input.charCodeAt(pos++));
      if (digit >= BASE) return undefined;
      if (digit > Math.floor((MAX_INT - i) / w)) return undefined;
      i += digit * w;
      const t = threshold(k, bias);
      if (digit < t) break;
      if (w > Math.floor(MAX_INT / (BASE - t))) return undefined;
      w *= BASE - t;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    if (Math.floor(i / len) > MAX_INT - n) return undefined;
    n += Math.floor(i / len);
    i %= len;
    if (n > MAX_CODE_POINT || (n >= 0xd800 && n <= 0xdfff)) return undefined;
    output.splice(i, 0, n);
    i++;
  }
  return output;
}

/** RFC 3492 Section 6.3 encoding, in lower case, of valid code points. */
export function punycodeEncode(input: readonly number[]): string {
  let n = INITIAL_N;
  let delta = 0;
  let bias = INITIAL_BIAS;
  let output = "";
  for (const c of input) if (c < 0x80) output += String.fromCharCode(c);
  const b = output.length;
  let h = b;
  if (b > 0) output += "-";
  while (h < input.length) {
    let m = MAX_CODE_POINT + 1;
    for (const c of input) if (c >= n && c < m) m = c;
    delta += (m - n) * (h + 1);
    n = m;
    for (const c of input) {
      if (c < n) delta++;
      if (c === n) {
        let q = delta;
        for (let k = BASE; ; k += BASE) {
          const t = threshold(k, bias);
          if (q < t) break;
          output += digitChar(t + ((q - t) % (BASE - t)));
          q = Math.floor((q - t) / (BASE - t));
        }
        output += digitChar(q);
        bias = adapt(delta, h + 1, h === b);
        delta = 0;
        h++;
      }
    }
    delta++;
    n++;
  }
  return output;
}

/**
 * Why `label` is not a structurally valid A-label, or `undefined` when it is
 * one or does not carry the `xn--` prefix. The ASCII label is compared
 * case-insensitively, so it is read in lower case; the decoded form is
 * checked as decoded.
 */
export function aLabelViolation(label: string): string | undefined {
  const ascii = label.toLowerCase();
  if (!ascii.startsWith(ACE_PREFIX)) return undefined;
  const encoded = ascii.slice(ACE_PREFIX.length);
  const cps = punycodeDecode(encoded);
  if (cps === undefined) return "does not decode under Punycode";
  if (punycodeEncode(cps) !== encoded) return "does not encode back to itself";
  if (cps.every((c) => c < 0x80)) return "decodes to an ASCII-only label";
  const u = String.fromCodePoint(...cps);
  if (u.normalize("NFC") !== u) return "decodes to a label not in NFC";
  if (u.toLowerCase() !== u) return "decodes to a label with an upper-case character";
  if (/^\p{M}/u.test(u)) return "decodes to a label beginning with a combining mark";
  if (cps[0] === HYPHEN || cps[cps.length - 1] === HYPHEN) {
    return "decodes to a label beginning or ending with a hyphen";
  }
  if (cps[2] === HYPHEN && cps[3] === HYPHEN) {
    return "decodes to a label with hyphens in its third and fourth positions";
  }
  return undefined;
}
