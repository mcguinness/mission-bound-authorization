// recipient_domain values: DNS names in ASCII form
// (resource-access#entry-validation: refused when "not a DNS name in ASCII
// form, with each internationalized label in its A-label form, or ends in a
// dot"), compared "as DNS names, case-insensitively and on whole labels"
// (resource-access#value-space-comparison).

// RFC 3492 Punycode parameters.
const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const MAX_INT = 0x7fffffff;

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
}

function threshold(k: number, bias: number): number {
  if (k <= bias) return TMIN;
  if (k >= bias + TMAX) return TMAX;
  return k - bias;
}

function basicToDigit(code: number): number {
  if (code >= 48 && code <= 57) return code - 22; // 0-9 are 26-35
  if (code >= 65 && code <= 90) return code - 65; // A-Z are 0-25
  if (code >= 97 && code <= 122) return code - 97; // a-z are 0-25
  return BASE;
}

function digitToBasic(digit: number): string {
  return String.fromCharCode(digit < 26 ? digit + 97 : digit + 22);
}

// RFC 3492 section 6.2, decoding. Returns undefined on any decoding failure.
function punycodeDecode(input: string): number[] | undefined {
  const output: number[] = [];
  const delimiter = input.lastIndexOf("-");
  const basic = delimiter < 0 ? 0 : delimiter;
  for (let j = 0; j < basic; j++) {
    const code = input.charCodeAt(j);
    if (code >= 0x80) return undefined;
    output.push(code);
  }
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;
  let index = basic > 0 ? basic + 1 : 0;
  while (index < input.length) {
    const oldI = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (index >= input.length) return undefined;
      const digit = basicToDigit(input.charCodeAt(index++));
      if (digit >= BASE) return undefined;
      if (digit > Math.floor((MAX_INT - i) / w)) return undefined;
      i += digit * w;
      const t = threshold(k, bias);
      if (digit < t) break;
      if (w > Math.floor(MAX_INT / (BASE - t))) return undefined;
      w *= BASE - t;
    }
    const length = output.length + 1;
    bias = adapt(i - oldI, length, oldI === 0);
    if (Math.floor(i / length) > MAX_INT - n) return undefined;
    n += Math.floor(i / length);
    i %= length;
    if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return undefined;
    output.splice(i, 0, n);
    i++;
  }
  return output;
}

// RFC 3492 section 6.3, encoding.
function punycodeEncode(input: readonly number[]): string {
  let output = "";
  for (const c of input) if (c < 0x80) output += String.fromCharCode(c);
  const basicCount = output.length;
  let handled = basicCount;
  if (basicCount > 0) output += "-";
  let n = INITIAL_N;
  let delta = 0;
  let bias = INITIAL_BIAS;
  while (handled < input.length) {
    let m = MAX_INT;
    for (const c of input) if (c >= n && c < m) m = c;
    delta += (m - n) * (handled + 1);
    n = m;
    for (const c of input) {
      if (c < n) delta++;
      if (c === n) {
        let q = delta;
        for (let k = BASE; ; k += BASE) {
          const t = threshold(k, bias);
          if (q < t) break;
          output += digitToBasic(t + ((q - t) % (BASE - t)));
          q = Math.floor((q - t) / (BASE - t));
        }
        output += digitToBasic(q);
        bias = adapt(delta, handled + 1, handled === basicCount);
        delta = 0;
        handled++;
      }
    }
    delta++;
    n++;
  }
  return output;
}

const HYPHEN = 0x2d;

// An A-label (RFC 5890 section 2.3.2.1): "xn--" followed by the Punycode of a
// U-label. The caller passes the label in lower case: the ASCII form compares
// case-insensitively (resource-access#entry-validation: "Letter case does not
// make a recipient_domain invalid"), and RFC 5891 section 5.3 lowercases an
// A-label before converting it. The decoded form is then checked exactly as
// decoded, never case-folded or normalized into a valid one.
//
// These are the structural checks of RFC 5891 sections 4.2.3.1, 4.2.3.2, 5.3
// and 5.4: the label decodes under RFC 3492; it encodes back to itself; the
// decoded form holds a non-ASCII code point (so it is an internationalized
// label), is in NFC, is in lower case, does not begin with a combining mark
// (General_Category M), does not begin or end with a hyphen, and does not
// have hyphens in both its third and fourth positions, counted in code points.
//
// They are not full IDNA2008 validity, which the draft's A-label requirement
// is. Not implemented: the RFC 5892 code point classes (PVALID, CONTEXTJ,
// CONTEXTO, DISALLOWED, UNASSIGNED), so a label holding a DISALLOWED or
// unassigned code point passes; the contextual rules (RFC 5891 section
// 4.2.3.3, RFC 5892 Appendix A); and the Bidi rule (RFC 5891 section 4.2.3.4,
// RFC 5893). Each needs Unicode property tables this package does not carry.
// The lower-case and combining-mark tests use the Unicode data of the
// JavaScript engine that runs this code.
function isALabel(lowerLabel: string): boolean {
  const encoded = lowerLabel.slice(4);
  // RFC 3492 decoding; undefined on a truncated integer, an overflow, a code
  // point above U+10FFFF or a surrogate, never an exception.
  const decoded = punycodeDecode(encoded);
  if (decoded === undefined || decoded.length === 0) return false;
  if (punycodeEncode(decoded) !== encoded) return false;
  if (!decoded.some((c) => c >= 0x80)) return false;
  const uLabel = String.fromCodePoint(...decoded);
  if (uLabel.normalize("NFC") !== uLabel) return false;
  if (uLabel.toLowerCase() !== uLabel) return false;
  if (/^\p{M}/u.test(uLabel)) return false;
  // RFC 5891 section 4.2.3.1, on code point positions, not UTF-16 units.
  if (decoded[0] === HYPHEN || decoded[decoded.length - 1] === HYPHEN) return false;
  if (decoded[2] === HYPHEN && decoded[3] === HYPHEN) return false;
  return true;
}

// LDH label: letters, digits and hyphen, not starting or ending with a hyphen,
// 1 to 63 octets (RFC 5890 section 2.3.1, RFC 1035 section 2.3.4).
const LDH_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

/** Whether a value is a valid recipient_domain (resource-access#entry-validation). */
export function isValidRecipientDomain(value: unknown): value is string {
  if (typeof value !== "string" || value === "") return false;
  // "or ends in a dot"
  if (value.endsWith(".")) return false;
  // RFC 1035 section 2.3.4: 255 octets on the wire, 253 in text form.
  if (value.length > 253) return false;
  for (const label of value.split(".")) {
    // ASCII form only: a non-ASCII character fails the LDH test.
    if (!LDH_LABEL.test(label)) return false;
    // The label is ASCII here, so lowering it changes letters A to Z only.
    const lower = label.toLowerCase();
    if (lower.startsWith("xn--") && !isALabel(lower)) return false;
  }
  return true;
}

/**
 * Whether candidate is equal to reference or a DNS subdomain of it, compared
 * case-insensitively on whole labels (resource-access#value-space-comparison:
 * "mail.example.com is within example.com and example.net is not").
 */
export function isWithinDomain(candidate: string, reference: string): boolean {
  const c = candidate.toLowerCase().split(".");
  const r = reference.toLowerCase().split(".");
  if (c.length < r.length) return false;
  const offset = c.length - r.length;
  return r.every((label, i) => c[offset + i] === label);
}
