/**
 * @spec AAT -02 Sections 3.2 and 3.4 (#1756): lossless JSON for Attenuating
 * Agent Tokens. A verifier must read numbers with their exact value and
 * syntax: NumericDates and depths have no fraction or exponent part, and an
 * argument or constraint value is admissible only when the JCS form of its
 * double denotes the same value. `JSON.parse` keeps neither, and keeps the
 * last of duplicate member names, which Section 8 rejects. This parser keeps
 * each number's source text, rejects duplicate members, and builds objects
 * with no prototype.
 */

/** A JSON number, held as its source text. */
export class AatNumber {
  constructor(readonly raw: string) {}
  get value(): number {
    return Number(this.raw);
  }
}

export type AatJson = null | boolean | string | AatNumber | AatJson[] | AatObject;
export interface AatObject {
  [member: string]: AatJson;
}

export class AatJsonError extends Error {}

/** Nesting deeper than this refuses rather than risk the stack. */
const MAX_NESTING = 512;
const NUMBER_RE = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/;
const INTEGER_RE = /^-?(?:0|[1-9][0-9]*)$/;

export function isAatObject(v: AatJson | undefined): v is AatObject {
  return typeof v === "object" && v !== null && !Array.isArray(v) && !(v instanceof AatNumber);
}

/** Parse `text` as one JSON value, rejecting duplicate member names. */
export function parseAatJson(text: string): AatJson {
  const p = new Parser(text);
  p.ws();
  const v = p.value(0);
  p.ws();
  if (p.pos !== text.length) throw new AatJsonError(`unexpected trailing input at ${p.pos}`);
  return v;
}

/**
 * @spec AAT -02 Section 8 step 2c: the top-level `jti` of a payload, read
 * before its signature is verified with a scan that builds nothing but that
 * member. Nested values are skipped, not parsed into objects. Returns
 * undefined when the payload is not a JSON object, has no `jti`, holds a value
 * that is not a string, or names it more than once with different values. A
 * repeated `jti` with one value is extracted here; full parsing after the
 * signature rejects the duplicate (step 3b or 4b).
 */
export function scanTopLevelJti(text: string): string | undefined {
  try {
    const p = new Parser(text);
    p.ws();
    if (text[p.pos] !== "{") return undefined;
    p.pos += 1;
    p.ws();
    let jti: string | undefined;
    let seen = false;
    let conflict = false;
    if (text[p.pos] === "}") return undefined;
    for (;;) {
      p.ws();
      const key = p.string();
      p.ws();
      p.expect(":");
      p.ws();
      if (key === "jti") {
        let value: string | undefined;
        if (text[p.pos] === '"') value = p.string();
        else p.skip(0);
        if (seen && value !== jti) conflict = true;
        seen = true;
        jti = value;
      } else p.skip(0);
      p.ws();
      if (text[p.pos] === ",") {
        p.pos += 1;
        continue;
      }
      p.expect("}");
      break;
    }
    p.ws();
    if (p.pos !== text.length || conflict) return undefined;
    return jti;
  } catch {
    return undefined;
  }
}

class Parser {
  pos = 0;
  constructor(private readonly s: string) {}

  ws(): void {
    while (this.pos < this.s.length) {
      const c = this.s[this.pos];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") this.pos += 1;
      else break;
    }
  }

  expect(ch: string): void {
    if (this.s[this.pos] !== ch) throw new AatJsonError(`expected ${ch} at ${this.pos}`);
    this.pos += 1;
  }

  value(depth: number): AatJson {
    if (depth > MAX_NESTING) throw new AatJsonError("nesting too deep");
    const c = this.s[this.pos];
    if (c === "{") return this.object(depth);
    if (c === "[") return this.array(depth);
    if (c === '"') return this.string();
    if (c === "t") return this.literal("true", true);
    if (c === "f") return this.literal("false", false);
    if (c === "n") return this.literal("null", null);
    return this.number();
  }

  /** Validate and step over one value without building it. */
  skip(depth: number): void {
    if (depth > MAX_NESTING) throw new AatJsonError("nesting too deep");
    const c = this.s[this.pos];
    if (c === "{") {
      this.pos += 1;
      this.ws();
      if (this.s[this.pos] === "}") {
        this.pos += 1;
        return;
      }
      for (;;) {
        this.ws();
        this.string();
        this.ws();
        this.expect(":");
        this.ws();
        this.skip(depth + 1);
        this.ws();
        if (this.s[this.pos] === ",") {
          this.pos += 1;
          continue;
        }
        this.expect("}");
        return;
      }
    }
    if (c === "[") {
      this.pos += 1;
      this.ws();
      if (this.s[this.pos] === "]") {
        this.pos += 1;
        return;
      }
      for (;;) {
        this.ws();
        this.skip(depth + 1);
        this.ws();
        if (this.s[this.pos] === ",") {
          this.pos += 1;
          continue;
        }
        this.expect("]");
        return;
      }
    }
    this.value(depth);
  }

  object(depth: number): AatObject {
    this.pos += 1;
    const out: AatObject = Object.create(null) as AatObject;
    const seen = new Set<string>();
    this.ws();
    if (this.s[this.pos] === "}") {
      this.pos += 1;
      return out;
    }
    for (;;) {
      this.ws();
      const key = this.string();
      if (seen.has(key)) throw new AatJsonError(`duplicate member name ${JSON.stringify(key)}`);
      seen.add(key);
      this.ws();
      this.expect(":");
      this.ws();
      out[key] = this.value(depth + 1);
      this.ws();
      if (this.s[this.pos] === ",") {
        this.pos += 1;
        continue;
      }
      this.expect("}");
      return out;
    }
  }

  array(depth: number): AatJson[] {
    this.pos += 1;
    const out: AatJson[] = [];
    this.ws();
    if (this.s[this.pos] === "]") {
      this.pos += 1;
      return out;
    }
    for (;;) {
      this.ws();
      out.push(this.value(depth + 1));
      this.ws();
      if (this.s[this.pos] === ",") {
        this.pos += 1;
        continue;
      }
      this.expect("]");
      return out;
    }
  }

  string(): string {
    this.expect('"');
    let out = "";
    for (;;) {
      const c = this.s[this.pos];
      if (c === undefined) throw new AatJsonError("unterminated string");
      this.pos += 1;
      if (c === '"') return out;
      if (c === "\\") {
        const e = this.s[this.pos];
        this.pos += 1;
        if (e === '"' || e === "\\" || e === "/") out += e;
        else if (e === "b") out += "\b";
        else if (e === "f") out += "\f";
        else if (e === "n") out += "\n";
        else if (e === "r") out += "\r";
        else if (e === "t") out += "\t";
        else if (e === "u") {
          const hex = this.s.slice(this.pos, this.pos + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new AatJsonError("bad unicode escape");
          out += String.fromCharCode(Number.parseInt(hex, 16));
          this.pos += 4;
        } else throw new AatJsonError("bad escape");
      } else {
        if (c.charCodeAt(0) < 0x20) throw new AatJsonError("control character in string");
        out += c;
      }
    }
  }

  literal<T>(word: string, v: T): T {
    if (this.s.slice(this.pos, this.pos + word.length) !== word)
      throw new AatJsonError(`bad literal at ${this.pos}`);
    this.pos += word.length;
    return v;
  }

  number(): AatNumber {
    const m = /^-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
      this.s.slice(this.pos, this.pos + 4096),
    );
    const raw = m?.[0];
    if (!raw || !NUMBER_RE.test(raw)) throw new AatJsonError(`bad value at ${this.pos}`);
    this.pos += raw.length;
    return new AatNumber(raw);
  }
}

/** A number written with no fraction or exponent part (Section 3.2). */
export function isIntegerSyntax(v: AatJson | undefined): v is AatNumber {
  return v instanceof AatNumber && INTEGER_RE.test(v.raw);
}

/** The ES / JCS serialization of a double (RFC 8785 Section 3.2.2.3). */
export function jcsNumber(d: number): string {
  if (Object.is(d, -0)) return "0";
  return String(d);
}

/** A decimal as sign, significant digits and power of ten, with no leading or trailing zeros. */
function decimalOf(raw: string): { neg: boolean; digits: string; exp: number } {
  const m = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(raw);
  if (!m) throw new AatJsonError(`not a number: ${raw}`);
  const frac = m[3] ?? "";
  let digits = (m[2] ?? "") + frac;
  let exp = Number.parseInt(m[4] ?? "0", 10) - frac.length;
  digits = digits.replace(/^0+/, "");
  const trailing = /0*$/.exec(digits)?.[0].length ?? 0;
  if (trailing > 0) {
    digits = digits.slice(0, digits.length - trailing);
    exp += trailing;
  }
  if (digits === "") return { neg: false, digits: "", exp: 0 };
  return { neg: m[1] === "-", digits, exp };
}

/**
 * @spec AAT -02 Section 3.4: a number is admissible when the JCS
 * serialization of its double denotes the same mathematical value as the
 * number as written.
 */
export function isAdmissibleNumber(raw: string): boolean {
  const d = Number(raw);
  if (!Number.isFinite(d)) return false;
  const a = decimalOf(raw);
  const b = decimalOf(jcsNumber(d));
  return a.neg === b.neg && a.digits === b.digits && a.exp === b.exp;
}

/** Every number anywhere in `v` is admissible. */
export function allNumbersAdmissible(v: AatJson): boolean {
  if (v instanceof AatNumber) return isAdmissibleNumber(v.raw);
  if (Array.isArray(v)) return v.every(allNumbersAdmissible);
  if (isAatObject(v)) return Object.values(v).every(allNumbersAdmissible);
  return true;
}

/** @spec RFC 8785: the JCS serialization of `v`; numbers are serialized from their double. */
export function jcs(v: AatJson): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "string") return JSON.stringify(v);
  if (v instanceof AatNumber) return jcsNumber(v.value);
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  const keys = Object.keys(v).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(v[k] as AatJson)}`).join(",")}}`;
}

/** `v` with its numbers as doubles, for callers outside the verifier. */
export function toPlainJson(v: AatJson): unknown {
  if (v instanceof AatNumber) return v.value;
  if (Array.isArray(v)) return v.map(toPlainJson);
  if (isAatObject(v)) {
    const out: Record<string, unknown> = {};
    // defineProperty, so a member named __proto__ stays a member.
    for (const [k, x] of Object.entries(v)) {
      Object.defineProperty(out, k, {
        value: toPlainJson(x),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  }
  return v;
}
