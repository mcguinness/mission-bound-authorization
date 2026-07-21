/**
 * Strict JSON parsing for committed inputs: rejects duplicate member names,
 * which core § canonicalization requires the AS to refuse before
 * canonicalization ("The AS MUST reject an input object containing
 * duplicate JSON member names"). JSON.parse silently keeps the last
 * duplicate, so this is a minimal recursive-descent parser.
 */

import type { JsonValue } from "./canonicalize.js";

export class DuplicateMemberError extends Error {
  constructor(readonly member: string) {
    super(`duplicate JSON member name: ${JSON.stringify(member)}`);
  }
}

export function parseStrictJson(text: string): JsonValue {
  const p = new Parser(text);
  const value = p.parseValue();
  p.skipWs();
  if (!p.atEnd()) throw new SyntaxError(`unexpected trailing input at ${p.pos}`);
  return value;
}

class Parser {
  pos = 0;
  constructor(private readonly s: string) {}

  atEnd(): boolean {
    return this.pos >= this.s.length;
  }

  skipWs(): void {
    while (!this.atEnd()) {
      const c = this.s[this.pos];
      if (c === " " || c === "\t" || c === "\n" || c === "\r") this.pos += 1;
      else break;
    }
  }

  parseValue(): JsonValue {
    this.skipWs();
    const c = this.s[this.pos];
    if (c === "{") return this.parseObject();
    if (c === "[") return this.parseArray();
    if (c === '"') return this.parseString();
    if (
      c === "t" ||
      c === "f" ||
      c === "n" ||
      c === "-" ||
      (c !== undefined && c >= "0" && c <= "9")
    ) {
      return this.parseLiteralOrNumber();
    }
    throw new SyntaxError(`unexpected character at ${this.pos}`);
  }

  private parseObject(): JsonValue {
    this.expect("{");
    const out: { [k: string]: JsonValue } = {};
    const seen = new Set<string>();
    this.skipWs();
    if (this.s[this.pos] === "}") {
      this.pos += 1;
      return out;
    }
    for (;;) {
      this.skipWs();
      const key = this.parseString();
      if (seen.has(key)) throw new DuplicateMemberError(key);
      seen.add(key);
      this.skipWs();
      this.expect(":");
      out[key] = this.parseValue();
      this.skipWs();
      const c = this.s[this.pos];
      if (c === ",") {
        this.pos += 1;
        continue;
      }
      if (c === "}") {
        this.pos += 1;
        return out;
      }
      throw new SyntaxError(`expected ',' or '}' at ${this.pos}`);
    }
  }

  private parseArray(): JsonValue {
    this.expect("[");
    const out: JsonValue[] = [];
    this.skipWs();
    if (this.s[this.pos] === "]") {
      this.pos += 1;
      return out;
    }
    for (;;) {
      out.push(this.parseValue());
      this.skipWs();
      const c = this.s[this.pos];
      if (c === ",") {
        this.pos += 1;
        continue;
      }
      if (c === "]") {
        this.pos += 1;
        return out;
      }
      throw new SyntaxError(`expected ',' or ']' at ${this.pos}`);
    }
  }

  private parseString(): string {
    // Delegate escape handling to JSON.parse over the raw string slice.
    if (this.s[this.pos] !== '"') throw new SyntaxError(`expected string at ${this.pos}`);
    let i = this.pos + 1;
    for (;;) {
      const c = this.s[i];
      if (c === undefined) throw new SyntaxError("unterminated string");
      if (c === "\\") {
        i += 2;
        continue;
      }
      if (c === '"') break;
      i += 1;
    }
    const raw = this.s.slice(this.pos, i + 1);
    this.pos = i + 1;
    return JSON.parse(raw) as string;
  }

  private parseLiteralOrNumber(): JsonValue {
    const rest = this.s.slice(this.pos);
    if (rest.startsWith("true")) {
      this.pos += 4;
      return true;
    }
    if (rest.startsWith("false")) {
      this.pos += 5;
      return false;
    }
    if (rest.startsWith("null")) {
      this.pos += 4;
      return null;
    }
    const m = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(rest);
    if (!m) throw new SyntaxError(`invalid number at ${this.pos}`);
    this.pos += m[0].length;
    return Number(m[0]);
  }

  private expect(c: string): void {
    if (this.s[this.pos] !== c) throw new SyntaxError(`expected '${c}' at ${this.pos}`);
    this.pos += 1;
  }
}
