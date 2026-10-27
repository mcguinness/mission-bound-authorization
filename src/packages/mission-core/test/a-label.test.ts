/**
 * @spec resource-access#entry-validation (#1376, D858): the structural A-label
 * checks a `recipient_domain` label carrying the `xn--` prefix meets. The
 * valid labels come from `url.domainToASCII`, an independent Punycode, for
 * U-labels already in lower case and NFC; each refused label's decoded form
 * is named beside it.
 */

import { domainToASCII } from "node:url";
import { describe, expect, it } from "vitest";
import { aLabelViolation, punycodeDecode, punycodeEncode } from "../src/a-label.js";

const U_LABELS = [
  "münchen",
  "bücher",
  "exämple",
  "παράδειγμα",
  "пример",
  "例子",
  "مثال",
  "ドメイン名例",
];

describe("Punycode (RFC 3492) decoding and encoding (#1376)", () => {
  it("decodes and encodes each A-label an independent encoder produces", () => {
    for (const u of U_LABELS) {
      const label = domainToASCII(u);
      expect(label.startsWith("xn--"), u).toBe(true);
      const cps = Array.from(u, (ch) => ch.codePointAt(0) as number);
      expect(punycodeDecode(label.slice(4)), u).toEqual(cps);
      expect(punycodeEncode(cps), u).toBe(label.slice(4));
    }
  });

  it("refuses, never throws on, a truncated integer, an overflow, an out-of-range code point, a surrogate, a non-basic character or an invalid digit", () => {
    for (const [input, why] of [
      ["9", "truncated: 9 needs a following digit"],
      ["999999999999", "overflow"],
      ["rf96i", "decodes to code point 1415195, above U+10FFFF"],
      ["dx8bm8e", "decodes to a surrogate"],
      ["mü-abc", "a non-basic character before the delimiter"],
      ["-abc", "a delimiter that ends no basic code points is an invalid digit"],
      ["ab_c", "an invalid digit"],
    ] as const) {
      expect(() => punycodeDecode(input), why).not.toThrow();
      expect(punycodeDecode(input), why).toBeUndefined();
    }
  });
});

describe("an xn-- label is a structurally valid A-label (@spec resource-access#entry-validation, #1376, D858)", () => {
  it("admits each valid A-label in any ASCII letter case", () => {
    for (const u of U_LABELS) {
      const label = domainToASCII(u);
      expect(aLabelViolation(label), label).toBeUndefined();
      expect(aLabelViolation(label.toUpperCase()), label).toBeUndefined();
    }
    expect(aLabelViolation("XN--Mnchen-3YA")).toBeUndefined();
  });

  it("does not judge a label without the xn-- prefix", () => {
    for (const label of ["example", "ab--cd", "a-b"])
      expect(aLabelViolation(label), label).toBeUndefined();
  });

  it("refuses each label whose decoded form the structural checks refuse, never repairing it", () => {
    for (const [label, decoded, violation] of [
      ["xn--9", "(truncated)", "does not decode under Punycode"],
      ["xn--rf96i", "(code point above U+10FFFF)", "does not decode under Punycode"],
      ["xn--dx8bm8e", "(a surrogate)", "does not decode under Punycode"],
      ["xn--abc-", "abc", "decodes to an ASCII-only label"],
      ["xn--mnchen-psa", "mÜnchen", "decodes to a label with an upper-case character"],
      ["XN--MNCHEN-PSA", "mÜnchen", "decodes to a label with an upper-case character"],
      ["xn--menchen-uge", "me, U+0301, nchen", "decodes to a label not in NFC"],
      ["xn--mnchen-hxd", "U+0301, mnchen", "decodes to a label beginning with a combining mark"],
      ["xn---mnchen-o2a", "-münchen", "decodes to a label beginning or ending with a hyphen"],
      ["xn--mnchen--n2a", "münchen-", "decodes to a label beginning or ending with a hyphen"],
      [
        "xn--m--nchen-65a",
        "mü--nchen",
        "decodes to a label with hyphens in its third and fourth positions",
      ],
    ] as const) {
      expect(aLabelViolation(label), `${label} (${decoded})`).toBe(violation);
    }
  });
});
