import { describe, expect, it } from "vitest";
import { ConfirmationError, parseConfirmation } from "../src/index.js";

describe("a credential's sender-constraint binding is read for structure only (@spec runtime-oauth#token-validation, #825 D402)", () => {
  it("reads an absent cnf as no binding, which a bearer profile may carry", () => {
    expect(parseConfirmation(undefined)).toBeUndefined();
  });

  it("reads a DPoP or an mTLS binding, or both, leaving other RFC 7800 members unread", () => {
    expect(parseConfirmation({ jkt: "k" })).toEqual({ jkt: "k" });
    expect(parseConfirmation({ "x5t#S256": "t" })).toEqual({ "x5t#S256": "t" });
    expect(parseConfirmation({ jkt: "k", "x5t#S256": "t", kid: "other" })).toEqual({
      jkt: "k",
      "x5t#S256": "t",
    });
  });

  it.each([
    ["null", null],
    ["an array", []],
    ["a string", "k"],
    ["an empty object", {}],
    ["only an unknown member", { kid: "other" }],
    ["an empty jkt", { jkt: "" }],
    ["a numeric jkt", { jkt: 42 }],
    ["an empty x5t#S256", { "x5t#S256": "" }],
    ["a well-formed jkt beside a malformed x5t#S256", { jkt: "k", "x5t#S256": 1 }],
  ])("refuses a present cnf that is %s", (_label, value) => {
    expect(() => parseConfirmation(value)).toThrow(ConfirmationError);
  });
});
