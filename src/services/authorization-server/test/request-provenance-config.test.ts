/**
 * @spec request-provenance#trust-configuration, request-provenance#verification
 * (#939 slice 2a-1)
 *
 * The request-provenance trust configuration and its loader in
 * `@mission/demo-data`: the shipped file, the vector's trust configuration as
 * a valid control, every refusal, and the declared bounds the README states.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadRequestProvenanceConfig,
  parseRequestProvenanceConfig,
  REQUEST_PROVENANCE_BOUND_CAPS,
  REQUEST_PROVENANCE_CONFIG,
} from "@mission/demo-data";
import { describe, expect, it } from "vitest";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonRecord = { [key: string]: Json };

const here = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(here, "../../..");
const SHIPPED_TEXT = readFileSync(resolve(SRC, "config/request-provenance.json"), "utf8");
const README = readFileSync(resolve(SRC, "config/README.md"), "utf8");
const VECTOR = JSON.parse(
  readFileSync(resolve(SRC, "../vectors/mission-request-provenance/assertion.json"), "utf8"),
) as { verifier_context: JsonRecord & { trust: { signers: JsonRecord[] } } };

/** The vector's trust configuration, enabled: the valid control every refusal mutates. */
function valid(): JsonRecord {
  const vc = structuredClone(VECTOR.verifier_context);
  return {
    enabled: true,
    clock_skew_seconds: vc.clock_skew_seconds as number,
    max_assertion_lifetime_seconds: vc.max_assertion_lifetime_seconds as number,
    max_capture_age_seconds: vc.max_capture_age_seconds as number,
    signers: vc.trust.signers,
  };
}

const signer = (c: JsonRecord): JsonRecord => (c.signers as JsonRecord[])[0] as JsonRecord;
const key = (c: JsonRecord): JsonRecord => (signer(c).keys as JsonRecord[])[0] as JsonRecord;
const jwk = (c: JsonRecord): JsonRecord => key(c).public_jwk as JsonRecord;

/** A mutation of the valid control. */
const with_ = (mutate: (c: JsonRecord) => void) => (): JsonRecord => {
  const c = valid();
  mutate(c);
  return c;
};

const SECTION = (() => {
  const start = README.indexOf("\n## `request-provenance.json`\n");
  const rest = README.slice(start + 1);
  const end = rest.indexOf("\n## ", 1);
  return start === -1 ? "" : end === -1 ? rest : rest.slice(0, end);
})();

describe("the request-provenance trust configuration loader (@spec request-provenance#trust-configuration, request-provenance#verification, #939)", () => {
  it("loads the shipped file: the type disabled and no signer authorized", () => {
    expect(loadRequestProvenanceConfig(SHIPPED_TEXT)).toStrictEqual(REQUEST_PROVENANCE_CONFIG);
    expect(REQUEST_PROVENANCE_CONFIG.enabled).toBe(false);
    expect(REQUEST_PROVENANCE_CONFIG.signers).toEqual([]);
  });

  it("loads the vector's trust configuration, keeping only each key's curve and coordinates, and accepts use and key_ops without giving them effect", () => {
    const loaded = parseRequestProvenanceConfig(valid());
    const control = valid();
    expect(loaded.signers).toHaveLength(1);
    expect(loaded.signers[0]?.keys[0]?.public_jwk).toStrictEqual({
      kty: "EC",
      crv: "P-256",
      x: jwk(control).x,
      y: jwk(control).y,
    });
    const withUse = with_((c) => {
      jwk(c).use = "sig";
      jwk(c).key_ops = ["verify"];
      jwk(c).alg = "ES256";
      jwk(c).kid = key(c).kid as string;
    })();
    expect(parseRequestProvenanceConfig(withUse)).toStrictEqual(loaded);
  });

  it.each([
    ["an unknown member at the root", with_((c) => { c.signer_discovery = true; }), /has unknown member signer_discovery/],
    ["an unknown member in a signer", with_((c) => { signer(c).jwks_uri = "https://intake.example.com/jwks"; }), /has unknown member jwks_uri/],
    ["an unknown member in a key", with_((c) => { key(c).use = "sig"; }), /has unknown member use/],
    ["an unknown member in an originator", with_((c) => { ((signer(c).originators as JsonRecord[])[0] as JsonRecord).acr = "phr"; }), /has unknown member acr/],
    ["an unknown member in a public JWK", with_((c) => { jwk(c).x5c = ["MIIB"]; }), /has unknown member x5c/],
    ["a signer iss named twice", with_((c) => { (c.signers as JsonRecord[]).push(structuredClone(signer(c))); }), /names a signer twice/],
    ["a kid named twice within one signer", with_((c) => { (signer(c).keys as JsonRecord[]).push(structuredClone(key(c))); }), /names a key of this signer twice/],
    ["a public JWK carrying the private member d", with_((c) => { jwk(c).d = "zJCwqPCNOl4dzbJ5CMOJuAwzvT_Iipsr84NW4Zrufk8"; }), /private member d/],
    ["a JWK whose kty is not EC", with_((c) => { jwk(c).kty = "RSA"; }), /must be an EC P-256 key/],
    ["a JWK whose crv is not P-256", with_((c) => { jwk(c).crv = "P-384"; }), /must be an EC P-256 key/],
    ["a JWK whose own alg is not ES256", with_((c) => { jwk(c).alg = "ES384"; }), /alg must be ES256/],
    ["a JWK whose own kid is another key's", with_((c) => { jwk(c).kid = "intake-2026-09"; }), /kid must equal the key's kid/],
    ["coordinates that are not a P-256 point", with_((c) => { jwk(c).y = jwk(c).x as string; }), /is not a P-256 public key/],
    ["a coordinate that is not 32 bytes", with_((c) => { jwk(c).x = Buffer.alloc(31, 1).toString("base64url"); }), /32-byte coordinate/],
    ["the alg RS256", with_((c) => { key(c).algs = ["RS256"]; }), /permits RS256; only ES256/],
    ["the alg HS256 beside ES256", with_((c) => { key(c).algs = ["ES256", "HS256"]; }), /permits HS256; only ES256/],
    ["the alg none", with_((c) => { key(c).algs = ["none"]; }), /permits none; only ES256/],
    ["an empty algs list", with_((c) => { key(c).algs = []; }), /algs must be non-empty/],
    ["an empty evidence_types list", with_((c) => { key(c).evidence_types = []; }), /evidence_types must be non-empty/],
    ["an empty keys list", with_((c) => { signer(c).keys = []; }), /keys must be non-empty/],
    ["an empty originators list", with_((c) => { signer(c).originators = []; }), /originators must be non-empty/],
    ["an empty channel_types list", with_((c) => { signer(c).channel_types = []; }), /channel_types must be non-empty/],
    ["an originator with sub beside another originator", with_((c) => { signer(c).originators = [{ iss: "https://idp.example.com", sub: "248289761001" }, { iss: "https://idp2.example.com" }]; }), /user-device signer/],
    ["a non-boolean enabled", with_((c) => { c.enabled = "true"; }), /enabled must be a boolean/],
  ])("refuses %s", (_what, build, message) => {
    expect(() => parseRequestProvenanceConfig(build())).toThrow(message);
  });

  it("refuses a duplicated member name in the file", () => {
    const text = SHIPPED_TEXT.replace('"enabled": false,', '"enabled": true, "enabled": false,');
    expect(text).not.toBe(SHIPPED_TEXT);
    expect(() => loadRequestProvenanceConfig(text)).toThrow(/ambiguous configuration/);
  });
});

describe("the declared bounds (@spec request-provenance#verification, #939)", () => {
  const BOUNDS = [
    "clock_skew_seconds",
    "max_assertion_lifetime_seconds",
    "max_capture_age_seconds",
  ] as const;

  it.each(
    BOUNDS.flatMap((bound) =>
      [0, -30, 1.5, "30", null].map((value) => [bound, JSON.stringify(value), value] as const),
    ),
  )("refuses %s of %s: a bound is a positive integer number of seconds", (bound, _shown, value) => {
    const c = valid();
    c[bound] = value;
    expect(() => parseRequestProvenanceConfig(c)).toThrow(
      new RegExp(`${bound} must be a positive integer`),
    );
  });

  it.each(BOUNDS.map((bound) => [bound, REQUEST_PROVENANCE_BOUND_CAPS[bound]] as const))(
    "refuses %s above its cap of %s, and accepts it at the cap",
    (bound, cap) => {
      const over = valid();
      over[bound] = cap + 1;
      expect(() => parseRequestProvenanceConfig(over)).toThrow(
        new RegExp(`${bound} exceeds its cap of ${cap}`),
      );
      const at = valid();
      at[bound] = cap;
      expect(parseRequestProvenanceConfig(at)[bound]).toBe(cap);
    },
  );

  it("declares each bound with its cap in config/README.md, and the shipped file's bounds are finite positive integers within them", () => {
    expect(SECTION).not.toBe("");
    const shipped = JSON.parse(SHIPPED_TEXT) as Record<string, unknown>;
    for (const bound of BOUNDS) {
      const value = shipped[bound];
      const cap = REQUEST_PROVENANCE_BOUND_CAPS[bound];
      expect(Number.isSafeInteger(value), bound).toBe(true);
      expect(value as number, bound).toBeGreaterThan(0);
      expect(value as number, bound).toBeLessThanOrEqual(cap);
      expect(REQUEST_PROVENANCE_CONFIG[bound], bound).toBe(value);
      expect(SECTION, bound).toContain(`| \`${bound}\` | ${value} | ${cap} |`);
    }
  });
});
