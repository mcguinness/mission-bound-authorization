import { createPrivateKey, createPublicKey } from "node:crypto";
import { serializeDictionary } from "structured-headers";
import { describe, expect, it } from "vitest";
import {
  buildSignatureBase,
  contentDigest,
  httpSign,
  httpVerify,
  normalizeRequest,
  signatureParams,
  verifyContentDigest,
} from "../src/index.js";

/**
 * Known-answer tests from the RFCs' own examples. Upstream AAuth publishes
 * no wire-level vectors (dickhardt/AAuth at 70d67375, dickhardt/signature-key
 * at 69f5ba26: placeholders only), so RFC 9421 Appendix B anchors the
 * signature base and the Ed25519 signature byte for byte.
 */

// RFC 9421 Appendix B.1.4, test-key-ed25519.
const TEST_KEY_ED25519 = {
  kty: "OKP",
  crv: "Ed25519",
  d: "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
  x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs",
};

// RFC 9421 Appendix B.2, test-request.
const testRequest = () =>
  normalizeRequest({
    method: "POST",
    url: "https://example.com/foo?param=Value&Pet=dog",
    headers: {
      host: "example.com",
      date: "Tue, 20 Apr 2021 02:07:55 GMT",
      "content-type": "application/json",
      "content-digest":
        "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
      "content-length": "18",
    },
    body: '{"hello": "world"}',
  });

const B26_PARAMS = () =>
  signatureParams(
    ["date", "@method", "@path", "@authority", "content-type", "content-length"],
    new Map<string, number | string>([
      ["created", 1618884473],
      ["keyid", "test-key-ed25519"],
    ]),
  );

describe("RFC 9421 Appendix B.2.6 (@spec rfc9421#section-2.5)", () => {
  it("builds the published signature base", () => {
    expect(buildSignatureBase(testRequest(), B26_PARAMS())).toBe(
      [
        '"date": Tue, 20 Apr 2021 02:07:55 GMT',
        '"@method": POST',
        '"@path": /foo',
        '"@authority": example.com',
        '"content-type": application/json',
        '"content-length": 18',
        '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
      ].join("\n"),
    );
  });

  it("serializes the published Signature-Input member", () => {
    expect(serializeDictionary(new Map([["sig-b26", B26_PARAMS()]]))).toBe(
      'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    );
  });

  it("produces the published Ed25519 signature and verifies it", () => {
    const base = Buffer.from(buildSignatureBase(testRequest(), B26_PARAMS()), "ascii");
    const privateKey = createPrivateKey({ key: TEST_KEY_ED25519, format: "jwk" });
    const publicKey = createPublicKey(privateKey);
    const signature = httpSign("Ed25519", privateKey, base);
    expect(signature.toString("base64")).toBe(
      "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==",
    );
    expect(httpVerify("Ed25519", publicKey, base, signature)).toBe(true);
    const altered = Buffer.from(base.toString("ascii").replace("POST", "PUT"), "ascii");
    expect(httpVerify("Ed25519", publicKey, altered, signature)).toBe(false);
  });
});

describe("RFC 9530 Appendix B digests (@spec rfc9530#section-2)", () => {
  const body = new TextEncoder().encode('{"hello": "world"}');

  it("computes the published sha-256 Content-Digest", () => {
    expect(contentDigest(body)).toBe("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:");
  });

  it("accepts the published sha-512 digest and rejects a mismatched body", () => {
    const field =
      "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";
    expect(verifyContentDigest(field, body)).toBe(true);
    expect(verifyContentDigest(field, new TextEncoder().encode('{"hello": "world!"}'))).toBe(false);
  });

  it("does not accept a field with no digest it computes", () => {
    expect(verifyContentDigest("md5=:Sd/dVLAcvNLSq16eXua5uQ==:", body)).toBe(false);
  });
});

describe("Content-Digest robustness (@spec rfc9530#section-2)", () => {
  const body = new TextEncoder().encode('{"hello": "world"}');

  it("treats a member named like an Object property as an unknown algorithm", () => {
    expect(verifyContentDigest("constructor=:AAAA:", body)).toBe(false);
    expect(
      verifyContentDigest(
        "constructor=:AAAA:, sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:",
        body,
      ),
    ).toBe(true);
  });

  it("requires every computable digest to match", () => {
    expect(
      verifyContentDigest(
        "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:, sha-512=:AAAA:",
        body,
      ),
    ).toBe(false);
  });
});

describe("derived components from the URI as sent (@spec rfc9421#section-2.2.6)", () => {
  it("keeps dot segments and percent-encoding in @path and @query", () => {
    const request = normalizeRequest({
      method: "GET",
      url: "https://example.com/a/%2e%2e/b{c}?x=%7B#frag",
      headers: {},
    });
    const base = buildSignatureBase(
      request,
      signatureParams(["@path", "@query", "@request-target", "@target-uri"], new Map()),
    );
    expect(base.split("\n").slice(0, 4)).toEqual([
      '"@path": /a/%2e%2e/b{c}',
      '"@query": ?x=%7B',
      '"@request-target": /a/%2e%2e/b{c}?x=%7B',
      '"@target-uri": https://example.com/a/%2e%2e/b{c}?x=%7B',
    ]);
  });
});
