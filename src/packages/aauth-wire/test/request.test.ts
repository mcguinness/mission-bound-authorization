import { randomUUID } from "node:crypto";
import { type InnerList, parseDictionary, serializeDictionary } from "structured-headers";
import { beforeEach, describe, expect, it } from "vitest";
import {
  buildSignatureBase,
  generateSigningKey,
  type HttpRequestMessage,
  httpSign,
  InMemoryReplayCache,
  jwkThumbprint,
  mintToken,
  normalizeRequest,
  SignatureError,
  type SigningKey,
  serializeSignatureKey,
  signRequest,
  type VerifyRequestOptions,
  verifyRequest,
} from "../src/index.js";
import { AGENT, AP, agentToken, FakeNetwork, NOW, NOW_MS, PS, RESOURCE } from "./fixtures.js";

let net: FakeNetwork;
let ap: ReturnType<FakeNetwork["issuer"]>;
let agentKey: SigningKey;

beforeEach(() => {
  net = new FakeNetwork();
  ap = net.issuer(AP, "aauth-agent.json");
  agentKey = generateSigningKey("Ed25519");
});

const options = (extra: Partial<VerifyRequestOptions> = {}): VerifyRequestOptions => ({
  resolver: net.resolver(),
  now: () => NOW_MS,
  ...extra,
});

/** Sign `message` as the agent, presenting `jwt` under the jwt scheme. */
function signAsAgent(
  message: HttpRequestMessage,
  jwt: string,
  extra: Partial<Parameters<typeof signRequest>[1]> = {},
): HttpRequestMessage {
  const added = signRequest(message, {
    alg: agentKey.alg,
    privateKey: agentKey.privateKey,
    signatureKey: { scheme: "jwt", jwt },
    created: NOW,
    ...extra,
  });
  return { ...message, headers: { ...(message.headers as Record<string, string>), ...added } };
}

const get = (url = `${RESOURCE}/api/documents`): HttpRequestMessage => ({
  method: "GET",
  url,
  headers: {},
});

const post = (url = `${PS}/token`): HttpRequestMessage => ({
  method: "POST",
  url,
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ resource_token: "x" }),
});

/**
 * Assert a SignatureError with `code`; `detail` pins the check that fired
 * where an earlier or later check would answer with the same code.
 */
async function rejects(
  promise: Promise<unknown>,
  code: string,
  detail?: RegExp,
): Promise<SignatureError> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(SignatureError);
  expect((err as SignatureError).code).toBe(code);
  if (detail) expect((err as SignatureError).detail).toMatch(detail);
  expect((err as SignatureError).status).toBe(401);
  expect((err as SignatureError).headers["signature-error"]).toMatch(new RegExp(`^error=${code}`));
  return err as SignatureError;
}

describe("signing and verifying an agent request (@spec aauth#section-11.3)", () => {
  it("verifies a GET signed under the jwt scheme with an agent token", async () => {
    const signed = signAsAgent(get(), await agentToken(ap, agentKey));
    const result = await verifyRequest(signed, options());
    expect(result.scheme).toBe("jwt");
    expect(result.alg).toBe("Ed25519");
    expect(result.token?.payload.sub).toBe(AGENT);
    expect(result.coveredComponents).toEqual(["@method", "@authority", "@path", "signature-key"]);
    const input = (signed.headers as Record<string, string>)["signature-input"] ?? "";
    expect(input).not.toMatch(/;alg=|;keyid=/);
  });

  it("verifies an ES256 agent key", async () => {
    agentKey = generateSigningKey("ES256");
    const signed = signAsAgent(get(), await agentToken(ap, agentKey));
    expect((await verifyRequest(signed, options())).alg).toBe("ES256");
  });

  it("covers Content-Digest and Content-Type on a body request to a PS", async () => {
    const signed = signAsAgent(post(), await agentToken(ap, agentKey));
    const result = await verifyRequest(signed, options({ requireBodyComponents: true }));
    expect(result.coveredComponents).toContain("content-digest");
    expect(result.coveredComponents).toContain("content-type");
  });

  it("verifies a server signing in its own right under jwks_uri", async () => {
    const ps = net.issuer(PS, "aauth-person.json");
    const message = post(`${RESOURCE}/revoke`);
    const added = signRequest(message, {
      alg: ps.alg,
      privateKey: ps.privateKey,
      signatureKey: { scheme: "jwks_uri", id: PS, dwk: "aauth-person.json", kid: ps.kid },
      created: NOW,
    });
    expect(added["signature-key"]).toBe(
      'sig=jwks_uri;id="https://ps.example";dwk="aauth-person.json";kid="key-1"',
    );
    const signed = {
      ...message,
      headers: { ...(message.headers as Record<string, string>), ...added },
    };
    const result = await verifyRequest(
      signed,
      options({ acceptedSchemes: ["jwks_uri"], requireBodyComponents: true }),
    );
    expect(result.signer).toEqual({ id: PS, dwk: "aauth-person.json", kid: "key-1" });
  });

  it("verifies a person token presented under the jwt scheme to the resource it names", async () => {
    const ps = net.issuer(PS, "aauth-person.json");
    const person = await mintToken(
      "aa-person+jwt",
      {
        iss: PS,
        dwk: "aauth-person.json",
        aud: RESOURCE,
        sub: "8f14e45f",
        jti: randomUUID(),
        iat: NOW,
        exp: NOW + 600,
        cnf: { jwk: agentKey.publicJwk },
      },
      ps,
    );
    const signed = signAsAgent(get(), person);
    const result = await verifyRequest(
      signed,
      options({ acceptedTokenTypes: ["aa-person+jwt"], audience: RESOURCE }),
    );
    expect(result.token?.typ).toBe("aa-person+jwt");
  });
});

describe("verification steps in order (@spec aauth#section-11.3.4)", () => {
  it("step 1: a missing Signature header is invalid_signature", async () => {
    const signed = signAsAgent(get(), await agentToken(ap, agentKey));
    const headers = { ...(signed.headers as Record<string, string>) };
    delete headers.signature;
    await rejects(
      verifyRequest({ ...signed, headers }, options()),
      "invalid_signature",
      /signature is missing/,
    );
  });

  it("step 2: an uncovered required component is invalid_input with required_input", async () => {
    const signed = signAsAgent(get(), await agentToken(ap, agentKey), {
      components: ["@method", "@authority", "signature-key"],
    });
    const err = await rejects(verifyRequest(signed, options()), "invalid_input");
    const field = parseDictionary(err.headers["signature-error"] ?? "");
    const required = field.get("required_input") as [[string, unknown][], unknown];
    expect(required[0].map(([c]) => c)).toEqual([
      "@method",
      "@authority",
      "@path",
      "signature-key",
    ]);
  });

  it("step 2: a PS body request without Content-Digest covered is invalid_input", async () => {
    const signed = signAsAgent(post(), await agentToken(ap, agentKey), {
      components: ["@method", "@authority", "@path", "signature-key", "content-type"],
    });
    await rejects(verifyRequest(signed, options({ requireBodyComponents: true })), "invalid_input");
  });

  it("step 3: created older than the window is invalid_signature", async () => {
    const signed = signAsAgent(get(), await agentToken(ap, agentKey), { created: NOW - 61 });
    await rejects(verifyRequest(signed, options()), "invalid_signature", /too old/);
  });

  it("step 3: created ahead of the window is clock_skew", async () => {
    const signed = signAsAgent(get(), await agentToken(ap, agentKey), { created: NOW + 61 });
    await rejects(verifyRequest(signed, options()), "clock_skew");
  });

  it("step 3: a past expires is invalid_signature", async () => {
    const signed = signAsAgent(get(), await agentToken(ap, agentKey), { expires: NOW - 1 });
    await rejects(verifyRequest(signed, options()), "invalid_signature", /has expired/);
  });

  it("step 4: a scheme AAuth does not use for agents is unsupported_scheme", async () => {
    const signed = signAsAgent(get(), await agentToken(ap, agentKey));
    const headers = signed.headers as Record<string, string>;
    headers["signature-key"] = 'sig=hwk;kty="OKP";crv="Ed25519";x="AAAA";alg="Ed25519"';
    const err = await rejects(verifyRequest(signed, options()), "unsupported_scheme");
    expect(err.headers["accept-signature-scheme"]).toBe("jwt");
  });

  it("step 5: a token of the wrong typ in Signature-Key is invalid_jwt", async () => {
    const signed = signAsAgent(
      get(),
      await mintToken("aa-resource+jwt", { iss: AP, dwk: "aauth-agent.json" }, ap),
    );
    await rejects(verifyRequest(signed, options()), "invalid_jwt", /typ/);
  });

  it("step 5: an expired agent token is expired_jwt", async () => {
    const signed = signAsAgent(get(), await agentToken(ap, agentKey, { exp: NOW - 1 }));
    await rejects(verifyRequest(signed, options()), "expired_jwt");
  });

  it("step 5: an agent token from an issuer whose metadata names another is issuer_mismatch", async () => {
    net.documents.set(`${AP}/.well-known/aauth-agent.json`, {
      issuer: "https://other.example",
      jwks_uri: `${AP}/jwks.json`,
    });
    const signed = signAsAgent(get(), await agentToken(ap, agentKey));
    await rejects(verifyRequest(signed, options()), "issuer_mismatch");
  });

  it("step 5: an agent token signed by a key the issuer does not publish is invalid_jwt", async () => {
    const forger = { ...generateSigningKey("Ed25519"), kid: ap.kid, id: AP };
    const signed = signAsAgent(get(), await agentToken(forger, agentKey));
    await rejects(verifyRequest(signed, options()), "invalid_jwt", /signature verification failed/);
  });

  it("step 5: a revoked agent token is revoked_jwt", async () => {
    const signed = signAsAgent(get(), await agentToken(ap, agentKey));
    await rejects(verifyRequest(signed, options({ isRevoked: () => true })), "revoked_jwt");
  });

  it("step 5: a person token naming another resource is invalid_jwt", async () => {
    const ps = net.issuer(PS, "aauth-person.json");
    const person = await mintToken(
      "aa-person+jwt",
      {
        iss: PS,
        dwk: "aauth-person.json",
        aud: "https://elsewhere.example",
        sub: "8f14e45f",
        jti: randomUUID(),
        iat: NOW,
        exp: NOW + 600,
        cnf: { jwk: agentKey.publicJwk },
      },
      ps,
    );
    const signed = signAsAgent(get(), person);
    await rejects(
      verifyRequest(signed, options({ acceptedTokenTypes: ["aa-person+jwt"], audience: RESOURCE })),
      "invalid_jwt",
      /aud/,
    );
  });

  it("step 6: a cnf.jwk without alg is unsupported_algorithm with Accept-Signature-Alg", async () => {
    const { alg: _alg, ...withoutAlg } = agentKey.publicJwk;
    const signed = signAsAgent(get(), await agentToken(ap, agentKey, { cnf: { jwk: withoutAlg } }));
    const err = await rejects(verifyRequest(signed, options()), "unsupported_algorithm", /no alg/);
    expect(err.headers["accept-signature-alg"]).toBe("Ed25519, ES256");
  });

  it("step 6: the polymorphic EdDSA identifier is unsupported_algorithm", async () => {
    const jwk = { ...agentKey.publicJwk, alg: "EdDSA" };
    const signed = signAsAgent(get(), await agentToken(ap, agentKey, { cnf: { jwk } }));
    await rejects(verifyRequest(signed, options()), "unsupported_algorithm", /EdDSA/);
  });

  it("step 6: a key whose kty disagrees with its alg is invalid_key", async () => {
    const jwk = { ...agentKey.publicJwk, alg: "ES256" };
    const signed = signAsAgent(get(), await agentToken(ap, agentKey, { cnf: { jwk } }));
    await rejects(verifyRequest(signed, options()), "invalid_key", /disagrees/);
  });

  it("step 7: a request signed by a key other than cnf.jwk is invalid_signature", async () => {
    const other = generateSigningKey("Ed25519");
    const signed = signAsAgent(get(), await agentToken(ap, other));
    await rejects(verifyRequest(signed, options()), "invalid_signature", /verification failed/);
  });

  it("step 7: a changed path after signing is invalid_signature", async () => {
    const signed = signAsAgent(get(), await agentToken(ap, agentKey));
    await rejects(
      verifyRequest({ ...signed, url: `${RESOURCE}/api/admin` }, options()),
      "invalid_signature",
      /verification failed/,
    );
  });
});

describe("freshness, replay and body binding (@spec aauth#section-11.3.4.2)", () => {
  it("refuses the same signed request twice inside the window", async () => {
    const signed = signAsAgent(get(), await agentToken(ap, agentKey));
    const replayCache = new InMemoryReplayCache();
    await verifyRequest(signed, options({ replayCache }));
    await rejects(
      verifyRequest(signed, options({ replayCache })),
      "invalid_signature",
      /duplicate/,
    );
  });

  it("refuses a body that does not match its covered Content-Digest", async () => {
    const signed = signAsAgent(post(), await agentToken(ap, agentKey));
    await rejects(
      verifyRequest({ ...signed, body: JSON.stringify({ resource_token: "y" }) }, options()),
      "invalid_signature",
      /Content-Digest/,
    );
  });
});

/**
 * Sign by hand, with covered components and parameters signRequest never
 * produces (it emits neither keyid nor component parameters).
 */
async function handSigned(
  components: [string, Map<string, string | boolean>][],
  params: Map<string, number | string>,
  jwt: string,
): Promise<HttpRequestMessage> {
  const message = get();
  const headers: Record<string, string> = {
    "signature-key": serializeSignatureKey("sig", { scheme: "jwt", jwt }),
  };
  const inner: InnerList = [components, params];
  const base = buildSignatureBase(normalizeRequest({ ...message, headers }), [
    components.filter(([, p]) => p.size === 0),
    params,
  ]);
  const signature = httpSign(agentKey.alg, agentKey.privateKey, Buffer.from(base, "ascii"));
  headers["signature-input"] = serializeDictionary(new Map([["sig", inner]]));
  headers.signature = serializeDictionary(
    new Map([["sig", [new Uint8Array(signature), new Map()]]]),
  );
  return { ...message, headers };
}

const bare = (names: string[]): [string, Map<string, string | boolean>][] =>
  names.map((n) => [n, new Map()]);

const BASE = ["@method", "@authority", "@path", "signature-key"];

describe("signature input handling (@spec rfc9421#section-2.5, aauth#section-11.3.3.2)", () => {
  it("accepts a keyid naming the Signature-Key key", async () => {
    const thumbprint = await jwkThumbprint(agentKey.publicJwk);
    const signed = await handSigned(
      bare(BASE),
      new Map<string, number | string>([
        ["created", NOW],
        ["keyid", thumbprint],
      ]),
      await agentToken(ap, agentKey),
    );
    expect((await verifyRequest(signed, options())).thumbprint).toBe(thumbprint);
  });

  it("refuses a keyid naming another key", async () => {
    const signed = await handSigned(
      bare(BASE),
      new Map<string, number | string>([
        ["created", NOW],
        ["keyid", "someone-else"],
      ]),
      await agentToken(ap, agentKey),
    );
    await rejects(verifyRequest(signed, options()), "invalid_key", /keyid/);
  });

  it("ignores an alg signature parameter", async () => {
    const signed = await handSigned(
      bare(BASE),
      new Map<string, number | string>([
        ["created", NOW],
        ["alg", "rsa-pss-sha512"],
      ]),
      await agentToken(ap, agentKey),
    );
    expect((await verifyRequest(signed, options())).alg).toBe("Ed25519");
  });

  it("refuses a duplicate covered component", async () => {
    const signed = await handSigned(
      bare(BASE),
      new Map([["created", NOW]]),
      await agentToken(ap, agentKey),
    );
    const headers = signed.headers as Record<string, string>;
    headers["signature-input"] = (headers["signature-input"] ?? "").replace(
      '("@method"',
      '("@method" "@method"',
    );
    await rejects(verifyRequest(signed, options()), "invalid_signature", /duplicate component/);
  });

  it("refuses a covered component with parameters", async () => {
    const components = bare(BASE);
    components.push(["signature-key", new Map([["sf", true]])]);
    const signed = await handSigned(
      components,
      new Map([["created", NOW]]),
      await agentToken(ap, agentKey),
    );
    await rejects(verifyRequest(signed, options()), "invalid_signature", /not supported/);
  });

  it("refuses a covered field that is absent from the request", async () => {
    const signed = signAsAgent(
      { ...get(), headers: { "content-type": "text/plain" } },
      await agentToken(ap, agentKey),
      { components: [...BASE, "content-type"] },
    );
    const headers = { ...(signed.headers as Record<string, string>) };
    delete headers["content-type"];
    await rejects(verifyRequest({ ...signed, headers }, options()), "invalid_signature", /absent/);
  });
});
