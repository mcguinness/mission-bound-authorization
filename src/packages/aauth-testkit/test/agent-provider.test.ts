import { generateSigningKey, verifyAgentToken } from "@mission/aauth-wire";
import { afterEach, describe, expect, it } from "vitest";
import { createAgentProvider, decodeClaims, LoopbackNetwork, ManualClock } from "../src/index.js";

let net: LoopbackNetwork;
afterEach(() => net.close());

describe("agent-provider stub (@spec aauth#section-5.1, aauth#section-5.3.1, aauth#section-11.2.1)", () => {
  it("publishes aauth-agent.json and a JWKS whose key carries alg", async () => {
    net = new LoopbackNetwork();
    const provider = createAgentProvider();
    await net.serve(provider.issuer, provider.handler);
    const meta = await net.fetchJson("https://ap.test/.well-known/aauth-agent.json");
    expect(meta.body).toMatchObject({
      issuer: "https://ap.test",
      jwks_uri: "https://ap.test/.well-known/jwks.json",
    });
    const jwks = await net.fetchJson("https://ap.test/.well-known/jwks.json");
    expect((jwks.body as { keys: unknown[] }).keys).toEqual([
      expect.objectContaining({ alg: "Ed25519", kid: "ap-key-1", kty: "OKP" }),
    ]);
  });

  it("issues agent tokens that verify, naming an identifier on its own domain", async () => {
    net = new LoopbackNetwork();
    const clock = new ManualClock();
    const provider = createAgentProvider({ now: clock.now });
    await net.serve(provider.issuer, provider.handler);
    const key = generateSigningKey("Ed25519");
    const jwt = await provider.issueAgentToken({
      local: "assistant",
      publicJwk: key.publicJwk,
      ps: "https://ps.test",
    });
    const verified = await verifyAgentToken(jwt, { resolver: net.resolver(), now: clock.now });
    expect(verified.header.typ).toBe("aa-agent+jwt");
    expect(verified.payload).toMatchObject({
      iss: "https://ap.test",
      dwk: "aauth-agent.json",
      sub: "aauth:assistant@ap.test",
      ps: "https://ps.test",
      cnf: { jwk: key.publicJwk },
    });
    const claims = decodeClaims(jwt);
    expect((claims.exp as number) - (claims.iat as number)).toBe(3600);
    expect(provider.issued).toEqual([claims.jti]);
  });

  it("assigns only top-level identifiers on its own domain", () => {
    const provider = createAgentProvider({ issuer: "https://agents.example.test" });
    expect(provider.agentIdentifier("planner.7f3c")).toBe("aauth:planner.7f3c@agents.example.test");
    expect(() => provider.agentIdentifier("planner+search1")).toThrow(/top-level/);
    expect(() => provider.agentIdentifier("My Agent")).toThrow(/top-level/);
    expect(() => createAgentProvider({ issuer: "https://ap.test:8443" })).toThrow(
      /server identifier/,
    );
  });
});
