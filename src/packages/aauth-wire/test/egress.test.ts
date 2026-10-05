import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import {
  createEgressAdmission,
  createFetchJson,
  type EgressRequest,
  generateSigningKey,
  isNonPublicAddress,
  JwksResolver,
  SignatureError,
  verifyAgentToken,
} from "../src/index.js";
import { AP, agentToken, FakeNetwork, NOW_MS, PUBLIC_DNS } from "./fixtures.js";

const metadata = (url: string): EgressRequest => ({
  url: new URL(url),
  kind: "metadata",
  issuer: AP,
});
const jwks = (url: string): EgressRequest => ({ url: new URL(url), kind: "jwks", issuer: AP });

describe("egress admission (@spec aauth#section-11.4, signature-key#section-7.3)", () => {
  const admit = createEgressAdmission({ lookup: PUBLIC_DNS });

  it.each([
    "https://127.0.0.1/.well-known/aauth-agent.json",
    "https://169.254.169.254/latest/meta-data",
    "https://10.0.0.5/jwks",
    "https://192.168.1.1/x",
    "https://[::1]/x",
    "https://[fd00::1]/x",
    "https://[::ffff:127.0.0.1]/x",
    "https://localhost/x",
    "https://api.localhost/x",
  ])("refuses a non-public destination %s", async (url) => {
    expect(await admit(metadata(url))).toBe(false);
  });

  it("refuses http", async () => {
    expect(await admit(metadata("http://ap.example/.well-known/aauth-agent.json"))).toBe(false);
  });

  it("refuses a host name that resolves to a private address", async () => {
    const privateDns = createEgressAdmission({
      lookup: async () => [{ address: "10.1.2.3", family: 4 }],
    });
    expect(await privateDns(metadata("https://ap.example/.well-known/aauth-agent.json"))).toBe(
      false,
    );
  });

  it("refuses a host name that does not resolve", async () => {
    const failing = createEgressAdmission({
      lookup: async () => {
        throw new Error("ENOTFOUND");
      },
    });
    expect(await failing(metadata("https://ap.example/.well-known/aauth-agent.json"))).toBe(false);
  });

  it("admits a public https destination", async () => {
    expect(await admit(metadata("https://ap.example/.well-known/aauth-agent.json"))).toBe(true);
  });

  it("refuses a cross-origin jwks_uri unless the deployment admits it", async () => {
    expect(await admit(jwks("https://cdn.example/jwks.json"))).toBe(false);
    expect(await admit(jwks("https://ap.example/jwks.json"))).toBe(true);
    const crossOrigin = createEgressAdmission({
      lookup: PUBLIC_DNS,
      admitCrossOriginJwks: (r) => r.url.hostname === "cdn.example",
    });
    expect(await crossOrigin(jwks("https://cdn.example/jwks.json"))).toBe(true);
  });

  it("admits a private destination only by explicit deployment configuration", async () => {
    const lab = createEgressAdmission({
      admitPrivateDestination: (u) => u.hostname === "10.0.0.5",
    });
    expect(await lab(metadata("https://10.0.0.5/x"))).toBe(true);
    expect(await lab(metadata("https://10.0.0.6/x"))).toBe(false);
  });

  it("classifies addresses", () => {
    expect(isNonPublicAddress("8.8.8.8")).toBe(false);
    expect(isNonPublicAddress("2001:4860:4860::8888")).toBe(false);
    expect(isNonPublicAddress("100.64.0.1")).toBe(true);
    expect(isNonPublicAddress("fe80::1")).toBe(true);
    expect(isNonPublicAddress("not-an-address")).toBe(true);
  });

  it("never fetches for an agent token whose iss is a private address", async () => {
    const net = new FakeNetwork();
    const ap = { ...net.issuer(AP, "aauth-agent.json"), id: "https://127.0.0.1" };
    const jwt = await agentToken(ap, generateSigningKey(), { sub: "aauth:assistant@127.0.0.1" });
    const err = await verifyAgentToken(jwt, { resolver: net.resolver(), now: () => NOW_MS }).catch(
      (e: unknown) => e,
    );
    expect((err as SignatureError).code).toBe("unknown_key");
    expect(net.fetched).toEqual([]);
  });

  it("never fetches a cross-origin jwks_uri named by metadata", async () => {
    const net = new FakeNetwork();
    const ap = net.issuer(AP, "aauth-agent.json");
    net.documents.set(`${AP}/.well-known/aauth-agent.json`, {
      issuer: AP,
      jwks_uri: "https://10.0.0.5/internal/jwks",
    });
    const jwt = await agentToken(ap, generateSigningKey());
    const err = await verifyAgentToken(jwt, { resolver: net.resolver(), now: () => NOW_MS }).catch(
      (e: unknown) => e,
    );
    expect((err as SignatureError).code).toBe("unknown_key");
    expect(net.fetched).toEqual([`${AP}/.well-known/aauth-agent.json`]);
  });
});

describe("bounded fetch (@spec signature-key#section-7.3)", () => {
  let server: Server | undefined;
  afterEach(() => {
    server?.close();
    server = undefined;
  });

  async function serve(handler: Parameters<typeof createServer>[1]): Promise<string> {
    server = createServer(handler);
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  it("refuses a response over the size limit", async () => {
    const base = await serve((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ keys: [], pad: "x".repeat(4096) }));
    });
    await expect(createFetchJson({ maxBytes: 1024 })(`${base}/jwks`)).rejects.toThrow(/exceeds/);
    expect((await createFetchJson()(`${base}/jwks`)).status).toBe(200);
  });

  it("gives up after the timeout", async () => {
    const base = await serve(() => {
      // Never answers.
    });
    await expect(createFetchJson({ timeoutMs: 50 })(`${base}/slow`)).rejects.toThrow();
  });

  it("does not follow redirects", async () => {
    const base = await serve((req, res) => {
      if (req.url === "/ok") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ keys: [] }));
        return;
      }
      res.writeHead(302, { location: "/ok" });
      res.end();
    });
    await expect(createFetchJson()(`${base}/moved`)).rejects.toThrow();
  });

  it("is what a resolver uses by default, behind the default admission", async () => {
    const resolver = new JwksResolver();
    const err = await resolver
      .resolveKey("https://127.0.0.1", "aauth-agent.json", "k")
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SignatureError);
    expect((err as SignatureError).code).toBe("unknown_key");
  });
});
