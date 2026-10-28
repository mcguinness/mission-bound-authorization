import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { createIssuerStub, LoopbackNetwork } from "../src/index.js";

let net: LoopbackNetwork;
const stray: Server[] = [];

afterEach(async () => {
  await net.close();
  for (const server of stray.splice(0)) server.close();
});

describe("loopback network", () => {
  it("carries a request to the registered port with Host the identifier's host", async () => {
    net = new LoopbackNetwork();
    await net.serve("https://echo.test", (req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ host: req.headers.host, target: req.url, method: req.method }));
    });
    const res = await net.request({ method: "GET", url: "https://echo.test/a/b?x=1" });
    expect(res.status).toBe(200);
    expect(res.json()).toEqual({ host: "echo.test", target: "/a/b?x=1", method: "GET" });
  });

  it("fetches a registered issuer's metadata through the bounded, pinned fetch", async () => {
    net = new LoopbackNetwork();
    const stub = createIssuerStub({ issuer: "https://ps.test", dwk: "aauth-person.json" });
    await net.serve(stub.issuer, stub.handler);
    const { status, body } = await net.fetchJson("https://ps.test/.well-known/aauth-person.json");
    expect(status).toBe(200);
    expect(body).toMatchObject({
      issuer: "https://ps.test",
      jwks_uri: "https://ps.test/.well-known/jwks.json",
    });
  });

  it("reaches nothing it has not registered, without connecting", async () => {
    net = new LoopbackNetwork();
    let hits = 0;
    const server = createServer((_req, res) => {
      hits += 1;
      res.end("{}");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    stray.push(server);
    const { port } = server.address() as AddressInfo;
    await expect(net.fetchJson("https://other.test/x")).rejects.toThrow(/not on this loopback/);
    await expect(net.request({ method: "GET", url: "https://other.test/x" })).rejects.toThrow(
      /not on this loopback/,
    );
    await expect(net.fetchJson(`http://127.0.0.1:${port}/x`)).rejects.toThrow(/https/);
    expect(hits).toBe(0);
  });

  it("refuses a URL that names a port, since identifiers carry none", async () => {
    net = new LoopbackNetwork();
    net.register("https://ps.test", 1);
    expect(() => net.transportUrl("https://ps.test:8443/x")).toThrow(/port/);
    expect(() => net.register("https://ps.test:8443", 1)).toThrow(/server identifier/);
  });

  it("admits egress to registered https hosts only, through the library's admission", async () => {
    net = new LoopbackNetwork();
    net.register("https://ps.test", 1);
    const admit = (url: string, kind: "metadata" | "jwks" = "metadata") =>
      net.admitEgress({ url: new URL(url), kind, issuer: "https://ps.test" });
    expect(await admit("https://ps.test/.well-known/aauth-person.json")).toBe(true);
    expect(await admit("https://other.test/.well-known/aauth-person.json")).toBe(false);
    expect(await admit("http://ps.test/.well-known/aauth-person.json")).toBe(false);
    expect(await admit("https://127.0.0.1/jwks", "metadata")).toBe(false);
    // A JWKS on another origin than its issuer is refused even when registered.
    net.register("https://cdn.test", 2);
    expect(await admit("https://cdn.test/jwks.json", "jwks")).toBe(false);
  });

  it("refuses connections to a host until it is restored, for requests and fetches alike", async () => {
    net = new LoopbackNetwork();
    let hits = 0;
    await net.serve("https://rs.test", (_req, res) => {
      hits += 1;
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
    await net.serve("https://ps.test", (_req, res) => res.end("{}"));
    const port = net.portOf("https://rs.test");
    await net.refuse("https://rs.test");
    expect(net.portOf("https://rs.test")).not.toBe(port);
    await expect(
      net.request({ method: "POST", url: "https://rs.test/revoke" }),
    ).rejects.toMatchObject({ code: "ECONNREFUSED" });
    await expect(
      net.fetchJson("https://rs.test/.well-known/aauth-resource.json"),
    ).rejects.toThrow();
    expect(hits).toBe(0);
    // Other hosts are reachable meanwhile.
    expect((await net.request({ method: "GET", url: "https://ps.test/" })).status).toBe(200);
    net.restore("https://rs.test");
    expect(net.portOf("https://rs.test")).toBe(port);
    expect((await net.request({ method: "POST", url: "https://rs.test/revoke" })).status).toBe(200);
    expect(hits).toBe(1);
  });

  it("refuses to refuse a host it does not know", async () => {
    net = new LoopbackNetwork();
    await expect(net.refuse("https://other.test")).rejects.toThrow(/not on this loopback/);
  });

  it("resolves an issuer's key through a resolver that stays on the network", async () => {
    net = new LoopbackNetwork();
    const stub = createIssuerStub({
      issuer: "https://ap.test",
      dwk: "aauth-agent.json",
      kid: "k1",
    });
    await net.serve(stub.issuer, stub.handler);
    const key = await net.resolver().resolveKey("https://ap.test", "aauth-agent.json", "k1");
    expect(key).toEqual(stub.key.publicJwk);
  });
});
