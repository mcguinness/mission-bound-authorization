import { afterEach, describe, expect, it } from "vitest";
import { EndpointSwitch, LoopbackNetwork } from "../src/index.js";

let net: LoopbackNetwork;
afterEach(() => net.close());

const RS = "https://rs.test";

/** A server whose handler answers 200 `{"ok":true}` and counts its calls. */
async function served(sw: EndpointSwitch): Promise<{ calls: string[] }> {
  const calls: string[] = [];
  await net.serve(
    RS,
    sw.wrap((req, res) => {
      calls.push(`${req.method} ${req.url}`);
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"ok":true}');
    }),
  );
  return { calls };
}

describe("endpoint switch (@spec aauth#section-11.12.3)", () => {
  it("passes every request through while available", async () => {
    net = new LoopbackNetwork();
    const sw = new EndpointSwitch({ path: "/revoke" });
    const { calls } = await served(sw);
    const res = await net.request({ method: "POST", url: `${RS}/revoke`, body: "{}" });
    expect(res.status).toBe(200);
    expect(res.json()).toEqual({ ok: true });
    expect(calls).toEqual(["POST /revoke"]);
    expect(sw.attempts).toEqual([{ method: "POST", path: "/revoke", mode: "available" }]);
  });

  it("answers its 5xx without calling the handler", async () => {
    net = new LoopbackNetwork();
    const sw = new EndpointSwitch({ path: "/revoke", status: 502 });
    const { calls } = await served(sw);
    sw.mode = "error";
    const res = await net.request({ method: "POST", url: `${RS}/revoke`, body: "{}" });
    expect(res.status).toBe(502);
    expect(res.json()).toMatchObject({ error: "server_error" });
    expect(calls).toEqual([]);
  });

  it("closes the connection with no response", async () => {
    net = new LoopbackNetwork();
    const sw = new EndpointSwitch({ path: "/revoke" });
    const { calls } = await served(sw);
    sw.mode = "reset";
    await expect(
      net.request({ method: "POST", url: `${RS}/revoke`, body: "{}" }),
    ).rejects.toThrow();
    expect(calls).toEqual([]);
    expect(sw.attempts.map((a) => a.mode)).toEqual(["reset"]);
  });

  it("answers 200 with a non-empty body that is not JSON", async () => {
    net = new LoopbackNetwork();
    const sw = new EndpointSwitch({ path: "/revoke" });
    const { calls } = await served(sw);
    sw.mode = "malformed";
    const res = await net.request({ method: "POST", url: `${RS}/revoke`, body: "{}" });
    expect(res.status).toBe(200);
    expect(res.body.length).toBeGreaterThan(0);
    expect(() => res.json()).toThrow();
    expect(calls).toEqual([]);
  });

  it("switches only its own method and path", async () => {
    net = new LoopbackNetwork();
    const sw = new EndpointSwitch({ path: "/revoke" });
    const { calls } = await served(sw);
    sw.mode = "error";
    const other = await net.request({ method: "POST", url: `${RS}/revoked`, body: "{}" });
    const get = await net.request({ method: "GET", url: `${RS}/revoke` });
    const query = await net.request({ method: "POST", url: `${RS}/revoke?x=1`, body: "{}" });
    expect([other.status, get.status, query.status]).toEqual([200, 200, 503]);
    expect(calls).toEqual(["POST /revoked", "GET /revoke"]);
    expect(sw.attempts).toEqual([{ method: "POST", path: "/revoke", mode: "error" }]);
  });

  it("refuses a status that is not a 5xx", () => {
    expect(() => new EndpointSwitch({ path: "/revoke", status: 429 })).toThrow(/5xx/);
  });
});
