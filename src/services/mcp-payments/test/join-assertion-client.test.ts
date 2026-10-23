/**
 * @spec authority-server#join-assertion-request (#1454; D685, D690)
 *
 * The PEP's Join Assertion client against a stub MAS endpoint that records
 * what it is sent: the request carries the Mission, the consuming PDP and the
 * acting token, and the caller's private-key JWT client assertion names the
 * MAS's issuer identifier as its sole `aud`, never the endpoint, as at
 * Mission Status. Any answer but 200 with an assertion yields none.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { decodeJwt, decodeProtectedHeader, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { joinAssertionClient } from "../src/index.js";

const ISSUER = "https://mas.example";
let server: Server;
let endpoint: string;
let received: Record<string, unknown>[] = [];
let answer: { status: number; body: unknown } = { status: 200, body: { assertion: "header.claims.signature" } };

beforeAll(async () => {
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      received.push(JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>);
      res.writeHead(answer.status, { "content-type": "application/json" });
      res.end(JSON.stringify(answer.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}/mission/join-assertion`;
});

afterAll(() => {
  server.closeAllConnections();
  server.close();
});

async function client() {
  const { privateKey } = await generateKeyPair("ES256");
  return joinAssertionClient({
    endpoint,
    issuer: ISSUER,
    audience: "pdp-1454",
    caller: { clientId: "pep-1454", privateKey, kid: "pep-key-1" },
    timeoutMs: 2000,
  });
}

describe("the PEP's Join Assertion client (@spec authority-server#join-assertion-request, #1454; D685, D690)", () => {
  it("authenticates with a client assertion whose aud is the MAS's issuer identifier alone, never the endpoint", async () => {
    received = [];
    answer = { status: 200, body: { assertion: "header.claims.signature" } };
    const obtained = await (await client()).obtain({ mission: { id: "msn_1454", issuer: ISSUER }, accessToken: "estate-token" });
    expect(obtained).toBe("header.claims.signature");
    expect(received).toHaveLength(1);
    const body = received[0] as Record<string, unknown>;
    expect(body).toMatchObject({
      mission_id: "msn_1454",
      audience: "pdp-1454",
      access_token: "estate-token",
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    });
    const assertion = body.client_assertion as string;
    const claims = decodeJwt(assertion);
    // The sole value, as a string: neither the endpoint nor a list naming it.
    expect(claims.aud).toBe(ISSUER);
    expect(claims.aud).not.toBe(endpoint);
    expect(claims).toMatchObject({ iss: "pep-1454", sub: "pep-1454" });
    expect(decodeProtectedHeader(assertion)).toMatchObject({ typ: "client-authentication+jwt", kid: "pep-key-1" });
  });

  it("yields no assertion for a refusal, such as the MAS's invalid_client", async () => {
    answer = { status: 400, body: { error: "invalid_client" } };
    expect(await (await client()).obtain({ mission: { id: "msn_1454", issuer: ISSUER }, accessToken: "estate-token" })).toBeUndefined();
  });
});
