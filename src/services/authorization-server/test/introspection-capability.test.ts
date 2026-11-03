/**
 * #2018: the OAuth binding's optional Introspection capability as a
 * deployment switch (`introspection`, adapters/capabilities.ts). Each
 * assembly here is the minimal configuration (`lifecycle-revoke` only) with
 * or without the switch, so the switch alone decides the surface. The
 * disabled configuration's wire witness is also
 * demo/test/minimal-baseline-config.test.ts; the full introspection
 * behavior is witnessed on the default assembly (introspection-endpoint.test.ts).
 *
 * The file runs on a controlled clock (D1091).
 */
const controlledClock = await vi.hoisted(async () => {
  const { CONTROLLED_CLOCK_MS, installControlledClock } = await import("./controlled-clock.helper.js");
  return installControlledClock(CONTROLLED_CLOCK_MS);
});

import { INTROSPECTION_PRINCIPALS, type IntrospectionPrincipal } from "@mission/demo-data";
import { afterAll, describe, expect, it, vi } from "vitest";
import type { ProviderCapability } from "../src/index.js";
import { approve, metadata, par, redeem, startAs, type Json, type SwitchedAs } from "./capability-switch.helper.js";

afterAll(() => controlledClock.restore());

/** The shipped plain-rs introspection principal (config/introspection.json). */
const RS_PLAIN = INTROSPECTION_PRINCIPALS.find((p) => p.principal_id === "rs-plain") as IntrospectionPrincipal;
const MINIMAL: ProviderCapability[] = ["lifecycle-revoke"];

/** POST /introspect, authenticated as `principal` (HTTP Basic), or unauthenticated with `null`. */
async function introspect(h: SwitchedAs, token: string, principal: IntrospectionPrincipal | null = RS_PLAIN) {
  const res = await fetch(`${h.issuer}/introspect`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(principal
        ? { authorization: `Basic ${Buffer.from(`${principal.principal_id}:${principal.secret}`).toString("base64")}` }
        : {}),
    },
    body: new URLSearchParams({ token }).toString(),
  });
  const text = await res.text();
  let body: Json;
  try {
    body = JSON.parse(text) as Json;
  } catch {
    body = { body: text };
  }
  return { status: res.status, body };
}

describe("the Introspection capability switch (#2018; @spec mission#optional-capabilities, mission#introspection)", () => {
  it("on, /introspect authenticates its caller and reports an issued Mission-bound token active with its Mission, and both introspection members are advertised", async () => {
    const h = await startAs([...MINIMAL, "introspection"]);
    try {
      const pushed = await par(h);
      expect(pushed.status, JSON.stringify(pushed.body)).toBe(201);
      const { code, missionId } = await approve(h, String(pushed.body.request_uri));
      const redeemed = await redeem(h, code);
      expect(redeemed.status, JSON.stringify(redeemed.body)).toBe(200);
      const token = String(redeemed.body.access_token);
      // An unauthenticated caller is refused.
      expect((await introspect(h, token, null)).status).toBe(401);
      const answered = await introspect(h, token);
      expect(answered.status, JSON.stringify(answered.body)).toBe(200);
      expect(answered.body.active).toBe(true);
      expect(answered.body.mission).toMatchObject({ id: missionId, issuer: h.issuer, state: "active" });
      const meta = await metadata(h);
      expect(meta.introspection_endpoint).toBe(`${h.issuer}/introspect`);
      expect(meta.introspection_endpoint_auth_methods_supported).toEqual(["client_secret_basic"]);
    } finally {
      await h.close();
    }
  });

  it("off, /introspect is not served (404) even to a registered principal, and neither member is advertised", async () => {
    const h = await startAs(MINIMAL);
    try {
      const answered = await introspect(h, "x.y.z");
      expect(answered.status, JSON.stringify(answered.body)).toBe(404);
      expect(answered.body).not.toHaveProperty("active");
      const meta = await metadata(h);
      expect(meta).not.toHaveProperty("introspection_endpoint");
      expect(meta).not.toHaveProperty("introspection_endpoint_auth_methods_supported");
    } finally {
      await h.close();
    }
  });

  it("off, construction refuses a configured introspecting consumer: an introspection principal needs the route", async () => {
    await expect(startAs(MINIMAL, { testIntrospectionPrincipals: [RS_PLAIN] })).rejects.toThrow(
      "introspection principals are configured, but the introspection capability is off: an introspecting consumer needs the /introspect route",
    );
    // With the switch on, the same principal is accepted.
    const h = await startAs([...MINIMAL, "introspection"], { testIntrospectionPrincipals: [{ ...RS_PLAIN, principal_id: "rs-extra" }] });
    await h.close();
  });
});
