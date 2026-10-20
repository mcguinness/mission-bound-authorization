/**
 * @spec runtime#input-resource-policy, authority-server#mission-join rule 8 (#818 slice 2, #828)
 *
 * The MAS pilot's Resource policy: stored OpenFGA entitlements for the
 * identities the gateway authenticated, under the ESTATE issuer, read by the
 * decision point with no Mission input, and administered with
 * `pnpm resource-policy` (`resourcePolicyAdmin`, the command's own code path)
 * naming the estate issuer. A joined request's Resource policy is evaluated on
 * the estate subject and client, never on the Mission-side identities the
 * mapping contract maps them to, so the policy stays a bound independent of
 * the join. Every case runs over a live OpenFGA and is skipped without one.
 *
 * Each test restores the store to the development seed before it ends, so the
 * tests do not depend on each other's order.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { EvaluationRequest } from "@mission/pdp";
import type { MasPilot } from "../src/mas-pilot/compose.js";
import { loadMasPilotConfig } from "../src/mas-pilot/config.js";
import { admin, approve, call, composeRecorded, estateToken, openfgaReachable, relocateEstate } from "./mas-pilot-support.js";

const up = await openfgaReachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping the MAS pilot Resource-policy tests");

/** This file's estate port: the other pilot file's estate holds the configured one. */
const ESTATE_PORT = 14824;
const config = relocateEstate(loadMasPilotConfig(), ESTATE_PORT);
const ESTATE = config.estate.issuer;
const MAS = config.mission_issuer;
const TENANT = config.resource_policy.tenants[0]?.tenant as string;

/** Grant or revoke the Mission-side identity u-1001 and estate-ap-bot-7f3 map to (alice, ap-agent), in full. */
async function missionSideIdentity(pilot: MasPilot, op: "grant" | "revoke"): Promise<void> {
  await admin(pilot, op, "--iss", MAS, "--sub", "alice", "--relation", "member", "--tenant", TENANT);
  await admin(pilot, op, "--iss", MAS, "--sub", "alice", "--relation", "reader", "--vendor", "acme");
  await admin(pilot, op, "--iss", MAS, "--client", "ap-agent", "--relation", "member", "--tenant", TENANT);
  await admin(pilot, op, "--iss", MAS, "--client", "ap-agent", "--relation", "client", "--vendor", "acme");
}

d("MAS pilot Resource policy: estate entitlements, administered and revoked (#818 slice 2)", () => {
  let pilot: MasPilot;
  let requests: EvaluationRequest[];
  let aliceMission: string;
  let danaMission: string;

  beforeAll(async () => {
    ({ pilot, requests } = await composeRecorded({ config }));
    aliceMission = approve(pilot, "alice", { label: "rp-alice" });
    danaMission = approve(pilot, "dana", { label: "rp-dana" });
  }, 30_000);
  afterAll(async () => {
    await pilot?.close();
  });

  it("permits a joined read for an estate subject and client entitled in the store under the estate issuer", async () => {
    expect(pilot.resourcePolicy.development).toBe(true);
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    const res = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(res.ok, JSON.stringify(res)).toBe(true);
    // The policy's inputs: the estate subject and client the gateway authenticated.
    const last = requests.at(-1);
    expect(last?.subject).toEqual({ id: "u-1001", properties: { iss: ESTATE } });
    expect(last?.context.actor?.client_id).toBe("estate-ap-bot-7f3");
  });

  it("revoking only the estate subject's entitlement denies resource_policy with no result, and granting it back permits", async () => {
    const first = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    const second = await estateToken(pilot, "estate-ap-bot-7f3", "u-1002", "invoices.read");
    await admin(pilot, "revoke", "--iss", ESTATE, "--sub", "u-1001", "--relation", "reader", "--vendor", "acme");
    const revoked = await call(pilot, first, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(revoked.ok).toBe(false);
    expect(revoked.denial_reason).toBe("resource_policy");
    expect(revoked.result).toBeUndefined();
    // Only that entitlement: another estate account on the same Mission still reads.
    expect((await call(pilot, second, aliceMission, "get_invoice", { invoice_id: "inv-1" })).ok).toBe(true);
    await admin(pilot, "grant", "--iss", ESTATE, "--sub", "u-1001", "--relation", "reader", "--vendor", "acme");
    const restored = await call(pilot, first, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(restored.ok, JSON.stringify(restored)).toBe(true);
  });

  it("evaluates the estate subject, not the Mission-side identity it maps to: with alice and ap-agent fully entitled, the revoked estate account is still denied", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    await admin(pilot, "revoke", "--iss", ESTATE, "--sub", "u-1001", "--relation", "reader", "--vendor", "acme");
    await missionSideIdentity(pilot, "grant");
    try {
      const res = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
      expect(res.ok).toBe(false);
      expect(res.denial_reason).toBe("resource_policy");
    } finally {
      await missionSideIdentity(pilot, "revoke");
      await admin(pilot, "grant", "--iss", ESTATE, "--sub", "u-1001", "--relation", "reader", "--vendor", "acme");
    }
  });

  it("keeps the two alices apart: the Mission-side alice's entitlement never satisfies the estate account named alice, and its own does", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "alice", "invoices.read");
    await admin(pilot, "revoke", "--iss", ESTATE, "--sub", "alice", "--relation", "reader", "--vendor", "acme");
    await admin(pilot, "revoke", "--iss", ESTATE, "--sub", "alice", "--relation", "member", "--tenant", TENANT);
    await admin(pilot, "grant", "--iss", MAS, "--sub", "alice", "--relation", "member", "--tenant", TENANT);
    await admin(pilot, "grant", "--iss", MAS, "--sub", "alice", "--relation", "reader", "--vendor", "acme");
    try {
      const other = await call(pilot, credential, danaMission, "get_invoice", { invoice_id: "inv-1" });
      expect(other.ok).toBe(false);
      expect(other.denial_reason).toBe("resource_policy");
    } finally {
      await admin(pilot, "revoke", "--iss", MAS, "--sub", "alice", "--relation", "reader", "--vendor", "acme");
      await admin(pilot, "revoke", "--iss", MAS, "--sub", "alice", "--relation", "member", "--tenant", TENANT);
      await admin(pilot, "grant", "--iss", ESTATE, "--sub", "alice", "--relation", "member", "--tenant", TENANT);
      await admin(pilot, "grant", "--iss", ESTATE, "--sub", "alice", "--relation", "reader", "--vendor", "acme");
    }
    const own = await call(pilot, credential, danaMission, "get_invoice", { invoice_id: "inv-1" });
    expect(own.ok, JSON.stringify(own)).toBe(true);
  });

  it("applies the client dimension to the estate client: revoking its authorized_client denies, the Mission-side identity never stands in, and restoring permits", async () => {
    const credential = await estateToken(pilot, "estate-ap-bot-7f3", "u-1001", "invoices.read");
    await admin(pilot, "revoke", "--iss", ESTATE, "--client", "estate-ap-bot-7f3", "--relation", "client", "--vendor", "acme");
    await missionSideIdentity(pilot, "grant");
    try {
      const res = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
      expect(res.ok).toBe(false);
      expect(res.denial_reason).toBe("resource_policy");
    } finally {
      await missionSideIdentity(pilot, "revoke");
      await admin(pilot, "grant", "--iss", ESTATE, "--client", "estate-ap-bot-7f3", "--relation", "client", "--vendor", "acme");
    }
    const restored = await call(pilot, credential, aliceMission, "get_invoice", { invoice_id: "inv-1" });
    expect(restored.ok, JSON.stringify(restored)).toBe(true);
  });
});

d("MAS pilot Resource policy: a restart attached to the same store keeps a revocation (#818 slice 2)", () => {
  it("a pilot attached to the first pilot's store and model reads the revocation made before the restart, and the grant that follows", async () => {
    const { pilot: before } = await composeRecorded({ config });
    const store = { storeId: before.resourcePolicy.storeId, modelId: before.resourcePolicy.modelId };
    try {
      await admin(before, "revoke", "--iss", ESTATE, "--sub", "u-1001", "--relation", "reader", "--vendor", "acme");
    } finally {
      await before.close();
    }
    const { pilot: after } = await composeRecorded({ config, resourcePolicyStore: { attach: store } });
    try {
      const missionId = approve(after, "alice", { label: "rp-restart" });
      const credential = await estateToken(after, "estate-ap-bot-7f3", "u-1001", "invoices.read");
      const revoked = await call(after, credential, missionId, "get_invoice", { invoice_id: "inv-1" });
      expect(revoked.ok).toBe(false);
      expect(revoked.denial_reason).toBe("resource_policy");
      expect(after.resourcePolicy).toMatchObject({ ...store, development: false });
      await admin(after, "grant", "--iss", ESTATE, "--sub", "u-1001", "--relation", "reader", "--vendor", "acme");
      const granted = await call(after, credential, missionId, "get_invoice", { invoice_id: "inv-1" });
      expect(granted.ok, JSON.stringify(granted)).toBe(true);
    } finally {
      await after.close();
    }
  }, 60_000);
});
