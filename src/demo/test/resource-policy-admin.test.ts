/**
 * @spec runtime#input-resource-policy (#828, D426): `pnpm resource-policy`,
 * the deployment's administration command for the independently
 * administered Resource policy. It attaches to the configured store and
 * model and never creates one; every change goes through `FgaDomainAdmin`.
 * The live grant and revoke against OpenFGA are in
 * resource-policy-as-native.test.ts.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { clientObject, Fga, FgaDomainAdmin, principalObject } from "@mission/pdp";
import {
  parseResourcePolicyCommand,
  ResourcePolicyUsageError,
  resourcePolicyAdmin,
  runResourcePolicyCommand,
} from "../src/resource-policy-admin.js";

const ISS = "http://localhost:4400";
const DEFAULTS = { url: "https://openfga.test", presharedKey: "key" };
const ALICE = principalObject({ iss: ISS, sub: "alice" });
const AP_AGENT = clientObject({ iss: ISS, client: "ap-agent" });

/** A stand-in OpenFGA client that records each write. */
function recordingFga() {
  const writes: unknown[] = [];
  const fga = { client: { write: async (body: unknown, opts: unknown) => void writes.push({ body, opts }) }, modelId: "model-1" } as unknown as Fga;
  return { fga, writes };
}

afterEach(() => vi.restoreAllMocks());

describe("pnpm resource-policy administers the stored entitlements (@spec runtime#input-resource-policy, #828)", () => {
  it("grant, revoke and move-invoice write exactly the stored tuples, issuer-local, through the admin path", async () => {
    const { fga, writes } = recordingFga();
    const admin = new FgaDomainAdmin(fga);
    const grant = parseResourcePolicyCommand(["grant", "--iss", ISS, "--sub", "alice", "--relation", "reader", "--vendor", "acme"]);
    expect(await runResourcePolicyCommand(grant, admin)).toBe(`granted ${ALICE} authorized_reader vendor:acme`);
    const revoke = parseResourcePolicyCommand(["revoke", "--iss", ISS, "--sub", "alice", "--relation", "payer", "--invoice", "inv-1"]);
    expect(await runResourcePolicyCommand(revoke, admin)).toBe(`revoked ${ALICE} authorized_payer invoice:inv-1`);
    const move = parseResourcePolicyCommand(["move-invoice", "--invoice", "inv-1", "--from", "acme", "--to", "globex"]);
    expect(await runResourcePolicyCommand(move, admin)).toBe("moved invoice:inv-1 from vendor:acme to vendor:globex");
    expect(writes).toEqual([
      { body: { writes: [{ user: ALICE, relation: "authorized_reader", object: "vendor:acme" }] }, opts: { authorizationModelId: "model-1" } },
      { body: { deletes: [{ user: ALICE, relation: "authorized_payer", object: "invoice:inv-1" }] }, opts: { authorizationModelId: "model-1" } },
      {
        body: {
          writes: [{ user: "vendor:globex", relation: "vendor", object: "invoice:inv-1" }],
          deletes: [{ user: "vendor:acme", relation: "vendor", object: "invoice:inv-1" }],
        },
        opts: { authorizationModelId: "model-1" },
      },
    ]);
  });

  it("administers the client and tenant dimensions (D429): a client's entitlement, a subject's or client's tenant membership, and a vendor's tenant, each one tuple", async () => {
    const { fga, writes } = recordingFga();
    const admin = new FgaDomainAdmin(fga);
    const lines = [];
    for (const argv of [
      ["revoke", "--iss", ISS, "--client", "ap-agent", "--relation", "client", "--vendor", "acme"],
      ["grant", "--iss", ISS, "--sub", "alice", "--relation", "member", "--tenant", "payments"],
      ["grant", "--iss", ISS, "--client", "ap-agent", "--relation", "member", "--tenant", "payments"],
      ["grant", "--relation", "tenant", "--tenant", "payments", "--vendor", "acme"],
    ]) {
      lines.push(await runResourcePolicyCommand(parseResourcePolicyCommand(argv), admin));
    }
    expect(lines).toEqual([
      `revoked ${AP_AGENT} authorized_client vendor:acme`,
      `granted ${ALICE} member tenant:payments`,
      `granted ${AP_AGENT} member tenant:payments`,
      "granted tenant:payments tenant vendor:acme",
    ]);
    expect(writes.map((w) => (w as { body: unknown }).body)).toEqual([
      { deletes: [{ user: AP_AGENT, relation: "authorized_client", object: "vendor:acme" }] },
      { writes: [{ user: ALICE, relation: "member", object: "tenant:payments" }] },
      { writes: [{ user: AP_AGENT, relation: "member", object: "tenant:payments" }] },
      { writes: [{ user: "tenant:payments", relation: "tenant", object: "vendor:acme" }] },
    ]);
  });

  it("refuses a command it does not fully understand, before any write", () => {
    const refused = [
      [],
      ["seed"],
      ["grant", "--iss", ISS, "--sub", "alice", "--relation", "owner", "--vendor", "acme"],
      ["grant", "--iss", ISS, "--sub", "alice", "--relation", "reader"],
      ["grant", "--iss", ISS, "--sub", "alice", "--relation", "reader", "--vendor", "acme", "--invoice", "inv-1"],
      ["grant", "--sub", "alice", "--relation", "reader", "--vendor", "acme"],
      ["grant", "--iss", ISS, "--sub", "alice", "--relation", "reader", "--vendor", "acme", "--client", "ap-agent"],
      ["revoke", "--iss", ISS, "--iss", ISS, "--sub", "alice", "--relation", "reader", "--vendor", "acme"],
      ["revoke", "--iss", ISS, "--sub", "--relation", "reader", "--vendor", "acme"],
      ["move-invoice", "--invoice", "inv-1", "--to", "globex"],
      // D429: a client's entitlement takes a client and a vendor only.
      ["grant", "--iss", ISS, "--sub", "alice", "--relation", "client", "--vendor", "acme"],
      ["grant", "--iss", ISS, "--client", "ap-agent", "--relation", "client", "--invoice", "inv-1"],
      // A membership names exactly one member and a tenant.
      ["grant", "--iss", ISS, "--sub", "alice", "--client", "ap-agent", "--relation", "member", "--tenant", "payments"],
      ["grant", "--iss", ISS, "--relation", "member", "--tenant", "payments"],
      ["grant", "--iss", ISS, "--sub", "alice", "--relation", "member", "--vendor", "acme"],
      // A vendor's tenant takes no principal.
      ["grant", "--iss", ISS, "--relation", "tenant", "--tenant", "payments", "--vendor", "acme"],
      ["grant", "--relation", "tenant", "--tenant", "payments", "--invoice", "inv-1"],
    ];
    for (const argv of refused) expect(() => parseResourcePolicyCommand(argv), JSON.stringify(argv)).toThrow(ResourcePolicyUsageError);
  });

  it("attaches to the configured store and model and never bootstraps one; without both ids it refuses before connecting", async () => {
    const { fga, writes } = recordingFga();
    const attach = vi.spyOn(Fga, "attach").mockResolvedValue(fga);
    const bootstrap = vi.spyOn(Fga, "bootstrap");
    const argv = ["grant", "--iss", ISS, "--sub", "alice", "--relation", "reader", "--vendor", "acme"];
    for (const env of [{}, { OPENFGA_STORE_ID: "store-1" }, { OPENFGA_MODEL_ID: "model-1" }]) {
      await expect(resourcePolicyAdmin(argv, env, DEFAULTS), JSON.stringify(env)).rejects.toThrow(/OPENFGA_STORE_ID and OPENFGA_MODEL_ID/);
    }
    expect(attach).not.toHaveBeenCalled();
    expect(await resourcePolicyAdmin(argv, { OPENFGA_STORE_ID: "store-1", OPENFGA_MODEL_ID: "model-1" }, DEFAULTS)).toBe(
      `granted ${ALICE} authorized_reader vendor:acme`,
    );
    expect(attach).toHaveBeenCalledWith({ apiUrl: DEFAULTS.url, presharedKey: DEFAULTS.presharedKey, storeId: "store-1", authorizationModelId: "model-1" });
    expect(bootstrap).not.toHaveBeenCalled();
    expect(writes).toHaveLength(1);
  });
});
