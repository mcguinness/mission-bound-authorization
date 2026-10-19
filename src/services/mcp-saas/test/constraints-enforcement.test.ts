/**
 * @spec resource-access#rs-enforcement (#1266, review on PR #1298)
 *
 * The SaaS resource enforces from the RAS-issued token alone and understands
 * one `constraints` key, `vendors`. An entry carrying any other key, or a
 * malformed `vendors` value, provides no authority there: a request only such
 * an entry covers is refused with the resource's usual insufficient-authority
 * error and has no effect. Entries are alternatives, so another applicable
 * entry the resource can fully enforce still authorizes on its own.
 *
 * Most cases run the whole pipeline (Mission AS approval, ID-JAG, RAS
 * redemption, SaaS tool call) with a RAS that emits whatever the grant
 * carries, so the SaaS guard is what each assertion exercises. Cases whose
 * token the pipeline cannot produce (a key no specification defines, a
 * malformed value) mint the RAS-issued token directly.
 */

import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  issueCrossDomainGrant,
  MissionKernel,
  validateMissionIntent,
} from "@mission/authorization-server";
import { ResourceAuthorizationServer } from "@mission/ras";
import { SAAS_ENFORCED_CONSTRAINTS, SAAS_RESOURCE, SaasMcpServer } from "../src/index.js";
import { testAuthoritySourceCatalog } from "@mission/authorization-server/test-support";

const AS_ISS = "https://as.test";
const RAS_ISS = "https://ras.ledgercloud.test";
const READ = "ledger:vendor.read";
const WRITE = "ledger:journal.write";
const RESOURCE_TO_AS = (r: string) => (r === SAAS_RESOURCE ? RAS_ISS : AS_ISS);
const POLICY = {
  policy_version: "saas-constraints-policy-1",
  ceiling: [{ type: "mission_resource_access", resource: SAAS_RESOURCE, actions: [READ, WRITE] }],
} as const;
/** The owner's reproduction on PR #1298: a window that closed long ago. */
const CLOSED_WINDOW = { time_window: { not_after: "2020-01-01T00:00:00Z" } };

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };
let kernel: MissionKernel;
let asKeys: Keys;
let rasKeys: Keys;
let agentKeys: Keys;
let agentJkt: string;
let ras: ResourceAuthorizationServer;
let saas: SaasMcpServer;
let approvals = 0;

beforeAll(async () => {
  asKeys = await generateKeyPair("ES256", { extractable: true });
  rasKeys = await generateKeyPair("ES256", { extractable: true });
  agentKeys = await generateKeyPair("ES256", { extractable: true });
  agentJkt = await calculateJwkThumbprint(await exportJWK(agentKeys.publicKey));
  const asPub = { ...(await exportJWK(asKeys.publicKey)), kid: "as-token", alg: "ES256" };
  const rasPub = { ...(await exportJWK(rasKeys.publicKey)), kid: "ras-token", alg: "ES256" };
  kernel = new MissionKernel({
    issuer: AS_ISS,
    policy: POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(POLICY.ceiling, ["ap-agent"], ["bob"]),
    statusKey: asKeys.privateKey,
    statusKid: "as-status",
  });
  // No resourceConstraintsSupported: this RAS mints every key the grant
  // carries, so a refusal below is the resource server's own.
  ras = new ResourceAuthorizationServer({
    localCeiling: POLICY.ceiling.map((e) => ({ ...e, actions: [...e.actions] })),
    localPolicyVersion: POLICY.policy_version,
    issuer: RAS_ISS,
    trustedIssuers: { [AS_ISS]: { keys: [asPub as never] } },
    signKey: rasKeys.privateKey,
    signKid: "ras-token",
    registeredClients: { [agentJkt]: "ledgercloud-ras-redeemer" },
    mapping: {
      id: "ras-test-map",
      version: "v1",
      entries: [
        {
          origin: { iss: AS_ISS, sub: "alice" },
          local_sub: "alice-ledgercloud",
          observed_at: "2020-01-01T00:00:00Z",
          valid_until: "2099-01-01T00:00:00Z",
        },
      ],
    },
    entitlement: { resolve: async () => ({ entitled: true, observed_at: new Date().toISOString() }) },
    entitlementStalenessBoundSeconds: 86_400,
  });
  saas = new SaasMcpServer({ rasIssuer: RAS_ISS, rasJwks: { keys: [rasPub as never] } });
});

/** Approve a Mission over `authority`, cross into the SaaS domain, and redeem. */
async function pipelineToken(authority: AuthorityEntry[]): Promise<string> {
  approvals += 1;
  const mission = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Post journal entries to LedgerCloud",
        target_resources: [SAAS_RESOURCE],
        expires_at: "2027-01-01T00:00:00Z",
      }),
    ),
    proposedAuthority: authority,
    subject: { iss: AS_ISS, sub: "alice" },
    approver: { iss: AS_ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-constraints-${approvals}`,
  });
  const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
    missionId: mission.id,
    targetAs: RAS_ISS,
    clientId: "ap-agent",
    cnfJkt: agentJkt,
    resourceToAs: RESOURCE_TO_AS,
  });
  const { access_token } = await ras.redeem(grant, agentJkt);
  return access_token;
}

/** A RAS-issued local token carrying exactly `authorizationDetails`. */
async function mintedToken(authorizationDetails: unknown[]): Promise<string> {
  const nowS = Math.floor(Date.now() / 1000);
  return new SignJWT({
    mission: { id: "msn-direct", issuer: AS_ISS },
    authorization_details: authorizationDetails,
    cnf: { jkt: agentJkt },
  })
    .setProtectedHeader({ alg: "ES256", kid: "ras-token", typ: "at+jwt" })
    .setSubject("alice-ledgercloud")
    .setIssuer(RAS_ISS)
    .setAudience(SAAS_RESOURCE)
    .setIssuedAt(nowS)
    .setExpirationTime(nowS + 120)
    .sign(rasKeys.privateKey);
}

async function dpopProof(): Promise<string> {
  return new SignJWT({ htu: SAAS_RESOURCE, htm: "POST" })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(agentKeys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(agentKeys.privateKey);
}

const claims = (token: string) => JSON.parse(Buffer.from(token.split(".")[1] as string, "base64url").toString());
const entry = (actions: string[], constraints?: Record<string, unknown>): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: SAAS_RESOURCE,
  actions,
  ...(constraints ? { constraints: constraints as AuthorityEntry["constraints"] } : {}),
});

async function write(token: string, vendorId: unknown = "acme") {
  return saas.callTool("post_journal_entry", { vendor_id: vendorId, amount: "125.00" }, token, await dpopProof());
}
async function read(token: string, vendorId: unknown = "acme") {
  return saas.callTool("get_vendor_bank_details", { vendor_id: vendorId }, token, await dpopProof());
}

describe("the SaaS resource fails closed on a constraint it does not enforce (@spec resource-access#rs-enforcement)", () => {
  it("refuses a journal write whose only covering entry carries a time_window, with no effect", async () => {
    const token = await pipelineToken([entry([WRITE], CLOSED_WINDOW)]);
    // The RAS minted the bound: the refusal below is the resource server's.
    expect(claims(token).authorization_details).toEqual([entry([WRITE], CLOSED_WINDOW)]);
    const before = saas.journalEntries().length;
    const res = await write(token);
    expect(res).toEqual({ ok: false, error: "out_of_authority" });
    expect(saas.journalEntries()).toHaveLength(before);
  });

  it("refuses a journal write whose only covering entry carries max_amount, which this resource does not enforce", async () => {
    const capped = { max_amount: { amount: "1000.00", currency: "USD" } };
    const token = await pipelineToken([entry([WRITE], capped)]);
    expect(claims(token).authorization_details).toEqual([entry([WRITE], capped)]);
    const before = saas.journalEntries().length;
    const res = await write(token);
    expect(res).toEqual({ ok: false, error: "out_of_authority" });
    expect(saas.journalEntries()).toHaveLength(before);
  });

  it("refuses an entry carrying a constraints key no specification defines", async () => {
    const token = await mintedToken([entry([READ, WRITE], { x_region: "eu" })]);
    expect(await read(token)).toEqual({ ok: false, error: "out_of_authority" });
    const before = saas.journalEntries().length;
    expect(await write(token)).toEqual({ ok: false, error: "out_of_authority" });
    expect(saas.journalEntries()).toHaveLength(before);
  });

  it("refuses an entry whose constraints member or vendors value is malformed", async () => {
    for (const malformed of [
      { ...entry([READ]), constraints: "vendors" },
      { ...entry([READ]), constraints: ["vendors"] },
      entry([READ], { vendors: [] }),
      entry([READ], { vendors: "acme" }),
      entry([READ], { vendors: ["acme", 7] }),
    ]) {
      const res = await read(await mintedToken([malformed]));
      expect(res, JSON.stringify(malformed)).toEqual({ ok: false, error: "out_of_authority" });
    }
  });
});

describe("the SaaS resource enforces vendors against the vendor the operation addresses (@spec resource-access#rs-enforcement)", () => {
  it("permits a journal write for a listed vendor and refuses one for an unlisted vendor, with no effect", async () => {
    const token = await pipelineToken([entry([READ, WRITE], { vendors: ["acme"] })]);
    expect(claims(token).authorization_details).toEqual([entry([READ, WRITE], { vendors: ["acme"] })]);
    const before = saas.journalEntries().length;
    const denied = await write(token, "globex");
    expect(denied).toEqual({ ok: false, error: "out_of_authority" });
    expect(saas.journalEntries()).toHaveLength(before);
    const permitted = await write(token, "acme");
    expect(permitted.ok, JSON.stringify(permitted)).toBe(true);
    expect(saas.journalEntries()).toHaveLength(before + 1);
    expect(saas.journalEntries().at(-1)?.vendor_id).toBe("acme");
  });

  it("refuses a vendor read when the request names no vendor as a string", async () => {
    const token = await mintedToken([entry([READ], { vendors: ["acme"] })]);
    const unnamed = await saas.callTool("get_vendor_bank_details", {}, token, await dpopProof());
    expect(unnamed).toEqual({ ok: false, error: "out_of_authority" });
    expect(await read(token, ["acme"])).toEqual({ ok: false, error: "out_of_authority" });
    const ok = await read(token, "acme");
    expect(ok.ok, JSON.stringify(ok)).toBe(true);
  });
});

describe("applicable SaaS entries are alternatives, never combined (@spec resource-access#rs-enforcement)", () => {
  it("authorizes through an unconstrained covering entry beside one it cannot enforce", async () => {
    const token = await pipelineToken([entry([WRITE], CLOSED_WINDOW), entry([WRITE])]);
    expect(claims(token).authorization_details).toEqual([entry([WRITE], CLOSED_WINDOW), entry([WRITE])]);
    const before = saas.journalEntries().length;
    const res = await write(token);
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(saas.journalEntries()).toHaveLength(before + 1);
  });

  it("refuses a request that only an entry it cannot enforce covers, while another entry still authorizes its own action", async () => {
    const token = await pipelineToken([entry([WRITE], CLOSED_WINDOW), entry([READ])]);
    const before = saas.journalEntries().length;
    expect(await write(token)).toEqual({ ok: false, error: "out_of_authority" });
    expect(saas.journalEntries()).toHaveLength(before);
    const res = await read(token);
    expect(res.ok, JSON.stringify(res)).toBe(true);
  });

  it("still authorizes both tools through an unconstrained entry", async () => {
    const token = await pipelineToken([entry([READ, WRITE])]);
    const before = saas.journalEntries().length;
    const r = await read(token, "globex");
    expect(r.ok, JSON.stringify(r)).toBe(true);
    const w = await write(token, "globex");
    expect(w.ok, JSON.stringify(w)).toBe(true);
    expect(saas.journalEntries()).toHaveLength(before + 1);
  });
});

describe("SaaS protected resource metadata names only the constraints keys it enforces (@spec resource-access#protected-resource-metadata)", () => {
  it("advertises exactly vendors", () => {
    expect(SAAS_ENFORCED_CONSTRAINTS).toEqual(["vendors"]);
    expect(saas.protectedResourceMetadata().mission_constraints_supported).toEqual(["vendors"]);
  });
});
