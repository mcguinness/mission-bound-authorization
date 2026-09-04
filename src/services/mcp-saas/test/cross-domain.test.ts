/**
 * M9 scenario 12: cross-domain via EMA / ID-JAG, end to end in-process.
 *
 * Mission AS issues a PoP-bound single-use ID-JAG (audience-scoped) by token
 * exchange -> RAS redeems it (JWT-bearer) into a short-lived local token
 * preserving the mission anchors -> the SaaS MCP server posts the journal
 * entry from the token alone. Replay rejected; after mission revocation the
 * next grant request is refused at the issuer; the residual local token dies
 * with its lease.
 */

import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  GateError,
  issueCrossDomainGrant,
  MissionKernel,
  validateMissionIntent,
} from "@mission/authorization-server";
import { ResourceAuthorizationServer } from "@mission/ras";
import { SaasMcpServer, SAAS_RESOURCE } from "../src/index.js";

const AS_ISS = "https://as.test";
const RAS_ISS = "https://ras.ledgercloud.test";
// @spec cross-domain#validation-at-resource-as (S-12): the RAS's own client
// registration, distinct from the grant's own client_id ("ap-agent", the
// origin agent). Two distinct destination clients so a test can prove
// neither's key nor identifier leaks onto the other's minted token.
const RAS_LOCAL_CLIENT_ID = "ledgercloud-ras-redeemer";
const RAS_LOCAL_CLIENT_ID_2 = "ledgercloud-ras-second-client";
const RESOURCE_TO_AS = (r: string) => (r === SAAS_RESOURCE ? RAS_ISS : AS_ISS);

// Policy ceiling includes the SaaS resource with the journal-write action.
const POLICY = {
  policy_version: "demo-policy-1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: SAAS_RESOURCE,
      actions: ["ledger:vendor.read", "ledger:journal.write"],
    },
  ],
} as const;

let kernel: MissionKernel;
let asKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let ras: ResourceAuthorizationServer;
let rasKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let saas: SaasMcpServer;
let agentKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let agentJkt: string;
let secondAgentKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let secondAgentJkt: string;

const intent = () =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Post journal entries to LedgerCloud",
      target_resources: [SAAS_RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
    }),
  );

const PROPOSED_AUTHORITY: AuthorityEntry[] = [
  { type: "mission_resource_access", resource: SAAS_RESOURCE, actions: ["ledger:vendor.read", "ledger:journal.write"] },
];

const approve = (n: number) =>
  kernel.approve({
    intent: intent(),
    proposedAuthority: PROPOSED_AUTHORITY,
    subject: { iss: AS_ISS, sub: "alice" },
    approver: { iss: AS_ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-${n}`,
  });

async function dpopProof(htu: string): Promise<string> {
  return new SignJWT({ htu, htm: "POST" })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(agentKeys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(agentKeys.privateKey);
}

beforeAll(async () => {
  asKeys = await generateKeyPair("ES256", { extractable: true });
  const asPub = { ...(await exportJWK(asKeys.publicKey)), kid: "as-token", alg: "ES256" };
  kernel = new MissionKernel({ issuer: AS_ISS, policy: POLICY as never, statusKey: asKeys.privateKey, statusKid: "as-status" });

  // Two distinct destination-local clients, registered at the RAS by key
  // BEFORE any redemption (S-12: this IS the RAS's own client authentication).
  agentKeys = await generateKeyPair("ES256", { extractable: true });
  agentJkt = await calculateJwkThumbprint(await exportJWK(agentKeys.publicKey));
  secondAgentKeys = await generateKeyPair("ES256", { extractable: true });
  secondAgentJkt = await calculateJwkThumbprint(await exportJWK(secondAgentKeys.publicKey));

  rasKeys = await generateKeyPair("ES256", { extractable: true });
  const rasPub = { ...(await exportJWK(rasKeys.publicKey)), kid: "ras-token", alg: "ES256" };
  ras = new ResourceAuthorizationServer({
    issuer: RAS_ISS,
    trustedIssuers: { [AS_ISS]: { keys: [asPub as never] } },
    signKey: rasKeys.privateKey,
    signKid: "ras-token",
    registeredClients: {
      [agentJkt]: RAS_LOCAL_CLIENT_ID,
      [secondAgentJkt]: RAS_LOCAL_CLIENT_ID_2,
    },
    // @spec cross-domain#origin-principal-mapping (#539): every approve()
    // call below uses subject { iss: AS_ISS, sub: "alice" } as BOTH the
    // Mission's global subject and (since this AS is its own issuer) the
    // ID-JAG's own top-level (iss, sub) -- one registered entry covers the
    // co-resolution check for every base grant this file mints.
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

describe("M9 scenario 12: cross-domain via EMA/ID-JAG", () => {
  it("issue ID-JAG -> redeem at RAS -> post journal entry from the token alone", async () => {
    const mission = approve(1);
    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: mission.id,
      targetAs: RAS_ISS,
      clientId: "ap-agent",
      cnfJkt: agentJkt,
      resourceToAs: RESOURCE_TO_AS,
    });

    // ID-JAG §3.1: the grant carries client_id (the acting client at the RAS).
    const grantClaims = JSON.parse(Buffer.from(grant.split(".")[1] as string, "base64url").toString());
    expect(grantClaims.client_id).toBe("ap-agent");

    const { access_token } = await ras.redeem(grant, agentJkt);
    const res = await saas.callTool(
      "post_journal_entry",
      { vendor_id: "acme", amount: "125.00" },
      access_token,
      await dpopProof(SAAS_RESOURCE),
    );
    expect(res.ok, JSON.stringify(res)).toBe(true);
    expect(saas.journalEntries()).toHaveLength(1);
    expect(saas.journalEntries()[0]?.mission_id).toBe(mission.id);
  });

  it("@spec cross-domain#validation-at-resource-as (S-12): the local token's client_id identifies the redeeming destination client, never the origin agent", async () => {
    const mission = approve(6);
    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: mission.id,
      targetAs: RAS_ISS,
      clientId: "ap-agent",
      cnfJkt: agentJkt,
      resourceToAs: RESOURCE_TO_AS,
    });
    const { access_token } = await ras.redeem(grant, agentJkt);
    const local = JSON.parse(Buffer.from(access_token.split(".")[1] as string, "base64url").toString());

    // Positive: the destination's own registration, per the RAS's own
    // conventions (an RFC 9068-style JWT local token -> client_id).
    expect(local.client_id).toBe(RAS_LOCAL_CLIENT_ID);

    // Negative: never the grant's client_id (the origin agent), and not a
    // value derived from the presenter key: origin identity travels only
    // via the Origin Principal members, never as the local client identity.
    expect(local.client_id).not.toBe("ap-agent");
    expect(local.client_id).not.toContain(agentJkt);
    expect(local.client_id).not.toBe(agentJkt);

    // The mission anchors are unaffected by this: client_id and mission.* are
    // independent fields on one mint call.
    expect(local.mission.id).toBe(mission.id);
    expect(local.mission.issuer).toBe(AS_ISS);
  });

  it("@spec cross-domain#validation-at-resource-as (S-12): a valid, sender-constrained origin grant is not enough on its own; an unregistered presenter key is invalid_client", async () => {
    // A fresh key the RAS never registered. The origin AS is perfectly
    // willing to issue a valid grant sender-constrained to it: origin-side
    // validity says nothing about whether the destination recognizes the
    // presenter as one of its own clients.
    const unregisteredKeys = await generateKeyPair("ES256", { extractable: true });
    const unregisteredJkt = await calculateJwkThumbprint(await exportJWK(unregisteredKeys.publicKey));

    const mission = approve(7);
    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: mission.id,
      targetAs: RAS_ISS,
      clientId: "ap-agent",
      cnfJkt: unregisteredJkt,
      resourceToAs: RESOURCE_TO_AS,
    });

    // Sender-constraint passes (the presenter holds the grant's own bound
    // key); redemption still fails because the RAS does not recognize this
    // key as belonging to any of its registered clients.
    await expect(ras.redeem(grant, unregisteredJkt)).rejects.toMatchObject({ code: "invalid_client" });
  });

  it("@spec cross-domain#validation-at-resource-as (S-12): two distinct registered destination clients each receive their own client_id, never the other's or the origin's", async () => {
    const missionA = approve(8);
    const { grant: grantA } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: missionA.id,
      targetAs: RAS_ISS,
      clientId: "ap-agent",
      cnfJkt: agentJkt,
      resourceToAs: RESOURCE_TO_AS,
    });
    const missionB = approve(9);
    const { grant: grantB } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: missionB.id,
      targetAs: RAS_ISS,
      clientId: "ap-agent",
      cnfJkt: secondAgentJkt,
      resourceToAs: RESOURCE_TO_AS,
    });

    const { access_token: tokenA } = await ras.redeem(grantA, agentJkt);
    const { access_token: tokenB } = await ras.redeem(grantB, secondAgentJkt);
    const localA = JSON.parse(Buffer.from(tokenA.split(".")[1] as string, "base64url").toString());
    const localB = JSON.parse(Buffer.from(tokenB.split(".")[1] as string, "base64url").toString());

    expect(localA.client_id).toBe(RAS_LOCAL_CLIENT_ID);
    expect(localB.client_id).toBe(RAS_LOCAL_CLIENT_ID_2);
    expect(localA.client_id).not.toBe(localB.client_id);
    expect(localA.client_id).not.toBe("ap-agent");
    expect(localB.client_id).not.toBe("ap-agent");
  });

  it("a replayed ID-JAG is rejected at the RAS (one-time jti)", async () => {
    const mission = approve(2);
    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: mission.id,
      targetAs: RAS_ISS,
      clientId: "ap-agent",
      cnfJkt: agentJkt,
      resourceToAs: RESOURCE_TO_AS,
    });
    await ras.redeem(grant, agentJkt);
    await expect(ras.redeem(grant, agentJkt)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("presenter-key mismatch is rejected (sender-constraint)", async () => {
    const mission = approve(3);
    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: mission.id,
      targetAs: RAS_ISS,
      clientId: "ap-agent",
      cnfJkt: agentJkt,
      resourceToAs: RESOURCE_TO_AS,
    });
    await expect(ras.redeem(grant, "different-jkt")).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("after revocation, the next grant request is refused at the issuer (lifecycle gate reaches across)", async () => {
    const mission = approve(4);
    kernel.transition(mission.id, "revoke");
    await expect(
      issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
        missionId: mission.id,
        targetAs: RAS_ISS,
        clientId: "ap-agent",
        cnfJkt: agentJkt,
        resourceToAs: RESOURCE_TO_AS,
      }),
    ).rejects.toBeInstanceOf(GateError);
  });

  it("the local token dies with its lease (exp never exceeds the grant)", async () => {
    const mission = approve(5);
    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: mission.id,
      targetAs: RAS_ISS,
      clientId: "ap-agent",
      cnfJkt: agentJkt,
      resourceToAs: RESOURCE_TO_AS,
    });
    const { access_token, expires_in } = await ras.redeem(grant, agentJkt);
    const claims = JSON.parse(Buffer.from(access_token.split(".")[1] as string, "base64url").toString());
    const grantClaims = JSON.parse(Buffer.from(grant.split(".")[1] as string, "base64url").toString());
    expect(claims.exp).toBeLessThanOrEqual(grantClaims.exp);
    expect(expires_in).toBeLessThanOrEqual(300);
    // mission anchors preserved; local iss is the RAS.
    expect(claims.iss).toBe(RAS_ISS);
    expect(claims.mission.issuer).toBe(AS_ISS);
    expect(claims.mission.id).toBe(mission.id);
  });

  it("out-of-scope tool at the SaaS server is denied token-only", async () => {
    // A mission scoped to vendor.read only; journal.write must be denied.
    const narrow = kernel.approve({
      intent: validateMissionIntent(
        JSON.stringify({
          goal: "Read only",
          target_resources: [SAAS_RESOURCE],
          expires_at: "2027-01-01T00:00:00Z",
        }),
      ),
      proposedAuthority: [{ type: "mission_resource_access", resource: SAAS_RESOURCE, actions: ["ledger:vendor.read"] }],
      subject: { iss: AS_ISS, sub: "alice" },
      approver: { iss: AS_ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-narrow",
    });
    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: narrow.id,
      targetAs: RAS_ISS,
      clientId: "ap-agent",
      cnfJkt: agentJkt,
      resourceToAs: RESOURCE_TO_AS,
    });
    const { access_token } = await ras.redeem(grant, agentJkt);
    const res = await saas.callTool("post_journal_entry", { vendor_id: "acme", amount: "1" }, access_token, await dpopProof(SAAS_RESOURCE));
    expect(res.ok).toBe(false);
    expect(res.error).toBe("out_of_authority");
  });

  /**
   * @spec cross-domain#dual-axis (#744) — the live demo's own seed: the
   * mission delegates both SaaS actions, but the mapped local principal is
   * currently entitled to the read alone. The redemption narrows rather
   * than refuses, and the SaaS PEP then permits the entitled action and
   * refuses the delegated but unentitled one from the same local token.
   */
  it("an entitlement entitled to the read alone narrows the local token, so the read permits and the delegated journal write is refused", async () => {
    const mission = approve(9);
    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: mission.id,
      targetAs: RAS_ISS,
      clientId: "ap-agent",
      cnfJkt: agentJkt,
      resourceToAs: RESOURCE_TO_AS,
    });
    const narrowingRas = new ResourceAuthorizationServer({
      issuer: RAS_ISS,
      trustedIssuers: { [AS_ISS]: { keys: [{ ...(await exportJWK(asKeys.publicKey)), kid: "as-token", alg: "ES256" } as never] } },
      signKey: rasKeys.privateKey,
      signKid: "ras-token",
      registeredClients: { [agentJkt]: RAS_LOCAL_CLIENT_ID },
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
      entitlement: {
        resolve: async () => ({
          entitled: true,
          observed_at: new Date().toISOString(),
          authority: [{ resource: SAAS_RESOURCE, actions: ["ledger:vendor.read"] }],
        }),
      },
      entitlementStalenessBoundSeconds: 86_400,
    });
    const { access_token } = await narrowingRas.redeem(grant, agentJkt);
    const local = JSON.parse(Buffer.from(access_token.split(".")[1] as string, "base64url").toString());
    expect(local.authorization_details).toEqual([
      { type: "mission_resource_access", resource: SAAS_RESOURCE, actions: ["ledger:vendor.read"] },
    ]);
    const read = await saas.callTool("get_vendor_bank_details", { vendor_id: "acme" }, access_token, await dpopProof(SAAS_RESOURCE));
    expect(read.ok, JSON.stringify(read)).toBe(true);
    const write = await saas.callTool("post_journal_entry", { vendor_id: "acme", amount: "1" }, access_token, await dpopProof(SAAS_RESOURCE));
    expect(write.ok).toBe(false);
    expect(write.error).toBe("out_of_authority");
  });
});
