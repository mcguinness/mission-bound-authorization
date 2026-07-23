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
  GateError,
  issueCrossDomainGrant,
  MissionKernel,
  validateMissionIntent,
} from "@mission/authorization-server";
import { ResourceAuthorizationServer } from "@mission/ras";
import { SaasMcpServer, SAAS_RESOURCE } from "../src/index.js";

const AS_ISS = "https://as.test";
const RAS_ISS = "https://ras.ledgercloud.test";
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

const intent = () =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Post journal entries to LedgerCloud",
      resources: [SAAS_RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
      proposed_authority: [
        { type: "mission_resource_access", resource: SAAS_RESOURCE, actions: ["ledger:vendor.read", "ledger:journal.write"] },
      ],
    }),
  );

const approve = (n: number) =>
  kernel.approve({
    intent: intent(),
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

  rasKeys = await generateKeyPair("ES256", { extractable: true });
  const rasPub = { ...(await exportJWK(rasKeys.publicKey)), kid: "ras-token", alg: "ES256" };
  ras = new ResourceAuthorizationServer({
    issuer: RAS_ISS,
    trustedIssuers: { [AS_ISS]: { keys: [asPub as never] } },
    signKey: rasKeys.privateKey,
    signKid: "ras-token",
  });
  saas = new SaasMcpServer({ rasIssuer: RAS_ISS, rasJwks: { keys: [rasPub as never] } });

  agentKeys = await generateKeyPair("ES256", { extractable: true });
  agentJkt = await calculateJwkThumbprint(await exportJWK(agentKeys.publicKey));
});

describe("M9 scenario 12: cross-domain via EMA/ID-JAG", () => {
  it("issue ID-JAG -> redeem at RAS -> post journal entry from the token alone", async () => {
    const mission = approve(1);
    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: mission.id,
      targetAs: RAS_ISS,
      cnfJkt: agentJkt,
      resourceToAs: RESOURCE_TO_AS,
    });

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

  it("a replayed ID-JAG is rejected at the RAS (one-time jti)", async () => {
    const mission = approve(2);
    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: mission.id,
      targetAs: RAS_ISS,
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
          resources: [SAAS_RESOURCE],
          expires_at: "2027-01-01T00:00:00Z",
          proposed_authority: [{ type: "mission_resource_access", resource: SAAS_RESOURCE, actions: ["ledger:vendor.read"] }],
        }),
      ),
      subject: { iss: AS_ISS, sub: "alice" },
      approver: { iss: AS_ISS, sub: "bob" },
      clientId: "ap-agent",
      approvalEventId: "apev-narrow",
    });
    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: narrow.id,
      targetAs: RAS_ISS,
      cnfJkt: agentJkt,
      resourceToAs: RESOURCE_TO_AS,
    });
    const { access_token } = await ras.redeem(grant, agentJkt);
    const res = await saas.callTool("post_journal_entry", { vendor_id: "acme", amount: "1" }, access_token, await dpopProof(SAAS_RESOURCE));
    expect(res.ok).toBe(false);
    expect(res.error).toBe("out_of_authority");
  });
});
