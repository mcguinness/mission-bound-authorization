/**
 * @spec draft-mcguinness-oauth-id-continuation-assertion-00 (continuation ID-JAG)
 *
 * The opt-in continuation extension to `issueCrossDomainGrant`: a single code
 * path that, when the caller passes the new optional fields, emits a fresh
 * `identity_continuation_handle`, an audience-local `sub`, a pre-built
 * (already-collapsed) `act` lineage, and a carried-not-refreshed root auth
 * envelope (`auth_time`/`acr`/`amr`). When the fields are omitted the grant is
 * byte-identical to the legacy ID-JAG. Self-contained: no RAS/SaaS on any path.
 */

import { type ActObject, extendChain, extendChainCollapsing } from "@mission/actor-chain";
import {
  calculateJwkThumbprint,
  type CryptoKey,
  decodeJwt,
  exportJWK,
  generateKeyPair,
} from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  issueCrossDomainGrant,
  MissionKernel,
  type MissionRecord,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const AS_ISS = "https://as.test";
const RAS_ISS = "https://ras.ledgercloud.test";
const RESOURCE = "https://saas.ledgercloud.test/mcp";
const CA = "https://chain-authority.example";
const RESOURCE_TO_AS = (r: string) => (r === RESOURCE ? RAS_ISS : AS_ISS);

// Ceiling includes exactly the resource the ID-JAG is audienced to.
const POLICY = {
  policy_version: "cont-policy-1",
  ceiling: [
    { type: "mission_resource_access", resource: RESOURCE, actions: ["ledger:journal.write"] },
  ],
} as const;

let kernel: MissionKernel;
let asKeys: { privateKey: CryptoKey; publicKey: CryptoKey };
let agentJkt: string;

const approve = (n: number): MissionRecord =>
  kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Post journal entries to LedgerCloud",
        target_resources: [RESOURCE],
        expires_at: "2027-01-01T00:00:00Z",
      }),
    ),
    proposedAuthority: [
      { type: "mission_resource_access", resource: RESOURCE, actions: ["ledger:journal.write"] },
    ],
    subject: { iss: AS_ISS, sub: "alice" }, // the GLOBAL subject
    approver: { iss: AS_ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-${n}`,
  });

const legacyInput = (missionId: string) => ({
  missionId,
  targetAs: RAS_ISS,
  clientId: "ap-agent",
  cnfJkt: agentJkt,
  resourceToAs: RESOURCE_TO_AS,
});

beforeAll(async () => {
  asKeys = await generateKeyPair("ES256", { extractable: true });
  kernel = new MissionKernel({
    issuer: AS_ISS,
    policy: POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(POLICY.ceiling, ["ap-agent", "delegate-svc"], ["bob"]),
    statusKey: asKeys.privateKey,
    statusKid: "as-status",
  });
  const agentKeys = await generateKeyPair("ES256", { extractable: true });
  agentJkt = await calculateJwkThumbprint(await exportJWK(agentKeys.publicKey));
});

describe("issueCrossDomainGrant — continuation ID-JAG (extended path)", () => {
  const HANDLE = "ich_0123456789abcdefABCD"; // 24 chars, base64url
  const LOCAL_SUB = "acct:alice@ledgercloud"; // audience-local, NOT the global "alice"
  const ENVELOPE = { auth_time: 1_700_000_000, acr: "urn:mace:acr:mfa", amr: ["pwd", "otp"] };

  it("emits handle, audience-local sub, act lineage, and the root auth envelope", async () => {
    const record = approve(1);
    // A realistic collapsed lineage: the same actor takes a fresh hop over an
    // inbound chain where it is already the outermost hop, so the caller's
    // `extendChainCollapsing` keeps a depth-1 `act` (no duplicate entry).
    const inbound: ActObject = { iss: CA, sub: "agent-7" };
    const builtAct = extendChainCollapsing({ iss: CA, sub: "agent-7" }, inbound);
    expect(builtAct).toEqual({ iss: CA, sub: "agent-7" }); // collapsed, depth 1

    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      ...legacyInput(record.id),
      sub: LOCAL_SUB,
      identityContinuationHandle: HANDLE,
      act: builtAct,
      authEnvelope: ENVELOPE,
    });
    const c = decodeJwt(grant);

    // Audience-local sub REPLACES the global subject.
    expect(c.sub).toBe(LOCAL_SUB);
    expect(c.sub).not.toBe(record.subject.sub);
    // Fresh continuation handle, carried verbatim.
    expect(c.identity_continuation_handle).toBe(HANDLE);
    // Pre-built lineage carried verbatim.
    expect(c.act).toEqual(builtAct);
    // Root envelope carried, not refreshed.
    expect(c.auth_time).toBe(ENVELOPE.auth_time);
    expect(c.acr).toBe(ENVELOPE.acr);
    expect(c.amr).toEqual(ENVELOPE.amr);
    // The legacy anchors are still all present.
    expect((c.cnf as { jkt: string }).jkt).toBe(agentJkt);
    expect((c.mission as { id: string; issuer: string }).id).toBe(record.id);
    expect((c.mission as { id: string; issuer: string }).issuer).toBe(AS_ISS);
    expect(Array.isArray(c.authorization_details)).toBe(true);
    expect((c.authorization_details as unknown[]).length).toBeGreaterThan(0);
    expect(c.client_id).toBe("ap-agent");
  });

  it("@spec mission#delegation (delegate model, P0-2) — a genuine delegate's grant names the delegate as client_id and nests the approved agent one level into act", async () => {
    // The Mission was approved for "ap-agent"; a DIFFERENT delegate ("delegate-svc")
    // is the one actually presenting and requesting THIS cross-domain grant.
    const record = approve(5);
    // Outermost act = the current delegate (the immediate/requesting client);
    // prior lineage (the approved agent) nests inward via act.act.
    const delegateAct = extendChain({ iss: AS_ISS, sub: "delegate-svc" }, { iss: AS_ISS, sub: "ap-agent" });

    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      missionId: record.id,
      targetAs: RAS_ISS,
      clientId: "delegate-svc", // the requesting client, NOT the approved agent
      cnfJkt: agentJkt,
      resourceToAs: RESOURCE_TO_AS,
      act: delegateAct,
    });
    const c = decodeJwt(grant);

    // client_id (top-level) is the OAuth client requesting THIS token (the
    // immediate client/current delegate), per RFC 8693 Section 4.3 / RFC 9068
    // Section 2.2 — NOT the Mission's approved agent.
    expect(c.client_id).toBe("delegate-svc");
    // act: the outermost entry is the current delegate; the approved agent's
    // prior lineage nests one level inward via act.act. (The approved agent's
    // identity is recoverable via this act chain / the Mission Record, not via
    // a separate mission claim member; see issue #433.)
    const act = c.act as ActObject;
    expect(act.sub).toBe("delegate-svc");
    expect(act.act?.sub).toBe("ap-agent");
  });

  it("omits absent auth-envelope sub-fields (partial envelope)", async () => {
    const record = approve(2);
    const { grant } = await issueCrossDomainGrant(kernel, asKeys.privateKey, "as-token", {
      ...legacyInput(record.id),
      authEnvelope: { auth_time: 123 },
    });
    const c = decodeJwt(grant);
    expect(c.auth_time).toBe(123);
    expect(c).not.toHaveProperty("acr");
    expect(c).not.toHaveProperty("amr");
  });
});

describe("issueCrossDomainGrant — legacy path is byte-identical", () => {
  it("with no continuation fields, sub is the global subject and no new claims appear", async () => {
    const record = approve(3);
    const { grant } = await issueCrossDomainGrant(
      kernel,
      asKeys.privateKey,
      "as-token",
      legacyInput(record.id),
    );
    const c = decodeJwt(grant);
    expect(c.sub).toBe(record.subject.sub); // the GLOBAL subject, unchanged
    for (const k of ["identity_continuation_handle", "act", "auth_time", "acr", "amr"]) {
      expect(c).not.toHaveProperty(k);
    }
  });

  it("pins the legacy payload key order (guards the conditional-emission refactor)", async () => {
    const record = approve(4);
    const { grant } = await issueCrossDomainGrant(
      kernel,
      asKeys.privateKey,
      "as-token",
      legacyInput(record.id),
    );
    // JSON.parse preserves string-key insertion order; jose appends the
    // registered claims after the constructor payload in setter order.
    expect(Object.keys(decodeJwt(grant))).toEqual([
      "mission",
      "authorization_details",
      "cnf",
      "sub",
      "client_id",
      "iss",
      "aud",
      "iat",
      "exp",
      "jti",
    ]);
  });
});
