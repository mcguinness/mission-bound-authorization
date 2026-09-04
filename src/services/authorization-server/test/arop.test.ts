/**
 * M7 AROP token-issuance completion. Scenario 6 (DTR) and scenario 7
 * (Transaction Challenge) both carry the ACTIVE Mission unchanged (D42: AROP
 * never widens); the separate Expansion flow (widening) is exercised alongside.
 * Exit invariants: issued tokens never broaden the originating request and
 * never outlive approved_until.
 */

import { calculateJwkThumbprint, createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { DERIVATION_POLICY } from "@mission/demo-data";
import {
  type AuthorityEntry,
  createExpansion,
  DeferralStore,
  MISSION_TXN_TOKEN_TYP,
  MissionKernel,
  mintTransactionToken,
  TXN_CHALLENGE_TYP,
  validateChallenge,
  validateMissionIntent,
} from "../src/index.js";
import { TXN_TOKEN_PROHIBITED_CLAIMS } from "@mission/core";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

/** Stand in for the Challenge-Issuing Resource (the resource owns the signing). */
async function signChallenge(
  claims: {
    txn: string;
    authorization_details: unknown[];
    iss: string;
    aud: string;
    reason: string;
    parameter_digest: string;
    mission: Record<string, unknown>;
    cnf: { jkt: string };
  },
  key: CryptoKey,
  kid: string,
): Promise<string> {
  return new SignJWT({
    txn: claims.txn,
    authorization_details: claims.authorization_details,
    reason: claims.reason,
    parameter_digest: claims.parameter_digest,
    mission: claims.mission,
    cnf: claims.cnf,
  })
    .setProtectedHeader({ alg: "ES256", kid, typ: TXN_CHALLENGE_TYP })
    .setIssuer(claims.iss)
    .setAudience(claims.aud)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(key);
}

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;

// A policy whose ceiling allows acme only; expansion widens to include globex.
const NARROW_POLICY = {
  policy_version: "demo-policy-1",
  ceiling: [
    {
      type: "mission_resource_access",
      resource: RESOURCE,
      actions: ["payments:invoice.read", "payments:payment.execute"],
      constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme", "globex"] },
    },
  ],
} as const;

let kernel: MissionKernel;
let statusKey: CryptoKey;

const intent = () =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Pay invoices",
      target_resources: [RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
    }),
  );

const proposal = (vendors: string[]): AuthorityEntry[] => [
  {
    type: "mission_resource_access",
    resource: RESOURCE,
    actions: ["payments:invoice.read", "payments:payment.execute"],
    constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors },
  },
];

const approveMission = (n: number, vendors: string[]) =>
  kernel.approve({
    intent: intent(),
    proposedAuthority: proposal(vendors),
    subject: { iss: ISS, sub: "alice" },
    approver: { iss: ISS, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-${n}`,
  });

beforeAll(async () => {
  const keys = await generateKeyPair("ES256", { extractable: true });
  statusKey = keys.privateKey;
  kernel = new MissionKernel({
    issuer: ISS,
    policy: NARROW_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(NARROW_POLICY.ceiling, ["ap-agent"]),
    statusKey,
    statusKid: "as-status",
  });
});

describe("M7 scenario 6: AROP over DTR (subset-of-Mission token, D42 -- never expands)", () => {
  it("deferred request for authority already in the Mission -> approve -> token carries the active Mission unchanged", () => {
    const mission = approveMission(1, ["acme"]); // active Mission with acme authority
    const deferrals = new DeferralStore(kernel);

    // Agent's held token is narrow; it defers for a subset of the Mission's authority.
    const requested: AuthorityEntry[] = [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:payment.execute"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ];
    const pending = deferrals.open({ missionId: mission.id, requested, clientId: "ap-agent" });
    expect(pending.error).toBe("authorization_pending");
    expect(pending.deferral_code).toMatch(/^dfr_/);

    // Polling before approval stays pending.
    expect((deferrals.redeem(pending.deferral_code) as { error: string }).error).toBe("authorization_pending");

    // Idempotent submission: same request returns the same handle.
    expect(deferrals.open({ missionId: mission.id, requested, clientId: "ap-agent" }).deferral_code).toBe(pending.deferral_code);

    // Bob approves with an approval expiry that bounds the credential.
    deferrals.approve(pending.deferral_code, "2026-12-31T00:00:00Z");
    const issued = deferrals.redeem(pending.deferral_code) as {
      mission: Record<string, unknown>;
      authorization_details: AuthorityEntry[];
      approved_until: string;
    };
    // D42: the token carries the ACTIVE Mission unchanged -- no successor, no predecessor.
    expect(issued.mission.id).toBe(mission.id);
    expect(issued.mission.predecessor).toBeUndefined();
    // No new Mission was created.
    expect(kernel.get(mission.id)?.state).toBe("active");
    // Granted authority is a subset of the active Mission.
    expect(issued.authorization_details[0]?.actions).toEqual(["payments:payment.execute"]);
    expect(issued.approved_until).toBe("2026-12-31T00:00:00Z");

    // Single redemption: a second redeem of an already-redeemed handle is a
    // malformed grant, not a denial -> invalid_grant (draft §5.6).
    expect((deferrals.redeem(pending.deferral_code) as { error: string }).error).toBe("invalid_grant");
    // An unknown deferral_code is likewise invalid_grant, distinct from a denial.
    expect((deferrals.redeem("dfr_does-not-exist") as { error: string }).error).toBe("invalid_grant");
  });

  it("an approver denial redeems as access_denied (distinct from an invalid_grant)", () => {
    const mission = approveMission(8, ["acme"]);
    const deferrals = new DeferralStore(kernel);
    const requested: AuthorityEntry[] = [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: ["payments:payment.execute"],
        constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme"] },
      },
    ];
    const pending = deferrals.open({ missionId: mission.id, requested, clientId: "ap-agent" });
    deferrals.deny(pending.deferral_code);
    expect((deferrals.redeem(pending.deferral_code) as { error: string }).error).toBe("access_denied");
  });

  it("a request that would widen the Mission is refused out_of_authority (use Expansion, not AROP)", () => {
    const mission = approveMission(2, ["acme"]); // acme only
    const deferrals = new DeferralStore(kernel);
    // globex is NOT in this Mission's authority -> AROP must not defer/widen.
    const widen: AuthorityEntry[] = [
      { type: "mission_resource_access", resource: RESOURCE, actions: ["payments:payment.execute"], constraints: { vendors: ["globex"] } },
    ];
    expect(() => deferrals.open({ missionId: mission.id, requested: widen, clientId: "ap-agent" })).toThrow(
      /exceeds the active Mission/,
    );
  });

  it("Mission Expansion (the separate widening flow) refuses when the predecessor is not active", () => {
    const predecessor = approveMission(3, ["acme"]);
    kernel.transition(predecessor.id, "revoke");
    expect(() =>
      createExpansion(kernel, {
        predecessorId: predecessor.id,
        intent: intent(),
        proposedAuthority: proposal(["acme", "globex"]),
        approver: { iss: ISS, sub: "bob" },
        approvalEventId: "apev-x",
        approvedUntil: "2026-12-31T00:00:00Z",
      }),
    ).toThrow(/not active/);
  });

  it("Mission Expansion widens via a fresh successor and supersedes the predecessor on redemption", () => {
    const predecessor = approveMission(4, ["acme"]);
    const { successor } = createExpansion(kernel, {
      predecessorId: predecessor.id,
      intent: intent(),
      proposedAuthority: proposal(["acme", "globex"]),
      approver: { iss: ISS, sub: "bob" },
      approvalEventId: "apev-exp",
      approvedUntil: "2026-12-31T00:00:00Z",
    });
    expect(successor.predecessor).toBe(predecessor.id);
    expect(successor.authority_set[0]?.constraints?.vendors).toContain("globex");
    kernel.supersedeOnRedemption(successor.id);
    expect(kernel.get(predecessor.id)?.state).toBe("superseded");
    expect(Date.parse(successor.expires_at)).toBeLessThanOrEqual(Date.parse("2026-12-31T00:00:00Z"));
  });
});

describe("challenge verification and the transaction token (@spec txn-authorization#transaction-token)", () => {
  it("verifies a challenge under its own issuer's keys and mints a conforming transaction token", async () => {
    const mission = approveMission(7, ["acme"]); // the active Mission (unchanged)
    const rsKeys = await generateKeyPair("ES256", { extractable: true });
    const rsPubJwk = { ...(await exportJWK(rsKeys.publicKey)), kid: "rs-txn", alg: "ES256" };
    const asKeys = await generateKeyPair("ES256", { extractable: true });
    const asPubJwk = { ...(await exportJWK(asKeys.publicKey)), kid: "as-txn", alg: "ES256" };
    const clientKeys = await generateKeyPair("ES256", { extractable: true });
    const cnfJkt = await calculateJwkThumbprint(await exportJWK(clientKeys.publicKey));

    const txn = "txn_abc123";
    const parameter_digest = "sha-256:deadbeefcafefeed";
    const requested = mission.authority_set
      .filter((e) => e.actions.includes("payments:payment.execute"))
      .map((e) => ({ ...e, actions: ["payments:payment.execute"] }));
    const missionClaim = kernel.missionClaim(mission) as unknown as Record<string, unknown>;
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: requested,
        iss: RESOURCE,
        aud: ISS,
        reason: "over-cap wire requires approval",
        parameter_digest,
        mission: missionClaim,
        cnf: { jkt: cnfJkt },
      },
      rsKeys.privateKey,
      "rs-txn",
    );

    // The TAS resolves the challenge issuer's keys from THAT issuer's set.
    const issuers = new Map([[RESOURCE, { jwks: createLocalJWKSet({ keys: [rsPubJwk as never] }) }]]);
    const validated = await validateChallenge(challenge, issuers, ISS);
    expect(validated.txn).toBe(txn);
    expect(validated.iss).toBe(RESOURCE);
    expect(validated.parameter_digest).toBe(parameter_digest);
    expect(validated.mission.id).toBe(mission.id);
    expect(validated.cnf.jkt).toBe(cnfJkt);

    // A signature by a DIFFERENT key under the same iss does not verify.
    const foreign = await generateKeyPair("ES256", { extractable: true });
    const forged = await signChallenge(
      {
        txn,
        authorization_details: requested,
        iss: RESOURCE,
        aud: ISS,
        reason: "forged",
        parameter_digest,
        mission: missionClaim,
        cnf: { jkt: cnfJkt },
      },
      foreign.privateKey,
      "rs-txn",
    );
    await expect(validateChallenge(forged, issuers, ISS)).rejects.toThrow(/did not verify/);

    const expS = Math.floor(Date.parse("2026-12-31T00:00:00Z") / 1000);
    const token = await mintTransactionToken({
      issuer: ISS,
      audience: RESOURCE,
      jti: "mtt_test_1",
      expS,
      subject: "alice",
      clientId: "ap-agent",
      txn,
      authorizationDetails: validated.authorization_details,
      parameterDigest: validated.parameter_digest,
      mission: validated.mission,
      cnfJkt,
      key: asKeys.privateKey,
      kid: "as-txn",
    });

    const { payload, protectedHeader } = await jwtVerify(token, createLocalJWKSet({ keys: [asPubJwk] } as never), {
      issuer: ISS,
      audience: RESOURCE,
      typ: MISSION_TXN_TOKEN_TYP,
    });
    expect(protectedHeader.typ).toBe(MISSION_TXN_TOKEN_TYP);
    expect(payload.txn).toBe(txn);
    expect(payload.aud).toBe(RESOURCE);
    expect(payload.sub).toBe("alice");
    expect(payload.client_id).toBe("ap-agent");
    expect(payload.jti).toBe("mtt_test_1");
    expect(payload.parameter_digest).toBe(parameter_digest);
    expect((payload.cnf as { jkt: string }).jkt).toBe(cnfJkt);
    expect((payload.mission as { id: string }).id).toBe(mission.id);
    expect((payload.mission as { predecessor?: string }).predecessor).toBeUndefined();
    expect(payload.exp).toBe(expS);
    expect(kernel.get(mission.id)?.state).toBe("active");
    // Nothing from the MUST NOT list rides here.
    for (const prohibited of TXN_TOKEN_PROHIBITED_CLAIMS) {
      expect(payload[prohibited], prohibited).toBeUndefined();
    }
  });
});
