/**
 * M7 AROP token-issuance completion. Scenario 6 (DTR) and scenario 7
 * (Transaction Challenge), both completing through a Mission Expansion.
 * Exit invariants: issued tokens never broaden the originating request and
 * never outlive approved_until.
 */

import { calculateJwkThumbprint, createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { DERIVATION_POLICY } from "@mission/demo-data";
import {
  createExpansion,
  DeferralStore,
  issueTxnToken,
  MissionKernel,
  signChallenge,
  successorMissionClaim,
  TxnReplayCache,
  TXN_TOKEN_TYP,
  validateChallenge,
  validateMissionIntent,
} from "../src/index.js";

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

const intent = (vendors: string[]) =>
  validateMissionIntent(
    JSON.stringify({
      goal: "Pay invoices",
      resources: [RESOURCE],
      expires_at: "2027-01-01T00:00:00Z",
      proposed_authority: [
        {
          type: "mission_resource_access",
          resource: RESOURCE,
          actions: ["payments:invoice.read", "payments:payment.execute"],
          constraints: { max_amount: { amount: "500.00", currency: "USD" }, vendors },
        },
      ],
    }),
  );

const approveMission = (n: number, vendors: string[]) =>
  kernel.approve({
    intent: intent(vendors),
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
    statusKey,
    statusKid: "as-status",
  });
});

describe("M7 scenario 6: AROP over DTR (deferred token -> expansion)", () => {
  it("requestable-denied deferred request -> deferral_code -> approve -> successor mission claim", () => {
    const predecessor = approveMission(1, ["acme"]); // narrow: acme only
    const deferrals = new DeferralStore(kernel);

    // Agent requests widened authority (globex) with completion_mode=deferred.
    const pending = deferrals.open({
      predecessorId: predecessor.id,
      intent: intent(["acme", "globex"]),
      clientId: "ap-agent",
    });
    expect(pending.error).toBe("authorization_pending");
    expect(pending.deferral_code).toMatch(/^dfr_/);

    // Polling before approval stays pending.
    const poll1 = deferrals.redeem(pending.deferral_code, { iss: ISS, sub: "bob" });
    expect((poll1 as { error: string }).error).toBe("authorization_pending");

    // Idempotent submission: same request returns the same handle.
    const again = deferrals.open({ predecessorId: predecessor.id, intent: intent(["acme", "globex"]), clientId: "ap-agent" });
    expect(again.deferral_code).toBe(pending.deferral_code);

    // Bob approves with an approval expiry that bounds the credential.
    deferrals.approve(pending.deferral_code, "2026-12-31T00:00:00Z");
    const result = deferrals.redeem(pending.deferral_code, { iss: ISS, sub: "bob" });
    const issued = result as { mission: Record<string, unknown>; successorId: string };
    expect(issued.mission.id).toBe(issued.successorId);
    // Successor carries the predecessor lineage member.
    expect(issued.mission.predecessor).toBe(predecessor.id);

    // Authority widened (globex now included) but only via the approval.
    const successor = kernel.get(issued.successorId);
    expect(successor?.authority_set[0]?.constraints?.vendors).toContain("globex");

    // Predecessor is superseded on first redemption.
    expect(kernel.get(predecessor.id)?.state).toBe("superseded");

    // Successor expiry is bounded by approved_until (never outlives it).
    expect(Date.parse(successor?.expires_at as string)).toBeLessThanOrEqual(Date.parse("2026-12-31T00:00:00Z"));

    // Single redemption: a second redeem fails.
    const replay = deferrals.redeem(pending.deferral_code, { iss: ISS, sub: "bob" });
    expect((replay as { error: string }).error).toBe("access_denied");
  });

  it("expansion refuses when the predecessor is not active", () => {
    const predecessor = approveMission(2, ["acme"]);
    kernel.transition(predecessor.id, "revoke");
    expect(() =>
      createExpansion(kernel, {
        predecessorId: predecessor.id,
        intent: intent(["acme", "globex"]),
        approver: { iss: ISS, sub: "bob" },
        approvalEventId: "apev-x",
        approvedUntil: "2026-12-31T00:00:00Z",
      }),
    ).toThrow(/not active/);
  });
});

describe("M7 scenario 7: AROP over Transaction Challenge", () => {
  it("RS signs a challenge -> AS validates + issues a txn-bound single-use token -> re-presented once", async () => {
    const predecessor = approveMission(3, ["acme"]);
    // RS signing key (rs-txn / txn_challenge_jwks_uri) and client DPoP key.
    const rsKeys = await generateKeyPair("ES256", { extractable: true });
    const rsPubJwk = { ...(await exportJWK(rsKeys.publicKey)), kid: "rs-txn", alg: "ES256" };
    const asKeys = await generateKeyPair("ES256", { extractable: true });
    const asPubJwk = { ...(await exportJWK(asKeys.publicKey)), kid: "as-token", alg: "ES256" };
    const clientKeys = await generateKeyPair("ES256", { extractable: true });
    const cnfJkt = await calculateJwkThumbprint(await exportJWK(clientKeys.publicKey));

    // RS returns a 401 challenge for an over-authority wire.
    const txn = "txn_abc123";
    const challenge = await signChallenge(
      {
        txn,
        authorization_details: [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:payment.execute"] }],
        iss: RESOURCE,
        aud: ISS,
        reason: "over-cap wire requires approval",
      },
      rsKeys.privateKey,
      "rs-txn",
    );

    // AS validates the challenge against the RS keys.
    const validated = await validateChallenge(challenge, { keys: [rsPubJwk as never] }, ISS);
    expect(validated.txn).toBe(txn);
    expect(validated.iss).toBe(RESOURCE);

    // AS issues a txn-bound, audience-restricted, single-use token via expansion.
    const { successor } = createExpansion(kernel, {
      predecessorId: predecessor.id,
      intent: intent(["acme"]),
      approver: { iss: ISS, sub: "bob" },
      approvalEventId: `apev_txn_${txn}`,
      approvedUntil: "2026-12-31T00:00:00Z",
    });
    const token = await issueTxnToken({
      txn,
      audience: RESOURCE,
      mission: successorMissionClaim(kernel, successor),
      authorizationDetails: validated.authorization_details,
      approvedUntil: "2026-12-31T00:00:00Z",
      cnfJkt,
      key: asKeys.privateKey,
      kid: "as-token",
      issuer: ISS,
    });

    // The token is audience-restricted, carries the txn, and is single_use.
    const { payload, protectedHeader } = await jwtVerify(token, createLocalJWKSet({ keys: [asPubJwk] } as never), {
      issuer: ISS,
      audience: RESOURCE,
    });
    expect(protectedHeader.typ).toBe(TXN_TOKEN_TYP);
    expect(payload.txn).toBe(txn);
    expect(payload.single_use).toBe(true);
    expect((payload.cnf as { jkt: string }).jkt).toBe(cnfJkt);
    expect(Date.parse("2026-12-31T00:00:00Z") / 1000).toBe(payload.exp);

    // RS honors the txn exactly once.
    const cache = new TxnReplayCache();
    expect(cache.accept(payload.txn as string)).toBe(true);
    expect(cache.accept(payload.txn as string)).toBe(false);
  });
});
