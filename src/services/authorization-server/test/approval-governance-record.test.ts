import { createHash, generateKeyPairSync, KeyObject, sign } from "node:crypto";
import { canonicalize } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  activateGovernedPolicy,
  AGR_JWS_CTY,
  AGR_JWS_TYP,
  type AgrAssertion,
  type ApprovalGovernanceRecord,
  ApprovalGovernanceError,
  approvalGovernanceRecordDigest,
  assertAccountableApprover,
  type AuthorityEntry,
  MissionKernel,
  type MissionRecord,
  recordGovernedPolicyConsent,
  signApprovalGovernanceRecord,
  type UnsignedApprovalGovernanceRecord,
  validateMissionIntent,
  verifyApprovalGovernanceRecord,
} from "../src/index.js";

/**
 * @spec approval-governance#envelope: the Approval Governance Record's
 * integrity envelope and the verifier's ordered steps. Exercised on a record
 * the issuer committed under `governed_policy`.
 */

const ISS = "https://as.test";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const ROOT_ID = "urn:policy:reconciler-root";

let key: CryptoKey;
let kernel: MissionKernel;
let mission: MissionRecord;
let record: ApprovalGovernanceRecord;

const readEntry: AuthorityEntry = {
  type: "mission_resource_access",
  resource: RESOURCE,
  actions: ["payments:invoice.read"],
  constraints: { vendors: ["acme"] },
};

beforeAll(async () => {
  key = (await generateKeyPair("ES256")).privateKey;
  const now = () => new Date("2026-07-01T00:00:00Z");
  kernel = new MissionKernel({
    issuer: ISS,
    policy: DERIVATION_POLICY as never,
    statusKey: key,
    statusKid: "as-status",
    authoritySourceCatalog: {
      humanPrincipals: ["dana"],
      entries: [
        {
          id: "reconciler",
          type: "service_owned",
          clients: ["svc-agent"],
          subjects: ["svc-reconciler"],
          activators: ["dana"],
          principals: ["svc-reconciler"],
          ceiling: DERIVATION_POLICY.ceiling as never,
        },
      ],
    },
    governedPolicyApproval: {
      roots: {
        [ROOT_ID]: {
          version: "1",
          content_type: "application/json",
          content: JSON.stringify({
            admits: { clients: ["svc-agent"], subjects: ["svc-reconciler"], authority_sources: ["service_owned"] },
            authority_ceiling: [readEntry],
            lifetime: { max_lifetime_s: 3600 },
            rules: { max_entries: 1 },
            recency: { ceilings: { default: 86400 }, clock_skew_s: 30 },
            classification: {
              standard: [
                "payments:invoice.list",
                "payments:invoice.read",
                "payments:vendor.read",
                "payments:payment.schedule",
                "payments:payment.schedule.cancel",
              ],
              irreversible_action: ["payments:payment.execute"],
              external_commitment: ["payments:remittance.send"],
            },
          }),
        },
      },
      approvers: { [ROOT_ID]: ["dana"] },
    },
    now,
  });
  const consent = recordGovernedPolicyConsent(kernel, {
    root: { id: ROOT_ID, version: "1" },
    approver: { iss: ISS, sub: "dana" },
    consentEventId: "gpce-envelope",
  });
  ({ mission, record } = activateGovernedPolicy(kernel, {
    consentId: consent.consent_id,
    approvalEventId: "ape-envelope",
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Reconcile", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
      { now: now() },
    ),
    clientId: "svc-agent",
  }));
});

const resolveKey = (kid: string) => (kid === "as-status" ? kernel.statusVerificationKey() : undefined);
const verifyAgainst = (r: ApprovalGovernanceRecord, m: MissionRecord = mission) =>
  verifyApprovalGovernanceRecord(r, { resolveKey, mission: m });
const clone = (r: ApprovalGovernanceRecord): ApprovalGovernanceRecord => JSON.parse(JSON.stringify(r));
const b64 = (v: unknown) => Buffer.from(canonicalize(v as never), "utf8").toString("base64url");

/** A JWS over the record minus envelope with a chosen protected header and signing key. */
const envelopeWith = (header: Record<string, unknown>, signer: KeyObject = KeyObject.from(key)): string => {
  const { envelope: _e, ...unsigned } = record;
  const input = `${b64(header)}.${b64(unsigned)}`;
  return `${input}.${sign("sha256", Buffer.from(input), { key: signer, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
};

describe("Approval Governance Record envelope (@spec approval-governance#envelope)", () => {
  it("verifies a committed record by its kid, signature, typ and cty, payload byte equality, and mission binding", () => {
    expect(verifyAgainst(record)).toBe(record);
    const [h, p] = record.envelope.value.split(".") as [string, string];
    expect(JSON.parse(Buffer.from(h, "base64url").toString("utf8"))).toEqual({
      alg: "ES256",
      kid: "as-status",
      typ: AGR_JWS_TYP,
      cty: AGR_JWS_CTY,
    });
    const { envelope: _e, ...unsigned } = record;
    expect(Buffer.from(p, "base64url").toString("utf8")).toBe(canonicalize(unsigned as never));
    expect(record.envelope.format).toBe("jws-compact");
  });

  it("rejects a record that differs from its signed payload, even though the signature verifies", () => {
    const edited = clone(record);
    edited.evaluation.evaluated_at = "2026-07-01T00:00:01.000Z";
    expect(() => verifyAgainst(edited)).toThrow(/differs from its signed payload/);
    const added = clone(record);
    added.assertions.push({ ...(record.assertions[0] as never), assertion_id: "ast_extra" });
    expect(() => verifyAgainst(added)).toThrow(ApprovalGovernanceError);
  });

  it("rejects an unresolvable kid, a signature by another key, and a typ or cty other than the Approval Governance pair", () => {
    const header = { alg: "ES256", kid: "as-status", typ: AGR_JWS_TYP, cty: AGR_JWS_CTY };
    expect(() => verifyAgainst({ ...record, envelope: { format: "jws-compact", value: envelopeWith({ ...header, kid: "unknown" }) } })).toThrow(
      /kid does not resolve/,
    );
    const other = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
    expect(() => verifyAgainst({ ...record, envelope: { format: "jws-compact", value: envelopeWith(header, other) } })).toThrow(
      /signature does not verify/,
    );
    for (const wrong of [
      { ...header, typ: "JWT" },
      { ...header, cty: "application/json" },
      { alg: "ES256", kid: "as-status" },
    ]) {
      expect(() => verifyAgainst({ ...record, envelope: { format: "jws-compact", value: envelopeWith(wrong) } })).toThrow(
        /typ and cty/,
      );
    }
    // A correctly formed envelope over the same record verifies.
    expect(() => verifyAgainst({ ...record, envelope: { format: "jws-compact", value: envelopeWith(header) } })).not.toThrow();
  });

  it("rejects an unsupported envelope format rather than accepting it unverified", () => {
    for (const format of ["jws-json", "none", ""]) {
      expect(() => verifyAgainst({ ...record, envelope: { ...record.envelope, format } })).toThrow(/unsupported/);
    }
  });

  it("rejects a record whose mission binding does not match the Mission it is retained with", () => {
    for (const other of [
      { ...mission, approval_event_id: "ape-other" },
      { ...mission, intent_hash: "sha-256:AAAA" },
      { ...mission, authority_hash: "sha-256:BBBB" },
      { ...mission, issuer: "https://other.test" },
    ]) {
      expect(() => verifyAgainst(record, other)).toThrow(/mission binding/);
    }
  });

  it("digests the complete record, envelope included", () => {
    const expected = `sha-256:${createHash("sha256").update(canonicalize(record as never), "utf8").digest("base64url")}`;
    expect(approvalGovernanceRecordDigest(record)).toBe(expected);
    // The same members under another signature are different record bytes.
    const resigned = signApprovalGovernanceRecord(record, kernel.statusSigner());
    expect(resigned.envelope.value).not.toBe(record.envelope.value);
    expect(() => verifyAgainst(resigned)).not.toThrow();
    expect(approvalGovernanceRecordDigest(resigned)).not.toBe(expected);
  });
});

/** Fixtures for the per-basis and per-kind rules, on typed `authority` objects. */
const ALICE = { iss: "https://idp.test", sub: "alice" };
const CFO = { iss: "https://idp.test", sub: "cfo" };
const humanBy = (assertion_id: string, principal = ALICE, decision: "approve" | "deny" = "approve"): AgrAssertion => ({
  assertion_id,
  principal,
  kind: "human",
  decision,
  decided_at: "2026-07-01T00:00:00.000Z",
  authority: { auth_time: "2026-06-30T23:59:00.000Z", acr: "urn:example:acr:phr", amr: ["hwk"] },
});
const policyBy = (assertion_id: string, principal = CFO, policy_id = "urn:policy:dlg"): AgrAssertion => ({
  assertion_id,
  principal,
  kind: "policy",
  decision: "approve",
  decided_at: "2026-07-01T00:00:00.000Z",
  authority: { policy_id, version: "7", approved_at: "2026-06-01T00:00:00.000Z" },
});
const serviceBy = (assertion_id: string, principal = { iss: ISS, sub: "model:judge" }): AgrAssertion => ({
  assertion_id,
  principal,
  kind: "service",
  decision: "approve",
  decided_at: "2026-07-01T00:00:00.000Z",
  authority: { logic_id: "judge", logic_version: "3", model_id: "judge", model_version: "3" },
});
const recordWith = (assertions: AgrAssertion[]): UnsignedApprovalGovernanceRecord => {
  const { envelope: _e, ...unsigned } = record;
  return {
    ...unsigned,
    assertions,
    evaluation: { ...unsigned.evaluation, contributing: assertions.map((a) => a.assertion_id) },
  };
};
const directBasis = {
  type: "direct" as const,
  consent_principal: ALICE,
  activation: { approval_event_id: "ape-direct" },
  activation_actor: ALICE,
  root_commitment: "sha-256:hjXlwWBY64-RPs1Z-E_gbyklNcViI5c9jiyMbE4KvFM",
};

describe("accountable-approver rule by approval basis (@spec approval-governance#accountable-assertion)", () => {
  it("direct: accepts exactly one human approve assertion of consent_principal beside contributing policy and service assertions", () => {
    const alice = humanBy("ast_alice");
    expect(assertAccountableApprover(recordWith([alice, policyBy("ast_dlg"), serviceBy("ast_judge")]), directBasis)).toEqual(alice);
  });

  it("direct: refuses a record whose consent_principal approves only through a policy or service assertion, twice, or not at all", () => {
    for (const assertions of [
      [policyBy("ast_p", ALICE)],
      [serviceBy("ast_s", ALICE)],
      [humanBy("ast_1"), humanBy("ast_2")],
      [humanBy("ast_1", ALICE, "deny")],
      [humanBy("ast_1", CFO)],
    ]) {
      expect(() => assertAccountableApprover(recordWith(assertions), directBasis)).toThrow(
        /direct record: exactly one approve assertion of kind human/,
      );
    }
  });

  it("governed_policy: counts only the consent principal's policy assertion that names the deciding policy", () => {
    if (mission.approval_basis.type !== "governed_policy") throw new Error("basis");
    const basis = mission.approval_basis;
    const accountable = record.assertions.find((a) => a.kind === "policy") as AgrAssertion;
    // The same human's policy assertion under another policy contributes without matching.
    const other = { ...accountable, assertion_id: "ast_other", authority: { ...accountable.authority, policy_id: "urn:policy:other" } };
    expect(assertAccountableApprover(recordWith([accountable, other]), basis)).toEqual(accountable);
    // Two assertions naming the deciding policy, or a human approval in its place, are refused.
    for (const assertions of [
      [accountable, { ...accountable, assertion_id: "ast_twice" }],
      [{ ...accountable, kind: "human" as const }],
      [{ ...accountable, kind: "service" as const }],
    ]) {
      expect(() => assertAccountableApprover(recordWith(assertions), basis)).toThrow(
        /governed_policy record: exactly one approve assertion of kind policy/,
      );
    }
  });

  it("other standing-consent bases: the approval_basis stands in, so no assertion is required or matched", () => {
    for (const type of ["template", "policy_drawdown", "ceiling_drawdown"] as const) {
      const basis = { ...directBasis, type, approved_at: "2026-06-01T00:00:00.000Z" } as never;
      expect(assertAccountableApprover(recordWith([serviceBy("ast_judge")]), basis)).toBeUndefined();
      expect(assertAccountableApprover(recordWith([policyBy("ast_dlg", ALICE), humanBy("ast_alice")]), basis)).toBeUndefined();
    }
  });
});
