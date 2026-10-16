import { createHash, generateKeyPairSync, KeyObject, sign } from "node:crypto";
import { canonicalize } from "@mission/core";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { type CryptoKey, generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  activateGovernedPolicy,
  AGR_JWS_CTY,
  AGR_JWS_TYP,
  type ApprovalGovernanceRecord,
  ApprovalGovernanceError,
  approvalGovernanceRecordDigest,
  type AuthorityEntry,
  MissionKernel,
  type MissionRecord,
  recordGovernedPolicyConsent,
  signApprovalGovernanceRecord,
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
