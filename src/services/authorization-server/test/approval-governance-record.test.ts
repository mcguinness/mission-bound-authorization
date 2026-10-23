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
  assertAssertionAuthority,
  assertContributing,
  assertGovernedPolicyRecord,
  type AuthorityEntry,
  checkPortableApprovalBinding,
  MissionKernel,
  type MissionRecord,
  type PortableMissionReference,
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
    const { cty: _c, ...noCty } = header;
    const { typ: _t, ...noTyp } = header;
    for (const wrong of [
      { ...header, typ: "JWT" },
      { ...header, cty: "application/json" },
      { alg: "ES256", kid: "as-status" },
      noCty,
      noTyp,
      { ...header, typ: "" },
      { ...header, cty: "mission-approval-governance+json; charset=utf-8" },
      { ...header, typ: "application/mission-approval-governance+jwt" },
      { ...header, typ: "text/mission-approval-governance+jws" },
      { ...header, typ: AGR_JWS_CTY, cty: AGR_JWS_TYP },
    ]) {
      expect(() => verifyAgainst({ ...record, envelope: { format: "jws-compact", value: envelopeWith(wrong) } })).toThrow(
        /typ and cty/,
      );
    }
    // A correctly formed envelope over the same record verifies.
    expect(() => verifyAgainst({ ...record, envelope: { format: "jws-compact", value: envelopeWith(header) } })).not.toThrow();
  });

  it("emits the typ and cty the registered media types abbreviate, with application/ omitted", () => {
    const [h] = record.envelope.value.split(".") as [string];
    const header = JSON.parse(Buffer.from(h, "base64url").toString("utf8")) as Record<string, unknown>;
    expect(header.typ).toBe("mission-approval-governance+jws");
    expect(header.cty).toBe("mission-approval-governance+json");
  });

  it("accepts the application/ forms and case variants of typ and cty, leaving the signed record and its digest as retained", () => {
    for (const [typ, cty] of [
      ["application/mission-approval-governance+jws", "application/mission-approval-governance+json"],
      ["application/mission-approval-governance+jws", "mission-approval-governance+json"],
      ["Mission-Approval-Governance+JWS", "APPLICATION/Mission-Approval-Governance+JSON"],
    ]) {
      const signed: ApprovalGovernanceRecord = {
        ...record,
        envelope: { format: "jws-compact", value: envelopeWith({ alg: "ES256", kid: "as-status", typ, cty }) },
      };
      const before = JSON.stringify(signed);
      const digest = approvalGovernanceRecordDigest(signed);
      expect(verifyAgainst(signed)).toBe(signed);
      expect(JSON.stringify(signed)).toBe(before);
      expect(approvalGovernanceRecordDigest(signed)).toBe(digest);
      const [h] = signed.envelope.value.split(".") as [string];
      expect(JSON.parse(Buffer.from(h, "base64url").toString("utf8"))).toMatchObject({ typ, cty });
    }
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

describe("assertion authority by kind (@spec approval-governance#assertion-authority)", () => {
  const withAuthority = (a: AgrAssertion, authority: Record<string, unknown>): AgrAssertion =>
    ({ ...a, authority }) as AgrAssertion;

  it("accepts the typed members of each kind: human authentication, policy version and approval, service logic and model", () => {
    for (const a of [
      humanBy("ast_h"),
      withAuthority(humanBy("ast_h_min"), { auth_time: "2026-06-30T23:59:00Z" }),
      policyBy("ast_p"),
      withAuthority(policyBy("ast_p_by"), { ...policyBy("x").authority, approved_by: CFO }),
      serviceBy("ast_s"),
      withAuthority(serviceBy("ast_s_rules"), { logic_id: "dlg-rules", logic_version: "12" }),
    ]) {
      expect(() => assertAssertionAuthority(a)).not.toThrow();
    }
  });

  it("refuses a missing or mistyped member of each kind", () => {
    const { auth_time: _t, ...noAuthTime } = humanBy("x").authority;
    const { policy_id: _i, ...noPolicyId } = policyBy("x").authority;
    const { version: _v, ...noVersion } = policyBy("x").authority;
    const { approved_at: _a, ...noApprovedAt } = policyBy("x").authority;
    const { logic_id: _l, ...noLogicId } = serviceBy("x").authority;
    const { logic_version: _lv, ...noLogicVersion } = serviceBy("x").authority;
    for (const [a, why] of [
      [withAuthority(humanBy("h1"), noAuthTime), /auth_time/],
      [withAuthority(humanBy("h2"), { auth_time: "yesterday" }), /auth_time/],
      [withAuthority(humanBy("h3"), { auth_time: "2026-06-30T23:59:00Z", acr: 5 }), /acr/],
      [withAuthority(humanBy("h4"), { auth_time: "2026-06-30T23:59:00Z", amr: "hwk" }), /amr/],
      [withAuthority(policyBy("p1"), noPolicyId), /policy_id and version/],
      [withAuthority(policyBy("p2"), noVersion), /policy_id and version/],
      [withAuthority(policyBy("p3"), noApprovedAt), /approved_at/],
      [withAuthority(policyBy("p4"), { ...policyBy("x").authority, approved_at: "2026-06-01" }), /approved_at/],
      [withAuthority(serviceBy("s1"), noLogicId), /logic_id and logic_version/],
      [withAuthority(serviceBy("s2"), noLogicVersion), /logic_id and logic_version/],
      [withAuthority(serviceBy("s3"), { logic_id: "judge", logic_version: "3", model_id: "judge" }), /model_id and model_version/],
      [{ ...humanBy("n1"), authority: null } as unknown as AgrAssertion, /not an object/],
    ] as const) {
      expect(() => assertAssertionAuthority(a)).toThrow(why);
    }
  });

  it("refuses an approved_by that differs from the policy assertion's principal", () => {
    const by = (approved_by: unknown) => withAuthority(policyBy("ast_p"), { ...policyBy("x").authority, approved_by });
    expect(() => assertAssertionAuthority(by(CFO))).not.toThrow();
    for (const other of [ALICE, { iss: "https://login.test", sub: "cfo" }, null, "cfo"]) {
      expect(() => assertAssertionAuthority(by(other))).toThrow(/approved_by is not the assertion's principal/);
    }
  });

  it("is enforced at the governed_policy commit gate, before the record is signed", () => {
    if (mission.approval_basis.type !== "governed_policy") throw new Error("basis");
    const { envelope: _e, ...unsigned } = record;
    const accountable = unsigned.assertions[0] as AgrAssertion;
    const withBy = (approved_by: unknown): UnsignedApprovalGovernanceRecord => ({
      ...unsigned,
      assertions: [withAuthority(accountable, { ...accountable.authority, approved_by })],
    });
    expect(() => assertGovernedPolicyRecord(withBy(accountable.principal), mission.approval_basis as never)).not.toThrow();
    expect(() => assertGovernedPolicyRecord(withBy({ iss: ISS, sub: "mallory" }), mission.approval_basis as never)).toThrow(
      /governed_policy record: assertion ast_policy authority: approved_by/,
    );
  });
});

describe("evaluation contributing (@spec approval-governance#record-members)", () => {
  const BOB = { iss: "https://idp.test", sub: "bob" };
  const CAROL = { iss: "https://idp.test", sub: "carol" };
  const coApproval = (contributing: string[]): UnsignedApprovalGovernanceRecord => ({
    ...recordWith([humanBy("ast_1"), humanBy("ast_2", BOB), humanBy("ast_3", CAROL, "deny")]),
    evaluation: { decision: "approved", evaluated_at: "2026-07-01T00:00:00.000Z", contributing },
  });

  it("lists the counted assertions; a recorded denial that did not block the approval is not contributing", () => {
    expect(() => assertContributing(coApproval(["ast_1", "ast_2"]))).not.toThrow();
    expect(() => assertContributing(coApproval(["ast_1", "ast_2", "ast_3"]))).toThrow(/deny assertion ast_3/);
    expect(() => assertContributing(coApproval(["ast_1", "ast_9"]))).toThrow(/does not carry: ast_9/);
  });

  it("is enforced at the governed_policy commit gate", () => {
    if (mission.approval_basis.type !== "governed_policy") throw new Error("basis");
    const { envelope: _e, ...unsigned } = record;
    const veto = humanBy("ast_veto", CAROL, "deny");
    const withDenial = (contributing: string[]): UnsignedApprovalGovernanceRecord => ({
      ...unsigned,
      assertions: [...unsigned.assertions, veto],
      evaluation: { ...unsigned.evaluation, contributing },
    });
    expect(() => assertGovernedPolicyRecord(withDenial(["ast_policy"]), mission.approval_basis as never)).not.toThrow();
    expect(() => assertGovernedPolicyRecord(withDenial(["ast_policy", "ast_veto"]), mission.approval_basis as never)).toThrow(
      /governed_policy record: evaluation counts deny assertion ast_veto/,
    );
  });
});

describe("portable approval-binding check (@spec approval-governance#portable-binding, #1572)", () => {
  /**
   * The vectors of approval-governance#portable-binding-vectors, on the record
   * committed above: each case changes one thing from a base pair of that
   * record, authenticated under the expected issuer's key, and a reference
   * disclosing its approval_event_id and Mission anchors.
   */
  const AS2 = "https://as2.test";
  const anchorOf = (label: string) => `sha-256:${createHash("sha256").update(label, "utf8").digest("base64url")}`;
  const COMMITMENT = anchorOf("approval-context-1");
  const OTHER_COMMITMENT = anchorOf("approval-context-2");
  const SHA512_ANCHOR = `sha-512:${createHash("sha512").update("intent", "utf8").digest("base64url")}`;
  const expected = { issuer: ISS, resolveKey };
  const as2Key = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const as2Signer = {
    kid: "as2-key",
    sign: (input: string) => sign("sha256", Buffer.from(input), { key: as2Key.privateKey, dsaEncoding: "ieee-p1363" }),
  };
  const as2ResolveKey = (kid: string) => (kid === "as2-key" ? as2Key.publicKey : undefined);
  const unsignedOf = (r: ApprovalGovernanceRecord): UnsignedApprovalGovernanceRecord => {
    const { envelope: _e, ...unsigned } = r;
    return unsigned;
  };
  /** The record with a change, re-signed by the expected issuer's key. */
  const resigned = (change: Partial<UnsignedApprovalGovernanceRecord>) =>
    signApprovalGovernanceRecord({ ...unsignedOf(record), ...change }, kernel.statusSigner());
  const referenceOf = (r: ApprovalGovernanceRecord): PortableMissionReference => ({
    approval_event_id: r.approval_event_id,
    issuer: r.mission.issuer,
    intent_hash: r.mission.intent_hash,
    authority_hash: r.mission.authority_hash,
  });
  const portable = (
    r: ApprovalGovernanceRecord | undefined,
    reference: PortableMissionReference | undefined,
    expectedIssuer = expected,
  ) => checkPortableApprovalBinding({ record: r, reference, expectedIssuer });
  const failure = { outcome: "failure", commitment_agreement: undefined };
  const insufficient = { outcome: "insufficient_evidence", commitment_agreement: undefined };

  it("case 1: succeeds with commitment agreement established when both artifacts carry an equal commitment", () => {
    const r = resigned({ approval_context_commitment: COMMITMENT });
    expect(portable(r, { ...referenceOf(r), approval_context_commitment: COMMITMENT })).toMatchObject({
      outcome: "success",
      commitment_agreement: "established",
    });
  });

  it("case 2: succeeds without commitment agreement when only one artifact carries a commitment", () => {
    const r = resigned({ approval_context_commitment: COMMITMENT });
    expect(portable(r, referenceOf(r))).toMatchObject({ outcome: "success", commitment_agreement: "not_established" });
    expect(portable(record, { ...referenceOf(record), approval_context_commitment: COMMITMENT })).toMatchObject({
      outcome: "success",
      commitment_agreement: "not_established",
    });
  });

  it("case 3: succeeds without commitment agreement when neither artifact carries a commitment", () => {
    expect(record.approval_context_commitment).toBeUndefined();
    const result = portable(record, referenceOf(record));
    expect(result).toMatchObject({ outcome: "success", commitment_agreement: "not_established" });
    expect(result.reason).toMatch(/commitment agreement not established/);
  });

  it("case 4: fails when both artifacts carry a commitment with different values, or the same value under an unrecognized algorithm prefix", () => {
    const r = resigned({ approval_context_commitment: COMMITMENT });
    expect(portable(r, { ...referenceOf(r), approval_context_commitment: OTHER_COMMITMENT })).toMatchObject(failure);
    const unrecognized = resigned({ approval_context_commitment: SHA512_ANCHOR });
    expect(
      portable(unrecognized, { ...referenceOf(unrecognized), approval_context_commitment: SHA512_ANCHOR }),
    ).toMatchObject(failure);
  });

  it("case 5: fails when the reference names another Mission Issuer", () => {
    expect(portable(record, { ...referenceOf(record), issuer: AS2 })).toMatchObject(failure);
  });

  it("case 6: fails when the reference names another approval event, though every Mission anchor matches", () => {
    expect(portable(record, { ...referenceOf(record), approval_event_id: "ape-other" })).toMatchObject(failure);
  });

  it("case 7: fails when the reference's intent_hash differs", () => {
    expect(portable(record, { ...referenceOf(record), intent_hash: anchorOf("another intent") })).toMatchObject(failure);
  });

  it("case 8: fails when the reference's authority_hash differs", () => {
    expect(portable(record, { ...referenceOf(record), authority_hash: anchorOf("another set") })).toMatchObject(
      failure,
    );
  });

  it("case 9: is insufficient evidence when the reference does not disclose approval_event_id, though both anchors match, or any other required value", () => {
    const { approval_event_id: _a, ...anchorsOnly } = referenceOf(record);
    expect(portable(record, anchorsOnly)).toMatchObject(insufficient);
    for (const name of ["issuer", "intent_hash", "authority_hash"] as const) {
      const { [name]: _drop, ...partial } = referenceOf(record);
      expect(portable(record, partial)).toMatchObject(insufficient);
    }
  });

  it("case 10: fails when the record's signature does not verify, its payload differs from the record, or its envelope format is unsupported", () => {
    const header = { alg: "ES256", kid: "as-status", typ: AGR_JWS_TYP, cty: AGR_JWS_CTY };
    const forged = { ...record, envelope: { format: "jws-compact", value: envelopeWith(header, as2Key.privateKey) } };
    expect(portable(forged, referenceOf(record))).toMatchObject(failure);
    const edited = clone(record);
    edited.evaluation.evaluated_at = "2026-07-01T00:00:01.000Z";
    expect(portable(edited, referenceOf(record))).toMatchObject(failure);
    expect(portable({ ...record, envelope: { ...record.envelope, format: "none" } }, referenceOf(record))).toMatchObject(
      failure,
    );
  });

  it("case 11: fails when the record verifies only under key material not trusted for the expected issuer, including that of the issuer it names", () => {
    // The base record, signed by another issuer's key: it verifies under that key material.
    const foreign = signApprovalGovernanceRecord(unsignedOf(record), as2Signer);
    expect(() => verifyApprovalGovernanceRecord(foreign, { resolveKey: as2ResolveKey, mission })).not.toThrow();
    expect(portable(foreign, referenceOf(record))).toMatchObject(failure);
    // A record naming that issuer, signed by its own key, with a reference that agrees.
    const selfAsserted = signApprovalGovernanceRecord(
      { ...unsignedOf(record), mission: { ...record.mission, issuer: AS2 } },
      as2Signer,
    );
    expect(portable(selfAsserted, referenceOf(selfAsserted))).toMatchObject(failure);
    expect(portable(selfAsserted, referenceOf(selfAsserted), { issuer: AS2, resolveKey: as2ResolveKey })).toMatchObject({
      outcome: "success",
    });
  });

  it("fails when the record names a Mission Issuer other than the expected one whose key material authenticated it", () => {
    const misnamed = resigned({ mission: { ...record.mission, issuer: AS2 } });
    expect(portable(misnamed, referenceOf(misnamed))).toMatchObject(failure);
  });

  it("case 12: fails when the reference is a Mandate whose iss differs from its mission.issuer", () => {
    expect(portable(record, { ...referenceOf(record), kind: "mandate", iss: AS2 })).toMatchObject(failure);
    expect(portable(record, { ...referenceOf(record), kind: "mandate" })).toMatchObject(failure);
    expect(portable(record, { ...referenceOf(record), kind: "mandate", iss: ISS })).toMatchObject({ outcome: "success" });
  });

  it("case 13: is insufficient evidence when no record, or no Mission reference, is supplied", () => {
    expect(portable(undefined, referenceOf(record))).toMatchObject(insufficient);
    expect(portable(record, undefined)).toMatchObject(insufficient);
  });

  it("case 14: fails when a required value carries an unrecognized algorithm prefix or is otherwise malformed, on either artifact, even where both agree", () => {
    expect(portable(record, { ...referenceOf(record), intent_hash: SHA512_ANCHOR })).toMatchObject(failure);
    expect(portable(record, { ...referenceOf(record), approval_event_id: 42 })).toMatchObject(failure);
    // No record to compare against: still a failure, not insufficient evidence.
    expect(portable(undefined, { ...referenceOf(record), intent_hash: SHA512_ANCHOR })).toMatchObject(failure);
    // Both carry the same unrecognized prefix: never compared as if it were sha-256.
    const unrecognized = resigned({ mission: { ...record.mission, intent_hash: SHA512_ANCHOR } });
    expect(portable(unrecognized, referenceOf(unrecognized))).toMatchObject(failure);
    // The record's own value, where the reference does not disclose it.
    const { intent_hash: _i, ...withoutIntent } = referenceOf(unrecognized);
    expect(portable(unrecognized, withoutIntent)).toMatchObject(failure);
  });

  it("reports a disclosed mismatch as a failure even when another required value is undisclosed", () => {
    const { approval_event_id: _a, ...rest } = referenceOf(record);
    expect(portable(record, { ...rest, intent_hash: anchorOf("another intent") })).toMatchObject(failure);
  });

  it("reports its success as the portable approval-binding check, never as verification against the Mission Record or a re-check", () => {
    const result = portable(record, referenceOf(record));
    expect(result.check).toBe("portable-approval-binding");
    expect(Object.keys(result).sort()).toEqual(["check", "commitment_agreement", "outcome", "reason"]);
    expect(result.reason).not.toMatch(/verified|re-check/);
  });
});
