/**
 * @spec approval-governance#record, approval-governance#envelope,
 * approval-governance#atomic-commitment: the Approval Governance Record
 * (AGR): the policy, assertions, and evaluation standing behind one approval
 * event, signed by the Mission Issuer and committed in the same transaction
 * as the Mission it governs.
 *
 * The record is issuer-retained control-plane state: it never rides a token
 * or a protocol message. Its committed form is the signed record, `envelope`
 * included; it is immutable, and a later governance action is a new record
 * about a new event, never an edit (this store has no update path).
 *
 * Signing is SYNCHRONOUS (the Status key through
 * {@link MissionKernel.statusSigner}, the Carryover Evidence precedent): the
 * creation transaction is synchronous, so the record is signed inside it,
 * after evaluation and before persistence, with no post-commit window in which
 * an active Mission has an unsigned record.
 */

import { createHash, type KeyObject, verify } from "node:crypto";
import type { ActivationPolicyRef } from "@mission/core";
import { canonicalize, type JsonValue } from "@mission/core";
import type { Database } from "@mission/store";
import type { ApprovalBasis, ApprovalBasisGovernedPolicy, MissionRecord } from "./types.js";

/** @spec approval-governance#envelope: the JWS protected `typ`. */
export const AGR_JWS_TYP = "application/mission-approval-governance+jws";
/** @spec approval-governance#envelope: the JWS protected `cty`. */
export const AGR_JWS_CTY = "application/mission-approval-governance+json";
/** @spec approval-governance#envelope: the one `format` this document defines. */
export const AGR_ENVELOPE_FORMAT = "jws-compact";

/** @spec approval-governance#record: an assertion's principal. */
export interface AgrPrincipal {
  iss: string;
  sub: string;
}

/** @spec approval-governance#record: one decision assertion. */
export interface AgrAssertion {
  assertion_id: string;
  principal: AgrPrincipal;
  kind: "human" | "service" | "policy";
  decision: "approve" | "deny";
  decided_at: string;
  /**
   * The provenance under which this principal was authorized to decide: a
   * {@link HumanAuthority}, {@link PolicyAuthority} or {@link ServiceAuthority}
   * by `kind` ({@link assertAssertionAuthority}).
   */
  authority: Record<string, JsonValue>;
  reason?: string;
}

/** @spec approval-governance#assertion-authority: a `human` assertion's `authority`. */
export interface HumanAuthority {
  /** RFC 3339: when the principal authenticated for this decision. */
  auth_time: string;
  /** REQUIRED when the issuer possesses it at the approval event. */
  acr?: string;
  /** REQUIRED when the issuer possesses them at the approval event. */
  amr?: string[];
}

/** @spec approval-governance#assertion-authority: a `policy` assertion's `authority`. */
export interface PolicyAuthority {
  policy_id: string;
  version: string;
  /** RFC 3339: the human approval of this exact version, from retained, authenticated governance state. */
  approved_at: string;
  /** Corroborated from the same state, never the asserting party's word; equals the assertion's `principal`. */
  approved_by?: AgrPrincipal;
}

/** @spec approval-governance#assertion-authority: a `service` assertion's `authority`. */
export interface ServiceAuthority {
  logic_id: string;
  logic_version: string;
  /** REQUIRED where a model produced the decision, with `model_version`. */
  model_id?: string;
  model_version?: string;
}

/** @spec approval-governance#record: every member except the integrity `envelope`. */
export interface UnsignedApprovalGovernanceRecord {
  approval_event_id: string;
  mission: { issuer: string; intent_hash: string; authority_hash: string };
  approval_policy: ActivationPolicyRef;
  assertions: AgrAssertion[];
  evaluation: { decision: "approved"; evaluated_at: string; contributing: string[] };
}

/** @spec approval-governance#record, approval-governance#envelope: the signed, retained form. */
export interface ApprovalGovernanceRecord extends UnsignedApprovalGovernanceRecord {
  envelope: { format: string; value: string };
}

/** A record failed construction or verification; nothing it governs commits. */
export class ApprovalGovernanceError extends Error {}

const b64url = (bytes: Buffer | string): string =>
  (typeof bytes === "string" ? Buffer.from(bytes, "utf8") : bytes).toString("base64url");

/** The record without `envelope`: the exact object the signature's payload canonicalizes. */
function withoutEnvelope(record: UnsignedApprovalGovernanceRecord | ApprovalGovernanceRecord): JsonValue {
  const { envelope: _drop, ...rest } = record as ApprovalGovernanceRecord;
  return rest as unknown as JsonValue;
}

/**
 * @spec approval-governance#envelope: sign the evaluated record: a JWS
 * Compact Serialization over the JCS canonical bytes of the record with
 * `envelope` removed, under the issuer's published key (`kid`), with the
 * protected `typ` and `cty` this document fixes.
 */
export function signApprovalGovernanceRecord(
  record: UnsignedApprovalGovernanceRecord,
  signer: { sign: (input: string) => Buffer; kid: string },
): ApprovalGovernanceRecord {
  const header = { alg: "ES256", kid: signer.kid, typ: AGR_JWS_TYP, cty: AGR_JWS_CTY };
  const signingInput = `${b64url(canonicalize(header as unknown as JsonValue))}.${b64url(canonicalize(withoutEnvelope(record)))}`;
  const value = `${signingInput}.${b64url(signer.sign(signingInput))}`;
  return { ...record, envelope: { format: AGR_ENVELOPE_FORMAT, value } };
}

/**
 * @spec approval-governance#envelope: the record digest: the encoded SHA-256
 * over the JCS canonical bytes of the COMPLETE record, `envelope` included.
 * The one byte sequence every external binding names.
 */
export function approvalGovernanceRecordDigest(record: ApprovalGovernanceRecord): string {
  const canonical = canonicalize(record as unknown as JsonValue);
  return `sha-256:${createHash("sha256").update(canonical, "utf8").digest("base64url")}`;
}

/**
 * @spec approval-governance#envelope: the verifier's steps, in order, refusing
 * on any failure: resolve the signing key from the protected `kid`; verify the
 * signature and the exact protected `typ`/`cty`; recompute the JCS canonical
 * bytes of the record with `envelope` removed; require byte-for-byte equality
 * with the decoded payload; validate the mission binding against the Mission
 * record the record is retained with. An unsupported `format` is refused, never
 * accepted unverified.
 */
export function verifyApprovalGovernanceRecord(
  record: ApprovalGovernanceRecord,
  opts: { resolveKey: (kid: string) => KeyObject | undefined; mission: MissionRecord },
): ApprovalGovernanceRecord {
  const envelope = record.envelope;
  if (!envelope || envelope.format !== AGR_ENVELOPE_FORMAT || typeof envelope.value !== "string") {
    throw new ApprovalGovernanceError("unsupported or missing envelope format");
  }
  const parts = envelope.value.split(".");
  if (parts.length !== 3) throw new ApprovalGovernanceError("malformed jws-compact envelope");
  const [h, p, s] = parts as [string, string, string];
  let header: Record<string, unknown>;
  try {
    header = JSON.parse(Buffer.from(h, "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    throw new ApprovalGovernanceError("malformed protected header");
  }
  // Step 1: the signing key from the protected `kid`.
  const key = typeof header.kid === "string" ? opts.resolveKey(header.kid) : undefined;
  if (!key) throw new ApprovalGovernanceError("protected kid does not resolve to the issuer's key material");
  // Step 2: the signature and the protected header.
  if (header.alg !== "ES256") throw new ApprovalGovernanceError("unsupported alg");
  const signed = verify("sha256", Buffer.from(`${h}.${p}`, "utf8"), { key, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url"));
  if (!signed) throw new ApprovalGovernanceError("signature does not verify");
  if (header.typ !== AGR_JWS_TYP || header.cty !== AGR_JWS_CTY) {
    throw new ApprovalGovernanceError("protected typ and cty are not the Approval Governance pair");
  }
  // Steps 3 and 4: the payload is exactly the canonical record minus envelope.
  const payload = Buffer.from(p, "base64url").toString("utf8");
  if (payload !== canonicalize(withoutEnvelope(record))) {
    throw new ApprovalGovernanceError("record differs from its signed payload");
  }
  // Step 5: the mission binding.
  assertMissionBinding(record, opts.mission);
  return record;
}

/**
 * @spec approval-governance#record: the record is bound to the Mission it is
 * retained with: its `approval_event_id` and its `mission` member (`issuer`,
 * `intent_hash`, `authority_hash`) each equal the committed Mission's.
 */
export function assertMissionBinding(record: UnsignedApprovalGovernanceRecord, mission: MissionRecord): void {
  if (
    record.approval_event_id !== mission.approval_event_id ||
    record.mission.issuer !== mission.issuer ||
    record.mission.intent_hash !== mission.intent_hash ||
    record.mission.authority_hash !== mission.authority_hash
  ) {
    throw new ApprovalGovernanceError("record mission binding does not match the Mission record");
  }
}

const samePrincipal = (a: AgrPrincipal, b: AgrPrincipal): boolean => a.iss === b.iss && a.sub === b.sub;

/** Strict RFC 3339 date-time shape, checked before `Date.parse` (the lifecycle endpoint's rule). */
const RFC3339_DATE_TIME = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;
const isInstant = (v: unknown): boolean =>
  typeof v === "string" && RFC3339_DATE_TIME.test(v) && !Number.isNaN(Date.parse(v));
const isText = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/**
 * @spec approval-governance#assertion-authority: an assertion's `authority` is
 * the typed object its `kind` fixes. human: `auth_time` (RFC 3339), with `acr`
 * (a string) and `amr` (an array of strings) where present. policy:
 * `policy_id`, `version` and `approved_at` (RFC 3339), and an `approved_by`
 * that, where present, equals the assertion's `principal` (corroborated
 * provenance, never the asserting party's word). service: `logic_id` and
 * `logic_version`, with `model_id` and `model_version` together where a model
 * produced the decision. A record carrying any other shape does not commit.
 */
export function assertAssertionAuthority(a: AgrAssertion): void {
  const fail = (why: string): never => {
    throw new ApprovalGovernanceError(`assertion ${a.assertion_id} authority: ${why}`);
  };
  const au = a.authority as Record<string, unknown> | null;
  if (au === null || typeof au !== "object" || Array.isArray(au)) fail("is not an object");
  const m = au as Record<string, unknown>;
  switch (a.kind) {
    case "human":
      if (!isInstant(m.auth_time)) fail("auth_time is not an RFC 3339 timestamp");
      if (m.acr !== undefined && !isText(m.acr)) fail("acr is not a string");
      if (m.amr !== undefined && !(Array.isArray(m.amr) && m.amr.every(isText))) fail("amr is not an array of strings");
      break;
    case "policy": {
      if (!isText(m.policy_id) || !isText(m.version)) fail("policy_id and version are required strings");
      if (!isInstant(m.approved_at)) fail("approved_at is not an RFC 3339 timestamp");
      const by = m.approved_by as AgrPrincipal | undefined;
      if (by !== undefined && !(by !== null && typeof by === "object" && samePrincipal(by, a.principal))) {
        fail("approved_by is not the assertion's principal");
      }
      break;
    }
    case "service":
      if (!isText(m.logic_id) || !isText(m.logic_version)) fail("logic_id and logic_version are required strings");
      if ((m.model_id !== undefined || m.model_version !== undefined) && !(isText(m.model_id) && isText(m.model_version))) {
        fail("model_id and model_version are required together");
      }
      break;
    default:
      fail(`kind ${String((a as { kind: unknown }).kind)} is not human, policy or service`);
  }
}

/**
 * @spec approval-governance#accountable-assertion: the accountable-approver
 * rule for the Mission's approval basis. Under `direct`, EXACTLY ONE `human`
 * assertion of `consent_principal` approves; under `governed_policy`, EXACTLY
 * ONE `policy` assertion of `consent_principal` that names the deciding policy
 * approves; any other named standing-consent basis satisfies the rule through
 * its authenticated `approval_basis`, so no assertion is required (and none is
 * fabricated). A `service` assertion never satisfies the rule. Returns the
 * accountable assertion, or undefined where the basis has none; a record that
 * fails the rule does not commit.
 */
export function assertAccountableApprover(
  record: UnsignedApprovalGovernanceRecord,
  basis: ApprovalBasis,
): AgrAssertion | undefined {
  const approvesAs = (a: AgrAssertion, kind: "human" | "policy"): boolean =>
    a.kind === kind && a.decision === "approve" && samePrincipal(a.principal, basis.consent_principal);
  let kind: "human" | "policy";
  let matching: AgrAssertion[];
  switch (basis.type) {
    case "direct":
      kind = "human";
      matching = record.assertions.filter((a) => approvesAs(a, kind));
      break;
    case "governed_policy": {
      kind = "policy";
      const deciding = basis.activation.policy;
      matching = record.assertions.filter(
        (a) => approvesAs(a, kind) && a.authority.policy_id === deciding.id && a.authority.version === deciding.version,
      );
      break;
    }
    default:
      return undefined;
  }
  if (matching.length !== 1) {
    throw new ApprovalGovernanceError(
      `${basis.type} record: exactly one approve assertion of kind ${kind} must match consent_principal`,
    );
  }
  return matching[0];
}

/**
 * @spec approval-governance#assertion-requirements,
 * approval-governance#governed-policy-record: the record under
 * `governed_policy`. Its accountable assertion
 * ({@link assertAccountableApprover}) is the one `policy` assertion of
 * `approval_basis.consent_principal` that names the deciding policy's `id` and
 * `version`, with `approved_at` equal to `approval_basis.approved_at`. The
 * record's `approval_policy` is the consented root, the evaluation approved,
 * and it relies on the accountable assertion. A record failing any of these
 * does not commit.
 */
export function assertGovernedPolicyRecord(
  record: UnsignedApprovalGovernanceRecord,
  basis: ApprovalBasisGovernedPolicy,
): void {
  const fail = (why: string): never => {
    throw new ApprovalGovernanceError(`governed_policy record: ${why}`);
  };
  const ids = record.assertions.map((a) => a.assertion_id);
  if (new Set(ids).size !== ids.length) fail("assertion_id values are not unique");
  for (const x of record.assertions) {
    try {
      assertAssertionAuthority(x);
    } catch (e) {
      fail((e as Error).message);
    }
  }
  if (record.approval_policy.digest !== basis.root_commitment) {
    fail("approval_policy.digest is not the consented root's commitment");
  }
  if (record.evaluation.decision !== "approved") fail("evaluation did not approve");
  if (!record.evaluation.contributing.every((id) => ids.includes(id))) {
    fail("evaluation relies on an assertion the record does not carry");
  }
  const a = assertAccountableApprover(record, basis) as AgrAssertion;
  if (a.authority.policy_id !== basis.adjudication.policy.id || a.authority.version !== basis.adjudication.policy.version) {
    fail("the accountable assertion does not name the deciding policy");
  }
  if (a.authority.approved_at !== basis.approved_at) {
    fail("the accountable assertion's approved_at is not approval_basis.approved_at");
  }
  if (!record.evaluation.contributing.includes(a.assertion_id)) {
    fail("the evaluation does not rely on the accountable assertion");
  }
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS approval_governance_records (
  approval_event_id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL UNIQUE,
  issuer TEXT NOT NULL,
  record_json TEXT NOT NULL,
  record_digest TEXT NOT NULL
) STRICT;
`;

/**
 * @spec approval-governance#atomic-commitment: the retained, signed records,
 * on the kernel database. Written only inside the creation transaction of the
 * Mission each governs, keyed by its `approval_event_id` (one record per
 * approval event, so a retried or concurrent activation of one event commits
 * one record). No update or delete path: a committed record is immutable.
 */
export class ApprovalGovernanceRecordStore {
  constructor(private readonly db: Database) {
    this.db.exec(SCHEMA);
  }

  /** Retain a signed record. Refused outside its Mission's creation transaction. */
  retainInCallerTx(missionId: string, record: ApprovalGovernanceRecord): void {
    if (!this.db.inTransaction) {
      throw new Error("an Approval Governance Record is retained only inside its Mission's creation transaction");
    }
    this.db
      .prepare(
        `INSERT INTO approval_governance_records (approval_event_id, mission_id, issuer, record_json, record_digest)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        record.approval_event_id,
        missionId,
        record.mission.issuer,
        JSON.stringify(record),
        approvalGovernanceRecordDigest(record),
      );
  }

  /** The record committed with a Mission, or undefined. */
  forMission(missionId: string): ApprovalGovernanceRecord | undefined {
    const row = this.db
      .prepare("SELECT record_json FROM approval_governance_records WHERE mission_id = ?")
      .get(missionId) as { record_json: string } | undefined;
    return row ? (JSON.parse(row.record_json) as ApprovalGovernanceRecord) : undefined;
  }

  /** How many records are committed (an audit read). */
  count(): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM approval_governance_records").get() as { n: number }).n;
  }
}
