/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-integrity
 * (anchor `decision-evidence-integrity`, lines 775-872 at 41f66a4a): the ONE
 * signing/verification primitive that section fixes for Decision Evidence,
 * Execution Evidence, and Refusal Records alike (line 805: "This procedure
 * applies wherever verification of the `evidence_envelope` is described in
 * this document"), and that the Mission Receipt section reuses for its own
 * `evidence_envelope` (line 1311).
 *
 * NOT the `draft-mcguinness-mission-evidence-envelope.md` mechanism: that is a
 * different, unrelated document whose own Introduction disclaims covering
 * Decision Evidence, Execution Evidence, the Mission Receipt, Consent
 * Evidence, or Approval Governance (issue #649 thread). This module
 * implements runtime-evidence.md's OWN algorithm only.
 *
 * Lives beside `evidence.ts` (not in `@mission/core`) because `@mission/core`
 * is deliberately dependency-free: canonicalization (`canonicalize`,
 * `canonicalDigest`) lives there and is reused here, but the actual JOSE
 * signing/verification mechanics live at the leaf that already depends on
 * `jose` (this package), the same split `packages/orchestration/src/evidence.ts`
 * already uses (an injected signer callback, never a jose import in the
 * dependency-free orchestration package). If a second producer (Harness
 * Egress, Protected Event Receipt, issue #649's deferred slices B/C) comes
 * to need this exact algorithm, promoting this module to a shared package is
 * the right move then; not done here ahead of an actual second consumer.
 */

import { canonicalize, type JsonValue } from "@mission/core";
import { type CompactVerifyResult, CompactSign, compactVerify } from "jose";
import {
  evaluateCompromiseBoundary,
  type RecoveryProof,
  type SigningKeyStatus,
} from "@mission/core";

/**
 * @spec runtime-evidence.md#iana (lines 2058-2086 at 41f66a4a): the JWS
 * `typ` this document registers for the complete secured representation:
 * ONE value for every record kind the envelope secures (`cty` is what
 * distinguishes the record kind, never `typ`).
 */
export const RUNTIME_EVIDENCE_JWS_TYP = "application/mission-runtime-evidence+jws";

/** @spec runtime-evidence.md#iana lines 2087-2111. */
export const DECISION_EVIDENCE_MEDIA_TYPE = "application/mission-decision-evidence+json";
/** @spec runtime-evidence.md#iana lines 2112-2136. */
export const EXECUTION_EVIDENCE_MEDIA_TYPE = "application/mission-execution-evidence+json";
/** @spec runtime-evidence.md#iana lines 2137-2161. */
export const REFUSAL_RECORD_MEDIA_TYPE = "application/mission-refusal-record+json";
/** @spec runtime-evidence.md#iana lines 2162-2188. */
export const MISSION_RECEIPT_MEDIA_TYPE = "application/mission-receipt+json";

/** The wire `evidence_envelope` member (runtime-evidence.md, every REQUIRED occurrence). */
export interface EvidenceEnvelope {
  format: "jws-compact";
  value: string;
}

/** Anything `jose`'s `CompactSign`/`compactVerify` accept as a key. */
export type EvidenceKeyLike = Parameters<CompactSign["sign"]>[0];

/** An emitter-scoped signing identity: one key, one `kid`, ES256 by default (MTI, line 834). */
export interface EvidenceSigningKey {
  kid: string;
  key: EvidenceKeyLike;
  alg?: "ES256";
}

/** The `emitter` member every signed record carries (runtime-evidence.md #decision-evidence-object). */
export interface EvidenceEmitterRef {
  id: string;
  role: string;
}

/**
 * Sign a record under runtime-evidence.md's integrity algorithm. `record`
 * MUST NOT already carry `evidence_envelope`: the payload is the JCS
 * canonical bytes of exactly the object passed in (line 783-784, "the
 * `evidence_envelope` member removed during signing"). `cty` is the
 * REQUIRED-record-kind media type (line 841-847); `typ` is always
 * {@link RUNTIME_EVIDENCE_JWS_TYP}.
 */
export async function signEvidenceEnvelope(
  record: JsonValue,
  cty: string,
  signer: EvidenceSigningKey,
): Promise<EvidenceEnvelope> {
  const payload = new TextEncoder().encode(canonicalize(record));
  const value = await new CompactSign(payload)
    .setProtectedHeader({ alg: signer.alg ?? "ES256", kid: signer.kid, typ: RUNTIME_EVIDENCE_JWS_TYP, cty })
    .sign(signer.key);
  return { format: "jws-compact", value };
}

/** What {@link resolveEvidenceKey} returns: the key plus its current status (compromise-boundary rule). */
export interface EvidenceKeyResolution {
  key: EvidenceKeyLike;
  status?: SigningKeyStatus;
}

/**
 * Resolve the verification key for one record. MUST bind the key to the
 * emitter's scope and, when the record carries one, its `audience` (lines
 * 808-818): a resolver that ignores `emitter`/`audience` and matches on
 * `kid` alone does not implement that binding. Returns `undefined` when no
 * key is published for that `(kid, emitter, audience)` combination: the
 * verifier then rejects with `key_not_resolvable`, covering both an unknown
 * `kid` and a genuine emitter/scope/audience mismatch (a key that exists but
 * is not published for the scope/audience the record claims).
 */
export type EvidenceKeyResolver = (params: {
  kid: string;
  emitter: EvidenceEmitterRef;
  audience?: string;
}) => EvidenceKeyResolution | undefined;

export type EvidenceVerifyFailure =
  | "unsupported_format"
  | "malformed"
  | "key_not_resolvable"
  | "byte_mismatch"
  | "signature_invalid"
  | "typ_mismatch"
  | "cty_mismatch"
  | "compromised_key_unproven";

export type EvidenceVerifyResult = { valid: true } | { valid: false; reason: EvidenceVerifyFailure };

function base64UrlDecode(segment: string): Uint8Array {
  return Buffer.from(segment, "base64url");
}

/**
 * Verify one signed record end to end, per the ordered MUST-steps of
 * `#decision-evidence-integrity` (lines 786-872): decode payload, recompute
 * the envelope-free canonical bytes, require byte equality BEFORE the
 * signature is checked (line 792-797: "The signature authenticates only its
 * own embedded payload; an outer object that differs from that payload is
 * unauthenticated, regardless of whether the signature itself verifies"),
 * then verify the signature and the protected header (`kid` resolution,
 * `alg`, `typ`, `cty`), then apply the compromise-boundary rule if the
 * resolved key is flagged compromised (lines 820-827).
 *
 * `record` is the COMPLETE outer object, `evidence_envelope` included.
 * `cty` is the media type this call expects for the record kind being
 * verified (Decision/Execution/Refusal/Receipt); a mismatch is rejected
 * (`cty_mismatch`) so a signature over one record kind cannot be cross-used
 * for another (line 850-851).
 */
export async function verifyEvidenceEnvelope(
  record: { emitter: EvidenceEmitterRef; audience?: string; evidence_envelope: EvidenceEnvelope } & Record<
    string,
    unknown
  >,
  cty: string,
  resolveKey: EvidenceKeyResolver,
  recoveryProof?: RecoveryProof,
): Promise<EvidenceVerifyResult> {
  const envelope = record.evidence_envelope;
  if (envelope.format !== "jws-compact") {
    return { valid: false, reason: "unsupported_format" };
  }

  const parts = envelope.value.split(".");
  if (parts.length !== 3) {
    return { valid: false, reason: "malformed" };
  }
  const [protectedB64, payloadB64] = parts as [string, string, string];

  let header: { kid?: unknown; alg?: unknown; typ?: unknown; cty?: unknown };
  try {
    header = JSON.parse(Buffer.from(base64UrlDecode(protectedB64)).toString("utf8"));
  } catch {
    return { valid: false, reason: "malformed" };
  }
  if (typeof header.kid !== "string") {
    return { valid: false, reason: "malformed" };
  }

  const resolution = resolveKey({
    kid: header.kid,
    emitter: record.emitter,
    ...(record.audience !== undefined ? { audience: record.audience } : {}),
  });
  if (resolution === undefined) {
    return { valid: false, reason: "key_not_resolvable" };
  }

  // Step 1 + 2 + 3 (lines 789-797): decode the payload, recompute the
  // envelope-free canonical bytes, and require byte equality BEFORE the
  // signature is checked: a still-valid signature over a divergent outer
  // object is rejected here, never reached by step 4.
  const decodedPayload = base64UrlDecode(payloadB64);
  const { evidence_envelope: _drop, ...withoutEnvelope } = record;
  const recomputed = new TextEncoder().encode(canonicalize(withoutEnvelope as unknown as JsonValue));
  if (!timingSafeEqualBytes(decodedPayload, recomputed)) {
    return { valid: false, reason: "byte_mismatch" };
  }

  // Step 4 (lines 798-799, 829-851): verify the signature and the protected
  // header. ES256 is the only algorithm this implementation offers (line
  // 834-836 fixes it mandatory-to-implement).
  let verified: CompactVerifyResult;
  try {
    verified = await compactVerify(envelope.value, resolution.key, { algorithms: ["ES256"] });
  } catch {
    return { valid: false, reason: "signature_invalid" };
  }
  if (verified.protectedHeader.typ !== RUNTIME_EVIDENCE_JWS_TYP) {
    return { valid: false, reason: "typ_mismatch" };
  }
  if (verified.protectedHeader.cty !== cty) {
    return { valid: false, reason: "cty_mismatch" };
  }

  if (resolution.status?.compromised) {
    const outcome = evaluateCompromiseBoundary(resolution.status, recoveryProof);
    if (outcome.applicable && !outcome.verified) {
      return { valid: false, reason: "compromised_key_unproven" };
    }
  }

  return { valid: true };
}

function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}
