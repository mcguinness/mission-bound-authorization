/**
 * @spec request-provenance#verification, request-provenance#replay,
 * request-provenance#recorded-facts (#939 slice 2a-2, D1119)
 *
 * The `mission-request-provenance` Intent Submission Evidence type as one
 * authorization server registers it: the pure verifier of steps 1 to 9
 * (`request-provenance.ts`), step 10's reservation in the AS's replay store
 * (`request-provenance-store.ts`), and the acceptance record later steps of
 * an accepted submission rely on.
 *
 * - **Carriers.** Only a carrier that owns an admission scope verifies the
 *   type: PAR, whose wrapper commits the scope on its `201` and releases it
 *   on anything else. Every other carrier (device authorization, template
 *   dispatch, child creation, expansion) calls verification with no scope
 *   and is refused before any signature work: an unwired carrier fails
 *   closed.
 * - **Verification work** (#1962, D1151). The dispatch charges one unit
 *   before calling `verify`. Verification performs exactly one signature
 *   verification (step 4), fetches no key and walks no chain, and the
 *   configured key's import is cached, so it charges nothing further.
 * - **Later steps** (D1119 Q1). The authorization endpoint's re-validation
 *   of the stored pushed request, the approval rendering, the decision and a
 *   deferred activation call `resume` with the carrier's reference for the
 *   accepted submission. It verifies no signature and is charged nothing. It
 *   returns the original verification's facts and time only when the
 *   committed acceptance record matches that submission, this AS, the exact
 *   Intent, the step's presenter (no `cnf`: PAR establishes none) and the
 *   byte-equal assertion; a missing record or any mismatch refuses. `exp`
 *   and the capture age passing after acceptance refuse nothing (Q2).
 */

import { computeAnchor, type JsonValue, MISSION_INTENT_EVIDENCE_TYP, parseStrictJson } from "@mission/core";
import {
  type IntentSubmissionEvidenceResumeInput,
  type IntentSubmissionEvidenceResumed,
  type IntentSubmissionEvidenceType,
  type IntentSubmissionEvidenceVerifyInput,
  IntentError,
} from "./intent.js";
import {
  checkRequestProvenanceEntry,
  REQUEST_PROVENANCE_EVIDENCE_TYPE,
  type RequestProvenanceTrust,
  verifyRequestProvenance,
} from "./request-provenance.js";
import type { RequestProvenanceRecord, RequestProvenanceStore } from "./request-provenance-store.js";

export interface RequestProvenanceEvidenceTypeOptions {
  /** The deployment's declared bounds and authorized signers. */
  trust: RequestProvenanceTrust;
  /** The replay store: reservations and acceptance records. */
  store: RequestProvenanceStore;
  /**
   * How long, from acceptance, the acceptance record must outlive `exp`
   * plus the clock-skew allowance: the longest pending operation that can
   * follow the accepted submission.
   */
  acceptanceRetentionSeconds: number;
  /** The AS's clock, for committing. Default the system clock. */
  now?: () => Date;
}

function refuse(message: string): IntentError {
  return new IntentError("invalid_mission_intent_evidence", `${REQUEST_PROVENANCE_EVIDENCE_TYPE}: ${message}`);
}

/** The assertion's (`iss`, `jti`), read from its claims set without verifying it: a lookup key only. */
function pairOf(assertion: string): { iss: string; jti: string } | undefined {
  const segments = assertion.split(".");
  if (segments.length !== 3) return undefined;
  let claims: JsonValue;
  try {
    claims = parseStrictJson(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(segments[1] as string, "base64url")));
  } catch {
    return undefined;
  }
  if (claims === null || typeof claims !== "object" || Array.isArray(claims)) return undefined;
  const iss = Object.hasOwn(claims, "iss") ? claims.iss : undefined;
  const jti = Object.hasOwn(claims, "jti") ? claims.jti : undefined;
  return typeof iss === "string" && typeof jti === "string" ? { iss, jti } : undefined;
}

/**
 * The `mission-request-provenance` evidence type for one authorization
 * server, bound to its trust configuration and replay store.
 */
export function createRequestProvenanceEvidenceType(
  opts: RequestProvenanceEvidenceTypeOptions,
): IntentSubmissionEvidenceType {
  const now = opts.now ?? (() => new Date());
  const retentionMs = opts.acceptanceRetentionSeconds * 1000;
  // One runner per store, so every hold of a submission names the same one
  // and the scope settles them in one transaction (#2060 review).
  const atomically = (steps: () => void): void => opts.store.transaction(steps);
  return {
    validate(entry) {
      const refused = checkRequestProvenanceEntry(entry);
      if (refused !== undefined) throw refuse(`step 1: ${refused.reason}`);
    },

    async verify(input: IntentSubmissionEvidenceVerifyInput) {
      // Only a carrier that decides acceptance and owns an admission scope
      // verifies the type; any other is refused before any signature work.
      const admission = input.admission;
      if (admission === undefined) {
        throw refuse("this submission carrier does not accept the evidence type");
      }
      const result = await verifyRequestProvenance(input.entry, {
        issuer: input.issuer,
        now: input.now,
        trust: opts.trust,
        intentHash: input.intentHash,
        presenter: input.presenter,
      });
      if (!result.ok) throw refuse(`step ${result.step}: ${result.reason}`);
      // 10. Reserve (iss, jti) with the acceptance record, atomically.
      const record: RequestProvenanceRecord = {
        iss: result.reservation.iss,
        jti: result.reservation.jti,
        expiresAtMs: result.reservation.expiresAt * 1000,
        issuer: input.issuer,
        intentHash: input.intentHash,
        presenter: structuredClone(input.presenter),
        assertion: (input.entry as unknown as { assertion: string }).assertion,
        artifactHash: computeAnchor(MISSION_INTENT_EVIDENCE_TYP, input.issuer, input.entry as never),
        verifiedAt: input.now.toISOString(),
        facts: result.facts,
      };
      const token = await opts.store.reserve(record, input.now.getTime());
      if (token === undefined) {
        throw refuse("step 10: replay: another submission has reserved or committed this (iss, jti)");
      }
      admission.hold({
        prepare(ref) {
          // One reading of the clock for the check and the commit it returns.
          const at = now().getTime();
          if (!opts.store.committable(token, at)) return undefined;
          return () => {
            if (!opts.store.commit(token, ref, at, at + retentionMs)) {
              throw new Error("a prepared (iss, jti) reservation did not commit");
            }
          };
        },
        release() {
          opts.store.release(token);
        },
        atomically,
      });
      return result.facts;
    },

    async resume(input: IntentSubmissionEvidenceResumeInput): Promise<IntentSubmissionEvidenceResumed> {
      const refused = checkRequestProvenanceEntry(input.entry);
      if (refused !== undefined) throw refuse(`step 1: ${refused.reason}`);
      const assertion = (input.entry as unknown as { assertion: string }).assertion;
      const pair = pairOf(assertion);
      const record = pair ? opts.store.accepted(pair.iss, pair.jti, input.now.getTime()) : undefined;
      if (record === undefined) throw refuse("no acceptance record for this submission's assertion");
      if (record.submissionRef !== input.accepted.ref) {
        throw refuse("the acceptance record belongs to another submission");
      }
      if (record.assertion !== assertion) throw refuse("the evidence entry is not the one accepted");
      if (record.issuer !== input.issuer) throw refuse("the acceptance record names another authorization server");
      if (record.intentHash !== input.intentHash) throw refuse("the acceptance record binds another Intent");
      // The presenter the step established, exactly: its client, and a
      // confirmation key only where the accepted exchange established the
      // same one. PAR establishes none, so a step that presents one differs.
      if (
        record.presenter.clientId !== input.presenter.clientId ||
        record.presenter.cnf?.jkt !== input.presenter.cnf?.jkt
      ) {
        throw refuse("the acceptance record binds another presenter");
      }
      return { facts: structuredClone(record.facts), verified_at: record.verifiedAt };
    },
  };
}
