/**
 * Shared fixture for PDP tests that reach the idempotency claim step (#917):
 * an Exact claim domain on a real file in a fresh temporary directory, over
 * either the shipped Enforcement Scope Statement or a fixture one that also
 * mediates `privileged_administration` (which the shipped deployment does
 * not offer), and a fresh well-formed `idempotency_key` per call.
 */

import { randomUUID } from "node:crypto";
import type { EnforcementScopeStatement } from "../src/enforcement-scope.js";
import { type ClaimDomainOptions, type IdempotencyClaimDomain, openEphemeralClaimDomain } from "../src/idempotency-claims.js";
import { RUNTIME_POSTURE } from "../src/runtime-posture.js";

/** The shipped statement's claim owner. */
export const CLAIM_OWNER = RUNTIME_POSTURE.pdps[0] as string;

/**
 * The shipped statement plus a fixture `privileged_administration` class:
 * mediated, with a published lease and the same Exact claim domain the two
 * shipped high-consequence classes name.
 */
export function statementWithPrivilegedAdministration(): EnforcementScopeStatement {
  const statement = structuredClone(RUNTIME_POSTURE) as unknown as EnforcementScopeStatement & {
    mediated_scope: { action_classes: string[] };
    extensions: { transaction_assurance: Array<Record<string, unknown>> };
  };
  statement.mediated_scope.action_classes = [...statement.mediated_scope.action_classes, "privileged_administration"];
  const template = statement.extensions.transaction_assurance[0] as Record<string, unknown>;
  statement.extensions.transaction_assurance = [
    ...statement.extensions.transaction_assurance,
    { ...template, mediated_class_or_scope: "privileged_administration" },
  ];
  return statement;
}

/** An Exact claim domain on a fresh temporary file; all three classes by default. */
export function openTestClaims(
  options: Partial<Omit<ClaimDomainOptions, "file">> = {},
): IdempotencyClaimDomain {
  return openEphemeralClaimDomain({
    owner: CLAIM_OWNER,
    statement: statementWithPrivilegedAdministration(),
    ...options,
  });
}

/** A fresh, well-formed `idempotency_key`: one intended execution. */
export function freshKey(): string {
  return `idem_${randomUUID()}`;
}
