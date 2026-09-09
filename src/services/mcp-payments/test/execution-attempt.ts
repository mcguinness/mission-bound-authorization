/**
 * @spec runtime-evidence#execution-evidence-object (issue #786)
 *
 * A synthetic {@link ExecutionAttempt} for tests that exercise one
 * post-permit recheck directly, without driving a whole enforcement pass.
 * The production path builds this context in `Pep.enforceInner`, only after
 * the permit's Decision Evidence verified and was retained; a test that
 * calls `reverify`/`reverifyList`/`reverifyCapability` in isolation supplies
 * the same shape here.
 *
 * `executionId` defaults to a fresh identity per call, which is the rule the
 * production path follows: one identity per disposition attempt. A test
 * proving the retry contract passes the SAME identity twice on purpose.
 */

import { newRecordId } from "@mission/pdp";
import { CANONICAL_RESOURCE, type ExecutionAttempt } from "../src/index.js";

export function testAttempt(input: {
  mission: { id: string; issuer: string; authority_hash?: string };
  action: string;
  /** The digest the linked Decision Evidence carried, absent when it carried none. */
  authorizedParameterDigest?: string;
  /** What a fresh observation of the effective parameters yields at the disposition. */
  observeEffectiveDigest?: () => string | undefined;
  evaluationId?: string;
  executionId?: string;
}): ExecutionAttempt {
  const evaluationId = input.evaluationId ?? newRecordId("dec");
  return {
    evaluationId,
    mission: input.mission,
    audience: CANONICAL_RESOURCE,
    action: input.action,
    ...(input.authorizedParameterDigest !== undefined
      ? { authorizedParameterDigest: input.authorizedParameterDigest }
      : {}),
    executionId: input.executionId ?? newRecordId("exe"),
    permitId: evaluationId,
    joinKey: `op:${input.mission.id}:${input.action}`,
    observeEffectiveDigest: input.observeEffectiveDigest ?? (() => undefined),
  };
}
