/**
 * @spec mission#submission-processing (#1897, D1035): the approval context a
 * rendering commits, and a decision re-establishes, covers the material
 * verified provenance as its normalized facts. It omits each element's
 * `verified_at`, which the AS generates at each verification, and no other
 * member: `type`, `artifact_hash` and `facts`, including any timestamp within
 * `facts`, stay committed.
 *
 * Deterministic: each verification instant is a fixed value, never the clock.
 * Pure, in-memory kernel, no network.
 */

import { generateKeyPair } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { approvalContext, changedParts } from "../src/adapters/approval-render-revision.js";
import type { AuthoritySourceResolution } from "../src/kernel/authority-source.js";
import { type AuthorityEntry, type IntentSubmissionEvidenceFact, MissionKernel, validateMissionIntent } from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RESOURCE = "https://api.test/invoices";
const ENTRY: AuthorityEntry = { type: "mission_resource_access", resource: RESOURCE, actions: ["invoice.read"] };
const INTENT = validateMissionIntent(
  JSON.stringify({ goal: "Reconcile invoices", target_resources: [RESOURCE], expires_at: "2099-01-01T00:00:00Z" }),
);
/** The source a rendering established; fixed, so only the evidence varies. */
const RESOLVED = { rootId: "root", catalogRevision: "rev-1", provenance: { type: "user_delegated" } } as unknown as AuthoritySourceResolution;

const FACTS = { admission_issuer: "https://admission.example", admitted_at: "2026-10-01T00:00:00Z" };
const fact = (over: Partial<IntentSubmissionEvidenceFact> = {}): IntentSubmissionEvidenceFact => ({
  type: "urn:test:intent-evidence:stub",
  artifact_hash: "sha-256:artifact-one",
  verified_at: "2026-10-30T09:00:00Z",
  facts: { ...FACTS },
  ...over,
});

let kernel: MissionKernel;
beforeAll(async () => {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  kernel = new MissionKernel({
    issuer: ISS,
    policy: { policy_version: "approval-context-provenance-1", ceiling: [ENTRY] },
    authoritySourceCatalog: testAuthoritySourceCatalog([ENTRY], ["agent"], ["approver"]),
    statusKey: privateKey,
    statusKid: "as-status",
  });
});

const context = (evidence?: IntentSubmissionEvidenceFact[]) =>
  approvalContext({
    kernel,
    issuer: ISS,
    intent: INTENT,
    proposal: undefined,
    authority: [ENTRY],
    clientId: "agent",
    subject: "alice",
    resolved: RESOLVED,
    scopeProjection: undefined,
    expiresAt: "2099-01-01T00:00:00Z",
    ...(evidence ? { submissionEvidence: evidence } : {}),
  });

describe("the approval context commits the verified submission facts without each verification's instant (@spec mission#submission-processing, #1897, D1035)", () => {
  it("two verifications of identical facts at distinct instants commit the same context", () => {
    const rendered = context([fact({ verified_at: "2026-10-30T09:00:00Z" })]);
    const decided = context([fact({ verified_at: "2026-10-30T09:05:00Z" })]);
    expect(rendered.context.submission_evidence).not.toBeNull();
    expect(decided.commitment).toBe(rendered.commitment);
    expect(changedParts(rendered.context, decided.context)).toEqual([]);
  });

  it("a change to type, artifact_hash or any member of facts, a timestamp within facts included, changes only the submission_evidence part", () => {
    const base = context([fact()]);
    for (const changed of [
      fact({ type: "urn:test:intent-evidence:other" }),
      fact({ artifact_hash: "sha-256:artifact-two" }),
      fact({ facts: { ...FACTS, admission_issuer: "https://admission-changed.example" } }),
      fact({ facts: { ...FACTS, admitted_at: "2026-10-02T00:00:00Z" } }),
    ]) {
      const current = context([changed]);
      expect(current.commitment, JSON.stringify(changed)).not.toBe(base.commitment);
      expect(changedParts(base.context, current.context)).toEqual(["submission_evidence"]);
    }
  });

  it("no presented evidence commits null, and presenting evidence changes the context", () => {
    const none = context();
    expect(none.context.submission_evidence).toBeNull();
    expect(changedParts(none.context, context([fact()]).context)).toEqual(["submission_evidence"]);
  });
});
