/**
 * @spec mission#record-content-members, mission#record-principal-members,
 * mission#submission-envelope (#2009, P4): the core-standalone example
 * fixture's Mission Record, read by the kernel's own record code. The
 * kernel resolves each anchor over the retained record and refuses a
 * recorded anchor that differs; it resolves the `direct` basis members the
 * record omits to their implied values; and its intake accepts the
 * fixture's Submission envelope.
 *
 * This checks digests and record shape only. It does not show that the AS
 * accepts the fixture's `payment_initiation` entry: the AS supports only
 * `mission_resource_access`, and the fixture's README says so.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  AnchorMismatchError,
  assertDirectBasisConsistent,
  type DirectBasisRecord,
  directBasisMembers,
  type MissionRecord,
  RECOGNIZED_RECORD_MEMBERS,
  resolvedAnchors,
  validateMissionIntentSubmission,
} from "../src/index.js";

interface Fixture {
  anchors: { intent_hash: string; proposal_hash: string; authority_hash: string };
  submission: { mission_intent: { intent: unknown } };
  record: MissionRecord;
  member_presence: {
    present: string[];
    implied: Record<"approval_basis.activation" | "approval_basis.activation_actor" | "approval_basis.root_commitment", unknown>;
    absent: Record<string, string>;
  };
}

const FIXTURE = JSON.parse(
  readFileSync(
    fileURLToPath(new URL("../../../../vectors/core-standalone/core-standalone.json", import.meta.url)),
    "utf8",
  ),
) as Fixture;

const { record } = FIXTURE;

/** The controlled clock: the record's creation instant. */
const CREATED = new Date(record.created_at);

describe("core-standalone fixture record (vectors/core-standalone)", () => {
  it("resolves each recorded anchor to the fixture's expected digest", () => {
    expect(resolvedAnchors(record)).toEqual(FIXTURE.anchors);
  });

  it("computes the same anchors from the record's objects when the record omits them", () => {
    const { intent_hash: _i, authority_hash: _a, proposal_hash: _p, ...bare } = record;
    expect(resolvedAnchors(bare as MissionRecord)).toEqual(FIXTURE.anchors);
  });

  it("refuses the record when a recorded anchor is not the anchor over its retained object", () => {
    const changed = { ...record, authority_set: [{ ...record.authority_set[0], creditorName: "Merchant B" }] };
    expect(() => resolvedAnchors(changed as MissionRecord)).toThrow(AnchorMismatchError);
  });

  it("resolves the omitted direct-basis members to the implied values the fixture lists", () => {
    const direct = record as unknown as DirectBasisRecord;
    expect(() => assertDirectBasisConsistent(direct)).not.toThrow();
    expect(directBasisMembers(direct)).toEqual({
      activation: FIXTURE.member_presence.implied["approval_basis.activation"],
      activation_actor: FIXTURE.member_presence.implied["approval_basis.activation_actor"],
      root_commitment: FIXTURE.member_presence.implied["approval_basis.root_commitment"],
    });
    expect(record.approval_basis).toStrictEqual({ type: "direct", consent_principal: record.subject });
  });

  it("carries only members the AS recognizes, as the presence lists state", () => {
    expect(Object.keys(record)).toEqual(FIXTURE.member_presence.present);
    for (const name of Object.keys(record)) expect(RECOGNIZED_RECORD_MEMBERS.has(name), name).toBe(true);
    for (const name of Object.keys(FIXTURE.member_presence.absent)) {
      const [top, inner] = name.split(".");
      const holder = inner ? (record as unknown as Record<string, Record<string, unknown>>)[top as string] : record;
      expect(holder, name).not.toHaveProperty(inner ?? (top as string));
    }
  });

  it("accepts the fixture's Submission envelope at intake and keeps the Intent unchanged", () => {
    const submission = validateMissionIntentSubmission(JSON.stringify(FIXTURE.submission.mission_intent), {}, { now: CREATED });
    expect(submission.intent).toEqual(record.intent);
    expect(submission.evidence).toBeUndefined();
  });
});
