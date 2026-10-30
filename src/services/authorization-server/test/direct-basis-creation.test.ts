/**
 * @spec mission#record-principal-members (#1912, D1048): for a `direct`
 * basis, `activation`, `activation_actor` and `root_commitment` are OPTIONAL,
 * and each MUST match its implied value when present. The AS refuses a record
 * that contradicts one at creation: `insertRecord`, the funnel every creating
 * body reaches, checks the basis before any write, so these witnesses call
 * the funnel itself rather than the standalone validator. A record that omits
 * the members is accepted and stored without them: nothing inserts an implied
 * value.
 */
import { DERIVATION_POLICY } from "@mission/demo-data";
import { generateKeyPair } from "jose";
import { describe, expect, it } from "vitest";
import {
  type ApprovalBasisDirect,
  DirectBasisMismatchError,
  MissionKernel,
  type MissionRecord,
  newMissionId,
  validateMissionIntent,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISSUER = "https://as.test";
const MEMBERS = ["activation", "activation_actor", "root_commitment"] as const;
type Member = (typeof MEMBERS)[number];

/** A kernel holding one approved direct Mission, the source a copy inherits. */
async function approved() {
  const { privateKey } = await generateKeyPair("ES256");
  const kernel = new MissionKernel({
    issuer: ISSUER,
    policy: DERIVATION_POLICY as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(DERIVATION_POLICY.ceiling, ["ap-agent"], ["bob"]),
    statusKey: privateKey,
    statusKid: "as-status",
  });
  const original = kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({
        goal: "Review",
        target_resources: [DERIVATION_POLICY.ceiling[0].resource],
        expires_at: new Date(Date.now() + 3_600_000).toISOString(),
      }),
    ),
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: "review-original",
  });
  return { kernel, original };
}

/** A copy of `original` under its own approval event, carrying `basis`. */
function copyWith(original: MissionRecord, event: string, basis: ApprovalBasisDirect): MissionRecord {
  return { ...original, id: newMissionId(), approval_event_id: event, approval_basis: basis };
}

/** Commit `record` through the creation funnel, inheriting `original`'s source. */
function create(kernel: MissionKernel, original: MissionRecord, record: MissionRecord): void {
  kernel.insertRecord(record, undefined, {
    source: { inherited: kernel.committedSourceBinding(original.id) },
    audiences: "fresh",
  });
}

describe("direct basis consistency at record creation (@spec mission#record-principal-members)", () => {
  it.each(MEMBERS)("refuses a direct record whose present %s contradicts its implied value before storing it", async (member) => {
    const { kernel, original } = await approved();
    try {
      const event = "review-copy";
      const principal = original.approval_basis.consent_principal;
      const basis: ApprovalBasisDirect = {
        type: "direct",
        consent_principal: principal,
        activation: { approval_event_id: event },
        activation_actor: principal,
        root_commitment: original.authority_hash,
      };
      if (member === "activation") basis.activation = { approval_event_id: "wrong-event" };
      if (member === "activation_actor") basis.activation_actor = { iss: ISSUER, sub: "wrong-person" };
      if (member === "root_commitment") basis.root_commitment = "sha-256:wrong-root";
      const record = copyWith(original, event, basis);
      let error: unknown;
      try {
        create(kernel, original, record);
      } catch (e) {
        error = e;
      }
      expect({ refused: error !== undefined, stored: kernel.get(record.id) !== undefined }).toEqual({
        refused: true,
        stored: false,
      });
      // Refused by the basis check, naming the member, not by another funnel check.
      expect(error).toBeInstanceOf(DirectBasisMismatchError);
      expect((error as DirectBasisMismatchError).member).toBe(member);
      expect(kernel.findByApprovalEvent(event)).toBeUndefined();
    } finally {
      kernel.close();
    }
  });

  it("stores a direct record whose three members are present at their implied values", async () => {
    // The control for the refusals above: the same copy, every member at its
    // implied value, is committed, so each refusal is the contradiction alone.
    const { kernel, original } = await approved();
    try {
      const event = "review-copy";
      const principal = original.approval_basis.consent_principal;
      const basis: ApprovalBasisDirect = {
        type: "direct",
        consent_principal: principal,
        activation: { approval_event_id: event },
        activation_actor: principal,
        root_commitment: original.authority_hash,
      };
      const record = copyWith(original, event, basis);
      create(kernel, original, record);
      expect(kernel.get(record.id)?.approval_basis).toStrictEqual(basis);
    } finally {
      kernel.close();
    }
  });

  it("stores a direct record that omits any or all of the three members, and reads it back without them", async () => {
    const { kernel, original } = await approved();
    try {
      const principal = original.approval_basis.consent_principal;
      const variants: [event: string, omitted: readonly Member[]][] = [
        ["omit-all", MEMBERS],
        ...MEMBERS.map((m): [string, readonly Member[]] => [`omit-${m}`, [m]]),
      ];
      for (const [event, omitted] of variants) {
        const full: ApprovalBasisDirect = {
          type: "direct",
          consent_principal: principal,
          activation: { approval_event_id: event },
          activation_actor: principal,
          root_commitment: original.authority_hash,
        };
        const basis = { ...full };
        for (const m of omitted) delete basis[m];
        const record = copyWith(original, event, basis);
        create(kernel, original, record);
        // The committed basis is exactly the one submitted: no implied member
        // was inserted at creation, and none is filled in on read.
        const stored = kernel.get(record.id);
        expect(stored?.approval_basis, event).toStrictEqual(basis);
        for (const m of omitted) expect(stored?.approval_basis, `${event}: ${m}`).not.toHaveProperty(m);
      }
    } finally {
      kernel.close();
    }
  });
});
